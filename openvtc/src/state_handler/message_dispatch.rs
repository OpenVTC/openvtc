//! Inbound DIDComm message dispatch for the TUI.
//!
//! Messages that don't need human input are auto-processed.
//! Messages requiring user decisions are queued as tasks in the inbox.
//!
//! The pure protocol logic (validators, the join-receipt / credential-issue
//! handlers, the VRC vetting + proof verification, and the replay guard) lives
//! in [`openvtc_core::messaging`] so it is testable without the TUI crate. This
//! module keeps only the async I/O orchestrator [`process_inbound_message`],
//! which imports and calls into core.

use std::sync::Arc;

use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use openvtc_core::didcomm::Messaging;
use openvtc_core::join::COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE;
use openvtc_core::messaging::{
    SeenMessages, check_message_age, check_task_capacity, create_finalize_message,
    credential_in_issue, credential_issue_admissible, handle_community_profile_show_response,
    handle_credential_issue, handle_join_status_response, handle_join_submit_receipt,
    handle_join_trust_task_error, handle_join_verdict, handle_member_removal_notice,
    is_trust_task_error_type, read_problem_report, require_thid, validate_did, verify_vrc_proof,
    vet_vrc_issued,
};
use openvtc_core::personhood::{
    PERSONHOOD_ASSERT_RESPONSE_TYPE, PERSONHOOD_CHALLENGE_RESPONSE_TYPE,
};
use openvtc_core::{
    MessageType,
    config::{Config, account::VtcDid},
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
    vrc::VRCRequestReject,
};
use tracing::{debug, info, warn};
use vta_sdk::protocols::PROBLEM_REPORT_TYPE;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
    JOIN_REQUEST_SUBMIT_RESPONSE_TYPE,
};
use vta_sdk::protocols::members::{
    MEMBER_REMOVAL_NOTICE_TYPE, MEMBER_REQUEST_VMC_TYPE, MEMBER_VMC_RESPONSE_TYPE,
};

/// Maximum allowed message body size in bytes (1 MB).
const MAX_MESSAGE_BODY_SIZE: usize = 1_048_576;

/// Maximum number of relationships allowed before rejecting new requests.
const MAX_RELATIONSHIPS: usize = 5_000;

/// Build, sign, and send the reciprocal member VMC for `(vtc_did, persona_id)` —
/// resolving that persona's runtime identity (DID / profile / mediator) and
/// signing key from `config`. Shared by the manual "issue VMC" action and the
/// auto-answer to a VTC `members/request-vmc/1.0`. Returns the DIDComm message id.
pub(crate) async fn issue_member_vmc_for(
    config: &Config,
    tdk: &TDK,
    vtc_did: &str,
    persona_id: openvtc_core::config::account::PersonaId,
    closes_request: Option<uuid::Uuid>,
) -> Result<(uuid::Uuid, serde_json::Value), openvtc_core::errors::OpenVTCError> {
    use openvtc_core::errors::OpenVTCError;
    // The grant we are acknowledging, as the community sent it. Without one
    // there is nothing to acknowledge: an acknowledgement names a specific
    // grant by digest, and a community that has issued us none has no
    // membership edge for us to complete.
    let grant = config
        .account
        .membership(vtc_did, persona_id)
        .and_then(|c| {
            c.credentials
                .get(&openvtc_core::CredentialKind::Membership)
                .cloned()
        })
        .ok_or_else(|| {
            OpenVTCError::Config(
                "this community has not issued us a membership credential, so there is \
                 nothing to acknowledge"
                    .into(),
            )
        })?;
    let id = config
        .identities
        .get(&persona_id)
        .ok_or_else(|| OpenVTCError::Config("persona identity unavailable".into()))?;
    let member_did = id.persona_did().to_string();
    let profile = id.profile().clone();
    let mediator = id.mediator_did.clone().unwrap_or_default();
    let atm = tdk
        .atm
        .as_ref()
        .ok_or_else(|| OpenVTCError::Config("messaging (ATM) unavailable".into()))?;
    let keys = config.get_persona_keys_for(persona_id, tdk).await?;
    openvtc_core::members::issue_and_send_member_vmc(
        &openvtc_core::members::Delivery {
            atm,
            profile: &profile,
            member_did: &member_did,
            vtc_did,
            mediator_did: &mediator,
        },
        &keys.signing.secret,
        &keys.authentication.secret,
        &grant,
        closes_request,
    )
    .await
}

/// Whether a document of `typ` may be a reply to a capability request.
fn is_capability_reply_type(typ: &str) -> bool {
    typ.starts_with("https://trusttasks.org/spec/governance/capability/")
        || is_trust_task_error_type(typ)
}

/// What an inbound message asks the loop to do, beyond mutating `Config`.
///
/// These are things this function cannot do itself: tearing down a session
/// needs the session manager, and the live personhood challenge belongs to
/// `State` rather than to the account. Collected here rather than as three
/// trailing `&mut Vec` parameters — same reason the community verbs grew a
/// `Performed` enum, and it keeps the signature within clippy's argument
/// budget as more effects arrive.
#[derive(Default)]
pub struct InboundEffects {
    /// Communities that resolved to an inactive status; the loop deregisters
    /// their sessions (R-S-3).
    pub inactivated: Vec<(VtcDid, openvtc_core::config::account::PersonaId)>,
    /// Capability replies, keyed by the request id they thread on.
    /// `(sender, thread id, reply)` — the view takes a reply only from the
    /// community it asked.
    pub capability_replies: Vec<(String, String, openvtc_core::capabilities::CapabilityReply)>,
    /// `git-ns/*` replies for the Repos panel, keyed by the request id they
    /// thread on.
    pub git_ns_replies: Vec<crate::state_handler::repos_actions::InboundReply>,
    /// Personhood challenges the community answered with. Display state with a
    /// ten-minute life — never persisted.
    pub personhood_challenges: Vec<openvtc_core::personhood::ChallengeReply>,
    /// Communities' answers to questions we put to them — a directory page, a
    /// stored profile, a resent grant, a manifest — for whoever is waiting.
    pub vetting_answers: Vec<openvtc_core::vetting::queries::CommunityAnswer>,
    /// Vetters' grants to check for revocation. The check fetches over HTTPS,
    /// so the loop runs it as a background job.
    pub vetting_grant_checks: Vec<openvtc_core::vetting::status::GrantCheck>,
    /// A message whose handling waits on a network-bound check (a DID resolve,
    /// a status-list fetch). The loop runs [`VerifyJob::run`] off the loop and
    /// hands the message back with the result; nothing about it is applied
    /// until then.
    pub deferred: Option<Deferred>,
}

/// A network-bound proof or status check a message needs before it can be
/// acted on, run off the dispatch loop so a slow resolve or fetch never
/// freezes the UI.
pub enum VerifyJob {
    /// An issued credential: proof against the issuer's document, validity,
    /// revocation (fails closed).
    Credential {
        /// The whole delivery: its own proof is checked before the credential's.
        document: serde_json::Value,
        sender: String,
    },
    /// A community's operational document (removal notice, join replies,
    /// profile, capability/git-ns replies, refusals).
    Operational {
        document: serde_json::Value,
        sender: String,
        our_dids: Vec<String>,
        /// The type the message is handled as, which the document's signed
        /// `type` must be (its kind and window follow from it).
        typ: String,
    },
    /// A relationship DID's binding proofs.
    DidBinding {
        did: String,
        did_proof: Option<serde_json::Value>,
        persona: String,
        persona_proof: Option<serde_json::Value>,
        peer: String,
        thid: String,
        role: openvtc_core::relationships::BindingRole,
    },
    /// A VRC's proof against its issuer's key.
    Vrc(Box<DTGCredential>),
    /// No check: the message needs none, but its sender has messages queued
    /// ahead of it, and it waits its turn behind them rather than overtaking
    /// them — a `members/request-vmc` behind the credential that makes the
    /// membership it asks about Active, say.
    Barrier,
    /// A check that never finishes (tests of the queue's timeout).
    #[cfg(test)]
    Hang,
    /// A check that panics (tests of the queue's supervision).
    #[cfg(test)]
    Panic,
}

/// The result of a [`VerifyJob`]. Recording (replay sets) and every state
/// change stay on the loop: this carries only what was proven.
pub enum PreVerified {
    Credential(
        Result<
            openvtc_core::issued_credential::VerifiedIssuedCredential,
            openvtc_core::issued_credential::IssuedCredentialError,
        >,
    ),
    Operational(
        Result<
            openvtc_core::operational::VerifiedOperational,
            openvtc_core::operational::OperationalError,
        >,
    ),
    DidBinding(Result<(), openvtc_core::relationships::DidBindingError>),
    Vrc(Result<(), String>),
    /// Nothing was checked ([`VerifyJob::Barrier`]).
    Barrier,
}

/// Where a message is in its handling.
pub enum Arrival<'a> {
    /// Just arrived. `waiting(sender)` says whether that sender has messages
    /// queued for a check ahead of this one, which it must not overtake.
    New { waiting: &'a dyn Fn(&str) -> bool },
    /// Queued for its check before a restart
    /// ([`openvtc_core::config::protected_config::ProtectedConfig::deferred_inbound`]).
    /// It passed the age and replay gates when it arrived; it is set aside
    /// again — for its check if it still passes the local checks, else to wait
    /// its turn and be refused by its handler then. It is never handled
    /// directly.
    Restored,
    /// Back from its check, with the result.
    Returning(PreVerified),
}

#[cfg(test)]
fn nobody_waiting(_: &str) -> bool {
    false
}

#[cfg(test)]
impl Arrival<'static> {
    /// Just arrived, with nothing queued ahead of it.
    pub const FRESH: Arrival<'static> = Arrival::New {
        waiting: &nobody_waiting,
    };
}

/// A message set aside until its check has run.
pub struct Deferred {
    /// The message as it arrived (it is dispatched again, from the top).
    pub message: Message,
    /// What to check.
    pub job: VerifyJob,
}

impl VerifyJob {
    /// Run the check. Network-bound; runs off the loop. Records nothing.
    pub async fn run(self, tdk: TDK) -> PreVerified {
        let now = chrono::Utc::now();
        match self {
            VerifyJob::Credential { document, sender } => PreVerified::Credential(
                openvtc_core::issued_credential::verify_issued_delivery(
                    &document,
                    &sender,
                    tdk.did_resolver(),
                    now,
                )
                .await,
            ),
            VerifyJob::Operational {
                document,
                sender,
                our_dids,
                typ,
            } => {
                let ours: Vec<&str> = our_dids.iter().map(String::as_str).collect();
                // The replay check is the loop's, at apply time, against the
                // live set; an empty set here only skips it.
                PreVerified::Operational(
                    openvtc_core::operational::verify_operational(
                        &document,
                        &sender,
                        &ours,
                        &typ,
                        tdk.did_resolver(),
                        &openvtc_core::operational::SeenDocuments::default(),
                        now,
                    )
                    .await,
                )
            }
            VerifyJob::DidBinding {
                did,
                did_proof,
                persona,
                persona_proof,
                peer,
                thid,
                role,
            } => PreVerified::DidBinding(
                openvtc_core::relationships::verify_did_binding(
                    &did,
                    did_proof.as_ref(),
                    &persona,
                    persona_proof.as_ref(),
                    &peer,
                    &thid,
                    role,
                    tdk.did_resolver(),
                )
                .await,
            ),
            VerifyJob::Vrc(vrc) => PreVerified::Vrc(verify_vrc_proof(&tdk, &vrc).await),
            VerifyJob::Barrier => PreVerified::Barrier,
            #[cfg(test)]
            VerifyJob::Hang => std::future::pending().await,
            #[cfg(test)]
            VerifyJob::Panic => panic!("a check that panics"),
        }
    }

    /// The result for a check that did not finish — it timed out, or its task
    /// failed. Always a refusal (fail closed) of the job's own kind.
    #[must_use]
    pub fn unfinished(&self) -> PreVerified {
        match self {
            VerifyJob::Credential { .. } => PreVerified::Credential(Err(
                openvtc_core::issued_credential::IssuedCredentialError::CheckUnfinished,
            )),
            VerifyJob::DidBinding { .. } => PreVerified::DidBinding(Err(
                openvtc_core::relationships::DidBindingError::CheckUnfinished,
            )),
            VerifyJob::Vrc(_) => PreVerified::Vrc(Err(
                "its proof's check did not finish (timed out or failed)".to_string(),
            )),
            VerifyJob::Barrier => PreVerified::Barrier,
            #[cfg(test)]
            VerifyJob::Hang | VerifyJob::Panic => PreVerified::Operational(Err(
                openvtc_core::operational::OperationalError::CheckUnfinished,
            )),
            VerifyJob::Operational { .. } => PreVerified::Operational(Err(
                openvtc_core::operational::OperationalError::CheckUnfinished,
            )),
        }
    }

    /// Whether this checks a relationship request's binding (DIDs the
    /// requester chose).
    #[must_use]
    pub fn is_relationship_request(&self) -> bool {
        matches!(
            self,
            VerifyJob::DidBinding {
                role: openvtc_core::relationships::BindingRole::Request,
                ..
            }
        )
    }

    /// Whether this is a [`VerifyJob::Barrier`] (nothing to check).
    #[cfg(test)]
    #[must_use]
    pub fn is_barrier(&self) -> bool {
        matches!(self, VerifyJob::Barrier)
    }

    /// The community a credential check is for — the one whose membership
    /// shows "verifying…" meanwhile.
    #[must_use]
    pub fn verifying_community(&self) -> Option<&str> {
        match self {
            VerifyJob::Credential { sender, .. } => Some(sender),
            _ => None,
        }
    }
}

/// The check `message` (opened) needs before it can be acted on, if any.
///
/// The cheap local checks come first, and only a message that passes them is
/// set aside for its network-bound check: one this client would refuse anyway
/// — a credential or operational document from a party we hold no membership
/// with, an accept answering nothing of ours, a VRC outside an established
/// relationship — never costs a resolve or a fetch, nor a place in the queue.
/// A message that fails them is not deferred: it goes straight to its handler,
/// which runs the same checks, says why, and refuses it (every handler fails
/// closed without a check result).
fn verification_job(
    config: &Config,
    message: &Message,
    from_did: &str,
    recipient_did: &str,
) -> Option<VerifyJob> {
    let typ = message.typ.as_str();
    // A community we hold a record with (Pending included): the only party
    // whose credentials and operational documents this client acts on.
    let member = !config.account.memberships_for(from_did).is_empty();
    let operational = || VerifyJob::Operational {
        document: message.body.clone(),
        sender: from_did.to_string(),
        our_dids: config
            .account
            .personas
            .values()
            .map(|p| p.did.clone())
            .collect(),
        typ: typ.to_string(),
    };
    if typ == CREDENTIAL_ISSUE_TYPE {
        let credential = credential_in_issue(message)?;
        // Issued by the community that sent it, to one of our personas, and
        // that community is one we hold a record with. (Which membership,
        // and whether it is live, the handler checks again once verified; a
        // vetter's grant passes here too.) A vetter's statement is vetting's,
        // checked by vetting.
        let to_us = credential
            .pointer("/credentialSubject/id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|subject| config.account.persona_id_for_did(subject).is_some());
        let from_issuer = openvtc_core::issued_credential::issuer_of(&credential) == Some(from_did);
        return (member && to_us && from_issuer).then(|| VerifyJob::Credential {
            document: message.body.clone(),
            sender: from_did.to_string(),
        });
    }
    // A community's answer to a vetting question: only from a community we
    // have business with — a question outstanding, an application, or a
    // membership (the same test vetting applies before taking one).
    if openvtc_core::vetting::inbound::is_community_answer_type(typ) {
        let business = config.private.vetting.asked(from_did)
            || config
                .private
                .vetting
                .applications
                .iter()
                .any(|a| a.community == from_did)
            || member;
        return business.then(operational);
    }
    if is_capability_reply_type(typ)
        || openvtc_core::git_ns::is_reply_type(typ)
        || [
            MEMBER_REMOVAL_NOTICE_TYPE,
            MEMBER_REQUEST_VMC_TYPE,
            JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
            JOIN_REQUEST_SUBMIT_RESPONSE_TYPE,
            JOIN_REQUEST_STATUS_RESPONSE_TYPE,
            COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE,
        ]
        .contains(&typ)
    {
        return member.then(operational);
    }
    match MessageType::try_from(message).ok()? {
        MessageType::RelationshipRequest => {
            let body: openvtc_core::relationships::RelationshipRequestBody =
                serde_json::from_value(message.body.clone()).ok()?;
            validate_did(&body.did).ok()?;
            relationship_request_admissible(
                config,
                &Arc::new(message.id.clone()),
                &Arc::new(from_did.to_string()),
            )
            .ok()?;
            Some(VerifyJob::DidBinding {
                did: body.did,
                did_proof: body.did_proof,
                persona: from_did.to_string(),
                persona_proof: body.persona_proof,
                peer: recipient_did.to_string(),
                thid: message.id.clone(),
                role: openvtc_core::relationships::BindingRole::Request,
            })
        }
        MessageType::RelationshipRequestAccepted => {
            let body: RelationshipAcceptBody = serde_json::from_value(message.body.clone()).ok()?;
            validate_did(&body.did).ok()?;
            let thid = message.thid.clone()?;
            // It answers a request of ours still waiting, from the party it
            // went to.
            config
                .private
                .relationships
                .awaiting(
                    &Arc::new(thid.clone()),
                    RelationshipState::RequestSent,
                    from_did,
                )
                .is_some()
                .then_some(())?;
            Some(VerifyJob::DidBinding {
                did: body.did,
                did_proof: body.did_proof,
                persona: from_did.to_string(),
                persona_proof: body.persona_proof,
                peer: recipient_did.to_string(),
                thid,
                role: openvtc_core::relationships::BindingRole::Accept,
            })
        }
        MessageType::VRCIssued => {
            let vrc: DTGCredential = serde_json::from_value(message.body.clone()).ok()?;
            // An established relationship, and the issuer pinned to it.
            vet_vrc_issued(
                &config.private.relationships,
                &config.private.tasks,
                &vrc,
                &Arc::new(from_did.to_string()),
                message.thid.as_deref(),
            )
            .ok()?;
            Some(VerifyJob::Vrc(Box::new(vrc)))
        }
        _ => None,
    }
}

/// Whether an inbound relationship request from `from_did` (task id
/// `task_id`) could be queued at all: room for the task, under the
/// relationship limit, no relationship with the sender already, and no
/// request from it already waiting. Local and cheap; run before the request's
/// proofs are checked, and again when it is handled.
fn relationship_request_admissible(
    config: &Config,
    task_id: &Arc<String>,
    from_did: &Arc<String>,
) -> Result<(), &'static str> {
    if check_task_capacity(config, task_id, from_did).is_err() {
        return Err("no room for another task");
    }
    if config.private.relationships.relationships.len() >= MAX_RELATIONSHIPS {
        return Err("relationship limit reached");
    }
    if config.private.relationships.get(from_did).is_some()
        || config
            .private
            .relationships
            .find_by_remote_did(from_did)
            .is_some()
    {
        return Err("a relationship with this party already exists");
    }
    let has_pending = config.private.tasks.tasks.values().any(|task| {
        matches!(&task.type_, TaskType::RelationshipRequestInbound { from, .. } if from == from_did)
    });
    if has_pending {
        return Err("a request from this party is already waiting");
    }
    Ok(())
}

/// An operational document that was not checked.
static NOT_CHECKED: Result<
    openvtc_core::operational::VerifiedOperational,
    openvtc_core::operational::OperationalError,
> = Err(openvtc_core::operational::OperationalError::NotChecked);

/// The operational result the off-loop check produced, or "not checked".
fn pre_operational(
    pre: &Option<PreVerified>,
) -> Result<
    openvtc_core::operational::VerifiedOperational,
    openvtc_core::operational::OperationalError,
> {
    match pre {
        Some(PreVerified::Operational(r)) => r.clone(),
        _ => Err(openvtc_core::operational::OperationalError::NotChecked),
    }
}

/// Whether a community's reply to a question of ours (capability, git-ns) may
/// be taken: it must be the community's signed operational document —
/// `authentication` key, addressed to the persona it arrived for, fresh, not
/// seen before ([`openvtc_core::operational`]). That holds for a refusal
/// (`trust-task-error`) as much as for a success: an unsigned refusal is
/// ignored, with a log line. The view then also checks the sender is the
/// community it asked.
///
/// `cached` holds the answer for this message once computed: a refusal can be
/// offered to both the capability and the git-ns view, and verifying it twice
/// would read the second as a replay of the first.
fn community_reply_proven(
    config: &mut Config,
    pre: &Option<PreVerified>,
    message: &Message,
    from_did: &str,
    recipient_did: &str,
    cached: &mut Option<bool>,
) -> bool {
    if let Some(answer) = *cached {
        return answer;
    }
    let refusal = is_trust_task_error_type(&message.typ);
    let now = chrono::Utc::now();
    let answer = match pre_operational(pre) {
        // Addressed to the persona it arrived for.
        Ok(v) if v.recipient() != recipient_did => {
            warn!(typ = %message.typ, "reply addressed to another persona — ignored");
            false
        }
        // Capability and git-ns views exist only for communities we belong
        // to, so a reply from anyone else has no standing, and is not recorded.
        Ok(_) if config.account.memberships_for(from_did).is_empty() => {
            warn!(typ = %message.typ, "reply from a community we hold no membership with — ignored");
            false
        }
        Ok(verified) => match verified
            .check(&config.private.seen_documents, now)
            .and_then(|()| verified.commit(&mut config.private.seen_documents, now))
        {
            Ok(()) => true,
            Err(e) => {
                warn!(typ = %message.typ, reason = %e, "community reply refused");
                false
            }
        },
        Err(e) => {
            if refusal {
                warn!(typ = %message.typ, reason = %e, "unverified community refusal ignored");
            } else {
                warn!(typ = %message.typ, reason = %e, "community reply refused");
            }
            false
        }
    };
    *cached = Some(answer);
    answer
}

/// The VTC's operational reply (a join receipt, verdict, status, refusal or
/// profile), as verified off the loop, and not a replay. Records nothing: the
/// caller commits it once the reply has matched something of ours.
fn community_document(
    config: &Config,
    pre: &Option<PreVerified>,
    from_did: &str,
) -> Result<
    openvtc_core::operational::VerifiedOperational,
    openvtc_core::operational::OperationalError,
> {
    // A community we hold no membership with (Pending included) has asked
    // nothing of ours to answer.
    if config.account.memberships_for(from_did).is_empty() {
        return Err(openvtc_core::operational::OperationalError::NoStanding);
    }
    let verified = pre_operational(pre)?;
    verified.check(&config.private.seen_documents, chrono::Utc::now())?;
    Ok(verified)
}

/// Commit a verified community reply that matched something of ours.
fn commit_community_document(
    config: &mut Config,
    verified: openvtc_core::operational::VerifiedOperational,
) {
    if let Err(e) = verified.commit(&mut config.private.seen_documents, chrono::Utc::now()) {
        warn!(reason = %e, "community reply acted on but not recorded");
    }
}

/// Process an inbound DIDComm message.
///
/// Auto-processes messages that don't need human input (pong, accept, finalize, reject).
/// Queues interactive tasks for messages that need user decisions (inbound requests, VRCs).
///
/// Returns `true` if Config was mutated and needs saving.
///
/// `pre` is `None` on arrival. A message whose handling needs a network-bound
/// check is then set aside in [`InboundEffects::deferred`] and nothing about it
/// is applied; the loop runs the check off the loop and calls this again with
/// its result, and the message is handled from the top with that result — so
/// nothing is ever acted on before its check has passed.
pub async fn process_inbound_message(
    config: &mut Config,
    tdk: &TDK,
    service: &Messaging,
    seen: &mut SeenMessages,
    message: &Message,
    effects: &mut InboundEffects,
    arrival: Arrival<'_>,
) -> Result<bool, anyhow::Error> {
    // A document recorded as acted on must be saved even when the handler
    // reports no other change — otherwise a restart forgets it and the
    // document can be replayed.
    let seen_before = config.private.seen_documents.revision();
    let changed = process_inbound(config, tdk, service, seen, message, effects, arrival).await?;
    Ok(changed || config.private.seen_documents.revision() != seen_before)
}

async fn process_inbound(
    config: &mut Config,
    tdk: &TDK,
    service: &Messaging,
    seen: &mut SeenMessages,
    message: &Message,
    effects: &mut InboundEffects,
    arrival: Arrival<'_>,
) -> Result<bool, anyhow::Error> {
    let InboundEffects {
        inactivated,
        capability_replies,
        git_ns_replies,
        personhood_challenges,
        vetting_answers,
        vetting_grant_checks,
        deferred,
    } = effects;
    // A message handed back with its check's result (or restored from before
    // a restart) already passed the age and replay gates on arrival; running
    // them again would drop it as a replay of itself.
    let (fresh, restored) = match &arrival {
        Arrival::New { .. } => (true, false),
        Arrival::Restored => (false, true),
        Arrival::Returning(_) => (false, false),
    };
    let returning = !fresh && !restored;
    // Drop messages outside the replay / freshness window before doing
    // any state-mutating work. Saves us from acting on stale captures
    // and from clock-skew–induced retries.
    if fresh && let Err(reason) = check_message_age(message) {
        warn!(
            id = %message.id,
            typ = %message.typ,
            from = ?message.from,
            "dropping inbound message: {reason}",
        );
        return Ok(false);
    }

    // Drop messages whose ID we've already seen this session. The TDK
    // already guards against unpack-level duplicates, but the LRU is a
    // belt-and-braces defense for mediator pickup retries and replay
    // attempts.
    if fresh && seen.observe(&message.id) {
        debug!(id = %message.id, typ = %message.typ, "dropping replayed message ID");
        return Ok(false);
    }
    // A restored message is remembered too, so the mediator redelivering it
    // is dropped as a replay.
    if restored {
        seen.observe(&message.id);
    }

    // The sender — a routing hint, not an identity. It selects the record a
    // message is about; every decision that turns on who said something is
    // gated on a proof by that party (`openvtc_core::proof_check`), not on this.
    //
    // Trust-pong messages may omit `from` (the thid linkage to our outbound
    // ping is sufficient for task cleanup).
    let from_did = match &message.from {
        Some(did) => Arc::new(did.to_string()),
        None => {
            // Allow pong through for task cleanup even without `from`
            if message.typ == openvtc_core::protocol_urls::TRUST_PONG {
                if let Some(task_id) = &message.thid {
                    config.private.tasks.remove(&Arc::new(task_id.to_string()));
                }
                debug!("trust-pong (no from) — task cleaned up");
                return Ok(true);
            }
            warn!("anonymous inbound message rejected (no 'from' field)");
            return Ok(false);
        }
    };

    // The persona this message was addressed to — the DID any auto-reply must be
    // sent *from*. Resolved from the envelope's `to`, falling back to the active
    // persona when `to` is absent or not one of ours. For a single-persona
    // account `to` is always that persona, so this is identical to the previous
    // `config.persona_did()` behaviour; with multiple personas it routes the
    // reply out of the right one.
    let recipient_did: String = message
        .to
        .as_ref()
        .and_then(|tos| tos.iter().find(|t| config.is_persona_did(t)))
        .cloned()
        .unwrap_or_else(|| config.persona_did().to_string());

    // The persona this message was addressed to, for D10 attribution: inbox
    // tasks created from this message are tagged with it so they scope to the
    // right community on the main page (R-C-6).
    let recipient_persona = config.account.persona_id_for_did(&recipient_did);

    // Validate message body size to prevent DoS via oversized payloads
    let body_size = serde_json::to_string(&message.body)
        .map(|s| s.len())
        .unwrap_or(0);
    if body_size > MAX_MESSAGE_BODY_SIZE {
        warn!(
            size = body_size,
            "rejecting oversized message body ({} bytes)", body_size
        );
        return Ok(false);
    }

    // The DIDComm binding envelope comes off before anything routes. Every
    // handler below dispatches on `message.typ`; an enveloped document names
    // its task only inside the body, so without this an enveloped reply would
    // match no handler and the ask it answers would wait out its timeout. A
    // community replies in the document's own type today and in the envelope
    // once it follows the binding (§5) fully — this reads both, the same way
    // (VTI #1687, Keyring VTI-42).
    let opened = openvtc_core::didcomm::open_didcomm_envelope(message);
    if opened.is_none() && message.typ == openvtc_core::capabilities::TRUST_TASK_ENVELOPE_TYPE {
        warn!(id = %message.id, from = %from_did, "binding envelope carries no typed document — dropped");
        return Ok(false);
    }
    let arrived = message;
    let message = opened.as_ref().unwrap_or(message);

    // A network-bound check runs off the loop. Set the message aside — nothing
    // about it is applied — and let the loop hand it back with the result.
    // A message back from waiting its turn behind its sender's checks was
    // triaged against state those checks have since changed: triage it again,
    // and set it aside for a check if it now needs one.
    let recheck = matches!(arrival, Arrival::Returning(PreVerified::Barrier));
    if !returning || recheck {
        let job = match (
            verification_job(config, message, &from_did, &recipient_did),
            &arrival,
        ) {
            (Some(job), _) => Some(job),
            // Kept across the restart because it had to wait its turn: it
            // waits again, and is handled — or refused — then.
            (None, Arrival::Restored) => Some(VerifyJob::Barrier),
            // Its sender has messages queued ahead of it (a credential being
            // checked, say): it waits its turn rather than being handled
            // against state those will change — a request that depends on a
            // membership still being verified would otherwise be dropped.
            (None, Arrival::New { waiting }) if waiting(&from_did) => Some(VerifyJob::Barrier),
            (None, _) => None,
        };
        if let Some(job) = job {
            *deferred = Some(Deferred {
                message: arrived.clone(),
                job,
            });
            return Ok(false);
        }
    }
    let pre = match arrival {
        Arrival::Returning(pre) => Some(pre),
        Arrival::New { .. } | Arrival::Restored => None,
    };

    // Computed at most once per message (see `community_reply_proven`).
    let mut reply_proven: Option<bool> = None;

    // Capability replies (governance/capability/*), in either carriage: hand
    // them to the state loop keyed by the document's `threadId` (== our request
    // id). This is a fan-in point waiting on nothing in particular, so the
    // document is classified against its own `threadId`; the correlation that
    // matters is `apply_capability_replies` matching it to the open view's
    // `pending_thid`, and an uncorrelated reply is dropped there.
    //
    // A `trust-task-error` is ambiguous here — it may refuse a capability
    // toggle or anything else we asked — so it is offered to the capability
    // view *and* falls through to the handlers below; each side drops an error
    // that threads on nothing of its own.
    if is_capability_reply_type(&message.typ)
        && let Some((thid, doc)) =
            openvtc_core::capabilities::parse_envelope_document(&message.body)
        && let Some(reply) = openvtc_core::capabilities::parse_capability_reply(&doc, &thid)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
        )
    {
        capability_replies.push((from_did.to_string(), thid, reply));
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }

    // Git namespace replies (git-ns/*), in either carriage, for the Repos
    // panel — keyed by the document's `threadId` and correlated there against
    // the one request the panel has outstanding; anything else is dropped.
    // A `trust-task-error` is offered here as well and falls through, for the
    // same reason as above.
    if openvtc_core::git_ns::is_reply_type(&message.typ)
        && let Some((_, doc)) = openvtc_core::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = openvtc_core::git_ns::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
        )
    {
        // The sender and the document's issuer travel with the answer: the
        // Repos view takes one only from the community it asked.
        git_ns_replies.push(crate::state_handler::repos_actions::InboundReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }

    // Peer identity vetting (docs/design/vetting-process.md): requests,
    // sessions, cards, statements, declines and refusals between members, and a
    // community's vetting requirements. Tried before the join and credential
    // routes below because it shares two of their types; `handle` returns
    // `None` for anything that is not vetting's, which falls through unchanged.
    if openvtc_core::vetting::inbound::may_claim(&message.typ) {
        let resolver =
            vta_sdk::trust_task_proof::TrustTaskVmResolver::new(tdk.did_resolver().clone());
        let ctx = openvtc_core::vetting::inbound::Context {
            account: &config.account,
            resolver: &resolver,
            did_resolver: tdk.did_resolver(),
            issued_credential: match &pre {
                Some(PreVerified::Credential(r)) => Some(r),
                _ => None,
            },
            // Always `Some`: an answer is taken only as checked off the loop,
            // never resolved here.
            community_answer: Some(match &pre {
                Some(PreVerified::Operational(r)) => r,
                _ => &NOT_CHECKED,
            }),
            recipient: recipient_persona.map(|p| (p, recipient_did.as_str())),
            now: chrono::Utc::now(),
        };
        if let Some(handled) = openvtc_core::vetting::inbound::handle(
            &mut config.private.vetting,
            &ctx,
            &mut config.private.seen_documents,
            message,
            &from_did,
        )
        .await
        {
            if let Some(reply) = handled.reply
                && let Err(e) =
                    openvtc_core::vetting::wire::send_reply(config, tdk, service, reply).await
            {
                warn!(to = %from_did, error = %e, "could not send vetting reply");
            }
            if let Some(answer) = handled.answer {
                vetting_answers.push(answer);
            }
            if let Some(check) = handled.grant_check {
                vetting_grant_checks.push(check);
            }
            let noticed = handled.notice.is_some();
            if let Some(notice) = handled.notice {
                config
                    .public
                    .logs
                    .insert(LogFamily::Community, notice.describe());
                if let Some((id, task)) = notice.task() {
                    config
                        .private
                        .tasks
                        .new_task_for(&Arc::new(id), task, recipient_persona);
                }
            }
            return Ok(handled.changed || noticed);
        }
    }

    // VTC join-requests submit-receipt: the VTC's asynchronous reply to our
    // submit, threaded (`thid`) on our submit message id. It carries the
    // authoritative VTC `requestId`; reconcile it onto the matching Pending
    // community record (which holds our submit message id as a placeholder).
    // It is a VTC Trust-Task type, not an openvtc relationship-protocol type,
    // so handle it before the `MessageType` conversion below (which rejects it).
    if message.typ == JOIN_REQUEST_SUBMIT_RECEIPT_TYPE {
        // The request id it carries becomes the handle the join is asked about
        // by, so it is taken only from the community's signed document.
        let verified = match community_document(config, &pre, &from_did) {
            Ok(v) => v,
            Err(e) => {
                warn!(reason = %e, "join submit-receipt refused");
                return Ok(false);
            }
        };
        let changed = handle_join_submit_receipt(&mut config.account, message, &from_did);
        if changed {
            commit_community_document(config, verified);
        }
        return Ok(changed);
    }

    // VTC credential delivery: on approve, the VTC pushes the issued VMC + role
    // VEC as separate `credential-exchange/issue` messages. Store each on the
    // community and flip Pending -> Active when the membership credential lands.
    if message.typ == CREDENTIAL_ISSUE_TYPE {
        // Snapshot before, so the log can say what *changed* rather than that a
        // message arrived. An issued membership credential is the moment a join
        // completes — the single most consequential inbound message there is,
        // and it used to be indistinguishable from any other in the log.
        let was_active = config
            .account
            .memberships_for(&from_did)
            .iter()
            .any(|m| m.status.is_active());
        // Nothing is stored until its proof verifies against the community's
        // DID document: the envelope proves who sent the message, not who
        // signed the credential inside it.
        let Some(credential) = credential_in_issue(message) else {
            warn!("credential-issue without credential_response.credential — ignoring");
            return Ok(false);
        };
        // The local checks come first: a credential this client could not
        // store anyway — from a party we hold no membership with, for someone
        // else, of an unknown kind — never costs a resolve or a status fetch.
        if let Err(reason) = credential_issue_admissible(&config.account, &credential, &from_did) {
            warn!("credential-issue ignored before verification: {reason}");
            return Ok(false);
        }
        // Checked off the loop, before this message was handled at all — and
        // the result must be for exactly this credential.
        let verified = match match pre {
            Some(PreVerified::Credential(Ok(v))) if *v.value() == credential => Ok(v),
            Some(PreVerified::Credential(Err(e))) => Err(e),
            _ => Err(openvtc_core::issued_credential::IssuedCredentialError::NotChecked),
        } {
            Ok(verified) => verified,
            Err(e) => {
                // The reason only: never the credential, and the DID stays out
                // of the log line (the activity feed names the community).
                warn!(reason = %e, "refused an issued credential");
                config.public.logs.insert(
                    LogFamily::Community,
                    format!("Refused a credential from community ({from_did}): {e}."),
                );
                return Ok(true);
            }
        };
        let outcome = handle_credential_issue(&mut config.account, verified, &from_did);
        // Admission is the moment the member owes the community its half of
        // the membership pair. Sending it here — naming the join request it
        // closes — is what `vtc/members/vmc/0.1`'s `requestId` is for; without
        // it the community's request sits `Approved` indefinitely, waiting for
        // a reciprocal that only ever arrived unlinked, if at all.
        //
        // Best-effort by nature: the credential we just received is already
        // stored and the membership is already Active. A failure to send ours
        // back is logged and leaves the join open — recoverable, either by the
        // member issuing manually or by the community asking with
        // `members/request-vmc`.
        if let Some((persona_id, request_id)) = outcome.closed_join {
            match issue_member_vmc_for(config, tdk, &from_did, persona_id, Some(request_id)).await {
                Ok((_, vmc)) => {
                    // Keep our half. The send is the only moment this document
                    // exists on this side, and a member who cannot show what
                    // they sent cannot answer whether they consented, nor
                    // re-send it without minting a different credential.
                    if let Some(record) = config.account.membership_mut(&from_did, persona_id) {
                        record.member_vmc = Some(vmc);
                    }
                    info!(
                        vtc = %from_did,
                        %request_id,
                        "sent our reciprocal membership credential, closing the join request"
                    )
                }
                Err(e) => warn!(
                    vtc = %from_did,
                    %request_id,
                    error = %e,
                    "could not send our reciprocal membership credential — the community's \
                     join request stays open"
                ),
            }
        }
        let changed = outcome.changed;
        if changed {
            let now_active = config
                .account
                .memberships_for(&from_did)
                .iter()
                .any(|m| m.status.is_active());
            config.public.logs.insert(
                LogFamily::Community,
                if now_active && !was_active {
                    format!("Admitted to community ({from_did}) — membership is now Active.")
                } else {
                    format!("Credential received from community ({from_did}).")
                },
            );
        }
        return Ok(changed);
    }

    // VTC join-requests submit `#response`: the synchronous admission verdict in
    // the trust-task join model (allow / deny / refer / request_more), threaded
    // (`thid`) on our submit message id. `allow` → Active, `deny` → Rejected; a
    // rejection inactivates the community so the loop deregisters the session.
    if message.typ == JOIN_REQUEST_SUBMIT_RESPONSE_TYPE {
        let verified = match community_document(config, &pre, &from_did) {
            Ok(v) => v,
            Err(e) => {
                warn!(reason = %e, "join verdict refused");
                return Ok(false);
            }
        };
        let outcome = handle_join_verdict(&mut config.account, message, &from_did);
        if outcome.changed {
            commit_community_document(config, verified);
        }
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    // DIDComm problem-report. It carries no proof, so it changes nothing — a
    // join is rejected only by the community's signed `trust-task-error` or
    // verdict. A report from a community we hold a record with is surfaced so a
    // refusal is not invisible; one from anyone else is dropped without a trace.
    if message.typ == PROBLEM_REPORT_TYPE {
        let Some(note) = read_problem_report(&config.account, message, &from_did) else {
            debug!("problem-report from a party we hold no membership with — ignored");
            return Ok(false);
        };
        warn!(
            code = %note.code,
            on_pending_join = note.on_pending_join,
            "community reported a problem (unsigned — not acted on)"
        );
        config.public.logs.insert(
            LogFamily::Community,
            format!(
                "Community ({from_did}) reported a problem [{}]: {} — unsigned, so nothing \
                 was changed",
                note.code, note.comment
            ),
        );
        return Ok(true);
    }

    // VTC trust-task-error: the framework failure document for a Trust Task join
    // ceremony (malformed / denied / internal), threaded on our submit id. Trust
    // Tasks signal failures with these documents, NOT DIDComm problem-reports —
    // without this branch a failed ceremony was an unknown type, silently dropped
    // into a stuck `Pending`. Matched by type prefix (version-agnostic).
    if is_trust_task_error_type(&message.typ) {
        // A refusal that rejects a join is taken only from the community's
        // signed document; an unsigned one is ignored with a log line.
        let verified = match community_document(config, &pre, &from_did) {
            Ok(v) => v,
            Err(e) => {
                warn!(reason = %e, "unverified community refusal ignored");
                return Ok(false);
            }
        };
        let outcome = handle_join_trust_task_error(&mut config.account, message, &from_did);
        if outcome.changed {
            commit_community_document(config, verified);
        }
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    // VTC join-requests status-response: the authoritative lifecycle resolution
    // (approved / rejected / deferred) for a Pending join, correlated by
    // `requestId` (R-B-8). A rejection inactivates the community, so report its
    // VTC DID up so the loop deregisters the session (R-S-3).
    if message.typ == JOIN_REQUEST_STATUS_RESPONSE_TYPE {
        let verified = match community_document(config, &pre, &from_did) {
            Ok(v) => v,
            Err(e) => {
                warn!(reason = %e, "join status response refused");
                return Ok(false);
            }
        };
        let outcome = handle_join_status_response(&mut config.account, message, &from_did);
        if outcome.changed {
            commit_community_document(config, verified);
        }
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    // VTC community-profile response: carries the community's declared
    // `relationshipIdentifierDefault`, which seeds the pairwise-vs-attributed
    // default of the new-relationship form (issue #241). Informational — it
    // updates stored community metadata and never inactivates a session.
    if message.typ == COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE {
        // Signed, and an answer to a profile question we asked this community.
        let verified = match community_document(config, &pre, &from_did) {
            Ok(v) => v,
            Err(e) => {
                warn!(reason = %e, "community profile response refused");
                return Ok(false);
            }
        };
        let asked = message
            .thid
            .as_deref()
            .is_some_and(|thid| openvtc_core::join::take_profile_query(&from_did, thid));
        if !asked {
            warn!("community profile response we did not ask for — ignored");
            return Ok(false);
        }
        commit_community_document(config, verified);
        let changed =
            handle_community_profile_show_response(&mut config.account, message, &from_did);
        return Ok(changed);
    }

    // VTC personhood challenge reply: carries the nonce an assertion must be
    // signed over, and the match code to read aloud. Reported up rather than
    // applied here — the challenge is display state with a ten-minute life,
    // and this function owns `Config`, which is the thing that gets persisted.
    // A single-use nonce has no business surviving a restart.
    if message.typ == PERSONHOOD_CHALLENGE_RESPONSE_TYPE {
        match openvtc_core::personhood::parse_challenge_reply(&message.body) {
            Ok(reply) => {
                debug!(
                    vtc = %from_did,
                    challenge = %reply.challenge_id,
                    "personhood challenge received",
                );
                personhood_challenges.push(reply);
            }
            // Includes the match-code disagreement, which is a real finding
            // rather than a malformed message: it means this client and the
            // community derive different codes from the same challenge, so
            // the spoken confirmation would be meaningless.
            Err(e) => warn!(vtc = %from_did, "unusable personhood challenge reply: {e}"),
        }
        return Ok(false);
    }

    // VTC personhood assertion result. The re-issued VMC carrying
    // `PersonhoodCredential` arrives separately as a credential-issue message,
    // which is what actually updates the wallet — this is the decision.
    if message.typ == PERSONHOOD_ASSERT_RESPONSE_TYPE {
        match openvtc_core::personhood::parse_assert_reply(&message.body) {
            Ok(reply) => info!(
                vtc = %from_did,
                did = %reply.did,
                personhood = reply.personhood,
                "personhood asserted",
            ),
            Err(e) => warn!(vtc = %from_did, "unusable personhood assert reply: {e}"),
        }
        return Ok(false);
    }

    // VTC member-VMC receipt (`members/vmc/1.0#response`): the VTC acknowledging
    // the reciprocal VMC we sent. Informational — log and move on.
    if message.typ == MEMBER_VMC_RESPONSE_TYPE {
        info!(vtc = %from_did, "VTC acknowledged our membership credential (member VMC receipt)");
        // The send reports only that a frame was accepted locally. This is the
        // first and only evidence the community actually took the credential,
        // so it belongs where the member can see it rather than in a log file.
        config.public.logs.insert(
            LogFamily::Community,
            format!("Community ({from_did}) acknowledged your membership credential."),
        );
        return Ok(true);
    }

    // VTC → member: "please issue + send your VMC" (`members/request-vmc/0.1`).
    // Auto-answer: the sender is the community VTC and the recipient is one of our
    // personas; if we hold an Active membership there, issue + send our reciprocal
    // VMC straight back. Best-effort — a failure is logged, not surfaced as a stuck
    // state (the admin can re-request, or the member can issue manually with `m`).
    //
    // Only on the community's signed request: the VTC pushes it as an
    // operational document, checked before dispatch like the removal notice —
    // its `authentication` key, addressed to the persona, fresh, not seen
    // before. The transport sender alone would let anyone who can reach us
    // make this client sign and send a credential.
    if message.typ == MEMBER_REQUEST_VMC_TYPE {
        let verified = match pre_operational(&pre) {
            Ok(v) => v,
            Err(e) => {
                warn!(vtc = %from_did, error = %e, "members/request-vmc is not the community's signed request — ignoring");
                return Ok(false);
            }
        };
        let now = chrono::Utc::now();
        if let Err(e) = verified.check(&config.private.seen_documents, now) {
            warn!(vtc = %from_did, error = %e, "members/request-vmc already acted on — ignoring");
            return Ok(false);
        }
        if let Err(e) = verified.commit(&mut config.private.seen_documents, now) {
            warn!(vtc = %from_did, error = %e, "members/request-vmc could not be recorded — ignoring");
            return Ok(false);
        }
        match recipient_persona {
            Some(persona_id)
                if config
                    .account
                    .membership(&from_did, persona_id)
                    .is_some_and(|c| c.status.is_active()) =>
            {
                match issue_member_vmc_for(config, tdk, &from_did, persona_id, None).await {
                    Ok((_, vmc)) => {
                        if let Some(record) = config.account.membership_mut(&from_did, persona_id) {
                            record.member_vmc = Some(vmc);
                        }
                        info!(
                            vtc = %from_did,
                            "auto-issued our membership credential in response to the VTC's request"
                        )
                    }
                    Err(e) => warn!(
                        vtc = %from_did,
                        error = %e,
                        "failed to auto-issue our membership credential on request"
                    ),
                }
            }
            _ => warn!(
                vtc = %from_did,
                "members/request-vmc with no matching Active membership — ignoring"
            ),
        }
        return Ok(false);
    }

    // VTC → member removal notice (`vtc/members/removal-notice/0.1`): the
    // community telling a member it removed them (issue #240). Unsolicited — not
    // threaded on anything we sent — and the first thing that can move a
    // membership into `Removed`. A removal inactivates the community, so report
    // its VTC DID up for the loop to deregister the session (R-S-3).
    if message.typ == MEMBER_REMOVAL_NOTICE_TYPE {
        // Only the community's signature ends a membership.
        let notice = match openvtc_core::messaging::bind_removal_notice(
            message,
            &from_did,
            &config.account,
            &mut config.private.seen_documents,
            pre_operational(&pre),
            chrono::Utc::now(),
        ) {
            Ok(notice) => notice,
            Err(e) => {
                warn!(reason = %e, "refused a removal notice");
                config.public.logs.insert(
                    LogFamily::Community,
                    format!("Ignored a removal notice from community ({from_did}): {e}."),
                );
                return Ok(true);
            }
        };
        let outcome = handle_member_removal_notice(&mut config.account, notice, &from_did);
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    let msg_type = match MessageType::try_from(message) {
        Ok(t) => t,
        Err(_) => {
            warn!(typ = %message.typ, "unknown message type — ignoring");
            return Ok(false);
        }
    };

    let thid_display = message.thid.as_deref().unwrap_or("none");
    debug!(
        msg_type = %msg_type.friendly_name(),
        from = %from_did,
        thid = %thid_display,
        id = %message.id,
        "processing inbound message"
    );

    match msg_type {
        // =====================================================================
        // Auto-processed (no user interaction needed)
        // =====================================================================
        MessageType::RelationshipRequestRejected => {
            let task_id = require_thid(message)?;
            let body: RelationshipRejectBody = serde_json::from_value(message.body.clone())?;

            // A rejection answers exactly one request of ours that is still
            // waiting, and comes from the party it was sent to. Anything else —
            // above all a thread id naming an established relationship — must
            // not tear a relationship down.
            let waiting = config
                .private
                .relationships
                .awaiting(&task_id, RelationshipState::RequestSent, &from_did)
                .is_some();
            if !waiting {
                warn!("reject for no waiting request of ours from this party — ignoring");
                return Ok(false);
            }

            // Extract the listener's local DID before async work + before any
            // mutation, so the `&Relationship` borrow ends here.
            let our_did = config
                .private
                .relationships
                .find_by_task_id(&task_id)
                .map(|rel| Arc::clone(&rel.our_did))
                .filter(|our_did| !config.is_persona_did(our_did.as_str()));
            let listener_to_remove =
                our_did.map(|our_did| super::didcomm::listener_id_for_did(&our_did, config));
            if let Some(lid) = listener_to_remove {
                // Infallible now: dropping a transport closes its socket and
                // forgets its wire, with nothing left that can fail.
                service.remove_listener(&lid).await;
            }
            let _ = config.private.relationships.remove_by_task_id(
                &task_id,
                &mut config.private.vrcs_issued,
                &mut config.private.vrcs_received,
            );
            config.private.tasks.remove(&task_id);

            config.public.logs.insert(
                LogFamily::Relationship,
                format!(
                    "Relationship request rejected by ({}). Reason: {}",
                    from_did,
                    body.reason.as_deref().unwrap_or("none")
                ),
            );
            info!(from = %from_did, "relationship request rejected (auto-processed)");
            Ok(true)
        }

        MessageType::RelationshipRequestAccepted => {
            let task_id = require_thid(message)?;
            let body: RelationshipAcceptBody = serde_json::from_value(message.body.clone())?;

            if let Err(e) = validate_did(&body.did) {
                warn!(from = %from_did, error = %e, "rejecting accept with invalid DID in body");
                return Ok(false);
            }

            // An accept answers exactly one request of ours: it is correlated
            // by its thread id (the request's id) and nothing else — never by
            // who the transport says sent it — and only while that request is
            // still waiting (`RequestSent`), from the party it was sent to.
            //
            // R20: with plain values we cannot hold a `&mut` across an `.await`,
            // so resolve and check with shared borrows, verify, then mutate.
            let Some(key) = config.private.relationships.awaiting(
                &task_id,
                RelationshipState::RequestSent,
                &from_did,
            ) else {
                warn!("accept answers no waiting request of ours from this party — ignoring");
                return Ok(false);
            };

            // The DID the respondent switches to must be proven for this
            // handshake, by that DID (and by the respondent's persona when it
            // is an R-DID). Without this the accept could point the
            // relationship at a DID the sender does not control.
            // Checked off the loop, before this message was handled at all.
            if let Err(e) = match &pre {
                Some(PreVerified::DidBinding(r)) => r.clone(),
                _ => Err(openvtc_core::relationships::DidBindingError::NotChecked),
            } {
                warn!(reason = %e, "relationship accept refused");
                config.public.logs.insert(
                    LogFamily::Relationship,
                    format!("Refused a relationship acceptance from ({from_did}): {e}."),
                );
                return Ok(true);
            }

            {
                let rel = config
                    .private
                    .relationships
                    .get_mut(&key)
                    .expect("key just resolved");
                rel.state = RelationshipState::Established;
                rel.remote_did = Arc::new(body.did.clone());
            }

            // Send finalize using persona DIDs (same as request and accept).
            // If the send fails, still persist the Established state.
            let finalize_msg = create_finalize_message(&recipient_did, &from_did, &task_id)?;

            if let Err(e) = super::didcomm::send_message(
                service,
                config,
                &finalize_msg,
                &recipient_did,
                &from_did,
            )
            .await
            {
                warn!(to = %from_did, error = %e, "failed to send finalize — relationship established locally");
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Relationship established with ({})", from_did),
            );
            info!(from = %from_did, "relationship accepted + finalize sent (auto-processed)");
            Ok(true)
        }

        MessageType::RelationshipRequestFinalize => {
            let task_id = require_thid(message)?;

            // A finalize closes exactly the handshake we accepted: correlated
            // by its thread id only, and only while our accept is waiting on it.
            let Some(key) = config.private.relationships.awaiting(
                &task_id,
                RelationshipState::RequestAccepted,
                &from_did,
            ) else {
                warn!("finalize closes no handshake of ours from this party — ignoring");
                return Ok(false);
            };
            if let Some(rel) = config.private.relationships.get_mut(&key) {
                rel.state = RelationshipState::Established;
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Relationship finalized with ({})", from_did),
            );
            info!(from = %from_did, "relationship finalized (auto-processed)");
            Ok(true)
        }

        MessageType::TrustPong => {
            if let Some(task_id) = &message.thid {
                config.private.tasks.remove(&Arc::new(task_id.to_string()));
            }
            debug!(from = %from_did, "trust-pong received (auto-processed)");
            Ok(true)
        }

        MessageType::VRCRequestRejected => {
            let task_id = require_thid(message)?;
            let body: VRCRequestReject = serde_json::from_value(message.body.clone())?;

            // A rejection closes only our own VRC request, on its thread, to the
            // party it was sent to — the thread id alone names no counterparty,
            // and anyone who learned it could otherwise delete the task.
            if !openvtc_core::tasks::is_our_vrc_request_to(
                &config.private.tasks,
                &config.private.relationships,
                &task_id,
                &from_did,
            ) {
                warn!("VRC reject for no request of ours to this party — ignoring");
                return Ok(false);
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Task,
                format!(
                    "VRC request rejected by ({}). Reason: {}",
                    from_did,
                    body.reason.as_deref().unwrap_or("none")
                ),
            );
            info!(from = %from_did, "VRC request rejected (auto-processed)");
            Ok(true)
        }

        // =====================================================================
        // Queued as tasks (need user interaction)
        // =====================================================================
        MessageType::RelationshipRequest => {
            let task_id = Arc::new(message.id.clone());
            let body: openvtc_core::relationships::RelationshipRequestBody =
                serde_json::from_value(message.body.clone())?;

            if let Err(e) = validate_did(&body.did) {
                warn!(from = %from_did, error = %e, "rejecting request with invalid DID in body");
                return Ok(false);
            }
            if let Err(reason) = relationship_request_admissible(config, &task_id, &from_did) {
                warn!(from = %from_did, "relationship request ignored: {reason}");
                return Ok(false);
            }

            // The DID the requester will use must be proven — by that DID, and
            // by the requesting persona when it is an R-DID — for exactly this
            // request (its id, its two parties). The transport sender alone is
            // a routing hint, not proof of who is asking or which DID they hold.
            // Checked off the loop, before this message was handled at all.
            if let Err(e) = match &pre {
                Some(PreVerified::DidBinding(r)) => r.clone(),
                _ => Err(openvtc_core::relationships::DidBindingError::NotChecked),
            } {
                warn!(reason = %e, "relationship request refused");
                return Ok(false);
            }

            let to_did = Arc::new(
                message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
            );

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::RelationshipRequestInbound {
                    from: from_did.clone(),
                    to: to_did,
                    request: body,
                },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound relationship request from ({})", from_did),
            );
            info!(from = %from_did, "relationship request queued in inbox");
            Ok(true)
        }

        MessageType::VRCRequest => {
            let task_id = Arc::new(message.id.clone());
            let body = serde_json::from_value(message.body.clone())?;

            let relationship = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .ok_or_else(|| {
                    anyhow::anyhow!("VRC request from ({}) but no relationship found", from_did)
                })?;

            // Only accept VRC requests from established relationships
            if relationship.state != RelationshipState::Established {
                warn!(from = %from_did, state = ?relationship.state, "VRC request from non-established relationship");
                return Ok(false);
            }
            let remote_p_did = Arc::clone(&relationship.remote_p_did);

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::VRCRequestInbound {
                    request: body,
                    remote_p_did,
                },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound VRC request from ({})", from_did),
            );
            info!(from = %from_did, "VRC request queued in inbox");
            Ok(true)
        }

        MessageType::VRCIssued => {
            let vrc: DTGCredential = serde_json::from_value(message.body.clone())?;

            // Task R2 hardening: require an established relationship, bind the
            // credential's issuer to the authenticated sender, and only let the
            // thid resolve our own pending outbound VRC request to that sender.
            let pending_request = match vet_vrc_issued(
                &config.private.relationships,
                &config.private.tasks,
                &vrc,
                &from_did,
                message.thid.as_deref(),
            ) {
                Ok(pending) => pending,
                Err(reason) => {
                    warn!(from = %from_did, issuer = %vrc.issuer(), "dropping VRC-issued message: {reason}");
                    return Ok(false);
                }
            };

            // Task R2 gate 4: the data-integrity proof must verify against the
            // issuer's resolved key before any state is touched.
            if let Err(reason) = match &pre {
                Some(PreVerified::Vrc(r)) => r.clone(),
                _ => Err("its proof was not checked".to_string()),
            } {
                warn!(from = %from_did, issuer = %vrc.issuer(), "dropping VRC-issued message: {reason}");
                return Ok(false);
            }

            // Only a verified response may resolve our pending outbound VRC
            // request; the inbox task reuses its id so the request is replaced
            // by the issued credential. Unsolicited (or unmatched-thid) VRCs
            // are queued under the message id and leave other tasks untouched.
            let task_id = pending_request
                .clone()
                .unwrap_or_else(|| Arc::new(message.id.clone()));
            if let Some(request_id) = &pending_request {
                config.private.tasks.remove(request_id);
            }

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::VRCIssued { vrc: Box::new(vrc) },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("VRC issued received from ({})", from_did),
            );
            info!(from = %from_did, "VRC issued queued in inbox");
            Ok(true)
        }

        MessageType::TrustPing => {
            // Trust pings are already auto-responded to in the messaging loop.
            // Just create an informational task so the user sees it.
            let task_id = Arc::new(message.id.clone());
            let to_did = Arc::new(
                message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
            );

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            // Find the relationship for this ping
            if let Some(remote_p_did) = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .map(|rel| Arc::clone(&rel.remote_p_did))
            {
                config.private.tasks.new_task_for(
                    &task_id,
                    TaskType::TrustPing {
                        from: from_did.clone(),
                        to: to_did,
                        remote_p_did,
                    },
                    recipient_persona,
                );
            }
            debug!(from = %from_did, "trust-ping task created");
            Ok(true)
        }

        _ => {
            warn!(msg_type = %message.typ, "unhandled message type");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::{test_config, test_tdk};
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use openvtc_core::config::account::{
        CommunityRecord, CommunityStatus, PersonaId, PersonaRecord,
    };

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
        openvtc_core::capabilities::sign_document(&mut document, key)
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
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": vtc,
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
        let service = openvtc_core::didcomm::start_empty_service(
            tx,
            tokio_util::sync::CancellationToken::new(),
        );
        let mut seen = SeenMessages::new();

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
            &m,
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
            &deferred.message,
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
            &m,
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
            &deferred.message,
            &mut effects,
            Arrival::Returning(pre),
        )
        .await
        .unwrap();
        assert!(status(&config, &vtc).is_active(), "activated once verified");
    }

    /// A result is taken only for the credential it was produced for.
    #[tokio::test]
    async fn a_check_result_for_another_credential_is_not_taken() {
        let (vtc, key) = community_key();
        let tdk = test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = openvtc_core::didcomm::start_empty_service(
            tx,
            tokio_util::sync::CancellationToken::new(),
        );
        let mut seen = SeenMessages::new();
        let mut config = pending_config(&vtc);

        let other = issue(&vtc, &key, membership_vmc(&vtc, &key).await).await;
        let mut effects = InboundEffects::default();
        process_inbound_message(
            &mut config,
            &tdk,
            &service,
            &mut seen,
            &other,
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
            &m,
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
        let service = openvtc_core::didcomm::start_empty_service(
            tx,
            tokio_util::sync::CancellationToken::new(),
        );
        let mut seen = SeenMessages::new();
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
            &m,
            &mut effects,
            Arrival::FRESH,
        )
        .await
        .unwrap();
        let deferred = effects.deferred.expect("set aside for its check");
        assert!(matches!(deferred.job, VerifyJob::Operational { .. }));
        assert_eq!(deferred.job.verifying_community(), None);
    }

    /// Dispatch `m` as `arrival`, returning the effects.
    async fn dispatch(
        config: &mut Config,
        tdk: &TDK,
        m: &Message,
        arrival: Arrival<'_>,
    ) -> InboundEffects {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = openvtc_core::didcomm::start_empty_service(
            tx,
            tokio_util::sync::CancellationToken::new(),
        );
        let mut seen = SeenMessages::new();
        let mut effects = InboundEffects::default();
        process_inbound_message(config, tdk, &service, &mut seen, m, &mut effects, arrival)
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
            openvtc_core::protocol_urls::RELATIONSHIP_REQUEST_ACCEPT.to_string(),
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
}
