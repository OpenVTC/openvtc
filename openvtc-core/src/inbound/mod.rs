//! Inbound message dispatch: what this client does with a message a peer or
//! community sent it.
//!
//! Messages that need no human input are applied to [`Config`] here; messages
//! that need a decision are queued as inbox tasks. Anything this cannot do
//! itself — tear down a session, show a challenge, hand a reply to a waiting
//! view — is reported up in [`InboundEffects`] for the caller (the TUI's
//! runtime loop, or a headless command via [`apply_inline`]) to act on.
//!
//! It lives in core, not the CLI crate, so it has no TUI dependency and core's
//! end-to-end harness can drive it (#530).

use std::sync::Arc;

use crate::didcomm::Messaging;
use crate::join::COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE;
use crate::messaging::{
    SeenMessages, check_message_age, check_task_capacity, create_finalize_message,
    credential_in_issue, credential_issue_admissible, handle_community_profile_show_response,
    handle_credential_issue, handle_join_status_response, handle_join_submit_receipt,
    handle_join_trust_task_error, handle_join_verdict, handle_member_removal_notice,
    is_trust_task_error_type, read_problem_report, require_thid, validate_did, verify_inbound_vrc,
    vet_vrc_issued,
};
use crate::pending_replies::{PendingReplies, ReplyKind};
use crate::personhood::{PERSONHOOD_ASSERT_RESPONSE_TYPE, PERSONHOOD_CHALLENGE_RESPONSE_TYPE};
use crate::vetting::protocol::JoinProtocol;
use crate::{
    MessageType,
    config::{Config, account::VtcDid},
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
    vrc::VRCRequestReject,
};
use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use tracing::{debug, info, warn};

pub mod registry;

use registry::Family;
use vta_sdk::protocols::PROBLEM_REPORT_TYPE;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
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
    persona_id: crate::config::account::PersonaId,
    closes_request: Option<uuid::Uuid>,
) -> Result<(uuid::Uuid, serde_json::Value), crate::errors::OpenVTCError> {
    use crate::errors::OpenVTCError;
    // The grant we are acknowledging, as the community sent it. Without one
    // there is nothing to acknowledge: an acknowledgement names a specific
    // grant by digest, and a community that has issued us none has no
    // membership edge for us to complete.
    let membership = config.account.membership(vtc_did, persona_id);
    let over_tsp = membership.is_some_and(|c| c.joined_over_tsp());
    let grant = membership
        .and_then(|c| {
            c.credentials
                .get(&crate::CredentialKind::Membership)
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
    // The acknowledgement goes the way the join went. Resolved fresh, as the
    // join poll does: it is the hop the routing layer seals to, and the
    // community's document may have changed since the submit.
    let tsp_mediator = if over_tsp {
        crate::config::peer_tsp_mediator(vtc_did).await
    } else {
        None
    };
    crate::members::issue_and_send_member_vmc(
        &crate::members::Delivery {
            atm,
            profile: &profile,
            member_did: &member_did,
            vtc_did,
            mediator_did: &mediator,
            tsp_mediator_did: tsp_mediator.as_deref(),
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
    typ.starts_with(crate::capabilities::CAPABILITY_TYPE_PREFIX) || is_trust_task_error_type(typ)
}

/// A community's reply to a request of ours, as handed to the view waiting on
/// it: who sent it, who signed it, and the thread it answers. The view takes a
/// reply only from the community it asked.
#[derive(Debug, Clone)]
pub struct ThreadedReply<R> {
    /// The transport-authenticated sender.
    pub from: String,
    /// The document's `issuer`.
    pub issuer: Option<String>,
    /// The request id the reply threads on.
    pub thid: String,
    /// The classified reply.
    pub reply: R,
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
    pub inactivated: Vec<(VtcDid, crate::config::account::PersonaId)>,
    /// Capability replies, keyed by the request id they thread on.
    /// `(sender, thread id, reply)` — the view takes a reply only from the
    /// community it asked.
    pub capability_replies: Vec<(String, String, crate::capabilities::CapabilityReply)>,
    /// `git-ns/*` replies for the Repos panel, keyed by the request id they
    /// thread on.
    pub git_ns_replies: Vec<ThreadedReply<crate::git_ns::Reply>>,
    /// `vtc/rooms/*` replies for the Rooms panel, keyed by the request id they thread on.
    pub rooms_replies: Vec<ThreadedReply<crate::community_rooms::Reply>>,
    /// `vtc/elections/*` replies for the Elections panel, keyed by the request id they thread
    /// on.
    pub elections_replies: Vec<ThreadedReply<crate::elections::Reply>>,
    /// Personhood challenges the community answered with. Display state with a
    /// ten-minute life — never persisted.
    pub personhood_challenges: Vec<crate::personhood::ChallengeReply>,
    /// Communities' answers to questions we put to them — a directory page, a
    /// stored profile, a resent grant, a manifest — for whoever is waiting.
    pub vetting_answers: Vec<crate::vetting::queries::CommunityAnswer>,
    /// Vetters' grants to check for revocation. The check fetches over HTTPS,
    /// so the loop runs it as a background job.
    pub vetting_grant_checks: Vec<crate::vetting::status::GrantCheck>,
    /// How renewals we asked for ended (`vtc/members/renew/0.1`), keyed by the
    /// community — the panel's status line says what happened.
    pub renewals: Vec<(String, crate::renewal::RenewalOutcome)>,
    /// Documents that may be a witness's answer to a witnessing in progress: its session or
    /// submission `#response`, or a `trust-task-error`. The loop hands each to the witnessing
    /// waiting on its thread, which verifies it as the witness's before reading it; one on a
    /// thread nobody waits on is dropped there.
    pub witness_replies: Vec<crate::witness::InboundReply>,
    /// Notifications (`notifications/notify`, `notifications/relay`) addressed to one of our
    /// personas, exactly as received. The loop hands each to the member's VTA and answers the
    /// sender (VTI-NTF-054); nothing here reads, filters or acts on them.
    pub notifications: Vec<crate::notifications::Received>,
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
        /// The DID the message came from.
        sender: String,
    },
    /// A community's operational document (removal notice, join replies,
    /// profile, capability/git-ns replies, refusals).
    Operational {
        /// The document as delivered.
        document: serde_json::Value,
        /// The DID the message came from, which must be the document's issuer.
        sender: String,
        /// Our DIDs, one of which must be the document's recipient.
        our_dids: Vec<String>,
        /// The type the message is handled as, which the document's signed
        /// `type` must be (its kind and window follow from it).
        typ: String,
    },
    /// A relationship DID's binding proofs.
    DidBinding {
        /// The relationship DID offered.
        did: String,
        /// Its holder's proof of control of it.
        did_proof: Option<serde_json::Value>,
        /// The sending persona DID.
        persona: String,
        /// The persona's proof that it names the relationship DID.
        persona_proof: Option<serde_json::Value>,
        /// Our DID the message was addressed to.
        peer: String,
        /// The handshake's thread id.
        thid: String,
        /// Which side of the handshake the proofs are for.
        role: crate::relationships::BindingRole,
    },
    /// A VRC's proof against its issuer's key.
    Vrc(Box<DTGCredential>),
    /// A community's answer to our renewal: the document's proof, and the
    /// re-issued VMC and role VAC it carries, each as an issued credential
    /// (proof, validity, revocation — fails closed).
    Renewal {
        /// The answer as delivered.
        document: serde_json::Value,
        /// The DID the message came from.
        sender: String,
        /// Our persona DIDs, one of which the answer must be addressed to and renew.
        our_dids: Vec<String>,
    },
    /// No check: the message needs none, but its sender has messages queued
    /// ahead of it, and it waits its turn behind them rather than overtaking
    /// them — a `members/request-vmc` behind the credential that makes the
    /// membership it asks about Active, say.
    Barrier,
    /// A check that never finishes (tests of the queue's timeout).
    #[cfg(any(test, feature = "test-support"))]
    Hang,
    /// A check that panics (tests of the queue's supervision).
    #[cfg(any(test, feature = "test-support"))]
    Panic,
}

/// The result of a [`VerifyJob`]. Recording (replay sets) and every state
/// change stay on the loop: this carries only what was proven.
pub enum PreVerified {
    /// An issued credential's check.
    Credential(
        Result<
            crate::issued_credential::VerifiedIssuedCredential,
            crate::issued_credential::IssuedCredentialError,
        >,
    ),
    /// An operational document's check.
    Operational(
        Result<crate::operational::VerifiedOperational, crate::operational::OperationalError>,
    ),
    /// A relationship DID's binding check.
    DidBinding(Result<(), crate::relationships::DidBindingError>),
    /// A VRC's proof check; the error says why it failed.
    Vrc(Result<(), String>),
    /// A renewal answer's check.
    Renewal(Result<crate::renewal::VerifiedRenewal, crate::renewal::RenewalError>),
    /// Nothing was checked ([`VerifyJob::Barrier`]).
    Barrier,
}

/// Where a message is in its handling.
pub enum Arrival<'a> {
    /// Just arrived. `waiting(sender)` says whether that sender has messages
    /// queued for a check ahead of this one, which it must not overtake.
    New {
        /// Whether a sender has messages queued for a check.
        waiting: &'a dyn Fn(&str) -> bool,
    },
    /// Queued for its check before a restart
    /// ([`crate::config::protected_config::ProtectedConfig::deferred_inbound`]).
    /// It passed the age and replay gates when it arrived; it is set aside
    /// again — for its check if it still passes the local checks, else to wait
    /// its turn and be refused by its handler then. It is never handled
    /// directly.
    Restored,
    /// Back from its check, with the result.
    Returning(PreVerified),
}

#[cfg(any(test, feature = "test-support"))]
fn nobody_waiting(_: &str) -> bool {
    false
}

#[cfg(any(test, feature = "test-support"))]
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
                crate::issued_credential::verify_issued_delivery(
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
                    crate::operational::verify_operational(
                        &document,
                        &sender,
                        &ours,
                        &typ,
                        tdk.did_resolver(),
                        &crate::operational::SeenDocuments::default(),
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
                crate::relationships::verify_did_binding(
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
            VerifyJob::Vrc(vrc) => {
                PreVerified::Vrc(verify_inbound_vrc(&tdk, &vrc, chrono::Utc::now()).await)
            }
            VerifyJob::Renewal {
                document,
                sender,
                our_dids,
            } => {
                let ours: Vec<&str> = our_dids.iter().map(String::as_str).collect();
                PreVerified::Renewal(
                    crate::renewal::verify_renewal_response(
                        &document,
                        &sender,
                        &ours,
                        tdk.did_resolver(),
                        now,
                    )
                    .await,
                )
            }
            VerifyJob::Barrier => PreVerified::Barrier,
            #[cfg(any(test, feature = "test-support"))]
            VerifyJob::Hang => std::future::pending().await,
            #[cfg(any(test, feature = "test-support"))]
            VerifyJob::Panic => panic!("a check that panics"),
        }
    }

    /// The result for a check that did not finish — it timed out, or its task
    /// failed. Always a refusal (fail closed) of the job's own kind.
    #[must_use]
    pub fn unfinished(&self) -> PreVerified {
        match self {
            VerifyJob::Credential { .. } => PreVerified::Credential(Err(
                crate::issued_credential::IssuedCredentialError::CheckUnfinished,
            )),
            VerifyJob::DidBinding { .. } => {
                PreVerified::DidBinding(Err(crate::relationships::DidBindingError::CheckUnfinished))
            }
            VerifyJob::Vrc(_) => PreVerified::Vrc(Err(
                "its proof's check did not finish (timed out or failed)".to_string(),
            )),
            VerifyJob::Renewal { .. } => {
                PreVerified::Renewal(Err(crate::renewal::RenewalError::CheckUnfinished))
            }
            VerifyJob::Barrier => PreVerified::Barrier,
            #[cfg(any(test, feature = "test-support"))]
            VerifyJob::Hang | VerifyJob::Panic => {
                PreVerified::Operational(Err(crate::operational::OperationalError::CheckUnfinished))
            }
            VerifyJob::Operational { .. } => {
                PreVerified::Operational(Err(crate::operational::OperationalError::CheckUnfinished))
            }
        }
    }

    /// Whether this checks a relationship request's binding (DIDs the
    /// requester chose).
    #[must_use]
    pub fn is_relationship_request(&self) -> bool {
        matches!(
            self,
            VerifyJob::DidBinding {
                role: crate::relationships::BindingRole::Request,
                ..
            }
        )
    }

    /// Whether this is a [`VerifyJob::Barrier`] (nothing to check).
    #[cfg(any(test, feature = "test-support"))]
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
    pending: &PendingReplies,
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
    let member_operational = || member.then(operational);
    match registry::classify(typ)? {
        Family::CredentialIssue => {
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
            let from_issuer = crate::issued_credential::issuer_of(&credential) == Some(from_did);
            (member && to_us && from_issuer).then(|| VerifyJob::Credential {
                document: message.body.clone(),
                sender: from_did.to_string(),
            })
        }
        // A community's answer to a vetting question: only from a community we
        // have business with — a question outstanding, an application, or a
        // membership (the same test vetting applies before taking one). The
        // rest of vetting's traffic is checked by vetting.
        Family::Vetting if crate::vetting::inbound::is_community_answer_type(typ) => {
            let business = config.private.vetting.asked(from_did)
                || config
                    .private
                    .vetting
                    .applications
                    .iter()
                    .any(|a| a.community == from_did)
                || member;
            business.then(operational)
        }
        // Our renewal's answer: only one threading on a renewal we asked this
        // community for. It carries credentials, so it is checked as both an
        // operational document and two issued credentials.
        Family::RenewalResponse => {
            let asked = message
                .thid
                .as_deref()
                .is_some_and(|thid| pending.is_awaited(ReplyKind::Renewal, from_did, thid));
            (member && asked).then(|| VerifyJob::Renewal {
                document: message.body.clone(),
                sender: from_did.to_string(),
                our_dids: config
                    .account
                    .personas
                    .values()
                    .map(|p| p.did.clone())
                    .collect(),
            })
        }
        // An election answer — or a refusal, which may be one — from the
        // community holding an election a notification told us of
        // (VTI-NTF-063), which may be one we hold no membership with: only on
        // a thread we sent it.
        Family::ElectionsReply | Family::TrustTaskError if !member => {
            awaited_election_answer(pending, message, from_did).then(operational)
        }
        Family::CapabilityReply
        | Family::GitNsReply
        | Family::RoomsReply
        | Family::ElectionsReply
        | Family::TrustTaskError
        | Family::JoinVerdict
        | Family::MemberRemovalNotice
        | Family::MemberRequestVmc
        | Family::JoinSubmitReceipt
        | Family::JoinStatusResponse
        | Family::CommunityProfileResponse => member_operational(),
        Family::RelationshipRequest => {
            relationship_request_job(config, message, from_did, recipient_did)
        }
        Family::RelationshipRequestAccepted => {
            relationship_accept_job(config, message, from_did, recipient_did)
        }
        Family::VrcIssued => {
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
        Family::Notification
        | Family::WitnessReply
        | Family::Vetting
        | Family::ProblemReport
        | Family::PersonhoodChallengeResponse
        | Family::PersonhoodAssertResponse
        | Family::MemberVmcResponse
        | Family::BindingEnvelope
        | Family::RelationshipRequestRejected
        | Family::RelationshipRequestFinalize
        | Family::TrustPing
        | Family::TrustPong
        | Family::VrcRequest
        | Family::VrcRequestRejected => None,
    }
}

/// A relationship request's binding check, if it could be queued at all.
fn relationship_request_job(
    config: &Config,
    message: &Message,
    from_did: &str,
    recipient_did: &str,
) -> Option<VerifyJob> {
    let body: crate::relationships::RelationshipRequestBody =
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
        role: crate::relationships::BindingRole::Request,
    })
}

/// A relationship accept's binding check, if it answers a request of ours
/// still waiting, from the party it went to.
fn relationship_accept_job(
    config: &Config,
    message: &Message,
    from_did: &str,
    recipient_did: &str,
) -> Option<VerifyJob> {
    let body: RelationshipAcceptBody = serde_json::from_value(message.body.clone()).ok()?;
    validate_did(&body.did).ok()?;
    let thid = message.thid.clone()?;
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
        role: crate::relationships::BindingRole::Accept,
    })
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

/// Whether `message` answers an elections request we sent `from_did` and still wait for — the
/// only standing a community we hold no membership with has here.
fn awaited_election_answer(pending: &PendingReplies, message: &Message, from_did: &str) -> bool {
    let thread = message.thid.as_deref().or_else(|| {
        message
            .body
            .get("threadId")
            .and_then(serde_json::Value::as_str)
    });
    thread.is_some_and(|t| pending.is_awaited(ReplyKind::ElectionAnswer, from_did, t))
}

/// An operational document that was not checked.
static NOT_CHECKED: Result<
    crate::operational::VerifiedOperational,
    crate::operational::OperationalError,
> = Err(crate::operational::OperationalError::NotChecked);

/// The operational result the off-loop check produced, or "not checked".
fn pre_operational(
    pre: &Option<PreVerified>,
) -> Result<crate::operational::VerifiedOperational, crate::operational::OperationalError> {
    match pre {
        Some(PreVerified::Operational(r)) => r.clone(),
        _ => Err(crate::operational::OperationalError::NotChecked),
    }
}

/// Whether a community's reply to a question of ours (capability, git-ns) may
/// be taken: it must be the community's signed operational document —
/// `authentication` key, addressed to the persona it arrived for, fresh, not
/// seen before ([`crate::operational`]). That holds for a refusal
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
    pending: &PendingReplies,
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
        // to, so a reply from anyone else has no standing, and is not recorded —
        // except an election answer on a thread we sent that community, for an
        // election a notification told us of (VTI-NTF-063).
        Ok(_)
            if config.account.memberships_for(from_did).is_empty()
                && !(crate::elections::is_reply_type(&message.typ)
                    && awaited_election_answer(pending, message, from_did)) =>
        {
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
) -> Result<crate::operational::VerifiedOperational, crate::operational::OperationalError> {
    // A community we hold no membership with (Pending included) has asked
    // nothing of ours to answer.
    if config.account.memberships_for(from_did).is_empty() {
        return Err(crate::operational::OperationalError::NoStanding);
    }
    let verified = pre_operational(pre)?;
    verified.check(&config.private.seen_documents, chrono::Utc::now())?;
    Ok(verified)
}

/// Commit a verified community reply that matched something of ours.
fn commit_community_document(
    config: &mut Config,
    verified: crate::operational::VerifiedOperational,
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
///
/// `authenticated` is the sender the transport bound to the frame
/// ([`crate::didcomm::DIDCommEvent::InboundMessage`]). The message is
/// handled as that sender only: one with no authenticated sender, or whose
/// `from` names someone else, is dropped before any handler sees it
/// ([`crate::didcomm::bound_sender`]).
#[allow(clippy::too_many_arguments)]
pub async fn process_inbound_message(
    config: &mut Config,
    tdk: &TDK,
    service: &Messaging,
    seen: &mut SeenMessages,
    pending: &mut PendingReplies,
    message: &Message,
    authenticated: Option<&str>,
    effects: &mut InboundEffects,
    arrival: Arrival<'_>,
) -> Result<bool, anyhow::Error> {
    // A document recorded as acted on must be saved even when the handler
    // reports no other change — otherwise a restart forgets it and the
    // document can be replayed.
    let seen_before = config.private.seen_documents.revision();
    let changed = process_inbound(
        config,
        tdk,
        service,
        seen,
        pending,
        message,
        authenticated,
        effects,
        arrival,
    )
    .await?;
    Ok(changed || config.private.seen_documents.revision() != seen_before)
}

#[allow(clippy::too_many_arguments)]
async fn process_inbound(
    config: &mut Config,
    tdk: &TDK,
    service: &Messaging,
    seen: &mut SeenMessages,
    pending: &mut PendingReplies,
    message: &Message,
    authenticated: Option<&str>,
    effects: &mut InboundEffects,
    arrival: Arrival<'_>,
) -> Result<bool, anyhow::Error> {
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

    // The sender: the DID the transport authenticated, and the `from` header
    // only where it names that same DID. A message with no authenticated
    // sender, or claiming someone else's `from`, is handled as nobody — no
    // inbox task, no reply, no receipt, no task removed. It selects the record
    // a message is about; decisions with lasting effect (a credential stored,
    // a membership ended, a relationship bound) are further gated on a proof
    // by that party (`crate::proof_check`).
    //
    // Before the replay cache: a message handled as nobody must not take up
    // the id of one that is, or the real one would be dropped as its replay.
    let from_did = match crate::didcomm::bound_sender(message.from.as_deref(), authenticated) {
        Ok(did) => Arc::new(did),
        Err(reason) => {
            warn!(
                id = %message.id,
                typ = %message.typ,
                claimed = ?message.from,
                "inbound message dropped: {reason}"
            );
            return Ok(false);
        }
    };

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
    let opened = crate::didcomm::open_didcomm_envelope(message);
    if opened.is_none() && message.typ == crate::capabilities::TRUST_TASK_ENVELOPE_TYPE {
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
            verification_job(config, pending, message, &from_did, &recipient_did),
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
            effects.deferred = Some(Deferred {
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

    let Some(family) = registry::classify(&message.typ) else {
        warn!(typ = %message.typ, "unknown message type — ignoring");
        return Ok(false);
    };
    let mut cx = Cx {
        tdk,
        service,
        pending,
        message,
        from_did,
        recipient_did,
        recipient_persona,
        pre,
    };
    let c = &mut cx;
    match family {
        Family::Notification => notification(config, c, effects),
        Family::CapabilityReply => capability_reply(config, c, effects),
        Family::GitNsReply => git_ns_reply(config, c, effects),
        Family::RoomsReply => rooms_reply(config, c, effects),
        Family::ElectionsReply => elections_reply(config, c, effects),
        Family::WitnessReply => witness_reply(c, effects),
        Family::Vetting => vetting(config, c, effects).await,
        Family::JoinSubmitReceipt => join_submit_receipt(config, c),
        Family::CredentialIssue => credential_issue(config, c, effects).await,
        Family::JoinVerdict => join_verdict(config, c, effects),
        Family::ProblemReport => problem_report(config, c, effects).await,
        Family::RenewalResponse => renewal_response(config, c, effects).await,
        Family::TrustTaskError => trust_task_error(config, c, effects).await,
        Family::JoinStatusResponse => join_status_response(config, c, effects),
        Family::CommunityProfileResponse => community_profile_response(config, c),
        Family::PersonhoodChallengeResponse => personhood_challenge(c, effects),
        Family::PersonhoodAssertResponse => personhood_assert(c),
        Family::MemberVmcResponse => member_vmc_response(config, c),
        Family::MemberRequestVmc => member_request_vmc(config, c).await,
        Family::MemberRemovalNotice => member_removal_notice(config, c, effects),
        // Reached only by an envelope `open_didcomm_envelope` could not open
        // (one that could has been routed as the document it carries).
        Family::BindingEnvelope => Ok(unclaimed(message)),
        Family::RelationshipRequest => peer(config, c, MessageType::RelationshipRequest).await,
        Family::RelationshipRequestRejected => {
            peer(config, c, MessageType::RelationshipRequestRejected).await
        }
        Family::RelationshipRequestAccepted => {
            peer(config, c, MessageType::RelationshipRequestAccepted).await
        }
        Family::RelationshipRequestFinalize => {
            peer(config, c, MessageType::RelationshipRequestFinalize).await
        }
        Family::TrustPing => peer(config, c, MessageType::TrustPing).await,
        Family::TrustPong => peer(config, c, MessageType::TrustPong).await,
        Family::VrcRequest => peer(config, c, MessageType::VRCRequest).await,
        Family::VrcRequestRejected => peer(config, c, MessageType::VRCRequestRejected).await,
        Family::VrcIssued => peer(config, c, MessageType::VRCIssued).await,
    }
}

/// What every family's handler reads about the message in hand.
struct Cx<'a> {
    tdk: &'a TDK,
    service: &'a Messaging,
    /// The requests we wait on an answer for: the gate for answers admitted
    /// only because we asked (a renewal, a profile, an election).
    pending: &'a mut PendingReplies,
    /// The message as routed (opened out of its binding envelope).
    message: &'a Message,
    /// The authenticated sender.
    from_did: Arc<String>,
    /// The persona it was addressed to — the DID any reply goes out as.
    recipient_did: String,
    recipient_persona: Option<crate::config::account::PersonaId>,
    /// The result of its off-loop check, if it had one.
    pre: Option<PreVerified>,
}

/// A message of a routed family that its handler did not take: logged, and
/// nothing changes.
fn unclaimed(message: &Message) -> bool {
    warn!(typ = %message.typ, "inbound message not taken by its handler — ignoring");
    false
}

/// [`Family::Notification`].
fn notification(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let InboundEffects { notifications, .. } = effects;
    // A notification addressed to one of our personas (VTI-NTF-054): handed to the member's
    // VTA exactly as received, whoever sent it — no acceptance policy here, which would be
    // declining on the principal's behalf. The loop deposits it and answers the sender; nothing
    // else is done because of it (VTI-NTF-053).
    if crate::notifications::is_notification_type(&message.typ) {
        match crate::notifications::addressee_of(&message.body)
            .filter(|addressee| config.account.persona_id_for_did(addressee).is_some())
        {
            Some(addressee) => notifications.push(crate::notifications::Received {
                document: message.body.clone(),
                sender: from_did.to_string(),
                addressee: addressee.to_string(),
                // The loop knows the carriage; it sets this.
                over_tsp: false,
            }),
            None => warn!(
                id = %message.id,
                "notification addressed to a DID this account holds no persona for — not handed \
                 to the VTA"
            ),
        }
        return Ok(false);
    }
    Ok(unclaimed(message))
}

/// [`Family::CapabilityReply`].
fn capability_reply(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let pre = cx.pre.take();
    // Computed at most once per message (see `community_reply_proven`).
    let mut reply_proven: Option<bool> = None;
    let InboundEffects {
        capability_replies, ..
    } = effects;
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
        && let Some((thid, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some(reply) = crate::capabilities::parse_capability_reply(&doc, &thid)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        capability_replies.push((from_did.to_string(), thid, reply));
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }
    Ok(unclaimed(message))
}

/// [`Family::GitNsReply`].
fn git_ns_reply(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let pre = cx.pre.take();
    // Computed at most once per message (see `community_reply_proven`).
    let mut reply_proven: Option<bool> = None;
    let InboundEffects { git_ns_replies, .. } = effects;
    // Git namespace replies (git-ns/*), in either carriage, for the Repos
    // panel — keyed by the document's `threadId` and correlated there against
    // the one request the panel has outstanding; anything else is dropped.
    // A `trust-task-error` is offered here as well and falls through, for the
    // same reason as above.
    if crate::git_ns::is_reply_type(&message.typ)
        && let Some((_, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = crate::git_ns::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        // The sender and the document's issuer travel with the answer: the
        // Repos view takes one only from the community it asked.
        git_ns_replies.push(ThreadedReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }
    Ok(unclaimed(message))
}

/// [`Family::RoomsReply`].
fn rooms_reply(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let pre = cx.pre.take();
    // Computed at most once per message (see `community_reply_proven`).
    let mut reply_proven: Option<bool> = None;
    let InboundEffects { rooms_replies, .. } = effects;
    // Data-room replies (vtc/rooms/*), in either carriage, for the Rooms panel — keyed by
    // `threadId` and correlated there against the one request the panel has outstanding.
    // A `trust-task-error` is offered here as well and falls through.
    if crate::community_rooms::is_reply_type(&message.typ)
        && let Some((_, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = crate::community_rooms::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        rooms_replies.push(ThreadedReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }
    Ok(unclaimed(message))
}

/// [`Family::ElectionsReply`].
fn elections_reply(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let pre = cx.pre.take();
    // Computed at most once per message (see `community_reply_proven`).
    let mut reply_proven: Option<bool> = None;
    let InboundEffects {
        elections_replies, ..
    } = effects;
    // Election replies (vtc/elections/*), in either carriage, for the Elections panel — keyed by
    // `threadId` and correlated there against the one request the panel has outstanding. A
    // `trust-task-error` is offered here as well and falls through.
    if crate::elections::is_reply_type(&message.typ)
        && let Some((_, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = crate::elections::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        elections_replies.push(ThreadedReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }
    Ok(unclaimed(message))
}

/// [`Family::WitnessReply`]. Without a `threadId` it answers nothing.
fn witness_reply(cx: &mut Cx<'_>, effects: &mut InboundEffects) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let InboundEffects {
        witness_replies, ..
    } = effects;
    // A witness's answers (`witness/session/0.2#response`, `witness/session/submit/0.2#response`),
    // for a witnessing of one of our relationships. They arrive on the relationship DID's own
    // listener, in either carriage, threaded on the session id. Nothing is read here: the
    // witnessing waiting on that thread verifies each as the witness's first. A
    // `trust-task-error` may be a witness's refusal as much as anything else's, so it is offered
    // here too and falls through, as it does for the capability and git-ns views above.
    if (crate::witness::is_reply_type(&message.typ) || is_trust_task_error_type(&message.typ))
        && message.body.get("threadId").is_some()
    {
        witness_replies.push(crate::witness::InboundReply {
            sender: from_did.to_string(),
            document: message.body.clone(),
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }
    Ok(unclaimed(message))
}

/// [`Family::Vetting`].
async fn vetting(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let tdk = cx.tdk;
    let service = cx.service;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let recipient_persona = cx.recipient_persona;
    let pre = cx.pre.take();
    let InboundEffects {
        vetting_answers,
        vetting_grant_checks,
        ..
    } = effects;
    // Peer identity vetting (docs/design/vetting-process.md): requests,
    // sessions, cards, statements, declines and refusals between members, and a
    // community's vetting requirements. Tried before the join and credential
    // routes below because it shares two of their types; `handle` returns
    // `None` for anything that is not vetting's, which falls through unchanged.
    if crate::vetting::inbound::may_claim(&message.typ) {
        let resolver =
            vta_sdk::trust_task_proof::TrustTaskVmResolver::new(tdk.did_resolver().clone());
        let ctx = crate::vetting::inbound::Context {
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
        if let Some(handled) = crate::vetting::inbound::handle(
            &mut config.private.vetting,
            &ctx,
            &mut config.private.seen_documents,
            message,
            &from_did,
        )
        .await
        {
            if let Some(reply) = handled.reply
                && let Err(e) = crate::vetting::wire::send_reply(config, tdk, service, reply).await
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
                    .private
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
    Ok(unclaimed(message))
}

/// [`Family::JoinSubmitReceipt`].
fn join_submit_receipt(config: &mut Config, cx: &mut Cx<'_>) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let pre = cx.pre.take();
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
    Ok(unclaimed(message))
}

/// [`Family::CredentialIssue`]: vetting's first (a vetter's statement or grant
/// arrives this way), then the community's credential.
async fn credential_issue(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let tdk = cx.tdk;
    let service = cx.service;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let recipient_persona = cx.recipient_persona;
    let pre = cx.pre.take();
    let InboundEffects {
        vetting_answers,
        vetting_grant_checks,
        ..
    } = effects;
    // Peer identity vetting (docs/design/vetting-process.md): requests,
    // sessions, cards, statements, declines and refusals between members, and a
    // community's vetting requirements. Tried before the join and credential
    // routes below because it shares two of their types; `handle` returns
    // `None` for anything that is not vetting's, which falls through unchanged.
    if crate::vetting::inbound::may_claim(&message.typ) {
        let resolver =
            vta_sdk::trust_task_proof::TrustTaskVmResolver::new(tdk.did_resolver().clone());
        let ctx = crate::vetting::inbound::Context {
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
        if let Some(handled) = crate::vetting::inbound::handle(
            &mut config.private.vetting,
            &ctx,
            &mut config.private.seen_documents,
            message,
            &from_did,
        )
        .await
        {
            if let Some(reply) = handled.reply
                && let Err(e) = crate::vetting::wire::send_reply(config, tdk, service, reply).await
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
                    .private
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

    // VTC credential delivery: on approve, the VTC pushes the issued VMC + role
    // VEC as separate `credential-exchange/issue` messages. Store each on the
    // community and flip Pending -> Active when the membership credential lands.
    if message.typ == CREDENTIAL_ISSUE_TYPE {
        // Snapshot before, so the log can say what *changed* rather than that a
        // message arrived. An issued membership credential is the moment a join
        // completes — the single most consequential inbound message there is,
        // and it must not read like any other in the log.
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
            _ => Err(crate::issued_credential::IssuedCredentialError::NotChecked),
        } {
            Ok(verified) => verified,
            Err(e) => {
                // The reason only: never the credential, and the DID stays out
                // of the log line (the activity feed names the community).
                warn!(reason = %e, "refused an issued credential");
                config
                    .account
                    .note_credential_refused(&from_did, Some(&e.to_string()));
                config.private.logs.insert(
                    LogFamily::Community,
                    format!("Refused a credential from community ({from_did}): {e}."),
                );
                return Ok(true);
            }
        };
        let outcome = handle_credential_issue(&mut config.account, verified, &from_did);
        if outcome.changed {
            config.account.note_credential_refused(&from_did, None);
        }
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
                        record.clear_retired(
                            crate::config::account::RetiredCredential::MEMBER_ACKNOWLEDGEMENT,
                        );
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
            config.private.logs.insert(
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
    Ok(unclaimed(message))
}

/// [`Family::JoinVerdict`].
fn join_verdict(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let pre = cx.pre.take();
    let InboundEffects { inactivated, .. } = effects;
    // VTC join-requests submit `#response`: the synchronous admission verdict in
    // the trust-task join model (allow / deny / refer / request_more), threaded
    // (`thid`) on our submit message id. `allow` → Active, `deny` → Rejected; a
    // rejection inactivates the community so the loop deregisters the session.
    if JoinProtocol::is_submit_response(&message.typ) {
        let verified = match community_document(config, &pre, &from_did) {
            Ok(v) => v,
            Err(e) => {
                warn!(reason = %e, "join verdict refused");
                return Ok(false);
            }
        };
        let outcome = handle_join_verdict(&mut config.account, message, &from_did);
        // A `requestMore` is the one verdict that asks the member to act, so
        // what it lacks is said where they will see it — not only in a trace.
        if let Some(needs) = crate::messaging::join_verdict_needs(message) {
            // Under a hidden-vetting criterion the join carried a proof, not statements, and
            // the sentence is about the proof.
            let hidden = config
                .private
                .vetting
                .applications
                .iter()
                .any(|a| a.community == from_did.as_str() && a.hidden.is_some());
            config.private.logs.insert(
                LogFamily::Community,
                format!(
                    "Community ({from_did}) has not decided your join yet: {}.",
                    crate::messaging::describe_join_needs(&needs, hidden)
                ),
            );
        }
        if outcome.changed {
            commit_community_document(config, verified);
        }
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }
    Ok(unclaimed(message))
}

/// [`Family::ProblemReport`]: vetting's first, then a community's report.
async fn problem_report(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let tdk = cx.tdk;
    let service = cx.service;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let recipient_persona = cx.recipient_persona;
    let pre = cx.pre.take();
    let InboundEffects {
        vetting_answers,
        vetting_grant_checks,
        ..
    } = effects;
    // Peer identity vetting (docs/design/vetting-process.md): requests,
    // sessions, cards, statements, declines and refusals between members, and a
    // community's vetting requirements. Tried before the join and credential
    // routes below because it shares two of their types; `handle` returns
    // `None` for anything that is not vetting's, which falls through unchanged.
    if crate::vetting::inbound::may_claim(&message.typ) {
        let resolver =
            vta_sdk::trust_task_proof::TrustTaskVmResolver::new(tdk.did_resolver().clone());
        let ctx = crate::vetting::inbound::Context {
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
        if let Some(handled) = crate::vetting::inbound::handle(
            &mut config.private.vetting,
            &ctx,
            &mut config.private.seen_documents,
            message,
            &from_did,
        )
        .await
        {
            if let Some(reply) = handled.reply
                && let Err(e) = crate::vetting::wire::send_reply(config, tdk, service, reply).await
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
                    .private
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
        config.private.logs.insert(
            LogFamily::Community,
            format!(
                "Community ({from_did}) reported a problem [{}]: {} — unsigned, so nothing \
                 was changed",
                note.code, note.comment
            ),
        );
        return Ok(true);
    }
    Ok(unclaimed(message))
}

/// [`Family::RenewalResponse`].
async fn renewal_response(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let tdk = cx.tdk;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let pre = cx.pre.take();
    let InboundEffects { renewals, .. } = effects;
    // The community's answer to a renewal we asked for
    // (`vtc/members/renew/0.1#response`): the re-issued VMC and role VAC,
    // verified off the loop as the community's signed document and as two
    // issued credentials. Stored on the membership, replacing what it held —
    // which is what clears a pre-v1 notice — and then answered with a fresh
    // acknowledgement, because the new grant has a new digest.
    if message.typ == crate::renewal::MEMBERS_RENEW_RESPONSE_TYPE {
        use crate::renewal::{RenewalError, RenewalOutcome};
        let thid = message.thid.as_deref().unwrap_or_default();
        let verified = match &pre {
            Some(PreVerified::Renewal(Ok(v))) => v.clone(),
            other => {
                let e = match other {
                    Some(PreVerified::Renewal(Err(e))) => e.clone(),
                    _ => RenewalError::NotChecked,
                };
                warn!(vtc = %from_did, reason = %e, "renewal reply refused");
                // Reported only when it threads on a renewal of ours: anything
                // else answers nothing the member is waiting on. The request is
                // not consumed — a forged reply must not be able to cancel the
                // genuine one still on its way.
                if cx.pending.is_awaited(ReplyKind::Renewal, &from_did, thid) {
                    config
                        .account
                        .note_credential_refused(&from_did, Some(&e.to_string()));
                    let outcome = RenewalOutcome::Failed(e.to_string());
                    config.private.logs.insert(
                        LogFamily::Community,
                        format!("Community ({from_did}): {}", outcome.describe()),
                    );
                    renewals.push((from_did.to_string(), outcome));
                    return Ok(true);
                }
                return Ok(false);
            }
        };
        let now = chrono::Utc::now();
        if let Err(e) = verified
            .document()
            .check(&config.private.seen_documents, now)
        {
            warn!(vtc = %from_did, reason = %e, "renewal reply refused");
            return Ok(false);
        }
        match cx.pending.take(ReplyKind::Renewal, &from_did, thid) {
            Some(crate::pending_replies::Purpose::Renewal { member_did })
                if member_did == verified.member_did() => {}
            _ => {
                warn!(vtc = %from_did, "renewal reply answers no renewal of ours — ignored");
                return Ok(false);
            }
        }
        commit_community_document(config, verified.document().clone());
        let outcome = match crate::renewal::apply_renewal(&mut config.account, &verified, &from_did)
        {
            Err(e) => RenewalOutcome::Failed(e.to_string()),
            Ok(summary) => {
                config.account.note_credential_refused(&from_did, None);
                // The new grant has a new digest, so the community is owed a
                // fresh acknowledgement — sent the way the join flow sends one
                // on admission. Best-effort: the renewed credentials are
                // already stored, and the member can send it with `m`.
                //
                // A renewal that rescued an approved join closes its
                // request, as the delivered credential would have.
                let acknowledged = match issue_member_vmc_for(
                    config,
                    tdk,
                    &from_did,
                    summary.persona,
                    summary.closed_join,
                )
                .await
                {
                    Ok((_, vmc)) => {
                        crate::renewal::store_acknowledgement(
                            &mut config.account,
                            &from_did,
                            summary.persona,
                            vmc,
                        );
                        Ok(())
                    }
                    Err(e) => {
                        warn!(
                            vtc = %from_did,
                            error = %e,
                            "membership renewed, but our acknowledgement could not be sent"
                        );
                        Err(e.to_string())
                    }
                };
                info!(
                    vtc = %from_did,
                    personhood = summary.personhood,
                    personhood_changed = summary.personhood_changed,
                    cleared_retired = summary.cleared_retired,
                    "membership renewed"
                );
                RenewalOutcome::Renewed {
                    summary,
                    acknowledged,
                }
            }
        };
        config.private.logs.insert(
            LogFamily::Community,
            format!("Community ({from_did}): {}", outcome.describe()),
        );
        renewals.push((from_did.to_string(), outcome));
        return Ok(true);
    }
    Ok(unclaimed(message))
}

/// [`Family::TrustTaskError`]: a refusal may answer any request we sent, so it
/// is offered to each view waiting on a thread (capability, `git-ns`, rooms,
/// elections, a witnessing), then to vetting, then to a renewal of ours, and
/// last to the join it may refuse. Each step drops a refusal that threads on
/// nothing of its own. The order is the order these were checked in before the
/// registry, and the join step always decides.
async fn trust_task_error(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let tdk = cx.tdk;
    let service = cx.service;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let recipient_persona = cx.recipient_persona;
    let pre = cx.pre.take();
    // Computed at most once per message (see `community_reply_proven`).
    let mut reply_proven: Option<bool> = None;
    let InboundEffects {
        inactivated,
        capability_replies,
        git_ns_replies,
        rooms_replies,
        elections_replies,
        vetting_answers,
        vetting_grant_checks,
        renewals,
        witness_replies,
        ..
    } = effects;
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
        && let Some((thid, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some(reply) = crate::capabilities::parse_capability_reply(&doc, &thid)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
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
    if crate::git_ns::is_reply_type(&message.typ)
        && let Some((_, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = crate::git_ns::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        // The sender and the document's issuer travel with the answer: the
        // Repos view takes one only from the community it asked.
        git_ns_replies.push(ThreadedReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }

    // Data-room replies (vtc/rooms/*), in either carriage, for the Rooms panel — keyed by
    // `threadId` and correlated there against the one request the panel has outstanding.
    // A `trust-task-error` is offered here as well and falls through.
    if crate::community_rooms::is_reply_type(&message.typ)
        && let Some((_, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = crate::community_rooms::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        rooms_replies.push(ThreadedReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }

    // Election replies (vtc/elections/*), in either carriage, for the Elections panel — keyed by
    // `threadId` and correlated there against the one request the panel has outstanding. A
    // `trust-task-error` is offered here as well and falls through.
    if crate::elections::is_reply_type(&message.typ)
        && let Some((_, doc)) = crate::capabilities::parse_envelope_document(&message.body)
        && let Some((thid, reply)) = crate::elections::parse_reply(&doc)
        && community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        )
    {
        elections_replies.push(ThreadedReply {
            from: from_did.to_string(),
            issuer: doc.issuer.clone(),
            thid,
            reply,
        });
        if !is_trust_task_error_type(&message.typ) {
            return Ok(false);
        }
    }

    // A witness's answers (`witness/session/0.2#response`, `witness/session/submit/0.2#response`),
    // for a witnessing of one of our relationships. They arrive on the relationship DID's own
    // listener, in either carriage, threaded on the session id. Nothing is read here: the
    // witnessing waiting on that thread verifies each as the witness's first. A
    // `trust-task-error` may be a witness's refusal as much as anything else's, so it is offered
    // here too and falls through, as it does for the capability and git-ns views above.
    if (crate::witness::is_reply_type(&message.typ) || is_trust_task_error_type(&message.typ))
        && message.body.get("threadId").is_some()
    {
        witness_replies.push(crate::witness::InboundReply {
            sender: from_did.to_string(),
            document: message.body.clone(),
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
    if crate::vetting::inbound::may_claim(&message.typ) {
        let resolver =
            vta_sdk::trust_task_proof::TrustTaskVmResolver::new(tdk.did_resolver().clone());
        let ctx = crate::vetting::inbound::Context {
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
        if let Some(handled) = crate::vetting::inbound::handle(
            &mut config.private.vetting,
            &ctx,
            &mut config.private.seen_documents,
            message,
            &from_did,
        )
        .await
        {
            if let Some(reply) = handled.reply
                && let Err(e) = crate::vetting::wire::send_reply(config, tdk, service, reply).await
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
                    .private
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

    // A refusal of a renewal we asked for — `vtc/members/renew:notMember`, or
    // anything else the community answers it with. Matched on the thread
    // before the join handler below, which would otherwise take it for a
    // refusal of a join and drop it for matching no pending request.
    if is_trust_task_error_type(&message.typ)
        && let Some(thid) = message.thid.as_deref()
        && cx.pending.is_awaited(ReplyKind::Renewal, &from_did, thid)
    {
        if !community_reply_proven(
            config,
            &pre,
            message,
            &from_did,
            &recipient_did,
            &mut reply_proven,
            cx.pending,
        ) {
            return Ok(false);
        }
        let _ = cx.pending.take(ReplyKind::Renewal, &from_did, thid);
        let outcome = crate::renewal::RenewalOutcome::Refused(
            crate::renewal::RenewalRefusal::read(&message.body),
        );
        warn!(vtc = %from_did, "renewal refused by the community");
        config.private.logs.insert(
            LogFamily::Community,
            format!("Community ({from_did}): {}", outcome.describe()),
        );
        renewals.push((from_did.to_string(), outcome));
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
        //
        // Every refusal is first offered to the capability and git-ns views
        // above, which prove it and record it as acted on. Checked again here
        // it would read as a replay of itself — and warn that a community
        // refusal was ignored, when it was the answer a view was waiting for.
        // Proven in this pass, it needs no second check; and unless it refuses
        // a join of ours it is none of this handler's business, so it is let
        // go quietly rather than reported as matching nothing.
        let verified = if reply_proven == Some(true) {
            let refuses_a_join = message
                .thid
                .as_deref()
                .and_then(|thid| uuid::Uuid::parse_str(thid).ok())
                .is_some_and(|id| {
                    config
                        .account
                        .membership_by_pending_request(&from_did, id)
                        .is_some()
                });
            if !refuses_a_join {
                debug!(
                    vtc = %from_did,
                    "community refusal for a capability or git-ns request — not a join's"
                );
                return Ok(false);
            }
            None
        } else {
            match community_document(config, &pre, &from_did) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(reason = %e, "unverified community refusal ignored");
                    return Ok(false);
                }
            }
        };
        let outcome = handle_join_trust_task_error(&mut config.account, message, &from_did);
        if outcome.changed
            && let Some(verified) = verified
        {
            commit_community_document(config, verified);
        }
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }
    Ok(unclaimed(message))
}

/// [`Family::JoinStatusResponse`].
fn join_status_response(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let pre = cx.pre.take();
    let InboundEffects { inactivated, .. } = effects;
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
    Ok(unclaimed(message))
}

/// [`Family::CommunityProfileResponse`].
fn community_profile_response(config: &mut Config, cx: &mut Cx<'_>) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let pre = cx.pre.take();
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
        let asked = message.thid.as_deref().is_some_and(|thid| {
            cx.pending
                .take(ReplyKind::CommunityProfile, &from_did, thid)
                .is_some()
        });
        if !asked {
            warn!("community profile response we did not ask for — ignored");
            return Ok(false);
        }
        commit_community_document(config, verified);
        let changed =
            handle_community_profile_show_response(&mut config.account, message, &from_did);
        return Ok(changed);
    }
    Ok(unclaimed(message))
}

/// [`Family::PersonhoodChallengeResponse`].
fn personhood_challenge(
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let InboundEffects {
        personhood_challenges,
        ..
    } = effects;
    // VTC personhood challenge reply: carries the nonce an assertion must be
    // signed over, and the match code to read aloud. Reported up rather than
    // applied here — the challenge is display state with a ten-minute life,
    // and this function owns `Config`, which is the thing that gets persisted.
    // A single-use nonce has no business surviving a restart.
    if message.typ == PERSONHOOD_CHALLENGE_RESPONSE_TYPE {
        match crate::personhood::parse_challenge_reply(&message.body) {
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
    Ok(unclaimed(message))
}

/// [`Family::PersonhoodAssertResponse`].
fn personhood_assert(cx: &mut Cx<'_>) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    // VTC personhood assertion result. The re-issued VMC carrying
    // `PersonhoodCredential` arrives separately as a credential-issue message,
    // which is what actually updates the wallet — this is the decision.
    if message.typ == PERSONHOOD_ASSERT_RESPONSE_TYPE {
        match crate::personhood::parse_assert_reply(&message.body) {
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
    Ok(unclaimed(message))
}

/// [`Family::MemberVmcResponse`].
fn member_vmc_response(config: &mut Config, cx: &mut Cx<'_>) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    // VTC member-VMC receipt (`members/vmc/1.0#response`): the VTC acknowledging
    // the reciprocal VMC we sent. Informational — log and move on.
    if message.typ == MEMBER_VMC_RESPONSE_TYPE {
        info!(vtc = %from_did, "VTC acknowledged our membership credential (member VMC receipt)");
        // The send reports only that a frame was accepted locally. This is the
        // first and only evidence the community actually took the credential,
        // so it belongs where the member can see it rather than in a log file.
        config.private.logs.insert(
            LogFamily::Community,
            format!("Community ({from_did}) acknowledged your membership credential."),
        );
        return Ok(true);
    }
    Ok(unclaimed(message))
}

/// [`Family::MemberRequestVmc`].
async fn member_request_vmc(config: &mut Config, cx: &mut Cx<'_>) -> Result<bool, anyhow::Error> {
    let tdk = cx.tdk;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_persona = cx.recipient_persona;
    let pre = cx.pre.take();
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
                            record.clear_retired(
                                crate::config::account::RetiredCredential::MEMBER_ACKNOWLEDGEMENT,
                            );
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
    Ok(unclaimed(message))
}

/// [`Family::MemberRemovalNotice`].
fn member_removal_notice(
    config: &mut Config,
    cx: &mut Cx<'_>,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let pre = cx.pre.take();
    let InboundEffects { inactivated, .. } = effects;
    // VTC → member removal notice (`vtc/members/removal-notice/0.1`): the
    // community telling a member it removed them (issue #240). Unsolicited — not
    // threaded on anything we sent — and the first thing that can move a
    // membership into `Removed`. A removal inactivates the community, so report
    // its VTC DID up for the loop to deregister the session (R-S-3).
    if message.typ == MEMBER_REMOVAL_NOTICE_TYPE {
        // Only the community's signature ends a membership.
        let notice = match crate::messaging::bind_removal_notice(
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
                config.private.logs.insert(
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
    Ok(unclaimed(message))
}

/// The OpenVTC relationship / VRC / trust-ping families, by their
/// [`MessageType`].
async fn peer(
    config: &mut Config,
    cx: &mut Cx<'_>,
    msg_type: MessageType,
) -> Result<bool, anyhow::Error> {
    let service = cx.service;
    let message = cx.message;
    let from_did = Arc::clone(&cx.from_did);
    let recipient_did = cx.recipient_did.clone();
    let recipient_persona = cx.recipient_persona;
    let pre = cx.pre.take();

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
                our_did.map(|our_did| crate::didcomm::listener_id_for_did(&our_did, config));
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

            config.private.logs.insert(
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
                _ => Err(crate::relationships::DidBindingError::NotChecked),
            } {
                warn!(reason = %e, "relationship accept refused");
                config.private.logs.insert(
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

            if let Err(e) = crate::didcomm::send_message(
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
            config.private.logs.insert(
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
            config.private.logs.insert(
                LogFamily::Relationship,
                format!("Relationship finalized with ({})", from_did),
            );
            info!(from = %from_did, "relationship finalized (auto-processed)");
            Ok(true)
        }

        MessageType::TrustPong => {
            // A pong closes only our own ping, on its thread, to the party
            // that answers — the thread id alone names no counterparty.
            let Some(task_id) = message.thid.as_deref().map(|t| Arc::new(t.to_string())) else {
                debug!(from = %from_did, "trust-pong on no thread — ignoring");
                return Ok(false);
            };
            if !is_our_ping_to(config, &task_id, &from_did) {
                warn!(from = %from_did, "trust-pong for no ping of ours to this party — ignoring");
                return Ok(false);
            }
            config.private.tasks.remove(&task_id);
            debug!(from = %from_did, "trust-pong received (auto-processed)");
            Ok(true)
        }

        MessageType::VRCRequestRejected => {
            let task_id = require_thid(message)?;
            let body: VRCRequestReject = serde_json::from_value(message.body.clone())?;

            // A rejection closes only our own VRC request, on its thread, to the
            // party it was sent to — the thread id alone names no counterparty,
            // and anyone who learned it could otherwise delete the task.
            if !crate::tasks::is_our_vrc_request_to(
                &config.private.tasks,
                &config.private.relationships,
                &task_id,
                &from_did,
            ) {
                warn!("VRC reject for no request of ours to this party — ignoring");
                return Ok(false);
            }

            config.private.tasks.remove(&task_id);
            config.private.logs.insert(
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
            let body: crate::relationships::RelationshipRequestBody =
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
                _ => Err(crate::relationships::DidBindingError::NotChecked),
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

            config.private.logs.insert(
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

            config.private.logs.insert(
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
            // issuer's resolved key, the credential must be inside its validity
            // window, and a status it names must be established as not revoked
            // — all before any state is touched.
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

            config.private.logs.insert(
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
    }
}

/// The runtime loop's inbound handling without the loop: dispatch, run any
/// deferred check inline, dispatch again with its result. `true` when the
/// config changed.
///
/// For headless commands that listen as a persona, so a message they were not
/// waiting for is applied rather than lost. Each command holds its own
/// `pending` table for the life of its listening, as the runtime loop holds
/// its own. Effects that need a live UI or a
/// session manager (a view's reply, a session to tear down) are dropped; the
/// account state they stand beside is applied.
///
/// `authenticated` is the sender the transport bound to the frame; the
/// message is handled as that sender only (see [`process_inbound_message`]).
pub async fn apply_inline(
    config: &mut Config,
    tdk: &TDK,
    messaging: &Messaging,
    seen: &mut SeenMessages,
    pending: &mut PendingReplies,
    message: &Message,
    authenticated: Option<&str>,
) -> bool {
    let nobody = |_: &str| false;
    let mut arrival = Arrival::New { waiting: &nobody };
    let mut message = message.clone();
    let mut changed = false;
    // Bounded: a returning message is handled, not set aside again.
    for _ in 0..3 {
        let mut effects = InboundEffects::default();
        match process_inbound_message(
            config,
            tdk,
            messaging,
            seen,
            pending,
            &message,
            authenticated,
            &mut effects,
            arrival,
        )
        .await
        {
            Ok(c) => changed |= c,
            Err(e) => warn!(error = %e, "inbound message not handled"),
        }
        let Some(deferred) = effects.deferred else {
            break;
        };
        arrival = Arrival::Returning(deferred.job.run(tdk.clone()).await);
        message = deferred.message;
    }
    changed
}

/// Whether `task_id` is a ping we sent to `from` — directly, or to the
/// relationship `from` answers for (a ping goes to the peer's relationship DID,
/// which is the DID its pong comes from).
fn is_our_ping_to(config: &Config, task_id: &Arc<String>, from: &Arc<String>) -> bool {
    let Some(task) = config.private.tasks.get_by_id(task_id) else {
        return false;
    };
    let TaskType::TrustPing {
        to, remote_p_did, ..
    } = &task.type_
    else {
        return false;
    };
    if vta_sdk::did_scid::same_reference(to, from) {
        return true;
    }
    config
        .private
        .relationships
        .find_by_remote_did(from)
        .is_some_and(|rel| {
            rel.remote_p_did == *remote_p_did
                && (vta_sdk::did_scid::same_reference(&rel.remote_did, to)
                    || vta_sdk::did_scid::same_reference(&rel.remote_p_did, to))
        })
}

#[cfg(test)]
mod tests;
