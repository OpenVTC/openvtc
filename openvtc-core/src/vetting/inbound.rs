//! Routing an inbound message to the applicant or the vetter side.
//!
//! [`handle`] claims the messages that belong to vetting and returns `None` for
//! everything else, so the caller's existing routing is untouched. Two message
//! types are shared, and those are claimed only when they are vetting's:
//!
//! - `credential-exchange/issue` carries a community's membership and role
//!   credentials, a community's vetter grant, and a vetter's statement. Only
//!   the last two are claimed: a vetter grant, which would otherwise take the
//!   member's role credential's place, and an identity-vetting statement
//!   ([`wire::delivered_statement`]). Everything else still reaches the join
//!   handler.
//! - `trust-task-error` answers any Trust Task. Only one threaded on a request
//!   or withdrawal of ours is claimed.
//!
//! Handling never sends. A reply comes back unsigned in [`Handled::reply`] for
//! the caller to sign as the named persona and send ([`wire::sign_and_send`]);
//! anything a person should see comes back as a [`Notice`]. An answer to a
//! question we put to a community — a directory page, a stored profile, a
//! resent grant — comes back as a [`CommunityAnswer`] for whoever is waiting.
//! A vetter's grant to check for revocation comes back as a [`GrantCheck`],
//! because the check fetches over HTTPS and the caller owns the network.

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::{debug, info, warn};
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, manifest as join_manifest,
};
use vta_sdk::protocols::vetting::{
    VETTER_ROLE, VETTING_DECLINE_TYPE, VETTING_REQUEST_RESPONSE_TYPE, VETTING_REQUEST_TYPE,
    VETTING_REVOKE_STATEMENT_RESPONSE_TYPE, VETTING_SESSION_RESPONSE_TYPE, VETTING_SESSION_TYPE,
    VETTING_VETTER_LIST_RESPONSE_TYPE, VETTING_VETTER_PROFILE_RESPONSE_TYPE,
    VETTING_VETTER_RESEND_RESPONSE_TYPE, decline, request, revoke_statement, role_matches, session,
    vetters,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::eligibility::{
    EligibilityExpectations, community_role, verify_eligibility_vp,
};

use super::applicant::{GrantStatus, VetterEligibility};
use super::book::{VetterGrant, VettingBook};
use super::queries::{CommunityAnswer, CommunityQuery, QueryKind, refusal_words};
use super::status::GrantCheck;
use super::vetter::{IncomingRequest, Intake};
use super::wire;
use crate::config::account::{Account, PersonaId};
use crate::messaging::is_trust_task_error_type;
use crate::tasks::TaskType;

/// What handling needs to know about us.
pub struct Context<'a> {
    /// Our memberships — a vetter must be an active member.
    pub account: &'a Account,
    /// Resolves the DIDs whose proofs are checked.
    pub resolver: &'a TrustTaskVmResolver,
    /// Our persona the message was addressed to, and its DID.
    pub recipient: Option<(PersonaId, &'a str)>,
    /// The clock.
    pub now: DateTime<Utc>,
}

/// The result of handling one message.
#[derive(Debug, Default)]
pub struct Handled {
    /// The book changed and wants saving.
    pub changed: bool,
    /// A reply to sign and send.
    pub reply: Option<Reply>,
    /// Something a person should see.
    pub notice: Option<Notice>,
    /// An answer to a question we put to a community.
    pub answer: Option<CommunityAnswer>,
    /// A vetter's grant to check for revocation, off the handler.
    pub grant_check: Option<GrantCheck>,
}

/// A reply to sign as `persona` and send to the document's recipient.
#[derive(Debug)]
pub struct Reply {
    /// The persona to sign as.
    pub persona: PersonaId,
    /// The unsigned document.
    pub document: TrustTask<Value>,
    /// A presentation to attach as `eligibilityVp` before signing
    /// ([`wire::send_reply`]).
    pub eligibility: Option<EligibilityPresentation>,
}

/// The vetter role credential to present with an acceptance, bound to the
/// request it answers (`vetting/request/0.1` rule 5).
#[derive(Debug, Clone)]
pub struct EligibilityPresentation {
    /// The community's role credentials.
    pub credentials: Vec<Value>,
    /// The `id` of the request being answered.
    pub nonce: String,
    /// The applicant's `joinDid`.
    pub domain: String,
}

/// Something that happened that a person should know about. The ones marked
/// *act* need them to do something.
#[derive(Debug, Clone, PartialEq)]
pub enum Notice {
    /// Vetter: someone redeemed a ticket. *Act:* open a session when together.
    RequestAccepted {
        /// Our handle.
        request_id: String,
        /// Their join DID.
        applicant: String,
        /// The community.
        community: String,
    },
    /// Applicant: a vetter took our request.
    VetterAccepted {
        /// The application.
        application_id: String,
        /// The vetter.
        vetter: String,
        /// Their presentation showed the community named them a vetter.
        shown_eligible: bool,
    },
    /// Vetter: a community named us a vetter.
    VetterGranted {
        /// The community.
        community: String,
        /// Until when.
        valid_until: Option<DateTime<Utc>>,
    },
    /// Applicant: a vetter refused our request.
    VetterRefused {
        /// The application.
        application_id: String,
        /// The vetter.
        vetter: String,
        /// The error code.
        code: String,
    },
    /// Applicant: a vetter opened a session. *Act:* confirm the code, send the card.
    SessionOpened {
        /// The application.
        application_id: String,
        /// The session.
        session_id: String,
        /// The vetter.
        vetter: String,
        /// The code to read aloud.
        match_code: String,
    },
    /// Vetter: a card arrived and verified. *Act:* check the person, attest or decline.
    CardReceived {
        /// Our handle.
        request_id: String,
        /// Their join DID.
        applicant: String,
    },
    /// Applicant: a statement arrived and verified.
    StatementReceived {
        /// The application.
        application_id: String,
        /// The statement.
        statement_id: String,
        /// The vetter.
        vetter: String,
    },
    /// Applicant: a vetter declined.
    Declined {
        /// The application.
        application_id: String,
        /// The vetter.
        vetter: String,
    },
    /// Applicant: the community's requirements are now known, or changed.
    RequirementsUpdated {
        /// The application.
        application_id: String,
        /// The community.
        community: String,
    },
    /// Vetter: the community recorded our withdrawal.
    WithdrawalRecorded {
        /// The statement.
        statement_id: String,
    },
    /// Vetter: the community refused our withdrawal.
    WithdrawalRefused {
        /// The statement.
        statement_id: String,
        /// The error code.
        code: String,
    },
    /// Vetter: the community stored our vetter profile.
    ProfilePublished {
        /// The community.
        community: String,
        /// Whether it lists us in its directory.
        listed: bool,
    },
    /// Vetter: the community refused our vetter profile.
    ProfileRefused {
        /// The community.
        community: String,
        /// The error code, e.g. `notEligible`.
        code: String,
    },
    /// Vetter: the community is delivering our grant credential again.
    GrantResent {
        /// The community.
        community: String,
        /// The credential's `validUntil`.
        valid_until: DateTime<Utc>,
    },
    /// Vetter: the community refused to resend our grant credential.
    ResendRefused {
        /// The community.
        community: String,
        /// The error code, e.g. `notGranted`.
        code: String,
    },
}

impl Notice {
    /// One line for the activity log.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Notice::RequestAccepted { applicant, .. } => {
                format!(
                    "Vetting request from {applicant} accepted — open a session when you are together."
                )
            }
            Notice::VetterAccepted {
                vetter,
                shown_eligible: true,
                ..
            } => format!("{vetter} accepted your vetting request."),
            Notice::VetterAccepted { vetter, .. } => format!(
                "{vetter} accepted your vetting request, but did not show that the community \
                 named them a vetter — their statement may not count."
            ),
            Notice::VetterGranted {
                community,
                valid_until,
            } => match valid_until {
                Some(until) => format!(
                    "{community} named you a vetter until {}. You can hand out tickets.",
                    until.format("%Y-%m-%d")
                ),
                None => format!("{community} named you a vetter."),
            },
            Notice::VetterRefused { vetter, code, .. } => {
                format!("{vetter} refused your vetting request [{code}].")
            }
            Notice::SessionOpened {
                vetter, match_code, ..
            } => format!(
                "{vetter} opened a vetting session. Read the code {match_code} to each other, then send your card."
            ),
            Notice::CardReceived { applicant, .. } => {
                format!(
                    "Vetting card from {applicant} verified — check the person, then attest or decline."
                )
            }
            Notice::StatementReceived { vetter, .. } => {
                format!("{vetter} signed a vetting statement for you.")
            }
            Notice::Declined { vetter, .. } => format!("{vetter} declined to vet you."),
            Notice::RequirementsUpdated { community, .. } => {
                format!("Vetting requirements for {community} updated.")
            }
            Notice::WithdrawalRecorded { statement_id } => {
                format!("The community recorded the withdrawal of statement {statement_id}.")
            }
            Notice::WithdrawalRefused { statement_id, code } => format!(
                "The community refused the withdrawal of statement {statement_id} [{code}]."
            ),
            Notice::ProfilePublished {
                community,
                listed: true,
            } => format!(
                "{community} published your vetter profile — applicants can find you in its \
                 directory."
            ),
            Notice::ProfilePublished { community, .. } => format!(
                "{community} stored your vetter profile. It is not listed, so only people you \
                 give a ticket to can reach you."
            ),
            Notice::ProfileRefused { community, code } => {
                refusal_words(QueryKind::VetterProfile, community, code)
            }
            Notice::GrantResent {
                community,
                valid_until,
            } => format!(
                "{community} is sending your vetter credential again (valid until {}).",
                valid_until.format("%Y-%m-%d")
            ),
            Notice::ResendRefused { community, code } => {
                refusal_words(QueryKind::VetterResend, community, code)
            }
        }
    }
}

impl Notice {
    /// The inbox task this notice raises, keyed by a stable id so a repeated
    /// message does not raise a second one. `None` for notices that only inform.
    #[must_use]
    pub fn task(&self) -> Option<(String, TaskType)> {
        match self {
            Notice::RequestAccepted {
                request_id,
                applicant,
                community,
            } => Some((
                format!("vetting-request-{request_id}"),
                TaskType::VettingRequestInbound {
                    request_id: request_id.clone(),
                    applicant: Arc::new(applicant.clone()),
                    community: community.clone(),
                },
            )),
            Notice::SessionOpened {
                application_id,
                session_id,
                vetter,
                ..
            } => Some((
                format!("vetting-session-{session_id}"),
                TaskType::VettingSessionInbound {
                    application_id: application_id.clone(),
                    session_id: session_id.clone(),
                    vetter: Arc::new(vetter.clone()),
                },
            )),
            Notice::CardReceived {
                request_id,
                applicant,
            } => Some((
                format!("vetting-card-{request_id}"),
                TaskType::VettingCardReceived {
                    request_id: request_id.clone(),
                    applicant: Arc::new(applicant.clone()),
                },
            )),
            _ => None,
        }
    }
}

/// Whether [`handle`] could claim a message of type `typ`. A cheap pre-check,
/// so a caller builds a DID resolver only for messages that may need one.
#[must_use]
pub fn may_claim(typ: &str) -> bool {
    typ.starts_with("https://trusttasks.org/spec/vetting/")
        || matches!(
            typ,
            VETTING_REVOKE_STATEMENT_RESPONSE_TYPE
                | VETTING_VETTER_LIST_RESPONSE_TYPE
                | VETTING_VETTER_PROFILE_RESPONSE_TYPE
                | VETTING_VETTER_RESEND_RESPONSE_TYPE
                | JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE
                | CREDENTIAL_ISSUE_TYPE
        )
        || is_trust_task_error_type(typ)
}

/// Handle `message` from the authenticated `sender` if it is vetting's.
pub async fn handle(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Option<Handled> {
    let handled = match message.typ.as_str() {
        VETTING_REQUEST_TYPE => take_request(book, ctx, message, sender).await,
        VETTING_REQUEST_RESPONSE_TYPE => accepted(book, ctx, message, sender).await,
        VETTING_SESSION_TYPE => session(book, ctx, message, sender).await,
        VETTING_SESSION_RESPONSE_TYPE => card(book, ctx, message, sender).await,
        VETTING_DECLINE_TYPE => declined(book, ctx, message, sender).await,
        VETTING_REVOKE_STATEMENT_RESPONSE_TYPE => withdrawal_recorded(book, message, sender),
        VETTING_VETTER_LIST_RESPONSE_TYPE => vetter_list(book, message, sender),
        VETTING_VETTER_PROFILE_RESPONSE_TYPE => profile_stored(book, message, sender),
        VETTING_VETTER_RESEND_RESPONSE_TYPE => resent(book, message, sender),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE => manifest(book, ctx, message, sender),
        CREDENTIAL_ISSUE_TYPE => return statement(book, ctx, message, sender).await,
        t if is_trust_task_error_type(t) => return refused(book, ctx, message, sender),
        _ => return None,
    };
    Some(handled)
}

async fn opened<P: DeserializeOwned>(
    message: &Message,
    sender: &str,
    resolver: &TrustTaskVmResolver,
) -> Option<wire::Opened<P>> {
    match wire::open(message, sender, resolver).await {
        Ok(opened) => Some(opened),
        Err(e) => {
            warn!(typ = %message.typ, %sender, error = %e, "vetting document refused");
            None
        }
    }
}

/// The thread a community's reply names: the envelope's, or the document's.
fn community_thread(message: &Message) -> Option<String> {
    message.thid.clone().or_else(|| {
        message
            .body
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

/// A community reply's payload. Replies are authenticated by transport and not
/// always signed, so no proof is required.
fn community_payload<P: DeserializeOwned>(message: &Message) -> Result<P, String> {
    let payload = message.body.get("payload").cloned().unwrap_or(Value::Null);
    serde_json::from_value(payload).map_err(|e| e.to_string())
}

/// A document from a community, whose replies are authenticated by transport
/// and not always signed: read the payload without requiring a proof.
fn community_reply<P: DeserializeOwned>(message: &Message) -> Option<(Option<String>, P)> {
    match community_payload(message) {
        Ok(p) => Some((community_thread(message), p)),
        Err(e) => {
            warn!(typ = %message.typ, error = %e, "malformed community reply");
            None
        }
    }
}

/// A community's answer to a question of ours of `kind`, with the question.
///
/// `None` when it answers nothing we asked. A payload this client cannot read,
/// for a question we did ask, becomes [`CommunityAnswer::Unreadable`]. The
/// person waiting then hears that the community and this client disagree,
/// rather than waiting out the timeout and being told nobody answered.
fn answer_to<P: DeserializeOwned>(
    book: &mut VettingBook,
    message: &Message,
    sender: &str,
    kind: QueryKind,
) -> Option<(CommunityQuery, Result<P, CommunityAnswer>)> {
    let Some(thread) = community_thread(message) else {
        debug!(typ = %message.typ, %sender, "community answer with no thread — ignored");
        return None;
    };
    let Some(query) = book.take_query(sender, &thread, Some(kind)) else {
        debug!(typ = %message.typ, %sender, "community answer to nothing we asked — ignored");
        return None;
    };
    let payload = community_payload::<P>(message).map_err(|detail| {
        warn!(typ = %message.typ, %sender, error = %detail, "unreadable community answer");
        CommunityAnswer::Unreadable {
            query: query.document_id.clone(),
            community: sender.to_string(),
            kind,
            detail,
        }
    });
    Some((query, payload))
}

async fn take_request(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Handled {
    let Some((persona, _)) = ctx.recipient else {
        return Handled::default();
    };
    let Some(opened) = opened::<request::v0_1::Payload>(message, sender, ctx.resolver).await else {
        return Handled::default();
    };
    let community = opened.payload.community.as_str().to_string();
    // A vetter is who the community named: an active member holding its live
    // role credential (design §10.3). The community checks again.
    let grant = book.vetter_grant(&community, persona, ctx.now).cloned();
    let eligible = grant.is_some()
        && ctx
            .account
            .membership(&community, persona)
            .is_some_and(|m| m.status.is_active());
    let throttle = book.throttle.clone();
    let intake = book.take_request(
        IncomingRequest {
            document_id: &opened.document.id,
            sender,
            persona,
            body: opened.payload,
            eligible,
        },
        ctx.now,
    );
    let throttled = book.throttle != throttle;
    match intake {
        Intake::Accepted(body) => {
            let request_id = body.request_id.as_str().to_string();
            let eligibility = grant.map(|g| EligibilityPresentation {
                credentials: vec![g.credential],
                nonce: opened.document.id.clone(),
                domain: sender.to_string(),
            });
            Handled {
                changed: true,
                reply: wire::response(&opened.document, &body)
                    .ok()
                    .map(|document| Reply {
                        persona,
                        document,
                        eligibility,
                    }),
                notice: Some(Notice::RequestAccepted {
                    request_id,
                    applicant: sender.to_string(),
                    community,
                }),
                ..Handled::default()
            }
        }
        Intake::Refused(code) => {
            info!(%sender, %code, "vetting request refused");
            Handled {
                changed: throttled,
                reply: wire::refusal(&opened.document, code, None)
                    .ok()
                    .map(|document| Reply {
                        persona,
                        document,
                        eligibility: None,
                    }),
                ..Handled::default()
            }
        }
        Intake::Silent => {
            debug!(%sender, "vetting request without a matching ticket — no answer");
            Handled {
                changed: throttled,
                ..Handled::default()
            }
        }
    }
}

async fn accepted(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Handled {
    let Some(opened) = opened::<request::v0_1::Response>(message, sender, ctx.resolver).await
    else {
        return Handled::default();
    };
    let Some(thread) = opened.document.thread_id.as_deref() else {
        return Handled::default();
    };
    let Some(application) = book.applications.iter_mut().find(|a| a.sent(thread)) else {
        warn!(%sender, "vetting acceptance for no request of ours");
        return Handled::default();
    };
    // Bound to our request by `nonce` and to us by `domain`, so a presentation
    // made for someone else, or before the vetter lost the role, does not pass.
    // A verified grant's `credentialStatus` is kept for the revocation check.
    let mut grant_status_entry: Option<Option<Value>> = None;
    // The presentation is verified **as received** rather than re-serialised
    // from the parsed response: it carries its own proof, and a parsed value
    // written back out is not guaranteed to be the same bytes.
    let presented = opened.document.payload.get("eligibilityVp");
    let eligibility = match presented {
        None => VetterEligibility::NotShown,
        Some(vp) => {
            let expect = EligibilityExpectations {
                vetter: sender,
                community: &application.community,
                role: application.vetter_role(),
                challenge: thread,
                domain: &application.join_did,
                now: ctx.now,
            };
            match verify_eligibility_vp(vp, &expect, ctx.resolver).await {
                Ok(verified) => {
                    grant_status_entry = Some(verified.credential_status().cloned());
                    VetterEligibility::Shown {
                        credential_id: verified.credential_id().map(str::to_string),
                        valid_until: verified.valid_until(),
                    }
                }
                Err(e) => {
                    warn!(%sender, error = %e, "vetter eligibility presentation did not verify");
                    VetterEligibility::Failed {
                        reason: e.to_string(),
                    }
                }
            }
        }
    };
    let shown_eligible = matches!(eligibility, VetterEligibility::Shown { .. });
    match application.on_accepted(thread, sender, opened.payload, eligibility, ctx.now) {
        Ok(()) => {
            let grant_check = match grant_status_entry {
                Some(Some(credential_status)) => {
                    let checking = GrantStatus::Checking { since: ctx.now };
                    let _ = application.record_grant_status(thread, sender, checking);
                    Some(GrantCheck {
                        application_id: application.id.clone(),
                        request_document_id: thread.to_string(),
                        vetter: sender.to_string(),
                        issuer: application.community.clone(),
                        credential_status,
                    })
                }
                Some(None) => {
                    let unknown = GrantStatus::Unknown {
                        reason: "the vetter's credential names no status list to check".into(),
                        checked_at: ctx.now,
                    };
                    let _ = application.record_grant_status(thread, sender, unknown);
                    None
                }
                None => None,
            };
            Handled {
                changed: true,
                notice: Some(Notice::VetterAccepted {
                    application_id: application.id.clone(),
                    vetter: sender.to_string(),
                    shown_eligible,
                }),
                grant_check,
                ..Handled::default()
            }
        }
        Err(e) => {
            warn!(%sender, error = %e, "vetting acceptance not applied");
            Handled::default()
        }
    }
}

async fn session(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Handled {
    let Some((persona, _)) = ctx.recipient else {
        return Handled::default();
    };
    let Some(opened) = opened::<session::v0_1::Payload>(message, sender, ctx.resolver).await else {
        return Handled::default();
    };
    let Some(application) = book.application_mut(opened.payload.domain.as_str(), persona) else {
        warn!(%sender, "vetting session for a community we are not applying to");
        return Handled::default();
    };
    match application.on_session(&opened.document.id, sender, opened.payload, ctx.now) {
        Ok(session) => Handled {
            changed: true,
            notice: Some(Notice::SessionOpened {
                application_id: application.id.clone(),
                session_id: session.id,
                vetter: sender.to_string(),
                match_code: session.match_code,
            }),
            ..Handled::default()
        },
        Err(e) => {
            warn!(%sender, error = %e, "vetting session not opened");
            Handled::default()
        }
    }
}

async fn card(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Handled {
    let Some((_, our_did)) = ctx.recipient else {
        return Handled::default();
    };
    // Opened as the payload it arrived as: the card's `digestMultibase` — what
    // the statement names — is taken over the bytes the applicant signed, so the
    // card is never parsed and written back out on the way to verification.
    let Some(opened) = opened::<Value>(message, sender, ctx.resolver).await else {
        return Handled::default();
    };
    let Some(session_id) = opened.document.thread_id.clone() else {
        return Handled::default();
    };
    let Some(card) = opened.payload.get("card") else {
        warn!(%sender, "vetting session response carries no card");
        return Handled::default();
    };
    match book
        .receive_card(our_did, sender, &session_id, card, ctx.resolver, ctx.now)
        .await
    {
        Ok(entry) => Handled {
            changed: true,
            notice: Some(Notice::CardReceived {
                request_id: entry.request_id.clone(),
                applicant: sender.to_string(),
            }),
            ..Handled::default()
        },
        Err(e) => {
            warn!(%sender, error = %e, "vetting card refused");
            Handled::default()
        }
    }
}

async fn declined(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Handled {
    let Some(opened) = opened::<decline::v0_1::Payload>(message, sender, ctx.resolver).await else {
        return Handled::default();
    };
    for application in &mut book.applications {
        if application
            .on_decline(sender, opened.payload.clone(), ctx.now)
            .is_ok()
        {
            return Handled {
                changed: true,
                notice: Some(Notice::Declined {
                    application_id: application.id.clone(),
                    vetter: sender.to_string(),
                }),
                ..Handled::default()
            };
        }
    }
    warn!(%sender, "vetting decline for no request of ours");
    Handled::default()
}

async fn statement(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Option<Handled> {
    if let Some(credential) = message.body.pointer("/credential_response/credential")
        && let Some((community, role)) = community_role(credential)
        && role_matches(&role, VETTER_ROLE)
    {
        return Some(vetter_grant(book, ctx, credential, community, sender));
    }
    let credential = wire::delivered_statement(&message.body)?;
    let Some((persona, _)) = ctx.recipient else {
        return Some(Handled::default());
    };
    for application in book
        .applications
        .iter_mut()
        .filter(|a| a.persona == persona && a.requests.iter().any(|r| r.vetter == sender))
    {
        match application
            .on_statement(sender, credential, ctx.resolver, ctx.now)
            .await
        {
            Ok(held) => {
                return Some(Handled {
                    changed: true,
                    notice: Some(Notice::StatementReceived {
                        application_id: application.id.clone(),
                        statement_id: held.id,
                        vetter: sender.to_string(),
                    }),
                    ..Handled::default()
                });
            }
            Err(e) => warn!(%sender, error = %e, "vetting statement refused"),
        }
    }
    Some(Handled::default())
}

/// A community's vetter role credential for one of our personas.
///
/// Kept when the community that it names issued it, sent it (authcrypt
/// authenticates the sender), and named the persona it was addressed to, which
/// must hold a membership there. Its proof is not checked here: it proves
/// nothing to us that the authenticated sender does not, and every applicant
/// it is presented to verifies it.
fn vetter_grant(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    credential: &Value,
    community: String,
    sender: &str,
) -> Handled {
    let Some((persona, our_did)) = ctx.recipient else {
        return Handled::default();
    };
    let issuer = credential
        .get("issuer")
        .and_then(|i| i.as_str().or_else(|| i.get("id").and_then(Value::as_str)));
    let subject = credential
        .pointer("/credentialSubject/id")
        .and_then(Value::as_str);
    if community != sender || issuer != Some(sender) || subject != Some(our_did) {
        warn!(%sender, %community, "vetter role credential not from its community, or not for us — ignored");
        return Handled::default();
    }
    if ctx.account.membership(&community, persona).is_none() {
        warn!(%community, "vetter role credential from a community we are not a member of — ignored");
        return Handled::default();
    }
    let valid_until = credential
        .get("validUntil")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    let changed = book.keep_vetter_grant(VetterGrant {
        community: community.clone(),
        persona,
        credential_id: credential
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string),
        valid_until,
        received_at: ctx.now,
        credential: credential.clone(),
    });
    Handled {
        changed,
        notice: changed.then_some(Notice::VetterGranted {
            community,
            valid_until,
        }),
        ..Handled::default()
    }
}

fn refused(
    book: &mut VettingBook,
    ctx: &Context<'_>,
    message: &Message,
    sender: &str,
) -> Option<Handled> {
    let thread = message
        .thid
        .as_deref()
        .or_else(|| message.body.get("threadId").and_then(Value::as_str))?;
    let code = message
        .body
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let detail = message
        .body
        .pointer("/payload/message")
        .and_then(Value::as_str)
        .map(str::to_string);

    if let Some(application) = book.applications.iter_mut().find(|a| a.sent(thread)) {
        return Some(
            match application.on_refused(thread, sender, code.clone(), detail, ctx.now) {
                Ok(()) => Handled {
                    changed: true,
                    notice: Some(Notice::VetterRefused {
                        application_id: application.id.clone(),
                        vetter: sender.to_string(),
                        code,
                    }),
                    ..Handled::default()
                },
                Err(e) => {
                    warn!(%sender, error = %e, "vetting refusal not applied");
                    Handled::default()
                }
            },
        );
    }
    if let Some(query) = book.take_query(sender, thread, None) {
        info!(community = %sender, %code, kind = ?query.kind, "community refused a question of ours");
        let (changed, notice) = match query.kind {
            QueryKind::VetterProfile => (
                book.on_profile_refused(sender, query.persona, &code, ctx.now),
                Some(Notice::ProfileRefused {
                    community: sender.to_string(),
                    code: code.clone(),
                }),
            ),
            QueryKind::VetterResend => (
                false,
                Some(Notice::ResendRefused {
                    community: sender.to_string(),
                    code: code.clone(),
                }),
            ),
            QueryKind::Manifest | QueryKind::VetterList => (false, None),
        };
        return Some(Handled {
            changed,
            notice,
            answer: Some(CommunityAnswer::Refused {
                query: query.document_id,
                community: sender.to_string(),
                kind: query.kind,
                code,
                message: detail,
            }),
            ..Handled::default()
        });
    }
    let statement_id = book
        .issued
        .iter()
        .find(|s| {
            s.community == sender
                && s.withdrawal
                    .as_ref()
                    .is_some_and(|w| w.document_id == thread)
        })?
        .id
        .clone();
    warn!(community = %sender, %code, "vetting statement withdrawal refused");
    Some(Handled {
        notice: Some(Notice::WithdrawalRefused { statement_id, code }),
        ..Handled::default()
    })
}

fn withdrawal_recorded(book: &mut VettingBook, message: &Message, sender: &str) -> Handled {
    let Some((Some(thread), body)) = community_reply::<revoke_statement::v0_1::Response>(message)
    else {
        return Handled::default();
    };
    match book.on_withdrawal_recorded(sender, &thread, body.recorded_at) {
        Some(issued) => Handled {
            changed: true,
            notice: Some(Notice::WithdrawalRecorded {
                statement_id: issued.id.clone(),
            }),
            ..Handled::default()
        },
        None => Handled::default(),
    }
}

fn manifest(book: &mut VettingBook, ctx: &Context<'_>, message: &Message, sender: &str) -> Handled {
    let thread = community_thread(message);
    let body = match community_payload::<join_manifest::v0_2::Response>(message) {
        Ok(body) => body,
        Err(detail) => {
            warn!(typ = %message.typ, error = %detail, "malformed community reply");
            // Whoever is waiting on this manifest hears why, now.
            let answer = book
                .take_manifest_queries(sender, thread.as_deref())
                .into_iter()
                .next()
                .map(|q| CommunityAnswer::Unreadable {
                    query: q.document_id,
                    community: sender.to_string(),
                    kind: QueryKind::Manifest,
                    detail,
                });
            return Handled {
                answer,
                ..Handled::default()
            };
        }
    };
    let mut handled = Handled {
        changed: book.learn_manifest(sender, &body, ctx.now),
        ..Handled::default()
    };
    for application in book
        .applications
        .iter_mut()
        .filter(|a| a.community == sender)
    {
        match application.adopt_manifest(&body) {
            Ok(true) => {
                handled.changed = true;
                handled.notice = Some(Notice::RequirementsUpdated {
                    application_id: application.id.clone(),
                    community: sender.to_string(),
                });
            }
            Ok(false) => {}
            Err(e) => warn!(community = %sender, error = %e, "community manifest not adopted"),
        }
    }
    if !book
        .take_manifest_queries(sender, thread.as_deref())
        .is_empty()
    {
        handled.answer = Some(CommunityAnswer::Manifest {
            community: sender.to_string(),
        });
    }
    handled
}

fn vetter_list(book: &mut VettingBook, message: &Message, sender: &str) -> Handled {
    let Some((query, page)) =
        answer_to::<vetters::list::v0_1::Response>(book, message, sender, QueryKind::VetterList)
    else {
        return Handled::default();
    };
    Handled {
        answer: Some(match page {
            Ok(page) => CommunityAnswer::Vetters {
                query: query.document_id,
                community: sender.to_string(),
                page,
            },
            Err(unreadable) => unreadable,
        }),
        ..Handled::default()
    }
}

fn profile_stored(book: &mut VettingBook, message: &Message, sender: &str) -> Handled {
    let Some((query, body)) = answer_to::<vetters::profile::v0_1::Response>(
        book,
        message,
        sender,
        QueryKind::VetterProfile,
    ) else {
        return Handled::default();
    };
    match body {
        Ok(body) => Handled {
            changed: book.on_profile_stored(sender, query.persona, &body),
            notice: Some(Notice::ProfilePublished {
                community: sender.to_string(),
                listed: body.listed,
            }),
            answer: Some(CommunityAnswer::ProfileStored {
                community: sender.to_string(),
                listed: body.listed,
                updated_at: body.updated_at,
            }),
            ..Handled::default()
        },
        Err(unreadable) => Handled {
            answer: Some(unreadable),
            ..Handled::default()
        },
    }
}

fn resent(book: &mut VettingBook, message: &Message, sender: &str) -> Handled {
    let Some((_, body)) = answer_to::<vetters::resend::v0_1::Response>(
        book,
        message,
        sender,
        QueryKind::VetterResend,
    ) else {
        return Handled::default();
    };
    match body {
        Ok(body) => Handled {
            notice: Some(Notice::GrantResent {
                community: sender.to_string(),
                valid_until: body.valid_until,
            }),
            answer: Some(CommunityAnswer::Resent {
                community: sender.to_string(),
                valid_until: body.valid_until,
            }),
            ..Handled::default()
        },
        Err(unreadable) => Handled {
            answer: Some(unreadable),
            ..Handled::default()
        },
    }
}
