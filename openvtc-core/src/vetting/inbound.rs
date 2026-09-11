//! Routing an inbound message to the applicant or the vetter side.
//!
//! [`handle`] claims the messages that belong to vetting and returns `None` for
//! everything else, so the caller's existing routing is untouched. Two message
//! types are shared, and those are claimed only when they are vetting's:
//!
//! - `credential-exchange/issue` carries both a community's membership
//!   credential and a vetter's statement. Only an identity-vetting statement
//!   is claimed ([`wire::delivered_statement`]); a membership credential still
//!   reaches the join handler, which would refuse a vetter as its issuer.
//! - `trust-task-error` answers any Trust Task. Only one threaded on a request
//!   or withdrawal of ours is claimed.
//!
//! Handling never sends. A reply comes back unsigned in [`Handled::reply`] for
//! the caller to sign as the named persona and send ([`wire::sign_and_send`]);
//! anything a person should see comes back as a [`Notice`].

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::{debug, info, warn};
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, JoinRequestManifestResponseBody,
};
use vta_sdk::protocols::vetting::{
    RevokeStatementResponseBody, VETTING_DECLINE_TYPE, VETTING_REQUEST_RESPONSE_TYPE,
    VETTING_REQUEST_TYPE, VETTING_REVOKE_STATEMENT_RESPONSE_TYPE, VETTING_SESSION_RESPONSE_TYPE,
    VETTING_SESSION_TYPE, VettingDeclineBody, VettingRequestAcceptedBody, VettingRequestBody,
    VettingSessionBody, VettingSessionResponseBody,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;

use super::book::VettingBook;
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
}

/// A reply to sign as `persona` and send to the document's recipient.
#[derive(Debug)]
pub struct Reply {
    /// The persona to sign as.
    pub persona: PersonaId,
    /// The unsigned document.
    pub document: TrustTask<Value>,
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
            Notice::VetterAccepted { vetter, .. } => {
                format!("{vetter} accepted your vetting request.")
            }
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
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE => manifest(book, message, sender),
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

/// A document from a community, whose replies are authenticated by transport
/// and not always signed: read the payload without requiring a proof.
fn community_reply<P: DeserializeOwned>(message: &Message) -> Option<(Option<String>, P)> {
    let thread = message.thid.clone().or_else(|| {
        message
            .body
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let payload = message.body.get("payload").cloned().unwrap_or(Value::Null);
    match serde_json::from_value(payload) {
        Ok(p) => Some((thread, p)),
        Err(e) => {
            warn!(typ = %message.typ, error = %e, "malformed community reply");
            None
        }
    }
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
    let Some(opened) = opened::<VettingRequestBody>(message, sender, ctx.resolver).await else {
        return Handled::default();
    };
    let community = opened.payload.community.clone();
    let is_member = ctx
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
            is_member,
        },
        ctx.now,
    );
    let throttled = book.throttle != throttle;
    match intake {
        Intake::Accepted(body) => {
            let request_id = body.request_id.clone();
            Handled {
                changed: true,
                reply: wire::response(&opened.document, &body)
                    .ok()
                    .map(|document| Reply { persona, document }),
                notice: Some(Notice::RequestAccepted {
                    request_id,
                    applicant: sender.to_string(),
                    community,
                }),
            }
        }
        Intake::Refused(code) => {
            info!(%sender, %code, "vetting request refused");
            Handled {
                changed: throttled,
                reply: wire::refusal(&opened.document, code, None)
                    .ok()
                    .map(|document| Reply { persona, document }),
                notice: None,
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
    let Some(opened) = opened::<VettingRequestAcceptedBody>(message, sender, ctx.resolver).await
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
    match application.on_accepted(thread, sender, opened.payload, ctx.now) {
        Ok(()) => Handled {
            changed: true,
            notice: Some(Notice::VetterAccepted {
                application_id: application.id.clone(),
                vetter: sender.to_string(),
            }),
            ..Handled::default()
        },
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
    let Some(opened) = opened::<VettingSessionBody>(message, sender, ctx.resolver).await else {
        return Handled::default();
    };
    let Some(application) = book.application_mut(&opened.payload.domain, persona) else {
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
    let Some(opened) = opened::<VettingSessionResponseBody>(message, sender, ctx.resolver).await
    else {
        return Handled::default();
    };
    let Some(session_id) = opened.document.thread_id.clone() else {
        return Handled::default();
    };
    match book
        .receive_card(
            our_did,
            sender,
            &session_id,
            opened.payload,
            ctx.resolver,
            ctx.now,
        )
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
    let Some(opened) = opened::<VettingDeclineBody>(message, sender, ctx.resolver).await else {
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
    let Some((Some(thread), body)) = community_reply::<RevokeStatementResponseBody>(message) else {
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

fn manifest(book: &mut VettingBook, message: &Message, sender: &str) -> Handled {
    let Some((_, body)) = community_reply::<JoinRequestManifestResponseBody>(message) else {
        return Handled::default();
    };
    let mut handled = Handled {
        changed: book.learn_manifest(sender, &body, chrono::Utc::now()),
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
    handled
}
