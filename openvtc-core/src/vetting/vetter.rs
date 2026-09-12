//! The vetter desk: requests people make of us as a vetter (design §8–§9).
//!
//! ```text
//! request+ticket ──▶ Accepted ──open session──▶ Session ──card──▶ CardReceived ──attest──▶ Attested
//!                        │                                            │
//!                        └──────────────────── decline ───────────────┴──▶ Declined
//! ```
//!
//! A request earns an answer only with a live ticket ([`super::tickets`]).
//! Accepting is automatic: the ticket was the vetter's consent to be asked,
//! and an immediate answer tells the applicant their request arrived.
//! Everything after — opening the session with the person present, the human
//! check, attesting or declining — is the vetter's decision.
//!
//! Signing the statement is attributable and the vetter is accountable for it
//! within the community, so it is never automatic. In V0 the confirmation is
//! the client's; VTA step-up is the V1 target (design D19).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::vetting::{
    CheckShape, ClaimType, IDENTITY_VETTING_ENDORSEMENT_TYPE, IdentityVettingEndorsement,
    ShapeError, VETTING_REQUEST_ERR_CAPACITY, VETTING_REQUEST_ERR_DECLINED,
    VETTING_REQUEST_ERR_METHOD_UNAVAILABLE, VETTING_REQUEST_ERR_NOT_ELIGIBLE, VettingDocumentation,
    VettingMethod, VettingRelationship, check_request, decline, documentation, request,
    revoke_statement, session,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::VettingError;
use vta_sdk::vetting::card::{CardExpectations, new_commitment_salt, verify_card};
use vta_sdk::vetting::match_code::vetting_match_code;
use vta_sdk::vetting::statement::{StatementDraft, verify_statement};

use super::book::{VetterPolicy, VettingBook};
use super::tickets::{self, Redemption};
use crate::config::account::PersonaId;

/// Why a desk step was refused.
#[derive(Debug, thiserror::Error)]
pub enum VetterError {
    /// No request with that id.
    #[error("no such vetting request")]
    NoSuchRequest,
    /// The request cannot take this step now.
    #[error("the request cannot {0} in its current state")]
    WrongState(&'static str),
    /// A payload broke its schema.
    #[error(transparent)]
    Shape(#[from] ShapeError),
    /// Building or verifying an artifact failed.
    #[error(transparent)]
    Vetting(#[from] VettingError),
    /// Liveness is required for this method (D10).
    #[error("confirm the match code with the person before attesting")]
    LivenessNotConfirmed,
    /// A document method with nothing recorded.
    #[error("say which documentation you relied on, or `none`")]
    NoDocumentation,
    /// Attesting to a claim the applicant did not show.
    #[error("the card has no `{0}` claim, so it cannot be marked verified")]
    ClaimNotOnCard(String),
    /// A required claim left unverified.
    #[error("`{0}` is required and has not been verified")]
    RequiredClaimNotVerified(String),
    /// No statement of ours with that id.
    #[error("no statement of ours has that id")]
    NoSuchStatement,
    /// The community already recorded the withdrawal.
    #[error("the community has already recorded this withdrawal")]
    AlreadyWithdrawn,
}

/// One request at the desk.
///
/// No `PartialEq`: it keeps the applicant's request as the generated
/// `vetting/request/0.1` payload, and the generated wire types derive only
/// `Serialize`, `Deserialize`, `Clone` and `Debug`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeskEntry {
    /// Our handle, sent to the applicant.
    pub request_id: String,
    /// The applicant's `vetting/request` document id.
    pub request_document_id: String,
    /// The applicant's join DID (and authenticated sender).
    pub applicant: String,
    /// The community.
    pub community: String,
    /// Our member persona in that community.
    pub persona: PersonaId,
    /// The ticket it came in on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
    /// What they asked.
    pub request: request::v0_1::Payload,
    /// Where it stands.
    pub state: DeskState,
    /// When it arrived.
    pub received_at: DateTime<Utc>,
    /// When it last moved.
    pub updated_at: DateTime<Utc>,
}

/// Where a desk request stands.
///
/// No `PartialEq`: a received card carries the generated card claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeskState {
    /// Waiting for the vetter to open a session.
    Accepted,
    /// A session is open; waiting for the applicant's card.
    Session {
        /// The session.
        session: DeskSession,
    },
    /// The card is in and verified; the human check is next.
    CardReceived {
        /// The session.
        session: DeskSession,
        /// The card.
        card: ReceivedCard,
    },
    /// We signed a statement.
    Attested {
        /// Its id.
        statement_id: String,
        /// When.
        issued_at: DateTime<Utc>,
        /// The card it attests to, kept for [`VetterPolicy::card_retention_days`].
        card: ReceivedCard,
    },
    /// We declined.
    Declined {
        /// The reason code we gave, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<decline::v0_1::PayloadCode>,
        /// When.
        at: DateTime<Utc>,
        /// The card, if one had arrived.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        card: Option<ReceivedCard>,
    },
}

/// A session we opened.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeskSession {
    /// The `vetting/session` document id.
    pub id: String,
    /// The challenge the card must carry.
    pub challenge: String,
    /// The method.
    pub method: VettingMethod,
    /// Claim types the card must carry.
    pub required_claims: Vec<String>,
    /// Claim types the card may carry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_claims: Vec<String>,
    /// When it closes.
    pub expires_at: DateTime<Utc>,
    /// The code both people read aloud.
    pub match_code: String,
}

/// A verified card. The claims and the card itself are forgotten after
/// [`VetterPolicy::card_retention_days`]; the digest and commitment remain.
///
/// No `PartialEq`: the claims are the generated card's.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedCard {
    /// `digestMultibase` of the card.
    pub digest_multibase: String,
    /// The applicant's identity commitment.
    pub identity_commitment: String,
    /// What the card showed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<session::v0_1::VettingCardClaim>,
    /// The signed card, exactly as received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    /// When it arrived.
    pub received_at: DateTime<Utc>,
}

/// A statement we signed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuedStatement {
    /// The statement id.
    pub id: String,
    /// Its `digestMultibase` — what a withdrawal names.
    pub digest_multibase: String,
    /// Who it is about.
    pub applicant: String,
    /// The community it counts in.
    pub community: String,
    /// The persona that signed it.
    pub persona: PersonaId,
    /// The method.
    pub method: VettingMethod,
    /// When.
    pub issued_at: DateTime<Utc>,
    /// Its `validUntil`.
    pub valid_until: DateTime<Utc>,
    /// Our withdrawal, once sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal: Option<Withdrawal>,
}

/// A withdrawal we sent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Withdrawal {
    /// The notice's document id — what the community's reply threads on.
    pub document_id: String,
    /// The reason we gave, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<revoke_statement::v0_1::PayloadReason>,
    /// When we sent it.
    pub sent_at: DateTime<Utc>,
    /// When the community recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<DateTime<Utc>>,
}

/// An inbound `vetting/request`, already opened and bound to its sender.
#[derive(Clone, Debug)]
pub struct IncomingRequest<'a> {
    /// The request document id.
    pub document_id: &'a str,
    /// The authenticated sender.
    pub sender: &'a str,
    /// Our persona it was addressed to.
    pub persona: PersonaId,
    /// The payload.
    pub body: request::v0_1::Payload,
    /// `persona` is an active member of `body.community` and holds its live
    /// vetter role credential.
    pub eligible: bool,
}

/// What an inbound request earns.
///
/// No `PartialEq`: the acceptance is the generated `#response`.
///
/// The acceptance is boxed because it dwarfs the other two: the generated
/// response carries an optional eligibility presentation, and a refusal is one
/// `&'static str`.
#[derive(Clone, Debug)]
pub enum Intake {
    /// Accepted; answer with this `#response`.
    Accepted(Box<request::v0_1::Response>),
    /// Refused; answer with a `trust-task-error` carrying this code.
    Refused(&'static str),
    /// No answer at all.
    Silent,
}

/// What the vetter attests to, from the checklist (design §9.3).
#[derive(Clone, Debug)]
pub struct Attestation {
    /// The method actually used.
    pub method: VettingMethod,
    /// What the vetter relied on — their own choice (D16).
    pub document_classes: Vec<String>,
    /// Claim types verified; at least the session's required ones.
    pub claims_verified: Vec<String>,
    /// The two people read the match code to each other.
    pub liveness_confirmed: bool,
    /// The vetter's declared relationship to the applicant.
    pub declared_relationship: VettingRelationship,
    /// Digest of the attestation text the vetter was shown.
    pub attestation_text_digest: Option<String>,
}

impl DeskEntry {
    /// The open session's match code, if a session is open.
    #[must_use]
    pub fn match_code(&self) -> Option<&str> {
        match &self.state {
            DeskState::Session { session } | DeskState::CardReceived { session, .. } => {
                Some(&session.match_code)
            }
            _ => None,
        }
    }

    /// A session nobody answered closes; the request waits for another.
    pub(crate) fn expire_session(&mut self, now: DateTime<Utc>) -> bool {
        if let DeskState::Session { session } = &self.state
            && session.expires_at <= now
        {
            self.state = DeskState::Accepted;
            self.updated_at = now;
            return true;
        }
        false
    }

    /// Forget what a card showed once `retention` has passed since the request
    /// closed; keep only what identifies it.
    pub(crate) fn forget_card_after(&mut self, retention: Duration, now: DateTime<Utc>) -> bool {
        let (closed_at, card) = match &mut self.state {
            DeskState::Attested {
                issued_at, card, ..
            } => (*issued_at, Some(card)),
            DeskState::Declined { at, card, .. } => (*at, card.as_mut()),
            _ => return false,
        };
        match card {
            Some(card) if now - closed_at >= retention && card.card.is_some() => {
                card.card = None;
                card.claims.clear();
                true
            }
            _ => false,
        }
    }
}

/// The `#response` accepting `entry`.
///
/// `acceptsDocumentation` is `minItems: 1` and unique on this line, where it
/// used to accept `[]`. A vetter who accepts no documentation at all — which V0
/// allows, for someone they already know (D16) — therefore **omits** the member
/// rather than sending an empty list the published response refuses, and a
/// token repeated in the vetter's own policy is listed once.
fn accepted_reply(
    entry: &DeskEntry,
    policy: &VetterPolicy,
) -> Result<request::v0_1::Response, ShapeError> {
    let schema = |e: &dyn std::fmt::Display| ShapeError::Schema(e.to_string());
    let mut accepted: Vec<request::v0_1::VettingDocumentation> = Vec::new();
    for token in &policy.accepts_documentation {
        let parsed = request::v0_1::VettingDocumentation::try_from(token.as_str())
            .map_err(|e| schema(&e))?;
        if !accepted.iter().any(|d| d.as_str() == parsed.as_str()) {
            accepted.push(parsed);
        }
    }
    request::v0_1::Response::try_from(
        request::v0_1::Response::builder()
            .request_id(entry.request_id.as_str())
            .accepts_documentation((!accepted.is_empty()).then_some(accepted)),
    )
    .map_err(|e| schema(&e))
}

/// [`accepted_reply`] as an [`Intake`]. A vetter whose own documentation list
/// the published response cannot carry answers `declined` rather than going
/// silent: the applicant learns their request arrived and was not taken.
fn accept(entry: &DeskEntry, policy: &VetterPolicy) -> Intake {
    match accepted_reply(entry, policy) {
        Ok(body) => Intake::Accepted(Box::new(body)),
        Err(_) => Intake::Refused(VETTING_REQUEST_ERR_DECLINED),
    }
}

impl VettingBook {
    /// Decide what an inbound request earns, and record it if accepted.
    ///
    /// The order of checks is deliberate: nothing that would tell a stranger
    /// about this vetter — membership, capacity, methods — is answered before
    /// a ticket has matched.
    pub fn take_request(&mut self, incoming: IncomingRequest<'_>, now: DateTime<Utc>) -> Intake {
        let IncomingRequest {
            document_id,
            sender,
            persona,
            body,
            eligible,
        } = incoming;
        if check_request(&body, sender).is_err() {
            return Intake::Silent;
        }
        if let Some(existing) = self
            .desk
            .iter()
            .find(|e| e.request_document_id == document_id && e.applicant == sender)
        {
            return accept(existing, &self.policy);
        }
        let Some(ticket) = body.ticket.as_ref() else {
            // Introductions are a vetter opt-in that V0 does not offer. The
            // published payload makes `introduction` an object rather than an
            // optional value, so "they sent one" is "it is not empty".
            return if body.introduction.is_empty() {
                Intake::Silent
            } else {
                Intake::Refused(VETTING_REQUEST_ERR_DECLINED)
            };
        };
        let ticket_id = match tickets::check(
            &self.tickets,
            &mut self.throttle,
            ticket,
            sender,
            body.community.as_str(),
            persona,
            now,
        ) {
            Redemption::Matched { ticket_id } => ticket_id,
            Redemption::Silent => return Intake::Silent,
            Redemption::Refused(code) => return Intake::Refused(code),
        };
        // The request task has its own copy of the method vocabulary; a ticket
        // holds the community's (see `super::same_token`).
        let preferred = body
            .preferred_method
            .as_ref()
            .and_then(|m| super::same_token::<_, VettingMethod>(m).ok());
        if !self
            .tickets
            .iter()
            .find(|t| t.id == ticket_id)
            .is_some_and(|t| t.offers(preferred))
        {
            return Intake::Refused(VETTING_REQUEST_ERR_METHOD_UNAVAILABLE);
        }
        if !eligible {
            return Intake::Refused(VETTING_REQUEST_ERR_NOT_ELIGIBLE);
        }
        if self.open_requests(persona) >= self.policy.max_open_requests {
            return Intake::Refused(VETTING_REQUEST_ERR_CAPACITY);
        }
        tickets::consume(&mut self.tickets, &ticket_id);
        let entry = DeskEntry {
            request_id: Uuid::new_v4().to_string(),
            request_document_id: document_id.to_string(),
            applicant: sender.to_string(),
            community: body.community.as_str().to_string(),
            persona,
            ticket_id: Some(ticket_id),
            request: body,
            state: DeskState::Accepted,
            received_at: now,
            updated_at: now,
        };
        let reply = accept(&entry, &self.policy);
        self.desk.push(entry);
        reply
    }

    /// Open a session for `request_id` — with the person in front of us or on
    /// the call. Reopening replaces an earlier session, whose card will no
    /// longer be accepted.
    ///
    /// # Errors
    ///
    /// No such request, one already closed, or a malformed session.
    pub fn open_session(
        &mut self,
        request_id: &str,
        method: VettingMethod,
        required_claims: Vec<String>,
        optional_claims: Vec<String>,
        session_document_id: &str,
        now: DateTime<Utc>,
    ) -> Result<session::v0_1::Payload, VetterError> {
        let length = self.policy.session_length();
        let entry = self
            .desk_entry_mut(request_id)
            .ok_or(VetterError::NoSuchRequest)?;
        if !entry.state.is_open() {
            return Err(VetterError::WrongState("open a session"));
        }
        let schema = |e: &dyn std::fmt::Display| ShapeError::Schema(e.to_string());
        let challenge = new_commitment_salt()?;
        // The session task has its own copy of the method vocabulary and its
        // own claim-type newtype, which is what refuses a claim that is not a
        // claim type at all.
        let task_method = super::same_token::<_, session::v0_1::VettingMethod>(&method)
            .map_err(|e| schema(&e))?;
        let required = required_claims
            .iter()
            .map(|c| {
                session::v0_1::PayloadRequiredClaimsItem::try_from(c.as_str())
                    .map_err(|e| schema(&e))
            })
            .collect::<Result<Vec<_>, ShapeError>>()?;
        let optional = optional_claims
            .iter()
            .map(|c| {
                session::v0_1::PayloadOptionalClaimsItem::try_from(c.as_str())
                    .map_err(|e| schema(&e))
            })
            .collect::<Result<Vec<_>, ShapeError>>()?;
        let body = session::v0_1::Payload::try_from(
            session::v0_1::Payload::builder()
                .request_id(request_id)
                .challenge(challenge.as_str())
                .domain(entry.community.as_str())
                .method(task_method)
                .required_claims(required)
                .optional_claims((!optional.is_empty()).then_some(optional))
                .expires_at(now + length),
        )
        .map_err(|e| schema(&e))?;
        body.check_shape()?;
        entry.state = DeskState::Session {
            session: DeskSession {
                id: session_document_id.to_string(),
                challenge,
                method,
                required_claims: required_claims.clone(),
                optional_claims: optional_claims.clone(),
                expires_at: body.expires_at,
                match_code: vetting_match_code(session_document_id),
            },
        };
        entry.updated_at = now;
        Ok(body)
    }

    /// The applicant's card for session `session_id`
    /// (`vetting/session#response`). Verified against everything the session
    /// bound it to before the vetter sees it.
    ///
    /// # Errors
    ///
    /// No open session from this applicant, a closed one, or a card that does
    /// not verify.
    /// `card` is the card **as received** rather than a re-serialised one: its
    /// `digestMultibase` is what the statement names, and a parsed card written
    /// back out is not guaranteed to be the same bytes.
    pub async fn receive_card(
        &mut self,
        vetter_did: &str,
        applicant: &str,
        session_id: &str,
        card: &Value,
        resolver: &TrustTaskVmResolver,
        now: DateTime<Utc>,
    ) -> Result<&DeskEntry, VetterError> {
        let entry = self
            .desk
            .iter_mut()
            .find(|e| {
                e.applicant == applicant
                    && matches!(&e.state, DeskState::Session { session } if session.id == session_id)
            })
            .ok_or(VetterError::NoSuchRequest)?;
        let DeskState::Session { session } = &entry.state else {
            unreachable!("matched a session above");
        };
        let session = session.clone();
        if session.expires_at <= now {
            return Err(VetterError::WrongState(
                "take a card after its session closed",
            ));
        }
        let verified = verify_card(
            card,
            &CardExpectations {
                audience: vetter_did,
                publisher: applicant,
                community: &entry.community,
                challenge: &session.challenge,
                domain: &entry.community,
                required_claims: &session.required_claims,
                now,
            },
            resolver,
        )
        .await?;
        let received = ReceivedCard {
            digest_multibase: verified.digest_multibase().to_string(),
            identity_commitment: verified.card().identity_commitment.as_str().to_string(),
            claims: verified.card().claims.clone(),
            card: Some(card.clone()),
            received_at: now,
        };
        entry.state = DeskState::CardReceived {
            session,
            card: received,
        };
        entry.updated_at = now;
        Ok(entry)
    }

    /// The statement to sign for `request_id`, from the vetter's checklist.
    ///
    /// # Errors
    ///
    /// No card yet, a checklist that does not support the statement, or a
    /// malformed endorsement.
    pub fn statement_draft(
        &self,
        request_id: &str,
        vetter_did: &str,
        attestation: Attestation,
        now: DateTime<Utc>,
    ) -> Result<StatementDraft, VetterError> {
        let entry = self
            .desk_entry(request_id)
            .ok_or(VetterError::NoSuchRequest)?;
        let DeskState::CardReceived { session, card } = &entry.state else {
            return Err(VetterError::WrongState("be attested"));
        };
        let schema = |e: &dyn std::fmt::Display| ShapeError::Schema(e.to_string());
        let documentary = attestation.method != VettingMethod::PriorAcquaintance;
        if documentary && !attestation.liveness_confirmed {
            return Err(VetterError::LivenessNotConfirmed);
        }
        // The shared endorsement never lists `none`: no document is the empty
        // list. So `none` is dropped here, and a documentary method left with
        // nothing to rely on is the same as naming no documentation at all.
        let document_classes = attestation
            .document_classes
            .iter()
            .filter(|d| d.as_str() != documentation::NONE)
            .map(|d| VettingDocumentation::try_from(d.as_str()).map_err(|e| schema(&e)))
            .collect::<Result<Vec<_>, ShapeError>>()?;
        if documentary && document_classes.is_empty() {
            return Err(VetterError::NoDocumentation);
        }
        if let Some(missing) = attestation
            .claims_verified
            .iter()
            .find(|t| !card.claims.iter().any(|c| c.type_.as_str() == t.as_str()))
        {
            return Err(VetterError::ClaimNotOnCard(missing.clone()));
        }
        if let Some(unverified) = session
            .required_claims
            .iter()
            .find(|t| !attestation.claims_verified.contains(t))
        {
            return Err(VetterError::RequiredClaimNotVerified(unverified.clone()));
        }
        let claims_verified = attestation
            .claims_verified
            .iter()
            .map(|c| ClaimType::try_from(c.as_str()).map_err(|e| schema(&e)))
            .collect::<Result<Vec<_>, ShapeError>>()?;
        let endorsement = IdentityVettingEndorsement {
            endorsement_type: IDENTITY_VETTING_ENDORSEMENT_TYPE.into(),
            community: entry.community.clone(),
            method: attestation.method,
            document_classes,
            claims_verified,
            liveness_confirmed: attestation.liveness_confirmed,
            identity_commitment: card.identity_commitment.clone(),
            card_digest_multibase: card.digest_multibase.clone(),
            declared_relationship: attestation.declared_relationship,
            attestation_text_digest: attestation.attestation_text_digest,
        };
        endorsement.check_shape()?;
        Ok(StatementDraft {
            id: format!("urn:uuid:{}", Uuid::new_v4()),
            issuer: vetter_did.to_string(),
            subject: entry.applicant.clone(),
            endorsement,
            valid_from: now,
            valid_until: now + self.policy.statement_validity(),
            task_context: session.id.clone(),
        })
    }

    /// Record the statement we signed for `request_id`, which closes the
    /// request. Verified first, so what we keep is what the applicant receives.
    ///
    /// # Errors
    ///
    /// No card to attest to, or a statement that does not verify.
    pub async fn record_statement(
        &mut self,
        request_id: &str,
        signed: &Value,
        resolver: &TrustTaskVmResolver,
        now: DateTime<Utc>,
    ) -> Result<IssuedStatement, VetterError> {
        let verified = verify_statement(signed, now, resolver).await?;
        let entry = self
            .desk_entry_mut(request_id)
            .ok_or(VetterError::NoSuchRequest)?;
        let DeskState::CardReceived { card, .. } = &entry.state else {
            return Err(VetterError::WrongState("be attested"));
        };
        let issued = IssuedStatement {
            id: verified.id().to_string(),
            digest_multibase: verified.digest_multibase().to_string(),
            applicant: entry.applicant.clone(),
            community: entry.community.clone(),
            persona: entry.persona,
            method: verified.endorsement().method,
            issued_at: now,
            valid_until: verified.valid_until(),
            withdrawal: None,
        };
        entry.state = DeskState::Attested {
            statement_id: issued.id.clone(),
            issued_at: now,
            card: card.clone(),
        };
        entry.updated_at = now;
        self.issued.push(issued.clone());
        Ok(issued)
    }

    /// Decline `request_id`. A vetter never has to give a reason.
    ///
    /// # Errors
    ///
    /// No such request, one already closed, or a malformed message.
    pub fn decline(
        &mut self,
        request_id: &str,
        code: Option<decline::v0_1::PayloadCode>,
        message: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<decline::v0_1::Payload, VetterError> {
        let entry = self
            .desk_entry_mut(request_id)
            .ok_or(VetterError::NoSuchRequest)?;
        if !entry.state.is_open() {
            return Err(VetterError::WrongState("be declined"));
        }
        let schema = |e: &dyn std::fmt::Display| ShapeError::Schema(e.to_string());
        let message = message
            .map(|m| decline::v0_1::PayloadMessage::try_from(m).map_err(|e| schema(&e)))
            .transpose()?;
        let body = decline::v0_1::Payload::try_from(
            decline::v0_1::Payload::builder()
                .request_id(request_id)
                .code(code)
                .message(message),
        )
        .map_err(|e| schema(&e))?;
        body.check_shape()?;
        let card = match &entry.state {
            DeskState::CardReceived { card, .. } => Some(card.clone()),
            _ => None,
        };
        entry.state = DeskState::Declined {
            code,
            at: now,
            card,
        };
        entry.updated_at = now;
        Ok(body)
    }

    /// The withdrawal notice for statement `statement_id`, recorded as sent
    /// under `document_id`. Sending again before the community has recorded it
    /// is allowed: withdrawal converges.
    ///
    /// # Errors
    ///
    /// No such statement, or one the community already recorded withdrawn.
    pub fn withdrawal(
        &mut self,
        statement_id: &str,
        reason: Option<revoke_statement::v0_1::PayloadReason>,
        document_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(revoke_statement::v0_1::Payload, IssuedStatement), VetterError> {
        let issued = self
            .issued
            .iter_mut()
            .find(|s| s.id == statement_id)
            .ok_or(VetterError::NoSuchStatement)?;
        if issued
            .withdrawal
            .as_ref()
            .is_some_and(|w| w.recorded_at.is_some())
        {
            return Err(VetterError::AlreadyWithdrawn);
        }
        let schema = |e: &dyn std::fmt::Display| ShapeError::Schema(e.to_string());
        let body = revoke_statement::v0_1::Payload::try_from(
            revoke_statement::v0_1::Payload::builder()
                .statement_id(issued.id.as_str())
                .statement_digest_multibase(issued.digest_multibase.as_str())
                .reason(reason),
        )
        .map_err(|e| schema(&e))?;
        body.check_shape()?;
        issued.withdrawal = Some(Withdrawal {
            document_id: document_id.to_string(),
            reason,
            sent_at: now,
            recorded_at: None,
        });
        Ok((body, issued.clone()))
    }

    /// The community recorded the withdrawal threaded on `document_id`.
    pub fn on_withdrawal_recorded(
        &mut self,
        community: &str,
        document_id: &str,
        recorded_at: DateTime<Utc>,
    ) -> Option<&IssuedStatement> {
        let issued = self.issued.iter_mut().find(|s| {
            s.community == community
                && s.withdrawal
                    .as_ref()
                    .is_some_and(|w| w.document_id == document_id)
        })?;
        if let Some(w) = issued.withdrawal.as_mut() {
            w.recorded_at = Some(recorded_at);
        }
        Some(issued)
    }
}
