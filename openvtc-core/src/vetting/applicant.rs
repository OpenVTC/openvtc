//! The applicant's side: one application to one community (design §9–§12).
//!
//! An application collects statements from vetters until the community's
//! published requirements are met, then rides the join request. Each vetter
//! goes through the same short life:
//!
//! ```text
//! Sent ──#response──▶ Accepted ──vetting/session──▶ Session ──statement──▶ Attested
//!   │                    │                             │
//!   └─trust-task-error─▶ Refused        vetting/decline └──▶ Declined
//! ```
//!
//! The checklist ([`Application::checklist`]) is **advisory**. It counts what
//! this client can verify — proofs, subject, community, commitment, age,
//! method floors — and assumes every vetter is eligible, because only the
//! community knows that. Copy built on it says "meets the published
//! requirements", never "approved" (D12).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use vta_sdk::protocols::join_requests::JoinRequestManifestResponseBody;
use vta_sdk::protocols::vetting::{
    CardClaim, DeclaredRelationship, DeclineCode, ShapeError, TicketPresentation, VETTER_ROLE,
    VettingDeclineBody, VettingMethod, VettingRequestAcceptedBody, VettingRequestBody,
    VettingRequirements, VettingSessionBody,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::VettingError;
use vta_sdk::vetting::card::{
    CardDraft, CardExpectations, MAX_CARD_VALIDITY, new_commitment_salt, verify_card,
};
use vta_sdk::vetting::match_code::vetting_match_code;
use vta_sdk::vetting::requirements::{
    Evaluation, REQUIREMENTS_DIGEST_MEMBER, StatementFacts, evaluate,
};
use vta_sdk::vetting::statement::verify_statement;

use crate::config::account::PersonaId;
use crate::persona::disclosure::ReleasedClaim;

/// Why an applicant-side step was refused.
#[derive(Debug, thiserror::Error)]
pub enum ApplicantError {
    /// Nothing we sent matches this reply.
    #[error("no request of ours matches this reply")]
    NoMatchingRequest,
    /// The request exists but cannot take this step now.
    #[error("the request cannot {0} in its current state")]
    WrongState(&'static str),
    /// A payload broke its schema.
    #[error(transparent)]
    Shape(#[from] ShapeError),
    /// The session names another community.
    #[error("the session is for a different community")]
    WrongCommunity,
    /// The session has closed.
    #[error("the session has expired")]
    SessionExpired,
    /// The card would lack a claim the session requires.
    #[error("the card needs a `{0}` claim")]
    MissingClaim(String),
    /// A claim was released without its value — proved as a predicate — and a
    /// vetter has to read the value to check it against a document.
    #[error("your face releases `{0}` without its value, and a vetter has to read it")]
    ValueWithheld(String),
    /// A credential-backed claim can no longer be proven.
    #[error("`{0}` can no longer be proven — refresh it under My Identity")]
    StaleClaim(String),
    /// The face now shows a value other than the one earlier cards committed to.
    #[error(
        "your face now shows a different `{0}` than the cards you already sent — the \
         community would refer the application"
    )]
    IdentityChanged(String),
    /// Building or verifying an artifact failed.
    #[error(transparent)]
    Vetting(#[from] VettingError),
    /// A statement is not about this application.
    #[error("the statement's {0} does not match this application")]
    Binding(&'static str),
    /// The community's manifest names no vetting.
    #[error("the community does not ask for vetting")]
    NoVettingCriterion,
    /// The community's requirements cannot be evaluated.
    #[error("the community's vetting requirements are unusable: {0}")]
    InvalidRequirements(String),
}

/// One application.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Application {
    /// Local handle.
    pub id: String,
    /// The community's VTC DID.
    pub community: String,
    /// The persona joining.
    pub persona: PersonaId,
    /// The DID every card is signed by and every statement names (D13).
    pub join_did: String,
    /// The VTA context the persona's face for this community is worn in. Set
    /// the first time a face is chosen or a card is sent, and reused as the
    /// membership's sub-context when the join goes through, so the face the
    /// vetters saw is the face the community sees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// The manifest criterion being gathered for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criterion_id: Option<String>,
    /// What that criterion requires, as last read from the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<VettingRequirements>,
    /// The criterion's `requirementsDigest`, sent with requests and the join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements_digest: Option<String>,
    /// One salt for the whole application, so every vetter sees the same
    /// identity commitment. Goes to vetters, never to the community.
    pub commitment_salt: String,
    /// The identity vetters have been shown, as the persona's face disclosed
    /// it. Every later card must show the same values: two cards that spell a
    /// name differently commit to different identities, and the community
    /// refers the application.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_claims: Vec<CardClaim>,
    /// Requests to vetters, newest last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<OutboundRequest>,
    /// Statements received.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statements: Vec<HeldStatement>,
    /// When the application started.
    pub created_at: DateTime<Utc>,
    /// Fields written by a newer build, preserved verbatim (D19).
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, Value>,
}

/// What an applicant could establish about a vetter from the eligibility
/// presentation that came with their acceptance.
///
/// Advisory, like the checklist: the community checks the vetter again when
/// it decides, and does not count a statement from one it has not named.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum VetterEligibility {
    /// The community's vetter role credential for this vetter verified, bound
    /// to our request. Whether the community has since revoked it is not
    /// checked here.
    Shown {
        /// The role credential's `id`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        credential_id: Option<String>,
        /// Its `validUntil`.
        valid_until: DateTime<Utc>,
    },
    /// The vetter presented nothing.
    NotShown,
    /// What they presented did not verify.
    Failed {
        /// Why.
        reason: String,
    },
}

/// One request to one vetter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutboundRequest {
    /// Our `vetting/request` document id — what the vetter's reply threads on.
    pub document_id: String,
    /// The vetter's DID.
    pub vetter: String,
    /// Where it stands.
    pub state: RequestState,
    /// What the vetter's acceptance showed of their eligibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility: Option<VetterEligibility>,
    /// When we sent it.
    pub sent_at: DateTime<Utc>,
    /// When it last moved.
    pub updated_at: DateTime<Utc>,
}

/// Where a request stands.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RequestState {
    /// Sent; no answer yet.
    Sent,
    /// The vetter took it.
    Accepted {
        /// The vetter's handle.
        request_id: String,
        /// What documentation the vetter accepts.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        accepts_documentation: Vec<String>,
        /// How the vetter proposes to meet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_hint: Option<String>,
    },
    /// The vetter opened a session; we owe them a card.
    Session {
        /// The vetter's handle.
        request_id: String,
        /// The open session.
        session: OpenSession,
        /// The card we sent, once we have.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        card: Option<SentCard>,
    },
    /// We hold the vetter's statement.
    Attested {
        /// The vetter's handle.
        request_id: String,
        /// The statement's id.
        statement_id: String,
    },
    /// The vetter declined.
    Declined {
        /// Their reason code, if they gave one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<DeclineCode>,
        /// Their note, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// The vetter refused the request itself (`trust-task-error`).
    Refused {
        /// The error code, e.g. `vetting/request:capacity`.
        code: String,
        /// Their note, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

/// A session a vetter opened with us.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OpenSession {
    /// The `vetting/session` document id.
    pub id: String,
    /// What the card must carry.
    pub challenge: String,
    /// What the card must carry.
    pub domain: String,
    /// The method.
    pub method: VettingMethod,
    /// Claim types the card must carry.
    pub required_claims: Vec<String>,
    /// Claim types the card may carry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_claims: Vec<String>,
    /// After this we do not present.
    pub expires_at: DateTime<Utc>,
    /// The code both people read aloud.
    pub match_code: String,
}

/// The card we sent into a session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SentCard {
    /// The card id.
    pub id: String,
    /// Its `digestMultibase` — the statement must name it.
    pub digest_multibase: String,
    /// Its commitment — the statement must repeat it.
    pub identity_commitment: String,
    /// When we sent it.
    pub sent_at: DateTime<Utc>,
}

/// A statement we hold.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HeldStatement {
    /// The statement id.
    pub id: String,
    /// The vetter.
    pub vetter: String,
    /// How they vetted us.
    pub method: VettingMethod,
    /// The relationship they declared.
    pub declared_relationship: DeclaredRelationship,
    /// What they relied on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_classes: Vec<String>,
    /// Claim types they verified.
    pub claims_verified: Vec<String>,
    /// Our identity commitment, as they signed it.
    pub identity_commitment: String,
    /// Start of validity.
    pub valid_from: DateTime<Utc>,
    /// End of validity.
    pub valid_until: DateTime<Utc>,
    /// When it arrived.
    pub received_at: DateTime<Utc>,
    /// The signed credential, exactly as received.
    pub credential: Value,
}

/// What a request to a vetter says besides the ticket.
#[derive(Clone, Debug, Default)]
pub struct RequestDraft {
    /// The method the applicant would prefer.
    pub preferred_method: Option<VettingMethod>,
    /// BCP 47 tags.
    pub languages: Vec<String>,
    /// A short note.
    pub message: Option<String>,
    /// Free-text availability.
    pub availability: Option<String>,
}

impl Application {
    /// A new application with a fresh commitment salt.
    ///
    /// # Errors
    ///
    /// Only if the platform has no randomness.
    pub fn new(
        community: &str,
        persona: PersonaId,
        join_did: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, VettingError> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            community: community.to_string(),
            persona,
            join_did: join_did.to_string(),
            context_id: None,
            criterion_id: None,
            requirements: None,
            requirements_digest: None,
            commitment_salt: new_commitment_salt()?,
            identity_claims: Vec::new(),
            requests: Vec::new(),
            statements: Vec::new(),
            created_at: now,
            extra: serde_json::Map::new(),
        })
    }

    /// Take the community's requirements from its manifest (0.2). Keeps the
    /// criterion already chosen when it still exists; otherwise the first that
    /// asks for vetting. Returns whether the requirements changed — a changed
    /// digest mid-application is worth telling the applicant about.
    ///
    /// # Errors
    ///
    /// [`ApplicantError::NoVettingCriterion`] or
    /// [`ApplicantError::InvalidRequirements`].
    pub fn adopt_manifest(
        &mut self,
        manifest: &JoinRequestManifestResponseBody,
    ) -> Result<bool, ApplicantError> {
        let with_vetting =
            |c: &&vta_sdk::protocols::join_requests::ManifestCriterion| c.vetting.is_some();
        let chosen = self
            .criterion_id
            .as_deref()
            .and_then(|id| {
                manifest
                    .criteria
                    .iter()
                    .filter(with_vetting)
                    .find(|c| c.id == id)
            })
            .or_else(|| manifest.criteria.iter().find(with_vetting))
            .ok_or(ApplicantError::NoVettingCriterion)?;
        let requirements = chosen.vetting.clone().expect("filtered on vetting");
        requirements
            .validate()
            .map_err(|e| ApplicantError::InvalidRequirements(e.0))?;
        let changed = self.requirements.as_ref() != Some(&requirements)
            || self.requirements_digest != chosen.requirements_digest;
        self.criterion_id = Some(chosen.id.clone());
        self.requirements = Some(requirements);
        self.requirements_digest = chosen.requirements_digest.clone();
        Ok(changed)
    }

    /// Build the `vetting/request` payload to `vetter` and record it as sent
    /// under `document_id`.
    ///
    /// # Errors
    ///
    /// [`ShapeError`] if the payload breaks the schema.
    pub fn prepare_request(
        &mut self,
        document_id: &str,
        vetter: &str,
        ticket: TicketPresentation,
        draft: RequestDraft,
        now: DateTime<Utc>,
    ) -> Result<VettingRequestBody, ShapeError> {
        let body = VettingRequestBody {
            community: self.community.clone(),
            requirements_digest: self.requirements_digest.clone(),
            join_did: self.join_did.clone(),
            ticket: Some(ticket),
            introduction: None,
            preferred_method: draft.preferred_method,
            languages: draft.languages,
            message: draft.message,
            availability: draft.availability,
            ext: None,
        };
        body.check_shape(&self.join_did)?;
        self.requests.push(OutboundRequest {
            document_id: document_id.to_string(),
            vetter: vetter.to_string(),
            state: RequestState::Sent,
            eligibility: None,
            sent_at: now,
            updated_at: now,
        });
        Ok(body)
    }

    /// Forget a request that never left — its send failed — so a retry is not
    /// shadowed by a record the vetter never saw. Returns whether one was removed.
    pub fn forget_unsent(&mut self, document_id: &str) -> bool {
        let before = self.requests.len();
        self.requests
            .retain(|r| !(r.document_id == document_id && r.state == RequestState::Sent));
        self.requests.len() != before
    }

    /// Whether we sent the request `document_id` (a reply's thread).
    #[must_use]
    pub fn sent(&self, document_id: &str) -> bool {
        self.requests.iter().any(|r| r.document_id == document_id)
    }

    fn by_thread(
        &mut self,
        thread: &str,
        vetter: &str,
    ) -> Result<&mut OutboundRequest, ApplicantError> {
        self.requests
            .iter_mut()
            .find(|r| r.document_id == thread && r.vetter == vetter)
            .ok_or(ApplicantError::NoMatchingRequest)
    }

    fn by_request_id(
        &mut self,
        request_id: &str,
        vetter: &str,
    ) -> Result<&mut OutboundRequest, ApplicantError> {
        self.requests
            .iter_mut()
            .rev()
            .find(|r| {
                r.vetter == vetter
                    && match &r.state {
                        RequestState::Accepted { request_id: id, .. }
                        | RequestState::Session { request_id: id, .. }
                        | RequestState::Attested { request_id: id, .. } => id == request_id,
                        _ => false,
                    }
            })
            .ok_or(ApplicantError::NoMatchingRequest)
    }

    /// The role a vetter must hold: the requirements' `eligibleVetters.role`,
    /// or `vetter` while they are unknown.
    #[must_use]
    pub fn vetter_role(&self) -> &str {
        self.requirements
            .as_ref()
            .map_or(VETTER_ROLE, |r| r.eligible_vetters.role.as_str())
    }

    /// The vetter accepted (`vetting/request#response`, threaded on our
    /// request), and `eligibility` is what its presentation showed. A repeat
    /// of the same acceptance is harmless.
    ///
    /// # Errors
    ///
    /// No matching request, a request already past acceptance, or a payload
    /// breaking its schema.
    pub fn on_accepted(
        &mut self,
        thread: &str,
        vetter: &str,
        body: VettingRequestAcceptedBody,
        eligibility: VetterEligibility,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicantError> {
        body.check_shape()?;
        let request = self.by_thread(thread, vetter)?;
        match &request.state {
            RequestState::Sent => {}
            RequestState::Accepted { request_id, .. } if *request_id == body.request_id => {}
            _ => return Err(ApplicantError::WrongState("be accepted")),
        }
        request.eligibility = Some(eligibility);
        request.state = RequestState::Accepted {
            request_id: body.request_id,
            accepts_documentation: body.accepts_documentation,
            session_hint: body.session_hint,
        };
        request.updated_at = now;
        Ok(())
    }

    /// The vetter refused the request (`trust-task-error`, threaded on it).
    ///
    /// # Errors
    ///
    /// No matching request, or one that was already answered.
    pub fn on_refused(
        &mut self,
        thread: &str,
        vetter: &str,
        code: String,
        message: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicantError> {
        let request = self.by_thread(thread, vetter)?;
        if request.state != RequestState::Sent {
            return Err(ApplicantError::WrongState("be refused"));
        }
        request.state = RequestState::Refused { code, message };
        request.updated_at = now;
        Ok(())
    }

    /// The vetter opened a session (`vetting/session`). Returns it, with the
    /// match code the two people read to each other.
    ///
    /// # Errors
    ///
    /// A malformed or expired session, one for another community, or one for
    /// a request this vetter never accepted.
    pub fn on_session(
        &mut self,
        session_document_id: &str,
        vetter: &str,
        body: VettingSessionBody,
        now: DateTime<Utc>,
    ) -> Result<OpenSession, ApplicantError> {
        body.check_shape()?;
        if body.domain != self.community {
            return Err(ApplicantError::WrongCommunity);
        }
        if body.expires_at <= now {
            return Err(ApplicantError::SessionExpired);
        }
        let request = self.by_request_id(&body.request_id, vetter)?;
        if matches!(request.state, RequestState::Attested { .. }) {
            return Err(ApplicantError::WrongState("open another session"));
        }
        let session = OpenSession {
            id: session_document_id.to_string(),
            challenge: body.challenge,
            domain: body.domain,
            method: body.method,
            required_claims: body.required_claims,
            optional_claims: body.optional_claims,
            expires_at: body.expires_at,
            match_code: vetting_match_code(session_document_id),
        };
        request.state = RequestState::Session {
            request_id: body.request_id,
            session: session.clone(),
            card: None,
        };
        request.updated_at = now;
        Ok(session)
    }

    /// The open session `session_id` and the vetter it is with.
    #[must_use]
    pub fn session(&self, session_id: &str) -> Option<(&str, &OpenSession)> {
        self.requests.iter().find_map(|r| match &r.state {
            RequestState::Session { session, .. } if session.id == session_id => {
                Some((r.vetter.as_str(), session))
            }
            _ => None,
        })
    }

    /// The claim types a card for `session_id` asks the face for: required,
    /// then optional.
    #[must_use]
    pub fn requested_claims(&self, session_id: &str) -> Vec<String> {
        self.session(session_id)
            .map(|(_, s)| {
                s.required_claims
                    .iter()
                    .chain(&s.optional_claims)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The card claims for `session_id` from what the face released (or would
    /// release — a preview has the same shape).
    ///
    /// Only the session's claim types are kept. Each needs a readable, current
    /// value, and a value vetters were already shown must not have changed.
    ///
    /// # Errors
    ///
    /// No such session, a required claim missing, a value withheld or stale, or
    /// an identity that differs from the cards already sent.
    pub fn card_claims(
        &self,
        session_id: &str,
        released: &[ReleasedClaim],
    ) -> Result<Vec<CardClaim>, ApplicantError> {
        let (_, session) = self
            .session(session_id)
            .ok_or(ApplicantError::NoMatchingRequest)?;
        let wanted = |t: &str| {
            session.required_claims.iter().any(|r| r == t)
                || session.optional_claims.iter().any(|o| o == t)
        };
        let mut claims = Vec::new();
        for claim in released.iter().filter(|c| wanted(&c.claim_type)) {
            if claim.stale {
                return Err(ApplicantError::StaleClaim(claim.claim_type.clone()));
            }
            let Some(value) = claim.value.clone() else {
                return Err(ApplicantError::ValueWithheld(claim.claim_type.clone()));
            };
            if self
                .identity_claims
                .iter()
                .any(|shown| shown.claim_type == claim.claim_type && shown.value != value)
            {
                return Err(ApplicantError::IdentityChanged(claim.claim_type.clone()));
            }
            claims.push(CardClaim {
                claim_type: claim.claim_type.clone(),
                value,
                provenance: claim
                    .provenance
                    .clone()
                    .unwrap_or_else(|| "unstated".to_string()),
            });
        }
        if let Some(missing) = session
            .required_claims
            .iter()
            .find(|t| !claims.iter().any(|c| &c.claim_type == *t))
        {
            return Err(ApplicantError::MissingClaim(missing.clone()));
        }
        Ok(claims)
    }

    /// Record a card that has been sent into `session_id`, and remember the
    /// identity it showed so later cards show the same.
    ///
    /// # Errors
    ///
    /// No such session, or claims that differ from those already shown.
    pub fn record_sent_card(
        &mut self,
        session_id: &str,
        card: SentCard,
        claims: &[CardClaim],
        now: DateTime<Utc>,
    ) -> Result<(), ApplicantError> {
        if let Some(changed) = claims.iter().find(|c| {
            self.identity_claims
                .iter()
                .any(|shown| shown.claim_type == c.claim_type && shown.value != c.value)
        }) {
            return Err(ApplicantError::IdentityChanged(changed.claim_type.clone()));
        }
        let request = self
            .requests
            .iter_mut()
            .find(|r| matches!(&r.state, RequestState::Session { session, .. } if session.id == session_id))
            .ok_or(ApplicantError::NoMatchingRequest)?;
        if let RequestState::Session { card: sent, .. } = &mut request.state {
            *sent = Some(card);
        }
        request.updated_at = now;
        for claim in claims {
            if !self
                .identity_claims
                .iter()
                .any(|shown| shown.claim_type == claim.claim_type)
            {
                self.identity_claims.push(claim.clone());
            }
        }
        Ok(())
    }

    /// The card to sign for `session_id`, from the claims the applicant chose
    /// to disclose. Only the session's required and optional claim types are
    /// kept; the identity commitment covers the required ones.
    ///
    /// # Errors
    ///
    /// No such session, an expired one, or a required claim missing.
    pub fn card_draft(
        &self,
        session_id: &str,
        claims: Vec<CardClaim>,
        now: DateTime<Utc>,
    ) -> Result<CardDraft, ApplicantError> {
        let (vetter, session) = self
            .session(session_id)
            .ok_or(ApplicantError::NoMatchingRequest)?;
        if session.expires_at <= now {
            return Err(ApplicantError::SessionExpired);
        }
        let claims: Vec<CardClaim> = claims
            .into_iter()
            .filter(|c| {
                session.required_claims.contains(&c.claim_type)
                    || session.optional_claims.contains(&c.claim_type)
            })
            .collect();
        if let Some(missing) = session
            .required_claims
            .iter()
            .find(|t| !claims.iter().any(|c| &c.claim_type == *t))
        {
            return Err(ApplicantError::MissingClaim(missing.clone()));
        }
        Ok(CardDraft {
            id: format!("urn:uuid:{}", Uuid::new_v4()),
            publisher: self.join_did.clone(),
            audience: vetter.to_string(),
            community: self.community.clone(),
            challenge: session.challenge.clone(),
            domain: session.domain.clone(),
            issued_at: now,
            validity: MAX_CARD_VALIDITY.min(session.expires_at - now),
            claims,
            identity_types: session.required_claims.clone(),
            salt: self.commitment_salt.clone(),
        })
    }

    /// Record the signed card we are sending into `session_id`. Verifies it the
    /// way the vetter will, so a card that would be refused never leaves.
    /// Returns what was recorded.
    ///
    /// # Errors
    ///
    /// No such session, or a card that does not verify.
    pub async fn record_card(
        &mut self,
        session_id: &str,
        card: &Value,
        resolver: &TrustTaskVmResolver,
        now: DateTime<Utc>,
    ) -> Result<SentCard, ApplicantError> {
        let join_did = self.join_did.clone();
        let community = self.community.clone();
        let request = self
            .requests
            .iter_mut()
            .find(|r| matches!(&r.state, RequestState::Session { session, .. } if session.id == session_id))
            .ok_or(ApplicantError::NoMatchingRequest)?;
        let RequestState::Session {
            session,
            card: sent,
            ..
        } = &mut request.state
        else {
            unreachable!("matched a session above");
        };
        let verified = verify_card(
            card,
            &CardExpectations {
                audience: &request.vetter,
                publisher: &join_did,
                community: &community,
                challenge: &session.challenge,
                domain: &session.domain,
                required_claims: &session.required_claims,
                now,
            },
            resolver,
        )
        .await?;
        let recorded = SentCard {
            id: verified.card().id.clone(),
            digest_multibase: verified.digest_multibase().to_string(),
            identity_commitment: verified.card().identity_commitment.clone(),
            sent_at: now,
        };
        *sent = Some(recorded.clone());
        request.updated_at = now;
        Ok(recorded)
    }

    /// A statement arrived from `vetter`. Verified and bound to this
    /// application — our join DID, this community, and the card we sent that
    /// vetter — before it is kept.
    ///
    /// # Errors
    ///
    /// A statement that does not verify, is about someone or something else,
    /// or answers no card of ours.
    pub async fn on_statement(
        &mut self,
        vetter: &str,
        credential: &Value,
        resolver: &TrustTaskVmResolver,
        now: DateTime<Utc>,
    ) -> Result<HeldStatement, ApplicantError> {
        let verified = verify_statement(credential, now, resolver).await?;
        if verified.issuer() != vetter {
            return Err(ApplicantError::Binding("issuer"));
        }
        if verified.subject() != self.join_did {
            return Err(ApplicantError::Binding("subject"));
        }
        let endorsement = verified.endorsement();
        if endorsement.community != self.community {
            return Err(ApplicantError::Binding("community"));
        }
        if let Some(held) = self.statements.iter().find(|s| s.id == verified.id()) {
            return Ok(held.clone());
        }
        let request = self
            .requests
            .iter_mut()
            .find(|r| {
                r.vetter == vetter
                    && matches!(&r.state, RequestState::Session { session, .. }
                        if session.id == verified.task_context())
            })
            .ok_or(ApplicantError::NoMatchingRequest)?;
        let RequestState::Session {
            request_id, card, ..
        } = &request.state
        else {
            unreachable!("matched a session above");
        };
        let card = card
            .as_ref()
            .ok_or(ApplicantError::WrongState("take a statement before a card"))?;
        if endorsement.card_digest_multibase != card.digest_multibase {
            return Err(ApplicantError::Binding("cardDigestMultibase"));
        }
        if endorsement.identity_commitment != card.identity_commitment {
            return Err(ApplicantError::Binding("identityCommitment"));
        }
        let held = HeldStatement {
            id: verified.id().to_string(),
            vetter: vetter.to_string(),
            method: endorsement.method,
            declared_relationship: endorsement.declared_relationship,
            document_classes: endorsement.document_classes.clone(),
            claims_verified: endorsement.claims_verified.clone(),
            identity_commitment: endorsement.identity_commitment.clone(),
            valid_from: verified.valid_from(),
            valid_until: verified.valid_until(),
            received_at: now,
            credential: credential.clone(),
        };
        request.state = RequestState::Attested {
            request_id: request_id.clone(),
            statement_id: held.id.clone(),
        };
        request.updated_at = now;
        self.statements.push(held.clone());
        Ok(held)
    }

    /// The vetter declined (`vetting/decline`).
    ///
    /// # Errors
    ///
    /// A malformed decline, or one for a request this vetter never accepted.
    pub fn on_decline(
        &mut self,
        vetter: &str,
        body: VettingDeclineBody,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicantError> {
        body.check_shape()?;
        let request = self.by_request_id(&body.request_id, vetter)?;
        if matches!(request.state, RequestState::Attested { .. }) {
            return Err(ApplicantError::WrongState("be declined after attesting"));
        }
        request.state = RequestState::Declined {
            code: body.code,
            message: body.message,
        };
        request.updated_at = now;
        Ok(())
    }

    /// Progress against the published requirements, as far as this client can
    /// tell. `None` until the requirements are known.
    #[must_use]
    pub fn checklist(&self, now: DateTime<Utc>) -> Option<Evaluation> {
        let requirements = self.requirements.as_ref()?;
        let facts: Vec<StatementFacts> = self
            .statements
            .iter()
            .filter(|s| s.valid_until > now)
            .map(|s| StatementFacts {
                statement_id: s.id.clone(),
                vetter: s.vetter.clone(),
                method: s.method,
                claims_verified: s.claims_verified.clone(),
                document_classes: s.document_classes.clone(),
                declared_relationship: s.declared_relationship,
                identity_commitment: s.identity_commitment.clone(),
                valid_from: s.valid_from,
                community_matches: true,
                // Only the community can say; see the module docs.
                eligible: true,
                revoked: false,
            })
            .collect();
        Some(evaluate(requirements, &facts, now))
    }

    /// The statements to present with the join request.
    #[must_use]
    pub fn presentable_statements(&self, now: DateTime<Utc>) -> Vec<Value> {
        self.statements
            .iter()
            .filter(|s| s.valid_until > now)
            .map(|s| s.credential.clone())
            .collect()
    }

    /// The join submission's `extensions`: the digest of the requirements the
    /// statements were gathered against, so the community applies the same
    /// criterion.
    #[must_use]
    pub fn join_extensions(&self) -> Value {
        match &self.requirements_digest {
            Some(digest) => json!({ REQUIREMENTS_DIGEST_MEMBER: digest }),
            None => Value::Null,
        }
    }
}
