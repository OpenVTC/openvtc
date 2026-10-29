//! The VTA as this client's hidden-vetting (PCS) engine — the `vta/pcs/*` Trust Tasks.
//!
//! Every PCS key — an applicant's, one per application, and a vetter's, one per community — is
//! held by the person's VTA, which runs every operation that needs one: creating an application,
//! taking in an attestation, building the admission proof; enrolling, drawing tokens, attesting.
//! This client keeps none of that material. It carries messages: what the VTA builds goes to the
//! community or the other party, and what they answer goes back to the VTA.
//!
//! What this client does keep is what the VTA says it holds ([`VetterView`],
//! [`ApplicationView`]) — non-secret summaries the schedule and the screens read between calls.
//! The VTA is the source of truth for both; a summary is replaced by the next answer.
//!
//! Each call takes the task's generated payload (so a request the schema refuses is caught here)
//! and reads the reply document itself rather than through `dispatch_trust_task`, because a
//! refusal's code is what the caller acts on (`noToken` is a wait, `notFound` is a fresh start)
//! and the SDK's typed error keeps it only as text.

use crate::specs::vta::pcs;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use trust_tasks_rs::RequestPayload;

/// The generated `vta/pcs/*` modules, for matching a refusal against a task's `error_codes`.
pub use crate::specs::vta::pcs as tasks;
use vta_sdk::client::VtaClient;

use super::hidden::HiddenParams;
use super::wire::pcs::{RootRequest, RootResponse, TokensRequest, TokensResponse};

/// Round-trip budget for an ordinary engine call, in seconds.
pub const TIMEOUT_SECS: u64 = 30;
/// Round-trip budget for a pairing-heavy one — proving, attesting, enrolling, verifying.
pub const PROOF_TIMEOUT_SECS: u64 = 90;

/// The prefix every refusal document's type carries.
const ERROR_TYPE_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// Why a call to the VTA's engine did not succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PcsError {
    /// The VTA answered and refused, with the code its specification declares
    /// (`vta/pcs/attest:noToken`). Match the code against the task's `error_codes`.
    #[error("your VTA refused: {message} ({code})")]
    Refused {
        /// The full declared code, as the VTA sent it.
        code: String,
        /// What it said.
        message: String,
    },
    /// No answer: the VTA could not be reached, or did not reply in time.
    #[error("could not reach your VTA: {0}")]
    Unreachable(String),
    /// A request this client could not build, or an answer it could not read.
    #[error("a hidden-vetting call to your VTA could not be read: {0}")]
    Unreadable(String),
}

impl PcsError {
    /// Whether the VTA refused with `code` — one of a task's declared `error_codes`.
    #[must_use]
    pub fn is(&self, code: trust_tasks_rs::DeclaredErrorCode) -> bool {
        matches!(self, Self::Refused { code: c, .. } if c == code.code)
    }

    /// Whether the refusal is the task's `notFound`: the VTA holds no such application or
    /// engine. Every `vta/pcs/*` task that takes one declares it under the same local name.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Refused { code, .. }
            if code.rsplit_once(':').is_some_and(|(_, local)| local == "notFound"))
    }
}

/// Send `payload` as `P`'s task and read its answer.
async fn call<P>(client: &VtaClient, payload: Value, timeout: u64) -> Result<P::Response, PcsError>
where
    P: RequestPayload,
    P::Response: DeserializeOwned,
{
    // Through the generated type first: a request the schema would refuse fails here, with the
    // member it is about, rather than as the VTA's `malformedRequest`.
    let typed: P = serde_json::from_value(payload)
        .map_err(|e| PcsError::Unreadable(format!("{}: {e}", P::TYPE_URI)))?;
    let payload = serde_json::to_value(&typed).map_err(|e| PcsError::Unreadable(e.to_string()))?;
    let reply = client
        .dispatch_trust_task_document(P::TYPE_URI, payload, timeout)
        .await
        .map_err(|e| PcsError::Unreachable(e.to_string()))?;
    let body = reply.get("payload").cloned().unwrap_or(Value::Null);
    let refused = reply
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.starts_with(ERROR_TYPE_PREFIX));
    if refused {
        let text = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        return Err(PcsError::Refused {
            code: text("code"),
            message: text("message"),
        });
    }
    serde_json::from_value(body)
        .map_err(|e| PcsError::Unreadable(format!("{} answer: {e}", P::TYPE_URI)))
}

/// Carry a generated value into this client's own shape, by the wire form both spell.
fn carry<A: Serialize, B: DeserializeOwned>(value: &A) -> Result<B, PcsError> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|e| PcsError::Unreadable(e.to_string()))
}

/// What a community publishes, in the form every engine task takes (`PublishedConfig`).
///
/// [`HiddenParams`] reads leniently — a missing tick length or event floor is a default there —
/// and the engine's schema states every member, so the defaults are written in here.
#[must_use]
pub fn parameters(params: &HiddenParams) -> Value {
    json!({
        "suite": params.suite,
        "helperKey": params.helper_key,
        "tokenKey": params.token_key,
        "vetterLabels": params.vetter_labels,
        "tokenLabels": params.token_labels,
        "dripPerTick": params.drip_per_tick.max(1),
        "tickLength": params.tick_length.clone().unwrap_or_else(|| DEFAULT_TICK_TEXT.to_string()),
        "events": params.events.iter().map(|e| json!({
            "eventId": e.event_id,
            "startDate": e.start_date,
            "endDate": e.end_date,
            "groupFloor": e.group_floor.max(1),
            "tiers": e.tiers.iter().map(|t| json!({
                "name": t.name,
                "dripPerTick": t.drip_per_tick.max(1),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// [`super::hidden::DEFAULT_TICK_LENGTH`], as a community would publish it.
const DEFAULT_TICK_TEXT: &str = "P3D";

// -------------------------------------------------------------------------------------------
// What this client keeps of the VTA's answers
// -------------------------------------------------------------------------------------------

/// The metadata of one attestation, as a vetter's statement would have said it, minus its
/// issuer — the hidden-vetting `StatementMeta`. Kept so the applicant's checklist can count what
/// it holds, and tell an attestation the community will refuse (another criterion, a closed
/// token label) without asking the VTA each time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationMeta {
    pub community: String,
    pub requirements_digest: String,
    pub method: vta_sdk::protocols::vetting::VettingMethod,
    pub claims_verified: Vec<String>,
    pub liveness_confirmed: bool,
    pub declared_relationship: vta_sdk::protocols::vetting::VettingRelationship,
    pub identity_commitment: String,
    pub card_digest_multibase: String,
    pub valid_from: chrono::NaiveDate,
    pub valid_until: chrono::NaiveDate,
    pub token_label: String,
    pub token_serial: String,
}

/// A hidden-vetting application as the VTA holds it — without its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationView {
    /// The VTA's handle for the application.
    pub application_id: String,
    /// The applicant's PCS identifier: what goes in each vetting request's `ext`, and what a
    /// vetter attests to.
    pub id: String,
    /// Each attestation held, in the order received.
    #[serde(default)]
    pub attestations: Vec<AttestationMeta>,
}

/// One draw of the drip, asked for and not yet answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrawView {
    pub label: String,
    pub tick: u32,
}

/// A vetter's engine for one community as the VTA holds it — without its key, credentials or
/// tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VetterView {
    /// The vetter's PCS identifier for the community.
    pub id: String,
    /// Class labels a credential is held under (`vetter/2026-10`), newest first.
    #[serde(default)]
    pub enrolled_labels: Vec<String>,
    /// Class labels asked for and not yet taken in.
    #[serde(default)]
    pub pending_labels: Vec<String>,
    /// Tokens held and not reserved.
    #[serde(default)]
    pub tokens_free: u64,
    /// Tokens held in all.
    #[serde(default)]
    pub tokens_held: u64,
    /// Draws asked for and not yet taken in or abandoned.
    #[serde(default)]
    pub draws_in_flight: Vec<DrawView>,
    /// Attestations made through this engine.
    #[serde(default)]
    pub attested: u64,
}

impl VetterView {
    /// Whether a credential is held under the class period `period` (`2026-10`).
    #[must_use]
    pub fn enrolled_for(&self, period: &str) -> bool {
        self.enrolled_labels
            .iter()
            .any(|l| l.trim_start_matches("vetter/") == period)
    }
}

// -------------------------------------------------------------------------------------------
// The applicant's tasks
// -------------------------------------------------------------------------------------------

/// `vta/pcs/applications/create` — a fresh key for one application under `community`'s
/// hidden-vetting criterion, used for that application and no other.
///
/// # Errors
/// [`PcsError`].
pub async fn create_application(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    join_did: &str,
    params: &HiddenParams,
) -> Result<ApplicationView, PcsError> {
    let answer = call::<pcs::applications::create::v0_1::Payload>(
        client,
        json!({
            "contextId": context_id,
            "community": community,
            "joinDid": join_did,
            "parameters": parameters(params),
        }),
        TIMEOUT_SECS,
    )
    .await?;
    carry(&answer.application)
}

/// `vta/pcs/applications/show`. `Ok(None)` when the VTA holds no such application.
///
/// # Errors
/// [`PcsError`].
pub async fn show_application(
    client: &VtaClient,
    application_id: &str,
) -> Result<Option<ApplicationView>, PcsError> {
    match call::<pcs::applications::show::v0_1::Payload>(
        client,
        json!({ "applicationId": application_id }),
        TIMEOUT_SECS,
    )
    .await
    {
        Ok(answer) => carry(&answer.application).map(Some),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(e),
    }
}

/// `vta/pcs/applications/delete` — destroy the application's key and attestations. An
/// application the VTA no longer holds is already gone, which is the outcome asked for.
///
/// # Errors
/// [`PcsError`].
pub async fn delete_application(client: &VtaClient, application_id: &str) -> Result<(), PcsError> {
    match call::<pcs::applications::delete::v0_1::Payload>(
        client,
        json!({ "applicationId": application_id }),
        TIMEOUT_SECS,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(e) if e.is_not_found() => Ok(()),
        Err(e) => Err(e),
    }
}

/// `vta/pcs/verify-attestation` — take in an attestation a vetter sent. Checked against the
/// community's published keys now, while the vetter is still there to ask again, rather than at
/// submit.
///
/// # Errors
/// [`PcsError`]; a refused attestation is
/// `pcs::verify_attestation::v0_1::error_codes::ATTESTATION_INVALID`.
pub async fn verify_attestation(
    client: &VtaClient,
    application_id: &str,
    params: &HiddenParams,
    attestation: &Value,
) -> Result<ApplicationView, PcsError> {
    let answer = call::<pcs::verify_attestation::v0_1::Payload>(
        client,
        json!({
            "applicationId": application_id,
            "parameters": parameters(params),
            "attestation": attestation,
        }),
        PROOF_TIMEOUT_SECS,
    )
    .await?;
    carry(&answer.application)
}

/// `vta/pcs/prove` — the proof the join submission carries in `extensions.hiddenVetting`,
/// bound to the community's `challenge`.
///
/// # Errors
/// [`PcsError`]; `pcs::prove::v0_1::error_codes::NO_USABLE_ATTESTATION` when nothing held can
/// count.
pub async fn prove(
    client: &VtaClient,
    application_id: &str,
    params: &HiddenParams,
    requirements_digest: &str,
    challenge: &str,
) -> Result<Value, PcsError> {
    let answer = call::<pcs::prove::v0_1::Payload>(
        client,
        json!({
            "applicationId": application_id,
            "parameters": parameters(params),
            "requirementsDigest": requirements_digest,
            "challenge": challenge,
        }),
        PROOF_TIMEOUT_SECS,
    )
    .await?;
    serde_json::to_value(&answer.hidden_vetting).map_err(|e| PcsError::Unreadable(e.to_string()))
}

// -------------------------------------------------------------------------------------------
// The vetter's tasks
// -------------------------------------------------------------------------------------------

/// `vta/pcs/root-request` — a blinded enrolment request under `label` (`vetter/2026-10`), to send
/// the community as `vtc/vetting/vetters/pcs-root`.
///
/// The first one for a community creates the vetter's engine there, bound to `member_did`: the
/// DID that signs every token draw. One engine per (context, community) for life — a second
/// member DID is `memberMismatch`.
///
/// # Errors
/// [`PcsError`].
pub async fn root_request(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    member_did: &str,
    params: &HiddenParams,
    label: &str,
) -> Result<RootRequest, PcsError> {
    let answer = call::<pcs::root_request::v0_1::Payload>(
        client,
        json!({
            "contextId": context_id,
            "community": community,
            "memberDid": member_did,
            "parameters": parameters(params),
            "label": label,
        }),
        PROOF_TIMEOUT_SECS,
    )
    .await?;
    carry(&answer.request)
}

/// `vta/pcs/root-accept` — unblind the community's answer into a class credential.
///
/// # Errors
/// [`PcsError`]; `NO_REQUEST_IN_FLIGHT` when the VTA asked for no such label (an answer already
/// taken, or one to a request it never made), `CREDENTIAL_INVALID` when the answer does not
/// verify under the published key.
pub async fn root_accept(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    params: &HiddenParams,
    response: &RootResponse,
) -> Result<VetterView, PcsError> {
    let answer = call::<pcs::root_accept::v0_1::Payload>(
        client,
        json!({
            "contextId": context_id,
            "community": community,
            "parameters": parameters(params),
            "response": { "label": response.label, "preCredential": response.pre_credential },
        }),
        PROOF_TIMEOUT_SECS,
    )
    .await?;
    carry(&answer.vetter)
}

/// `vta/pcs/tokens/request` — one draw: `count` blinded serials under `label` for `tick`, to send
/// the community as `vtc/vetting/vetters/pcs-tokens`.
///
/// # Errors
/// [`PcsError`]; `ALREADY_IN_FLIGHT` for a draw asked for and not yet answered.
pub async fn tokens_request(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    params: &HiddenParams,
    label: &str,
    tick: u32,
    count: usize,
) -> Result<TokensRequest, PcsError> {
    let answer = call::<pcs::tokens::request::v0_1::Payload>(
        client,
        json!({
            "contextId": context_id,
            "community": community,
            "parameters": parameters(params),
            "label": label,
            "tick": tick,
            "count": count,
        }),
        TIMEOUT_SECS,
    )
    .await?;
    carry(&answer.request)
}

/// `vta/pcs/tokens/accept` — take a served draw into the wallet. Returns how many tokens it added,
/// and the engine after.
///
/// # Errors
/// [`PcsError`]; `NO_DRAW_IN_FLIGHT` for a draw the VTA did not ask for (or already took),
/// `TOKENS_INVALID` for tokens that do not verify.
pub async fn tokens_accept(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    params: &HiddenParams,
    served: &TokensResponse,
) -> Result<(u64, VetterView), PcsError> {
    let answer = call::<pcs::tokens::accept::v0_1::Payload>(
        client,
        json!({
            "contextId": context_id,
            "community": community,
            "parameters": parameters(params),
            "response": {
                "label": served.label,
                "tick": served.tick,
                "preCredentials": served.pre_credentials,
            },
        }),
        TIMEOUT_SECS,
    )
    .await?;
    let received: u64 = carry(&answer.received)?;
    Ok((received, carry(&answer.vetter)?))
}

/// `vta/pcs/tokens/abandon` — forget a draw the community refused, so its serials do not wait
/// for an answer that is never coming. A draw the VTA no longer holds is already forgotten.
///
/// # Errors
/// [`PcsError`].
pub async fn tokens_abandon(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    label: &str,
    tick: u32,
) -> Result<Option<VetterView>, PcsError> {
    match call::<pcs::tokens::abandon::v0_1::Payload>(
        client,
        json!({
            "contextId": context_id,
            "community": community,
            "draw": { "label": label, "tick": tick },
        }),
        TIMEOUT_SECS,
    )
    .await
    {
        Ok(answer) => carry(&answer.vetter).map(Some),
        Err(e) if e.is(pcs::tokens::abandon::v0_1::error_codes::NO_DRAW_IN_FLIGHT) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `vta/pcs/attest` — spend a token and attest for `applicant_id`, after the human check. The
/// answer is the `vetting/attestation/0.1` payload to send the applicant.
///
/// `meta` is the statement the named path would have signed, minus its issuer and token
/// (`AttestMeta`): the VTA binds the token it spends.
///
/// # Errors
/// [`PcsError`]; `NOT_ENROLLED` and `NO_TOKEN` are states the vetter waits out.
pub async fn attest(
    client: &VtaClient,
    context_id: &str,
    community: &str,
    params: &HiddenParams,
    applicant_id: &str,
    meta: Value,
    prefer_label: Option<&str>,
) -> Result<Value, PcsError> {
    let mut payload = json!({
        "contextId": context_id,
        "community": community,
        "parameters": parameters(params),
        "applicantId": applicant_id,
        "meta": meta,
    });
    if let Some(label) = prefer_label {
        payload["preferLabel"] = json!(label);
    }
    let answer = call::<pcs::attest::v0_1::Payload>(client, payload, PROOF_TIMEOUT_SECS).await?;
    serde_json::to_value(&answer.attestation).map_err(|e| PcsError::Unreadable(e.to_string()))
}

/// `vta/pcs/vetter/show`. `Ok(None)` when the VTA holds no engine for the community yet.
///
/// # Errors
/// [`PcsError`].
pub async fn vetter_show(
    client: &VtaClient,
    context_id: &str,
    community: &str,
) -> Result<Option<VetterView>, PcsError> {
    match call::<pcs::vetter::show::v0_1::Payload>(
        client,
        json!({ "contextId": context_id, "community": community }),
        TIMEOUT_SECS,
    )
    .await
    {
        Ok(answer) => carry(&answer.vetter).map(Some),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> HiddenParams {
        serde_json::from_value(json!({
            "suite": "ps-ddh-bls12381",
            "helperKey": "zHelper",
            "tokenKey": "zToken",
            "vetterLabels": ["vetter/2026-10"],
            "tokenLabels": ["token/2026-10"],
        }))
        .unwrap()
    }

    /// What a community publishes leniently is written out in full for the engine, and the
    /// result is a `PublishedConfig` the engine's schema accepts.
    #[test]
    fn parameters_fill_in_what_the_engine_requires() {
        let value = parameters(&params());
        assert_eq!(value["tickLength"], "P3D");
        assert_eq!(value["events"], json!([]));
        let payload = json!({
            "contextId": "ctx",
            "community": "did:example:vtc",
            "joinDid": "did:key:z6Mk",
            "parameters": value,
        });
        serde_json::from_value::<pcs::applications::create::v0_1::Payload>(payload)
            .expect("the engine's schema accepts the parameters");
    }

    #[test]
    fn a_refusal_is_matched_by_its_declared_code() {
        let code = pcs::attest::v0_1::error_codes::NO_TOKEN;
        let refused = PcsError::Refused {
            code: code.code.to_string(),
            message: "no token".into(),
        };
        assert!(refused.is(code));
        assert!(!refused.is(pcs::attest::v0_1::error_codes::NOT_ENROLLED));
        assert!(!refused.is_not_found());
        let missing = PcsError::Refused {
            code: pcs::vetter::show::v0_1::error_codes::NOT_FOUND
                .code
                .to_string(),
            message: String::new(),
        };
        assert!(missing.is_not_found());
    }
}
