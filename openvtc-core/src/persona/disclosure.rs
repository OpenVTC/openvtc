//! Releasing what a face shows, and the permanent record of every release.
//!
//! # Only when someone asks
//!
//! The two writing halves of `persona/disclosure/*` are a preview and the
//! present it authorises, and they exist to be driven by a verifier's request:
//! someone asks, a human is shown exactly what would go, and only then does
//! anything leave. A "disclose something now" button with nobody asking would
//! be a request with no requester — the one shape the two-call gate exists to
//! prevent.
//!
//! Peer vetting has a requester. A vetter's `vetting/session` names the claim
//! types they will check against the person in front of them, so [`preview`]
//! and [`present`] are driven by that session: the verifier is the vetter, the
//! challenge is the session's, and the holder approves the preview before the
//! card is signed (`docs/design/vetting-process.md` §9.2).
//!
//! [`history`] answers the question asked after the fact: what does anyone
//! already know, and how did they come to know it. It is **holder-scoped**, and
//! the one read in this module family that deliberately spans every context.
//!
//! # A rung is not a detail
//!
//! The same claim type released at two proof rungs is two very different
//! disclosures — `whole` hands every verifier an identical issuer signature to
//! join on, while `predicate` proves a statement without handing over the
//! claim. A history that listed types and dropped rungs would show two
//! materially different acts as one line repeated.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;

/// One claim in a release, as the history reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosedClaim {
    /// The vocabulary token — `email.work`.
    pub claim_type: String,
    /// How strongly it was hidden: `predicate`, `derived`, `selective`,
    /// `whole`, ordered most private first.
    pub rung: String,
}

/// One release, already reduced to what a panel row needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureRow {
    pub disclosure_id: String,
    /// The trust context it happened in.
    pub context_id: String,
    /// Who it went to.
    pub verifier_did: String,
    /// The persona it was made as.
    pub persona_did: String,
    pub claims: Vec<DisclosedClaim>,
    /// What the verifier said it was for, if they said.
    pub purpose: Option<String>,
    /// Set when the release minted a durable credential — the one kind that is
    /// still live and still revocable, which is why it is named rather than
    /// folded in with the rest.
    pub durable_credential_id: Option<String>,
    pub disclosed_at: String,
}

impl DisclosureRow {
    fn from_wire(value: &Value) -> Self {
        let string_at = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_default()
        };
        Self {
            disclosure_id: string_at("disclosureId"),
            context_id: string_at("contextId"),
            verifier_did: string_at("verifierDid"),
            persona_did: string_at("personaDid"),
            claims: value
                .get("claims")
                .and_then(Value::as_array)
                .map(|claims| {
                    claims
                        .iter()
                        .map(|claim| DisclosedClaim {
                            claim_type: claim
                                .get("type")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            // An unrecorded rung reads as `whole`, the least
                            // private answer. The conservative reading for an
                            // unassessed disclosure is the one that overstates
                            // exposure — claiming an unlinkability the proof
                            // may not have provided is the error that cannot be
                            // undone.
                            rung: claim
                                .get("rung")
                                .and_then(Value::as_str)
                                .unwrap_or("whole")
                                .to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            purpose: value
                .get("purpose")
                .and_then(Value::as_str)
                .map(str::to_string),
            durable_credential_id: value
                .get("durableCredentialId")
                .and_then(Value::as_str)
                .map(str::to_string),
            disclosed_at: string_at("disclosedAt"),
        }
    }

    /// The attributes as one line: `email.work (whole), age.over18 (yes/no only)`.
    ///
    /// The rung travels with every attribute rather than being summarised, because
    /// there is no summary of a mixed release that is not misleading in one
    /// direction or the other — and because severity inverts intuition: a
    /// credential shown *whole* links the holder more than an attribute they simply
    /// asserted.
    #[must_use]
    pub fn describe_claims(&self) -> String {
        if self.claims.is_empty() {
            return "no attributes recorded".to_string();
        }
        self.claims
            .iter()
            .map(|c| format!("{} ({})", c.claim_type, rung_label(&c.rung)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What a person reads for a proof rung
/// (`design-docs/persona-vocabulary.md`). An unrecognised rung is shown
/// verbatim rather than mapped to a friendlier neighbour: the words carry a
/// privacy ordering, and guessing one would misstate how much left.
#[must_use]
fn rung_label(rung: &str) -> &str {
    match rung {
        "whole" => "whole",
        "selectiveDisclosure" => "partly",
        "derived" => "derived",
        "predicate" => "yes/no only",
        other => other,
    }
}

/// The renderer a vetting card is built from: the one that carries provenance.
pub const RCARD_RENDERER: &str = "rcard";

/// One claim as a disclosure carries it — what the holder is shown in a
/// preview, and what left in the artifact. The two have the same shape.
#[derive(Clone, Debug, PartialEq)]
pub struct ReleasedClaim {
    /// The vocabulary token — `name.legal`.
    pub claim_type: String,
    /// Absent when the claim is proved as a predicate: the verifier learns an
    /// answer, never the value.
    pub value: Option<Value>,
    /// Where the value came from: `selfAsserted`, `credentialBacked`, …
    /// Absent only when the renderer dropped it.
    pub provenance: Option<String>,
    /// A credential-backed value that could not be re-derived.
    pub stale: bool,
}

impl ReleasedClaim {
    fn from_wire(value: &Value) -> Self {
        Self {
            claim_type: value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            value: value.get("value").cloned().filter(|v| !v.is_null()),
            // The preview names the kind; the artifact carries the whole
            // provenance object. Only the kind travels on.
            provenance: match value.get("provenance") {
                Some(Value::String(kind)) => Some(kind.clone()),
                Some(other) => other
                    .get("kind")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                None => None,
            },
            stale: value.get("stale").and_then(Value::as_bool).unwrap_or(false),
        }
    }
}

/// A preview: what would leave, held by the agent until presented or expired.
#[derive(Clone, Debug, PartialEq)]
pub struct Preview {
    /// Single use; [`present`] consumes it.
    pub preview_id: String,
    pub claims: Vec<ReleasedClaim>,
    pub expires_at: String,
}

/// Ask what `persona_did`'s face in `context_id` would show `verifier_did`.
///
/// Signs nothing and sends nothing. The claims come back so the holder can be
/// shown them before [`present`] releases them.
pub async fn preview(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
    verifier_did: &str,
    requested_claims: Vec<String>,
    purpose: &str,
) -> Result<Preview, OpenVTCError> {
    let value = client
        .persona_disclosure_preview(
            context_id,
            persona_did,
            verifier_did,
            requested_claims,
            Some(purpose),
            Some(RCARD_RENDERER),
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona disclosure preview failed: {e}")))?;
    let preview_id = value
        .get("previewId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| OpenVTCError::Vta("the disclosure preview carried no previewId".into()))?
        .to_string();
    Ok(Preview {
        preview_id,
        claims: value
            .get("claims")
            .and_then(Value::as_array)
            .map(|claims| claims.iter().map(ReleasedClaim::from_wire).collect())
            .unwrap_or_default(),
        expires_at: value
            .get("expiresAt")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// What a present released.
#[derive(Clone, Debug, PartialEq)]
pub struct Presented {
    pub disclosure_id: String,
    pub claims: Vec<ReleasedClaim>,
}

/// Why a present did not release anything.
#[derive(Debug, thiserror::Error)]
pub enum PresentError {
    /// A claim needs a fresh approval. The preview survives: approve on the
    /// device, then present the same preview again.
    #[error("a claim in this disclosure needs your approval first")]
    StepUpRequired,
    /// Anything else. The preview may be gone.
    #[error("{0}")]
    Failed(String),
}

/// Release what the preview `preview_id` showed, bound to `challenge`.
///
/// # Errors
///
/// [`PresentError::StepUpRequired`] when the agent wants a fresh approval —
/// the one refusal that leaves the preview usable.
pub async fn present(
    client: &VtaClient,
    context_id: &str,
    preview_id: &str,
    challenge: Option<&str>,
) -> Result<Presented, PresentError> {
    let value = client
        .persona_disclosure_present(context_id, preview_id, challenge, None)
        .await
        .map_err(|e| {
            let message = e.to_string();
            // `persona/disclosure/present/1.0` refuses with a
            // specification-extended code the SDK reports as text.
            if message.contains("stepUpRequired") {
                PresentError::StepUpRequired
            } else {
                PresentError::Failed(format!("persona disclosure present failed: {message}"))
            }
        })?;
    let claims = value
        .get("artifact")
        .map(artifact_claims)
        .transpose()
        .map_err(PresentError::Failed)?
        .ok_or_else(|| PresentError::Failed("the disclosure carried no artifact".into()))?;
    Ok(Presented {
        disclosure_id: value
            .get("disclosureId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        claims,
    })
}

/// The claims in a rendered artifact, in the order the renderer numbered them.
///
/// The artifact travels as a JSON string; an object is accepted too.
fn artifact_claims(artifact: &Value) -> Result<Vec<ReleasedClaim>, String> {
    let parsed;
    let document = match artifact {
        Value::String(text) => {
            parsed = serde_json::from_str::<Value>(text)
                .map_err(|e| format!("the disclosure artifact is not JSON: {e}"))?;
            &parsed
        }
        other => other,
    };
    let claims = document
        .get("claims")
        .and_then(Value::as_object)
        .ok_or("the disclosure artifact carries no claims")?;
    let mut numbered: Vec<(&String, &Value)> = claims.iter().collect();
    numbered.sort_by(|a, b| a.0.cmp(b.0));
    Ok(numbered
        .into_iter()
        .map(|(_, claim)| ReleasedClaim::from_wire(claim))
        .collect())
}

/// Every release, newest first, across every context.
///
/// `limit` caps the read: a history is append-only and unbounded, and a panel
/// that asked for all of it would grow slower for the whole life of the
/// account.
pub async fn history(
    client: &VtaClient,
    limit: std::num::NonZeroU64,
) -> Result<Vec<DisclosureRow>, OpenVTCError> {
    let value = client
        .persona_disclosure_history(None, None, None, None, Some(limit), None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona disclosure history failed: {e}")))?;

    let mut rows: Vec<DisclosureRow> = value
        .get("disclosures")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(DisclosureRow::from_wire).collect())
        .unwrap_or_default();
    // Newest first: the question a holder opens this with is almost always
    // "what just went out", not "what went out when I set the account up".
    rows.sort_by(|a, b| b.disclosed_at.cmp(&a.disclosed_at));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rungs are shown in the words the vocabulary fixes, and an unrecognised
    /// one is passed through rather than mapped to a friendlier neighbour — the
    /// four words carry a privacy ordering, so guessing would misstate how much
    /// of the attribute left.
    #[test]
    fn a_fact_carries_its_rung_into_the_row() {
        let row = DisclosureRow::from_wire(&serde_json::json!({
            "disclosureId": "01D",
            "contextId": "ctx",
            "verifierDid": "did:webvh:example.com:acme",
            "claims": [
                { "type": "email.work", "rung": "whole" },
                { "type": "age.over18", "rung": "predicate" },
            ],
            "disclosedAt": "2026-09-06T10:00:00Z",
        }));
        assert_eq!(
            row.describe_claims(),
            "email.work (whole), age.over18 (yes/no only)"
        );
    }

    #[test]
    fn an_unknown_rung_is_shown_verbatim() {
        let row = DisclosureRow::from_wire(&serde_json::json!({
            "claims": [{ "type": "email.work", "rung": "someFutureRung" }],
        }));
        assert_eq!(row.describe_claims(), "email.work (someFutureRung)");
    }

    /// An unrecorded rung reads as `whole`.
    ///
    /// It is the least private of the four, and the conservative answer for an
    /// unassessed release is the one that *overstates* what left. Defaulting
    /// the other way would tell a holder a claim was proved without being
    /// handed over, when nothing in the record says so.
    #[test]
    fn an_unrecorded_rung_reads_as_the_least_private_one() {
        let row = DisclosureRow::from_wire(&serde_json::json!({
            "claims": [{ "type": "email.work" }],
        }));
        assert_eq!(row.claims[0].rung, "whole");
    }

    /// The artifact's claims come back in the renderer's order, with the
    /// provenance kind lifted out of its object and a predicate left valueless.
    #[test]
    fn an_artifact_yields_its_claims_in_order() {
        let artifact = serde_json::json!({
            "type": ["VerifiableDataStructure", "RelationshipCard"],
            "claims": {
                "0001": { "type": "age.over18", "predicate": { "op": "gte" },
                          "provenance": { "kind": "credentialBacked", "credentialId": "c1",
                                          "claimPath": "/age" } },
                "0000": { "type": "name.legal", "value": "Alice Example",
                          "provenance": { "kind": "selfAsserted" } },
            },
            "unsigned": true,
        })
        .to_string();
        let claims = artifact_claims(&Value::String(artifact)).unwrap();
        assert_eq!(claims[0].claim_type, "name.legal");
        assert_eq!(claims[0].value, Some(serde_json::json!("Alice Example")));
        assert_eq!(claims[0].provenance.as_deref(), Some("selfAsserted"));
        assert_eq!(claims[1].value, None);
        assert_eq!(claims[1].provenance.as_deref(), Some("credentialBacked"));
    }

    /// A preview names provenance by kind alone.
    #[test]
    fn a_preview_claim_reads_its_provenance_kind() {
        let claim = ReleasedClaim::from_wire(&serde_json::json!({
            "type": "name.legal", "value": "Alice Example",
            "provenance": "selfAsserted", "rung": "whole", "newToThisVerifier": true,
        }));
        assert_eq!(claim.provenance.as_deref(), Some("selfAsserted"));
        assert!(!claim.stale);
    }

    #[test]
    fn an_artifact_without_claims_is_refused() {
        assert!(artifact_claims(&Value::String("{}".into())).is_err());
        assert!(artifact_claims(&Value::String("not json".into())).is_err());
    }

    /// A release with nothing recorded says so, rather than rendering as a
    /// blank line that reads like a release of nothing.
    #[test]
    fn a_factless_record_says_so() {
        let row = DisclosureRow::default();
        assert_eq!(row.describe_claims(), "no attributes recorded");
    }
}
