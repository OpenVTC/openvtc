//! Answering what a community asks an applicant to tell it about themselves.
//!
//! A join manifest (0.2) may carry `requestedAttributes`: claim types, never
//! values, each `required` or not, each with a `purpose` shown before anything
//! is sent. The applicant answers from the face their persona wears in the
//! community's context, and the answers ride the join submit as `attributes`.
//!
//! # Through the disclosure path, deliberately
//!
//! The values are not read out of the pool and pasted into the submit. They go
//! out through `persona/disclosure/preview` → `present`, in the community's
//! context, with the community as verifier. That is what puts them in the
//! holder's own disclosure history — the record that later answers "who did I
//! tell my name to" — and it is the only path on which a claim the holder marked
//! `release: stepUp` is gated as they asked. A submit carrying values that never
//! passed through a disclosure would be the one place this product hands over
//! identity data without keeping a record of having done so.
//!
//! # Self-asserted
//!
//! What leaves here is the applicant's own statement. The community is required
//! to treat it as such (`vtc/join-requests/submit/0.2`), and nothing in this
//! module presents it as anything else.

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::join_requests::JoinRequestAttribute;
use vta_sdk::protocols::join_requests::manifest::v0_2;

use crate::errors::OpenVTCError;

/// One thing the community asks, as the applicant is shown it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asked {
    pub claim_type: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// What the manifest asks, in its own order. Empty when it asks nothing.
#[must_use]
pub fn asked(manifest: &v0_2::Response) -> Vec<Asked> {
    manifest
        .requested_attributes
        .iter()
        .map(|r| Asked {
            claim_type: r.type_.to_string(),
            required: r.required,
            purpose: r.purpose.as_ref().map(|p| p.to_string()),
        })
        .collect()
}

/// A disclosure the holder is about to approve: what would leave, and what the
/// community asks that the face cannot answer.
#[derive(Clone, Debug, PartialEq)]
pub struct AnswerPreview {
    /// Consumed by [`present`]. Single-use and short-lived.
    pub preview_id: String,
    /// `(claim type, value)` as it would leave. A value the agent withheld —
    /// a predicate, say — is `None`, and is not sent as an answer.
    pub claims: Vec<(String, Option<Value>)>,
    /// Required types the face does not show. Non-empty means the submit would
    /// be refused with `attributesMissing`, so the holder is told now, while
    /// they can still wear a different face or add the attribute.
    pub missing_required: Vec<String>,
}

/// Preview answering `asked` from what `persona_did` wears in `context_id`.
///
/// Asks the agent only for the requested types (`requestedClaims`), so the
/// preview can never show — and `present` can never release — anything the
/// community did not ask for.
pub async fn preview(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
    community_did: &str,
    asked: &[Asked],
) -> Result<AnswerPreview, OpenVTCError> {
    let requested: Vec<String> = asked.iter().map(|a| a.claim_type.clone()).collect();
    let response = client
        .persona_disclosure_preview(
            context_id,
            persona_did,
            community_did,
            requested,
            Some("joining the community"),
            None,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not preview the answers: {e}")))?;
    preview_from_response(&response, asked)
}

/// The pure half of [`preview`], separated so it is testable without an agent.
pub fn preview_from_response(
    response: &Value,
    asked: &[Asked],
) -> Result<AnswerPreview, OpenVTCError> {
    let preview_id = response
        .get("previewId")
        .and_then(Value::as_str)
        .ok_or_else(|| OpenVTCError::Vta("the preview carried no previewId".into()))?
        .to_string();
    let claims: Vec<(String, Option<Value>)> = response
        .get("claims")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter_map(|c| {
                    let t = c.get("type")?.as_str()?.to_string();
                    Some((t, c.get("value").cloned()))
                })
                .collect()
        })
        .unwrap_or_default();
    let missing_required = asked
        .iter()
        .filter(|a| a.required)
        .filter(|a| {
            !claims
                .iter()
                .any(|(t, v)| *t == a.claim_type && v.is_some())
        })
        .map(|a| a.claim_type.clone())
        .collect();
    Ok(AnswerPreview {
        preview_id,
        claims,
        missing_required,
    })
}

/// Release what the preview showed, and turn it into the submit's `attributes`.
///
/// Writes the disclosure record before the artifact comes back (the agent's
/// ordering), so a join that is then refused still leaves the holder a true
/// account of what they told the community.
pub async fn present(
    client: &VtaClient,
    context_id: &str,
    preview_id: &str,
) -> Result<Vec<JoinRequestAttribute>, OpenVTCError> {
    let response = client
        .persona_disclosure_present(context_id, preview_id, None, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not release the answers: {e}")))?;
    let artifact = response
        .get("artifact")
        .and_then(Value::as_str)
        .ok_or_else(|| OpenVTCError::Vta("the disclosure carried no artifact".into()))?;
    attributes_from_artifact(artifact)
}

/// The claims a disclosure artifact carries, as submit `attributes`.
///
/// The artifact is the agent's relationship card: `claims` maps an ordinal to
/// `{type, value?, provenance?}`. Only `type` and `value` travel — provenance
/// is not the community's to read here, since the answer is self-asserted
/// whatever the attribute's provenance, and a claim with no value (a
/// predicate) is not an answer.
pub fn attributes_from_artifact(artifact: &str) -> Result<Vec<JoinRequestAttribute>, OpenVTCError> {
    let card: Value = serde_json::from_str(artifact)
        .map_err(|e| OpenVTCError::Vta(format!("the disclosure artifact is not JSON: {e}")))?;
    let Some(claims) = card.get("claims").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    // Ordinal keys sort in the order the agent wrote them.
    let mut ordered: Vec<(&String, &Value)> = claims.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(b.0));
    Ok(ordered
        .into_iter()
        .filter_map(|(_, c)| {
            Some(JoinRequestAttribute {
                claim_type: c.get("type")?.as_str()?.to_string(),
                value: c.get("value")?.clone(),
            })
        })
        .collect())
}

/// What `face` would answer for each thing asked, in the order asked: the
/// value it shows for that type, or `None` when it shows none.
///
/// Read from the face's resolved claims — the same values a disclosure from it
/// would carry — so what the holder approves on the page is what leaves. A
/// stale claim answers nothing: it would be refused at disclosure.
#[must_use]
pub fn shown_by(
    asked: &[Asked],
    resolved: &[crate::persona::profile::ResolvedClaim],
) -> Vec<(String, Option<Value>)> {
    asked
        .iter()
        .map(|a| {
            let value = resolved
                .iter()
                .find(|c| c.claim_type == a.claim_type && !c.stale)
                .and_then(|c| c.value.clone());
            (a.claim_type.clone(), value)
        })
        .collect()
}

/// Required types `shown` leaves unanswered.
#[must_use]
pub fn unanswered_required(asked: &[Asked], shown: &[(String, Option<Value>)]) -> Vec<String> {
    asked
        .iter()
        .filter(|a| a.required)
        .filter(|a| !shown.iter().any(|(t, v)| *t == a.claim_type && v.is_some()))
        .map(|a| a.claim_type.clone())
        .collect()
}

/// Whether a disclosure preview would send exactly what the holder approved.
///
/// The holder approves values on the page before the persona exists; the
/// disclosure is previewed after it wears the face. Anything that changed in
/// between — an attribute edited in another window, a face rearranged — must
/// stop the join rather than send something the holder did not see.
#[must_use]
pub fn preview_matches(preview: &AnswerPreview, approved: &[(String, Value)]) -> bool {
    let sent: Vec<(&str, &Value)> = preview
        .claims
        .iter()
        .filter_map(|(t, v)| v.as_ref().map(|v| (t.as_str(), v)))
        .collect();
    sent.len() == approved.len()
        && approved
            .iter()
            .all(|(t, v)| sent.iter().any(|(st, sv)| *st == t && *sv == v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ask(t: &str, required: bool) -> Asked {
        Asked {
            claim_type: t.into(),
            required,
            purpose: None,
        }
    }

    #[test]
    fn a_required_type_the_face_does_not_show_is_named_before_anything_leaves() {
        let asked = [ask("name.display", true), ask("address.country", false)];
        let p = preview_from_response(
            &json!({ "previewId": "p1", "claims": [ { "type": "address.country", "value": "SG" } ] }),
            &asked,
        )
        .unwrap();
        assert_eq!(p.missing_required, vec!["name.display".to_string()]);

        let ok = preview_from_response(
            &json!({ "previewId": "p1", "claims": [ { "type": "name.display", "value": "Ada" } ] }),
            &asked,
        )
        .unwrap();
        assert!(ok.missing_required.is_empty());
    }

    #[test]
    fn a_withheld_value_does_not_answer_a_required_type() {
        // A predicate claim carries no value; it cannot answer "what is your
        // name", and treating it as though it did would submit nothing and be
        // refused after the holder had approved.
        let p = preview_from_response(
            &json!({ "previewId": "p1", "claims": [ { "type": "name.display" } ] }),
            &[ask("name.display", true)],
        )
        .unwrap();
        assert_eq!(p.missing_required, vec!["name.display".to_string()]);
    }

    #[test]
    fn the_artifact_becomes_attributes_in_order_without_provenance() {
        let card = json!({
            "type": ["VerifiableDataStructure", "RelationshipCard"],
            "claims": {
                "0001": { "type": "address.country", "value": "SG",
                          "provenance": { "kind": "selfAsserted" } },
                "0000": { "type": "name.display", "value": "Ada" },
                "0002": { "type": "person.ageOver", "predicate": { "gte": 18 } },
            },
            "unsigned": true,
        })
        .to_string();
        let attrs = attributes_from_artifact(&card).unwrap();
        assert_eq!(
            serde_json::to_value(&attrs).unwrap(),
            json!([
                { "type": "name.display", "value": "Ada" },
                { "type": "address.country", "value": "SG" },
            ])
        );
    }

    #[test]
    fn a_preview_that_changed_since_approval_does_not_match() {
        let approved = vec![("name.display".to_string(), json!("Ada"))];
        let same = AnswerPreview {
            preview_id: "p".into(),
            claims: vec![("name.display".into(), Some(json!("Ada")))],
            missing_required: vec![],
        };
        assert!(preview_matches(&same, &approved));
        let edited = AnswerPreview {
            claims: vec![("name.display".into(), Some(json!("Ada King")))],
            ..same.clone()
        };
        assert!(!preview_matches(&edited, &approved));
        let more = AnswerPreview {
            claims: vec![
                ("name.display".into(), Some(json!("Ada"))),
                ("address.country".into(), Some(json!("SG"))),
            ],
            ..same
        };
        assert!(
            !preview_matches(&more, &approved),
            "one more value than approved"
        );
    }
}
