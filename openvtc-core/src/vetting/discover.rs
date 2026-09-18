//! Reading a community's join manifest from the REST endpoint it publishes.
//!
//! A community that vets says what it requires *before* anything about the
//! applicant is sent (`docs/design/vetting-process.md` §6.1, "informed
//! non-application"). [`crate::vetting::wire::manifest_request`] asks that
//! question over DIDComm — which needs a mediator socket, a persona to ask as,
//! and a loop that can hear the answer. A first join has none of those: before
//! any community is joined there is no inbound arm to hear a reply on, so the
//! one question an applicant most needs answered is the one that could not be
//! asked.
//!
//! The same answer is served over HTTPS. A VTC publishes a `VTCRest` service in
//! its DID document, and `POST {endpoint}/v1/trust-tasks` dispatches on the
//! document's `type` — so a `join-requests/manifest/0.2` document gets the
//! manifest back, signed, with no session, no mediator and no inbound arm.
//!
//! # Nothing about the applicant is sent
//!
//! The request carries **no `issuer`**: the manifest is a public read and the
//! service answers one that names nobody. That matters beyond tidiness — the
//! join page promises "nothing about you has been sent to {community}", and
//! stamping a persona DID on a pre-application question would quietly make that
//! false. Reading what a community asks of applicants must not tell it who is
//! considering applying.
//!
//! # What is trusted, and why
//!
//! The endpoint is attacker-influenced: it comes out of a DID document naming
//! a host this client then dials. So the same guards the health probe uses
//! apply — HTTPS only, no redirects, no proxy, no userinfo, and a resolver that
//! refuses a name pointing at a non-routable address ([`ProbePolicy`]).
//!
//! The answer is then trusted only as far as its proof. A manifest is what an
//! applicant gathers evidence *against*: a forged one could ask for a passport
//! scan the real community never wanted, which makes an unverified manifest a
//! phishing surface in the same way an unverified agent name is. So the reply's
//! Data-Integrity proof is verified and the proven signer must be the community
//! being asked — the claimed `issuer` alone is not enough, and neither is TLS
//! to a host the DID document named.

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vta_sdk::protocols::join_requests::{JOIN_REQUEST_MANIFEST_0_2_TYPE, manifest};
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_with};

use crate::health::ProbePolicy;

/// The DID-document service type a VTC publishes its REST API under.
const VTC_REST_SERVICE_TYPE: &str = "VTCRest";

/// The Trust Task document endpoint, relative to the published REST base.
const TRUST_TASKS_PATH: &str = "v1/trust-tasks";

/// Total and connect budget for the fetch. Finite by rule R1.2: a hung service
/// must produce an error, never a hung command.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a community's manifest could not be read over its published endpoint.
///
/// The variants are the distinctions rule R6.4 asks for: an operator has to be
/// able to tell "this community does not publish one" from "the network did not
/// reach it" from "it answered and refused" from "it answered something this
/// client cannot read" — because those have four different next steps. One
/// fixed hint for all four is what the rule forbids.
#[derive(Debug, Clone)]
pub enum DiscoverError {
    /// The DID document publishes no `VTCRest` service, so there is nowhere to
    /// ask. Not a failure of this community — an older one, or one that serves
    /// its ceremony only over messaging.
    NoEndpoint,
    /// The published URL is not one this client will dial, and why.
    Blocked(String),
    /// The endpoint did not answer.
    Unreachable(String),
    /// It answered and declined.
    Refused { status: u16, detail: String },
    /// It answered something that is not a manifest this client can read.
    Unreadable(String),
    /// The answer carries no usable proof, or one that does not verify.
    Unproven(String),
    /// The answer verifies, but against a DID that is not the community asked.
    WrongSigner { proven: String },
}

impl std::fmt::Display for DiscoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEndpoint => {
                write!(f, "it publishes no REST endpoint to ask over")
            }
            Self::Blocked(reason) => {
                write!(f, "the endpoint it publishes cannot be used ({reason})")
            }
            Self::Unreachable(error) => {
                write!(f, "its endpoint could not be reached ({error})")
            }
            Self::Refused { status, detail } => {
                write!(f, "its endpoint refused the question ({status}: {detail})")
            }
            Self::Unreadable(detail) => write!(
                f,
                "its answer is in a form this client cannot read ({detail})"
            ),
            Self::Unproven(detail) => {
                write!(f, "its answer could not be shown to be genuine ({detail})")
            }
            Self::WrongSigner { proven } => write!(
                f,
                "its answer was signed by {proven}, which is not the community asked"
            ),
        }
    }
}

impl std::error::Error for DiscoverError {}

/// The `VTCRest` endpoint `doc` publishes, if it publishes one.
///
/// `type` is read as both a string and an array, because a DID document may
/// write either and a community that used the array form is not thereby
/// without a REST endpoint.
#[must_use]
pub fn rest_endpoint(doc: &Value) -> Option<String> {
    let services = doc.get("service")?.as_array()?;
    services.iter().find_map(|svc| {
        let matches = match svc.get("type") {
            Some(Value::String(t)) => t == VTC_REST_SERVICE_TYPE,
            Some(Value::Array(types)) => types
                .iter()
                .any(|t| t.as_str() == Some(VTC_REST_SERVICE_TYPE)),
            _ => false,
        };
        if !matches {
            return None;
        }
        // A `serviceEndpoint` may be a bare string or an object with a `uri`.
        match svc.get("serviceEndpoint") {
            Some(Value::String(uri)) => Some(uri.clone()),
            Some(Value::Object(map)) => map.get("uri").and_then(Value::as_str).map(str::to_string),
            _ => None,
        }
    })
}

/// The Trust Task document endpoint under `base`, vetted for dialling.
fn trust_tasks_url(base: &str, policy: ProbePolicy) -> Result<reqwest::Url, DiscoverError> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/{TRUST_TASKS_PATH}");
    crate::health::vet_probe_url(&url, policy).map_err(DiscoverError::Blocked)
}

/// The manifest question, as a document that names nobody.
///
/// Built by hand rather than through [`crate::trust_task_doc::build`] because
/// that one stamps an `issuer`, and this request deliberately has none — see
/// the module's "Nothing about the applicant is sent".
fn anonymous_request(community_did: &str) -> Value {
    serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": JOIN_REQUEST_MANIFEST_0_2_TYPE,
        "recipient": community_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {},
    })
}

/// Read `community_did`'s join manifest from the REST endpoint `doc` publishes.
///
/// `doc` is the community's already-resolved DID document. `resolver` verifies
/// the answer's proof; it is separate from `doc` because the proof's
/// verification method is resolved in its own right rather than read out of a
/// document the answer came packaged with.
pub async fn fetch_manifest(
    doc: &Value,
    community_did: &str,
    resolver: &DIDCacheClient,
    policy: ProbePolicy,
) -> Result<manifest::v0_2::Response, DiscoverError> {
    let endpoint = rest_endpoint(doc).ok_or(DiscoverError::NoEndpoint)?;
    let url = trust_tasks_url(&endpoint, policy)?;

    let mut builder = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if policy == ProbePolicy::PublicOnly {
        builder = builder.dns_resolver(affinidi_did_web::guarded_dns_resolver());
    }
    let client = builder
        .build()
        .map_err(|e| DiscoverError::Blocked(e.to_string()))?;

    let response = client
        .post(url)
        .json(&anonymous_request(community_did))
        .send()
        .await
        .map_err(|e| DiscoverError::Unreachable(e.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| DiscoverError::Unreachable(e.to_string()))?;
    if !status.is_success() {
        return Err(DiscoverError::Refused {
            status: status.as_u16(),
            detail: refusal_detail(&body),
        });
    }

    let reply: TrustTask<Value> =
        serde_json::from_str(&body).map_err(|e| DiscoverError::Unreadable(e.to_string()))?;

    // Proof before payload: nothing is read out of a document that has not been
    // shown to come from the community being asked.
    let proven = verify_trust_task_proof_with(&reply, &TrustTaskVmResolver::new(resolver.clone()))
        .await
        .map_err(|e| DiscoverError::Unproven(e.to_string()))?;
    if proven != community_did {
        return Err(DiscoverError::WrongSigner { proven });
    }

    serde_json::from_value(reply.payload).map_err(|e| DiscoverError::Unreadable(e.to_string()))
}

/// The `message` out of a `trust-task-error` body, or the body itself.
///
/// A refusal names why it refused, and that sentence is the whole value of the
/// variant — falling back to the raw body keeps a non-Trust-Task error (a proxy
/// page, say) from becoming an empty parenthesis. Bounded, because it is
/// someone else's text on its way to a terminal.
fn refusal_detail(body: &str) -> String {
    let detail = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("payload")
                .and_then(|p| p.get("message"))
                .or_else(|| v.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.to_string());
    crate::display::truncate_chars(&detail, 200).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc_with(service: Value) -> Value {
        json!({ "id": "did:webvh:x", "service": service })
    }

    #[test]
    fn the_rest_endpoint_is_found_under_either_type_form() {
        let string_form = doc_with(json!([
            { "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": "did:webvh:m" },
            { "id": "#vtc-rest", "type": "VTCRest", "serviceEndpoint": "https://vtc.example" },
        ]));
        assert_eq!(
            rest_endpoint(&string_form).as_deref(),
            Some("https://vtc.example")
        );

        // A document that writes `type` as an array has a REST endpoint too.
        let array_form = doc_with(json!([
            { "id": "#vtc-rest", "type": ["VTCRest"], "serviceEndpoint": "https://vtc.example" },
        ]));
        assert_eq!(
            rest_endpoint(&array_form).as_deref(),
            Some("https://vtc.example")
        );

        // And so does one that writes the endpoint as an object.
        let object_form = doc_with(json!([
            { "id": "#vtc-rest", "type": "VTCRest",
              "serviceEndpoint": { "uri": "https://vtc.example" } },
        ]));
        assert_eq!(
            rest_endpoint(&object_form).as_deref(),
            Some("https://vtc.example")
        );
    }

    /// No REST service is a community to ask over messaging instead, not an
    /// error to report — which is why it has a variant of its own.
    #[test]
    fn a_community_publishing_no_rest_service_has_no_endpoint() {
        let messaging_only = doc_with(json!([
            { "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": "did:webvh:m" },
        ]));
        assert!(rest_endpoint(&messaging_only).is_none());
        assert!(rest_endpoint(&json!({ "id": "did:webvh:x" })).is_none());
    }

    /// The endpoint comes out of someone else's document, so the guards that
    /// apply to a health probe apply here — and a refusal says which one bit.
    #[test]
    fn a_published_endpoint_is_vetted_before_it_is_dialled() {
        let blocked = |url: &str| {
            matches!(
                trust_tasks_url(url, ProbePolicy::PublicOnly),
                Err(DiscoverError::Blocked(_))
            )
        };
        assert!(blocked("http://vtc.example"), "plaintext");
        assert!(blocked("https://user:pw@vtc.example"), "userinfo");
        assert!(blocked("https://127.0.0.1"), "loopback");
        assert!(blocked("file:///etc/passwd"), "scheme");

        let ok = trust_tasks_url("https://vtc.example/", ProbePolicy::PublicOnly)
            .expect("a public https endpoint is dialled");
        assert_eq!(ok.as_str(), "https://vtc.example/v1/trust-tasks");

        // A development stack on loopback is reachable under the other policy,
        // which is the whole difference between them.
        assert!(trust_tasks_url("http://127.0.0.1:8080", ProbePolicy::AllowPrivate).is_ok());
    }

    /// The request must name nobody: reading what a community asks of
    /// applicants cannot be what tells it who is considering applying.
    #[test]
    fn the_question_carries_no_issuer() {
        let request = anonymous_request("did:webvh:community");
        assert!(
            request.get("issuer").is_none(),
            "a pre-application read must not name the reader"
        );
        assert_eq!(request["recipient"], "did:webvh:community");
        assert_eq!(request["type"], JOIN_REQUEST_MANIFEST_0_2_TYPE);
        assert!(request["payload"].as_object().is_some_and(|p| p.is_empty()));
    }

    #[test]
    fn a_refusal_is_reported_by_its_message_not_its_envelope() {
        let trust_task_error = r#"{"type":"…/trust-task-error/0.5",
            "payload":{"code":"malformedRequest","message":"body did not parse"}}"#;
        assert_eq!(refusal_detail(trust_task_error), "body did not parse");

        // A plain `message` (not every refusal is a Trust Task error).
        assert_eq!(
            refusal_detail(r#"{"message":"unauthorized"}"#),
            "unauthorized"
        );

        // Anything else is shown as it came, so an HTML proxy page does not
        // become an empty parenthesis.
        assert_eq!(refusal_detail("<html>502</html>"), "<html>502</html>");
    }

    /// Each variant has a different next step for the operator, so each says
    /// something different — rule R6.4.
    #[test]
    fn every_failure_says_which_one_it_is() {
        let said = |e: DiscoverError| e.to_string();
        let all = [
            said(DiscoverError::NoEndpoint),
            said(DiscoverError::Blocked("loopback".into())),
            said(DiscoverError::Unreachable("dns".into())),
            said(DiscoverError::Refused {
                status: 503,
                detail: "down".into(),
            }),
            said(DiscoverError::Unreadable("bad json".into())),
            said(DiscoverError::Unproven("no proof".into())),
            said(DiscoverError::WrongSigner {
                proven: "did:webvh:someone-else".into(),
            }),
        ];
        let mut seen = all.clone().to_vec();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), all.len(), "two failures read the same");
        assert!(all.iter().all(|s| !s.is_empty()));
    }
}
