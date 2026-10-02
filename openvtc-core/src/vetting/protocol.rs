//! Which `vtc/join-requests` version a community speaks: `manifest/0.3` +
//! `submit/0.3`, or the `manifest/0.2` + `submit/0.2` it replaced.
//!
//! A community serves exactly one. VTI-13 dropped 0.2 without a transition, so
//! a client that spoke one version could not join communities on the other
//! until every community had moved. This client speaks both: it asks for 0.3
//! first, falls back to 0.2 when the community refuses the version
//! ([`is_version_refusal`]), remembers which one the community answered, and
//! submits in that version.
//!
//! Inside, a manifest is kept in its 0.2 shape ([`manifest::v0_2::Response`]),
//! which the book, the applicant and the attribute questions all read. A 0.3
//! manifest is carried into that shape by [`read_manifest`], and what 0.3 adds
//! per criterion — above all whether meeting it admits or only submits for
//! review — is kept alongside as [`CriterionMeta`].

use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::Payload as _;
use trust_tasks_rs::specs::vtc::join_requests::{manifest, submit};

/// Whether a Trust Task error `code` says the community does not serve the
/// version asked — the refusal that means "ask in the other one".
///
/// Both codes, because a VTC answers with either: `unsupportedVersion` when it
/// serves the task at another version (a 0.2 community asked for 0.3, naming
/// what it serves in `details.servedVersions`), `unsupportedType` when it does
/// not route the URI at all. Keying on the second alone would never fall back
/// against a live 0.2 community, which answers the first.
#[must_use]
pub fn is_version_refusal(code: &str) -> bool {
    matches!(code, "unsupportedType" | "unsupportedVersion")
}

/// A `vtc/join-requests` version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinProtocol {
    /// `manifest/0.3` + `submit/0.3` (Keyring VTI-13). Asked first.
    #[default]
    V0_3,
    /// `manifest/0.2` + `submit/0.2`, for a community that has not moved.
    V0_2,
}

impl JoinProtocol {
    /// The manifest request type.
    pub fn manifest_type(self) -> &'static str {
        match self {
            Self::V0_3 => manifest::v0_3::Payload::TYPE_URI,
            Self::V0_2 => manifest::v0_2::Payload::TYPE_URI,
        }
    }

    /// The manifest response type.
    pub fn manifest_response_type(self) -> &'static str {
        match self {
            Self::V0_3 => manifest::v0_3::Response::TYPE_URI,
            Self::V0_2 => manifest::v0_2::Response::TYPE_URI,
        }
    }

    /// The submit request type.
    pub fn submit_type(self) -> &'static str {
        match self {
            Self::V0_3 => submit::v0_3::Payload::TYPE_URI,
            Self::V0_2 => submit::v0_2::Payload::TYPE_URI,
        }
    }

    /// The submit response type.
    pub fn submit_response_type(self) -> &'static str {
        match self {
            Self::V0_3 => submit::v0_3::Response::TYPE_URI,
            Self::V0_2 => submit::v0_2::Response::TYPE_URI,
        }
    }

    /// The version a manifest response of type `typ` is in.
    pub fn from_manifest_response(typ: &str) -> Option<Self> {
        [Self::V0_3, Self::V0_2]
            .into_iter()
            .find(|p| p.manifest_response_type() == typ)
    }

    /// The version a manifest request of type `typ` is in.
    pub fn from_manifest_request(typ: &str) -> Option<Self> {
        [Self::V0_3, Self::V0_2]
            .into_iter()
            .find(|p| p.manifest_type() == typ)
    }

    /// Whether `typ` is a submit response of either version.
    pub fn is_submit_response(typ: &str) -> bool {
        [Self::V0_3, Self::V0_2]
            .into_iter()
            .any(|p| p.submit_response_type() == typ)
    }

    /// The version to fall back to when a community refuses this one as
    /// `unsupportedType`, if any.
    pub fn fallback(self) -> Option<Self> {
        match self {
            Self::V0_3 => Some(Self::V0_2),
            Self::V0_2 => None,
        }
    }
}

/// Whether meeting a criterion admits the applicant, or only submits the
/// request for an administrator to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Admission {
    Automatic,
    Review,
}

/// What `manifest/0.3` says about one criterion beyond its 0.2 shape.
///
/// A 0.2 manifest says none of it: it is `None` throughout, and a 0.2
/// community's criteria are described as they always were.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CriterionMeta {
    /// The criterion this describes.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<Admission>,
    /// Whether the criterion requires an invitation credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_required: Option<bool>,
}

/// The 0.3 members a 0.2 criterion does not have, removed when a 0.3 manifest
/// is carried into the 0.2 shape (which refuses unknown members).
const V0_3_ONLY_CRITERION_MEMBERS: [&str; 3] =
    ["admission", "credentialIssuers", "invitationRequired"];

/// Read a manifest payload in `protocol` into the 0.2 shape the rest of the
/// client reads, plus what 0.3 adds per criterion.
///
/// A 0.3 payload is checked against its own generated type first, so a
/// malformed 0.3 manifest is refused as 0.3 rather than half-accepted as 0.2.
/// It is then carried across: the 0.3-only members are taken out, and an
/// absent `presentationDefinition` — optional in 0.3, required in 0.2 — becomes
/// the empty definition 0.2 means by "nothing to present".
pub fn read_manifest(
    protocol: JoinProtocol,
    payload: &Value,
) -> Result<(manifest::v0_2::Response, Vec<CriterionMeta>), serde_json::Error> {
    match protocol {
        JoinProtocol::V0_2 => Ok((serde_json::from_value(payload.clone())?, Vec::new())),
        JoinProtocol::V0_3 => {
            let v3: manifest::v0_3::Response = serde_json::from_value(payload.clone())?;
            let meta = v3
                .criteria
                .iter()
                .map(|c| CriterionMeta {
                    id: c.id.to_string(),
                    // An admission this client does not know reads as review:
                    // the one claim it must never make wrongly is that meeting
                    // a criterion admits.
                    admission: Some(match c.admission {
                        manifest::v0_3::CriterionAdmission::Automatic => Admission::Automatic,
                        _ => Admission::Review,
                    }),
                    invitation_required: c.invitation_required,
                })
                .collect();
            let mut as_v2 = payload.clone();
            if let Some(criteria) = as_v2.get_mut("criteria").and_then(Value::as_array_mut) {
                for criterion in criteria.iter_mut().filter_map(Value::as_object_mut) {
                    for member in V0_3_ONLY_CRITERION_MEMBERS {
                        criterion.remove(member);
                    }
                    criterion
                        .entry("presentationDefinition")
                        .or_insert_with(|| Value::Object(Default::default()));
                }
            }
            Ok((serde_json::from_value(as_v2)?, meta))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DIGEST: &str = "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";

    fn v3_manifest() -> Value {
        json!({
            "communityDid": "did:webvh:example.com:community",
            "criteria": [
                {
                    "id": "invited",
                    "admission": "automatic",
                    "invitationRequired": true,
                    "requirementsDigest": DIGEST,
                },
                {
                    "id": "review",
                    "admission": "review",
                    "credentialIssuers": "any",
                    "presentationDefinition": { "credentials": [] },
                    "requirementsDigest": DIGEST,
                },
            ]
        })
    }

    /// A 0.3 manifest reads into the 0.2 shape with every criterion intact, and
    /// what 0.3 adds is kept beside it.
    #[test]
    fn a_v0_3_manifest_is_read_into_the_v0_2_shape_with_its_admission() {
        let (manifest, meta) = read_manifest(JoinProtocol::V0_3, &v3_manifest()).unwrap();
        assert_eq!(manifest.criteria.len(), 2);
        assert_eq!(meta.len(), 2);
        assert_eq!(meta[0].id, "invited");
        assert_eq!(meta[0].admission, Some(Admission::Automatic));
        assert_eq!(meta[0].invitation_required, Some(true));
        assert_eq!(meta[1].admission, Some(Admission::Review));
        assert!(
            manifest.criteria[0]
                .requirements_digest
                .as_ref()
                .is_some_and(|d| d.to_string() == DIGEST)
        );
    }

    /// A 0.3 manifest missing what 0.3 requires is refused, not carried
    /// across as a 0.2 one.
    #[test]
    fn a_malformed_v0_3_manifest_is_refused() {
        let mut m = v3_manifest();
        m["criteria"][0]
            .as_object_mut()
            .unwrap()
            .remove("admission");
        assert!(read_manifest(JoinProtocol::V0_3, &m).is_err());
    }

    /// The versions name the right types and fall back one way only.
    #[test]
    fn the_versions_name_their_types_and_fall_back_once() {
        assert!(
            JoinProtocol::V0_3
                .manifest_type()
                .ends_with("/manifest/0.3")
        );
        assert!(JoinProtocol::V0_2.submit_type().ends_with("/submit/0.2"));
        assert_eq!(
            JoinProtocol::from_manifest_response(JoinProtocol::V0_3.manifest_response_type()),
            Some(JoinProtocol::V0_3)
        );
        assert!(JoinProtocol::is_submit_response(
            JoinProtocol::V0_2.submit_response_type()
        ));
        assert_eq!(JoinProtocol::V0_3.fallback(), Some(JoinProtocol::V0_2));
        assert_eq!(JoinProtocol::V0_2.fallback(), None);
        assert!(is_version_refusal("unsupportedVersion"));
        assert!(is_version_refusal("unsupportedType"));
        assert!(!is_version_refusal("permissionDenied"));
    }
}
