//! The `vtc/join-requests` version this client speaks: `manifest/0.4` + `submit/0.3`.
//!
//! `manifest/0.4` is 0.3 plus one optional member, `directoryDisclosure`: what
//! the community's member directory would show about the person joining, and
//! to whom ([`super::disclosure`]). Its submit is 0.3, which names the criterion
//! a request is decided under.
//!
//! The VTC serves only the current versions, so this client asks in those and
//! nothing older: the 0.2 and 0.3 fallbacks it once carried are gone. A version
//! saved by a build that still spoke them reads as this one ([`JoinProtocol`]).
//!
//! Inside, a manifest is kept in the 0.2 shape ([`Manifest`]) — the SDK's
//! vetting model, which `vta_sdk::protocols::vetting` reads and the book, the
//! applicant and the attribute questions all read. A 0.4 manifest is carried
//! into that shape by [`read_manifest`], and what 0.3 added per criterion —
//! above all whether meeting it admits or only submits for review — is kept
//! alongside as [`CriterionMeta`]. That shape moves when the SDK's model does.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_rs::Payload as _;

use crate::specs::vtc::join_requests::{manifest::v0_4 as manifest, submit::v0_3 as submit};

/// The manifest as the rest of the client reads it: the SDK's 0.2-shaped vetting
/// model (see the module docs).
#[allow(deprecated)]
pub type Manifest = vta_sdk::protocols::join_requests::manifest::v0_2::Response;

/// The `vtc/join-requests` version: `manifest/0.4` + `submit/0.3`.
///
/// One version, kept as a type because it is saved with a pending request and
/// named on every manifest and submit. `v0_3` and `v0_2`, which a build that
/// still fell back could have saved, read as it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinProtocol {
    /// `manifest/0.4` + `submit/0.3`.
    #[default]
    #[serde(alias = "v0_3", alias = "v0_2")]
    V0_4,
}

impl JoinProtocol {
    /// The manifest request type.
    pub fn manifest_type(self) -> &'static str {
        manifest::Payload::TYPE_URI
    }

    /// The manifest response type.
    pub fn manifest_response_type(self) -> &'static str {
        manifest::Response::TYPE_URI
    }

    /// The submit request type.
    pub fn submit_type(self) -> &'static str {
        submit::Payload::TYPE_URI
    }

    /// The submit response type.
    pub fn submit_response_type(self) -> &'static str {
        submit::Response::TYPE_URI
    }

    /// The version a manifest response of type `typ` is in.
    pub fn from_manifest_response(typ: &str) -> Option<Self> {
        (typ == Self::V0_4.manifest_response_type()).then_some(Self::V0_4)
    }

    /// The version a manifest request of type `typ` is in.
    pub fn from_manifest_request(typ: &str) -> Option<Self> {
        (typ == Self::V0_4.manifest_type()).then_some(Self::V0_4)
    }

    /// Whether `typ` is a submit response.
    pub fn is_submit_response(typ: &str) -> bool {
        typ == Self::V0_4.submit_response_type()
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

/// What the manifest says about one criterion beyond its 0.2 shape.
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

/// The members a 0.2 criterion does not have, removed when a manifest is
/// carried into the 0.2 shape (which refuses unknown members).
const NOT_IN_V0_2_CRITERION: [&str; 3] = ["admission", "credentialIssuers", "invitationRequired"];

/// Read a `manifest/0.4` payload into the 0.2 shape the rest of the client
/// reads, plus what it says per criterion beyond that.
///
/// The payload is checked against its own generated type first, so a malformed
/// manifest is refused rather than half-accepted. It is then carried across:
/// `directoryDisclosure` is read on its own ([`super::disclosure::read`]) and
/// taken out first, then the criterion members 0.2 lacks, and an absent
/// `presentationDefinition` — optional now, required in 0.2 — becomes the empty
/// definition 0.2 means by "nothing to present".
pub fn read_manifest(
    _protocol: JoinProtocol,
    payload: &Value,
) -> Result<(Manifest, Vec<CriterionMeta>), serde_json::Error> {
    // The directory statement is read on its own, so a malformed one is reported as
    // such (`DirectoryStatement::Malformed`) without making the criteria unreadable.
    let mut criteria_only = payload.clone();
    if let Some(members) = criteria_only.as_object_mut() {
        members.remove(super::disclosure::MANIFEST_MEMBER);
    }
    let current: manifest::Response = serde_json::from_value(criteria_only.clone())?;
    let meta = current
        .criteria
        .iter()
        .map(|c| CriterionMeta {
            id: c.id.to_string(),
            // An admission this client does not know reads as review: the one
            // claim it must never make wrongly is that meeting a criterion admits.
            admission: Some(match c.admission {
                manifest::CriterionAdmission::Automatic => Admission::Automatic,
                _ => Admission::Review,
            }),
            invitation_required: c.invitation_required,
        })
        .collect();
    let mut as_v2 = criteria_only;
    if let Some(criteria) = as_v2.get_mut("criteria").and_then(Value::as_array_mut) {
        for criterion in criteria.iter_mut().filter_map(Value::as_object_mut) {
            for member in NOT_IN_V0_2_CRITERION {
                criterion.remove(member);
            }
            criterion
                .entry("presentationDefinition")
                .or_insert_with(|| Value::Object(Default::default()));
        }
    }
    Ok((serde_json::from_value(as_v2)?, meta))
}

#[cfg(test)]
// The tests read the kept 0.2-shaped model ([`Manifest`]); see the module docs.
#[allow(deprecated)]
mod tests {
    use super::*;
    use serde_json::json;

    const DIGEST: &str = "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";

    fn v4_manifest() -> Value {
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

    /// A manifest reads into the 0.2 shape with every criterion intact, and
    /// what it adds is kept beside it.
    #[test]
    fn a_manifest_is_read_into_the_v0_2_shape_with_its_admission() {
        let (manifest, meta) = read_manifest(JoinProtocol::V0_4, &v4_manifest()).unwrap();
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

    /// A manifest missing what it requires is refused, not carried across.
    #[test]
    fn a_malformed_manifest_is_refused() {
        let mut m = v4_manifest();
        m["criteria"][0]
            .as_object_mut()
            .unwrap()
            .remove("admission");
        assert!(read_manifest(JoinProtocol::V0_4, &m).is_err());
    }

    /// The directory statement is read on its own: even a malformed one leaves the
    /// criteria readable, and it does not reach the 0.2 shape.
    #[test]
    fn the_directory_statement_is_read_apart() {
        let mut m = v4_manifest();
        m[super::super::disclosure::MANIFEST_MEMBER] = json!({ "anything": true });
        let (manifest, meta) = read_manifest(JoinProtocol::V0_4, &m).unwrap();
        assert_eq!(manifest.criteria.len(), 2);
        assert_eq!(meta[1].admission, Some(Admission::Review));
    }

    /// The version names the current types, and a version an older build saved
    /// reads as it.
    #[test]
    fn the_version_names_its_types_and_reads_older_saved_values() {
        let p = JoinProtocol::V0_4;
        assert!(p.manifest_type().ends_with("/manifest/0.4"));
        assert!(p.submit_type().ends_with("/submit/0.3"));
        assert_eq!(
            JoinProtocol::from_manifest_response(p.manifest_response_type()),
            Some(p)
        );
        assert_eq!(
            JoinProtocol::from_manifest_request(p.manifest_type()),
            Some(p)
        );
        assert!(JoinProtocol::is_submit_response(p.submit_response_type()));
        assert_eq!(
            JoinProtocol::from_manifest_response(
                "https://trusttasks.org/spec/vtc/join-requests/manifest/0.3#response"
            ),
            None
        );
        for saved in ["v0_4", "v0_3", "v0_2"] {
            assert_eq!(
                serde_json::from_value::<JoinProtocol>(json!(saved)).unwrap(),
                JoinProtocol::V0_4
            );
        }
        assert_eq!(serde_json::to_value(p).unwrap(), json!("v0_4"));
    }
}
