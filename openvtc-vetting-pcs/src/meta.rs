//! The application contexts (design §4.1): what each attestation is bound to, and what the
//! proof is bound to. Both sides encode them with the same code; the VTC rebuilds them from
//! the public data it receives and never takes context bytes from the prover.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vta_sdk::protocols::vetting::{VettingMethod, VettingRelationship};

use crate::ProtoError;

/// The public metadata of one hidden statement: the fields of the V0 `IdentityVetting`
/// endorsement that the VTC counts, minus any identifier of the vetter. Sent beside the
/// attestation; bound into its `ctx_j`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatementMeta {
    pub community: String,
    pub requirements_digest: String,
    pub method: VettingMethod,
    pub claims_verified: Vec<String>,
    pub liveness_confirmed: bool,
    pub declared_relationship: VettingRelationship,
    pub identity_commitment: String,
    pub card_digest_multibase: String,
    /// Day granularity only: an exact time would let the VTC line statements up with vetter
    /// activity (§6).
    pub valid_from: NaiveDate,
    pub valid_until: NaiveDate,
    /// The token spent on this attestation (§5.1 step 3): binds the serial into `ctx_j`, so a
    /// token cannot move to another attestation.
    pub token_label: String,
    pub token_serial: String,
}

impl StatementMeta {
    /// The `app_j` bytes: a domain separator and the JCS (RFC 8785) form of this value, which
    /// is what the vetter binds and what the VTC rebuilds. Canonical, so the two cannot differ
    /// over member order or number formatting.
    pub fn context_bytes(&self) -> Result<Vec<u8>, ProtoError> {
        let mut out = b"openvtc/hidden-vetting/statement/0.1\0".to_vec();
        out.extend(jcs(self)?);
        Ok(out)
    }

    /// A stable identifier for one statement: the digest of its metadata. Two statements of one
    /// vetter differ here and share a tag.
    pub fn digest(&self) -> Result<String, ProtoError> {
        Ok(hex::encode(Sha256::digest(self.context_bytes()?)))
    }
}

/// What the proof `π_0` is bound to (`app_0`): the VTC's single-use challenge and the binding of
/// the applicant's PCS `id` to the persona DID they join with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofContext {
    pub challenge: String,
    pub audience: String,
    pub join_did: String,
    /// Stand-in for the Data Integrity proof by the join persona's key over
    /// `(id, community, requirementsDigest)` (§4.2). The prototype has no DIDs, so it binds the
    /// digest only.
    pub id_binding: String,
}

impl ProofContext {
    pub fn context_bytes(&self) -> Result<Vec<u8>, ProtoError> {
        let mut out = b"openvtc/hidden-vetting/proof/0.1\0".to_vec();
        out.extend(jcs(self)?);
        Ok(out)
    }
}

/// The JCS (RFC 8785) encoding of a value.
fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| ProtoError::Serialization(e.to_string()))
}

/// The digest the join persona would sign (§4.2).
pub fn id_binding(
    id_text: &str,
    community: &str,
    requirements_digest: &str,
    join_did: &str,
) -> String {
    let mut h = Sha256::new();
    for part in [id_text, community, requirements_digest, join_did] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}
