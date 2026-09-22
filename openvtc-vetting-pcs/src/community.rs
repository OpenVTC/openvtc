//! A community's PUBLISHED parameters: what a member needs to attest, prove or check, and
//! nothing the community keeps to itself.
//!
//! The applicant and vetter engines work from this rather than from [`crate::vtc::Vtc`],
//! because in a deployment they never hold the community object at all — they hold what the
//! manifest published (`vetting.ext`, design §8). The community's own copy is
//! [`Vtc::params`](crate::vtc::Vtc::params), so the tests drive the same code path a client
//! does.

use predicate_credential_system::{
    pcs::{Predicate, PredicateCredentialSystem, SetupParams},
    serialization::{from_bytes, from_multibase},
};

use crate::{
    ProtoError,
    scheme::{Fr, Hvk, Open, deployment_label},
    token::{TokenSpend, TokenVerifier},
};

/// The published half of a community's hidden-vetting deployment.
pub struct CommunityParams {
    community: String,
    open: Open,
    hvk: Hvk,
    tokens: TokenVerifier,
    /// Live vetter class labels, current first, exactly as published (`vetter/2026-10`).
    vetter_labels: Vec<String>,
}

impl CommunityParams {
    /// From what a manifest carries: the two verification keys as multibase, and the live
    /// labels.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if a key cannot be decoded, or the deployment parameters
    /// cannot be derived.
    pub fn published(
        community: &str,
        hvk: &str,
        tvk: &str,
        vetter_labels: Vec<String>,
        token_labels: Vec<String>,
    ) -> Result<Self, ProtoError> {
        let hvk: Hvk = from_bytes(&from_multibase(hvk)?)?;
        let tvk = from_bytes(&from_multibase(tvk)?)?;
        Self::new(community, hvk, tvk, vetter_labels, token_labels)
    }

    /// From values already decoded.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be derived from the label.
    pub fn new(
        community: &str,
        hvk: Hvk,
        tvk: <crate::scheme::Base as predicate_credential_system::cred::CredentialBase>::VerificationKey,
        vetter_labels: Vec<String>,
        token_labels: Vec<String>,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            community: community.to_string(),
            open: Open::setup(SetupParams::new(deployment_label(community)))?,
            hvk,
            tokens: TokenVerifier::new(community, tvk, token_labels)?,
            vetter_labels,
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn open(&self) -> &Open {
        &self.open
    }
    pub fn hvk(&self) -> &Hvk {
        &self.hvk
    }
    pub fn tokens(&self) -> &TokenVerifier {
        &self.tokens
    }
    /// Live vetter labels, current first.
    pub fn vetter_labels(&self) -> &[String] {
        &self.vetter_labels
    }

    /// The root predicate of a published vetter label.
    pub fn vetter_predicate(label: &str) -> Predicate {
        Predicate::root(label.as_bytes().to_vec())
    }

    /// `φ` of every live vetter label: what a client checks an attestation's class against.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if a label cannot be encoded.
    pub fn live_phis(&self) -> Result<Vec<Fr>, ProtoError> {
        self.vetter_labels
            .iter()
            .map(|l| Ok(self.open.enc_pred(&Self::vetter_predicate(l))?))
            .collect()
    }

    /// Whether a token verifies under the published token key and a live label.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the label's `φ` cannot be derived.
    pub fn token_ok(&self, spend: &TokenSpend) -> Result<bool, ProtoError> {
        self.tokens.signature_ok(spend)
    }
}
