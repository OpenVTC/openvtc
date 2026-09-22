//! The instantiation and the labels (design §13 C1).
//!
//! - ONE deployment label per community, with no epoch in it: `pp`, and so every applicant's
//!   `id`, is fixed for the life of the community.
//! - ONE long-lived helper key `hvk`; it rotates only on compromise.
//! - The epoch is in the CLASS label of the vetter root predicate, `vetter/<period>`. The
//!   helper's AllowList holds the live labels, so one proof may mix epochs.
//! - Tokens use a separate deployment label and key (never `hvk`), with the period in the token
//!   label `token/<period>` or `token/event/<id>`.

use ark_bls12_381::{Bls12_381, G1Projective};
use predicate_credential_system::{
    cred::PS,
    hash::bls12_381::G1Hasher,
    kiprf::DDH,
    pcs::{AllowList, PCS, Predicate},
    serialization::{to_bytes, to_multibase},
};

use crate::ProtoError;

pub type E = Bls12_381;
pub type G1 = G1Projective;
pub type Fr = ark_bls12_381::Fr;
/// `Σ-PS`: the paper's main instantiation, and the base the tokens reuse.
pub type Base = PS<E>;
pub type Tag = DDH<G1, G1Hasher>;
/// The scheme with the default policy: for users, and for deriving `pp`.
pub type Open = PCS<E, Base, Tag>;
/// The scheme as the helper runs it: never with the default policy.
pub type Helper = PCS<E, Base, Tag, AllowList<Fr>>;
/// The helper's verification key, published in the manifest.
pub type Hvk = <Base as predicate_credential_system::cred::CredentialBase>::VerificationKey;

pub fn deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#vetting-pcs").into_bytes()
}

pub fn token_deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#vetting-token").into_bytes()
}

/// The vetter root predicate for one epoch.
pub fn vetter_predicate(period: &str) -> Predicate {
    Predicate::root(format!("vetter/{period}").into_bytes())
}

/// The verify-only applicant predicate: `n` distinct vetters (§13 C4: any `n`, because the VTC
/// never issues under it).
pub fn hidden_vetting_predicate(n: u32) -> Predicate {
    Predicate::new(n, b"hidden-vetting".to_vec())
}

pub fn monthly_token_label(period: &str) -> String {
    format!("token/{period}")
}

pub fn event_token_label(event_id: &str) -> String {
    format!("token/event/{event_id}")
}

/// Multibase text of a group element (identifiers, tags).
pub fn point_text(p: &G1) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(p)?))
}

/// Multibase text of a scalar (serials).
pub fn scalar_text(s: &Fr) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(s)?))
}
