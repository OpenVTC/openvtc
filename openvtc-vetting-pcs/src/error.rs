//! Errors of the prototype. Library errors keep their reason.

use predicate_credential_system::Error as PcsError;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("pcs: {0}")]
    Pcs(#[from] PcsError),
    #[error("member {0} holds no live vetter grant")]
    NotAVetter(String),
    #[error("label {0} is not live")]
    LabelNotLive(String),
    #[error("member {0} is bound to another PCS identifier")]
    IdentifierRebound(String),
    #[error("member {member} already holds a credential under {label}")]
    AlreadyIssued { member: String, label: String },
    #[error("member {member} was already served tokens for tick {tick}")]
    AlreadyServedThisTick { member: String, tick: u32 },
    #[error("asked for {asked} tokens; this community drips {quota} a tick")]
    OverQuota { asked: usize, quota: usize },
    #[error("token opening proof {0} does not verify")]
    BadOpeningProof(usize),
    #[error("vetter is at capacity; next free token from tick {available_from}")]
    AtCapacity { available_from: u32 },
    #[error("no credential under a live vetter label")]
    NoLiveCredential,
    #[error("challenge unknown or already used")]
    BadChallenge,
    #[error("statement count {statements} differs from the proof's {attestations}")]
    CountMismatch {
        statements: usize,
        attestations: usize,
    },
    #[error("the proof does not verify: {0}")]
    ProofRejected(PcsError),
    #[error("received attestation does not verify: {0}")]
    AttestationRejected(String),
    #[error("event mode refused: {0}")]
    EventRefused(String),
    #[error("serialization: {0}")]
    Serialization(String),
}
