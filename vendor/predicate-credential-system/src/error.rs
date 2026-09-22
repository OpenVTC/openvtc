//! The crate-wide error type.
//!
//! The paper writes `⊥` for every failing algorithm. In this crate `⊥` is `Err(Error::..)` for
//! algorithms that produce a value (and `None` for [`KIPRF::eval`](crate::kiprf::KIPRF::eval)),
//! while verifiers return `bool` and never panic on adversarial input. The variants below name
//! the individual `⊥` cases so that callers and tests can tell them apart.

use ark_ec::hashing::HashToCurveError;
use ark_serialize::SerializationError;

/// Every way an algorithm of this crate can output `⊥`.
///
/// The type is `Clone + PartialEq + Eq` so that tests can assert on the exact failure; foreign
/// errors (serialization, hash-to-curve) are therefore carried as their display string.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // ----- sigma layer ---------------------------------------------------------------------
    /// The prover was asked to prove a statement its witness does not satisfy
    /// (`(x, w) ∉ R`; Def. "Sigma protocol" only defines the honest prover on `(x, w) ∈ R`).
    #[error("the witness does not satisfy the relation")]
    WitnessDoesNotSatisfyRelation,
    /// An equation refers to a witness coordinate that was never allocated in this relation.
    #[error("equation references scalar variable #{index}, but only {allocated} are allocated")]
    UnallocatedVariable {
        /// Index of the offending variable.
        index: usize,
        /// Number of variables allocated in the relation.
        allocated: usize,
    },
    /// A vector (witness, responses, message, generators, ...) has the wrong length.
    #[error("length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// The length required by the statement.
        expected: usize,
        /// The length that was supplied.
        actual: usize,
    },

    // ----- KI-PRF --------------------------------------------------------------------------
    /// `TagEval(K, s) = ⊥`: the tag is undefined at this point (Def. "Non-adaptive
    /// key-injective pseudorandom function", partial-domain case; e.g. `K + s = 0` for
    /// `Tag_DY`).
    #[error("the tag function is undefined at this point")]
    UndefinedTag,
    /// `ValidTag(T, s) = 0` (Def. "Sigma-friendly non-adaptive key-injective PRF"), e.g.
    /// `T = 1`.
    #[error("inadmissible tag encoding")]
    InvalidTag,

    // ----- credential base -----------------------------------------------------------------
    /// A key is outside its key space (e.g. a zero component where the paper samples from
    /// `Z_p^*`), or is degenerate in a way that would make a relation vacuous (e.g. `Ỹ_1 = 1`
    /// for `Σ-PS`; see `CredentialBase::is_well_formed_key`).
    #[error("invalid key")]
    InvalidKey,
    /// A message is outside the signing-message space `M_Σ` (e.g. an identity component of an
    /// SPS-EQ message vector).
    #[error("message outside the message space")]
    InvalidMessage,
    /// A credential does not verify, or is malformed.
    #[error("invalid credential")]
    InvalidCredential,
    /// A blinded pre-credential is malformed or does not unblind to a valid credential.
    #[error("invalid pre-credential")]
    InvalidPreCredential,
    /// An issuance encoding `C` is malformed or inadmissible.
    #[error("invalid issuance encoding")]
    InvalidIssuanceEncoding,

    // ----- PCS layer -----------------------------------------------------------------------
    /// A Fiat-Shamir proof (`π_0`, or a stand-alone proof) does not verify.
    #[error("invalid proof")]
    InvalidProof,
    /// An attestation `att_j` does not verify (`VerifyAtt = 0`).
    #[error("invalid attestation")]
    InvalidAttestation,
    /// The number of attestations differs from the threshold `k` of the predicate `f_k`.
    #[error("wrong number of attestations: the predicate requires {expected}, got {actual}")]
    WrongAttestationCount {
        /// The threshold `k`.
        expected: usize,
        /// The number of attestations supplied.
        actual: usize,
    },
    /// Two attestations carry the same tag (`CheckAtts_P`: `|{T_j}| ≠ k`).
    #[error("two attestations carry the same tag")]
    DuplicateAttester,
    /// The requester's own tag occurs among the attestation tags (`CheckAtts_P`: `T_0 ∈ {T_j}`).
    #[error("self-attestation: the requester's tag occurs among the attestation tags")]
    SelfAttestation,
    /// The public attribute policy `P` rejects the disclosed predicate labels.
    #[error("the attribute policy rejects the disclosed predicate labels")]
    PolicyRejected,
    /// `id ≠ Tag(usk, c_0)`: the identifier does not belong to the user key it is used with, so
    /// `(id, usk) ∉ supp(UKeyGen(pp))`, which membership in `R_PCS` requires (Def. "PCS
    /// authorization relation").
    #[error("the identifier does not belong to the user key")]
    IdentifierMismatch,
    /// The issuance state does not belong to the `(usk, f)` it is used with (`Unblind`, step 2).
    #[error("the issuance state does not match the user key and predicate")]
    IssuanceStateMismatch,
    /// The credential base needs `id = g_1^usk` but the tag parameters do not provide it: `Σ-EQ`
    /// with `Tag_DY`, or with a `Tag_DDH` instance whose point `htag(c_0) = g_1` is not
    /// programmed (proof sketch of the Lemma on `Σ-EQ`, §3.2.3).
    #[error("the credential base is incompatible with the tag instantiation")]
    IncompatibleBaseAndTag,
    /// A threshold-0 predicate on the ordinary `Prove → VerifyProof → Issue` path: it would hand
    /// out credentials without any endorser. Threshold 0 is reserved for root predicates, which
    /// have an explicitly named path of their own.
    #[error("threshold 0 is not a valid predicate")]
    ZeroThreshold,
    /// The root path (Remark "Chaining and the base case") was given a predicate with a
    /// non-zero threshold; a root predicate `f_root` has threshold 0.
    #[error("the root path requires a root predicate (threshold 0)")]
    NotARootPredicate,
    /// Received public parameters are not the output of the transparent `Setup` for their own
    /// deployment label.
    #[error("public parameters are not an output of Setup: {0}")]
    InvalidPublicParameters(&'static str),

    // ----- encoding / hashing --------------------------------------------------------------
    /// An object handed to an algorithm contains a value that is NOT an element of the group its
    /// type stands for: a point that is not on the curve, or not in the prime-order subgroup
    /// (`ark_serialize::Valid::check` fails). The payload names the offending argument.
    ///
    /// Implementation note. In the paper every `T_j`, `T_0`, `C`, `cred*`, `hvk`, ... is a group
    /// element by definition. In code a value of type `E::G1` is only ASSUMED to be one:
    /// validated decoding ([`crate::serialization::from_bytes`], the compact decoders) guarantees
    /// it, but a value that was decoded without validation, from an uncompressed encoding, or assembled
    /// by hand need not be. The algorithms of [`crate::pcs`] therefore re-validate what they
    /// receive from another party and do not depend on how it was built. This is load-bearing:
    /// pairing checks are blind to a component of small order in a `G_1` argument, and a Schnorr
    /// clause whose target carries a component of order 3 (the cofactor of BLS12-381 `G_1` is
    /// divisible by 3) is forgeable with probability 1/3 per attempt, which would let ONE
    /// attester pass for several and a requester endorse itself.
    #[error("not an element of its prime-order group (curve or subgroup check failed): {0}")]
    InvalidGroupElement(&'static str),
    /// A value the paper requires to be non-degenerate is the identity / zero
    /// ("verification must re-impose what the algebra drops").
    #[error("degenerate input: {0}")]
    DegenerateInput(&'static str),
    /// Canonical (de)serialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Bytes were left over after deserializing a value (non-canonical wire encoding).
    #[error("trailing bytes after the encoded value")]
    TrailingBytes,
    /// Hashing to the curve failed.
    #[error("hash-to-curve error: {0}")]
    HashToCurve(String),
}

impl From<SerializationError> for Error {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<HashToCurveError> for Error {
    fn from(e: HashToCurveError) -> Self {
        Self::HashToCurve(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_errors_convert() {
        let e: Error = SerializationError::InvalidData.into();
        assert!(matches!(e, Error::Serialization(_)));
        let e: Error = HashToCurveError::MapToCurveError("no point".into()).into();
        assert_eq!(e, Error::HashToCurve("no point".into()));
    }

    #[test]
    fn display_is_informative() {
        let e = Error::LengthMismatch {
            expected: 3,
            actual: 2,
        };
        assert_eq!(e.to_string(), "length mismatch: expected 3, got 2");
    }
}
