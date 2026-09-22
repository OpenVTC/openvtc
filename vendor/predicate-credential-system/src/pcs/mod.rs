//! Predicate credential systems: the syntax of Def. "Predicate credential system" (paper §4) and
//! the modular threshold construction of §5.1 (protocol box "Modular threshold predicate
//! credential construction").
//!
//! | paper | here |
//! |---|---|
//! | Def. "Predicate credential system": the ten algorithms | the trait [`PredicateCredentialSystem`] |
//! | the protocol box of §5.1, generic over base and tag | [`PCS`] ([`construction`]), which implements the trait |
//! | the predicate family `{f_k}`, `EncPred`, the attribute policy `P` | [`Predicate`], [`enc_pred`], [`AttributePolicy`] ([`predicate`]) |
//! | `pp`, `hsk`, `usk`, `cred`, `att_j`, `π`, `st_iss` | [`types`] |
//! | `ctx_j`, `ctx_0` | [`context`] |
//! | "parse `π` in a fixed format" (§5.5); the sizes of the comparison table (§5.3) | [`codec`] |
//! | "compatible" parameters of `Setup` step 1 | [`check_compatibility`], [`check_dv_compatibility`] |
//!
//! [`PCS`] covers the publicly verifiable bases `Σ-PS`, `Σ-BBS` and `Σ-EQ`. "The displayed
//! `Σ-MAC` candidate does not instantiate this box as written: using it requires a
//! designated-verifier PCS variant in which its verification key remains in `hsk` and the helper
//! runs the keyed attestation and issuance-proof verifiers" (§5.1). That variant is NOT
//! implemented yet; it will live in a submodule `pcs::dv` next to [`construction`], built on
//! [`SigmaFriendlyDVCredentialBase`] and [`check_dv_compatibility`] and bound by the last rule
//! below.
//!
//! # Rules the construction has to keep
//!
//! Implementation notes. None of them is a statement of the paper; each records a decision
//! taken while the building blocks were hardened, in the place where the construction is
//! written.
//!
//! * **Restart loops run behind the compatibility check.** `UKeyGen` of the box restarts while a
//!   tag evaluation is `⊥`. Under degenerate tag parameters every evaluation is `⊥`, so the loop
//!   runs only under an instance for which [`check_compatibility`] (or
//!   [`check_dv_compatibility`]) returned `Ok`; both refuse an instance that fails
//!   [`PCSTag::is_well_formed`] with [`Error::DegenerateInput`]. That covers `Setup` and every
//!   place where a `pp` is accepted from outside.
//! * **The contexts bind the deployment label.** `ctx_j` and `ctx_0` of the box start with `pp`,
//!   and `pp = (pp_Σ, pp_Tag, EncPred, H_0, H_1, c_0)` contains the oracles. In code the oracles
//!   are fixed functions of a deployment label ([`crate::hash`]), so the digest of `pp` that
//!   enters the contexts has to cover the label itself next to `pp_Σ`, `pp_Tag` and `c_0`. The
//!   algebraic parameters alone do not determine it: `pp_Σ` is empty for `Σ-PS` and `Σ-EQ`, and
//!   `pp_Tag` of `Tag_DY` is the same generator in every deployment.
//! * **`Unblind` fails closed, once, for every base.** The `Unblind` algorithms of the bases
//!   follow their boxes: they remove the blinding and do NOT verify the result
//!   ([`CredentialBase::unblind`](crate::cred::CredentialBase::unblind)). The
//!   construction's `Unblind` therefore runs `VerifyCred` on the credential it is about to
//!   return and outputs `⊥` ([`Error::InvalidPreCredential`]) if that fails, so that a wrong
//!   answer of the helper is noticed at issuance and not at the first `Attest`. The box returns
//!   `cred` unverified; honest executions are unaffected, and the syntax has room for it
//!   (`Unblind → cred / ⊥`; the box of the out-of-scope `Σ-vSIS` base verifies inside its own
//!   `Unblind`). The check presupposes a well-formed
//!   `hvk` ([`CredentialBase::is_well_formed_key`](crate::cred::CredentialBase::is_well_formed_key)).
//!   The designated-verifier variant cannot do this: a user has no `dvk` and "cannot verify a
//!   credential alone" (after Def. "Designated-verifier credential base").
//! * **Verifiers do not depend on how their inputs were built.** The paper's `T_j`, `T_0`, `C`,
//!   `cred*`, `hvk`, ... are group elements by definition; a value of type `E::G1` is one only
//!   if its producer made sure. Attestations, issuance proofs and root requests have public
//!   fields and can be decoded without validation, so every algorithm of the construction that
//!   consumes an object of another party re-validates it first (curve and prime-order subgroup
//!   of EVERY group element, `ark_serialize::Valid::check`) and outputs `⊥`
//!   ([`Error::InvalidGroupElement`]) otherwise. Without this, a tag shifted by a point of
//!   order 3 is a "distinct" tag whose Schnorr clause verifies after three attempts on average,
//!   and the two checks Theorem "Predicate soundness" rests on (pairwise-distinct attesters,
//!   no self-attestation) can be passed by ONE key ([`construction`], "Received objects are
//!   re-validated"). The designated-verifier variant has to keep the same rule.
//! * **A helper key belongs to one deployment.** `hsk` records the digest of its `pp`, and
//!   `Issue` and the root path refuse it under another one ([`HelperSecretKey`]): credentials
//!   are signatures under `hvk`, and nothing else in a credential of `Σ-PS` or `Σ-EQ` names the
//!   deployment.
//! * **The keyed attestation relation never leaves the helper.** In the designated-verifier
//!   variant the verifier's side of `R_att` contains what
//!   [`possession_clauses_verifier`](SigmaFriendlyDVCredentialBase::possession_clauses_verifier)
//!   derives from `dvk` and from attacker-chosen input; for `Σ-MAC` three such targets give a
//!   universal forgery (module docs of [`crate::cred::mac`]). The keyed relation is
//!   built inside the attestation verifier, handed to the Fiat-Shamir verifier and dropped
//!   there. There is no public builder for it outside `cfg(any(test, feature = "test-utils"))`,
//!   unlike for the relations of the publicly verifiable bases, and no error value or log line
//!   carries one of its group elements: one bit leaves the verifier.

pub mod codec;
pub mod construction;
pub mod context;
pub mod predicate;
#[cfg(test)]
pub(crate) mod test_support;
pub mod types;

use core::fmt::Debug;

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub use self::{
    construction::{MAX_KEYGEN_ATTEMPTS, PCS},
    predicate::{AcceptAll, AllowList, AttributePolicy, Predicate, enc_pred},
    types::{
        Attestation, Credential, HelperSecretKey, IssuanceProof, IssuanceState, PublicParameters,
        RootRequest, SetupParams, UserSecretKey,
    },
};
use crate::{
    cred::{SigmaFriendlyCredentialBase, SigmaFriendlyDVCredentialBase},
    error::Error,
    kiprf::PCSTag,
};

/// "Generate compatible algebraic parameters `pp_Σ` and `pp_Tag`" (construction box, `Setup`
/// step 1), as a check on a tag INSTANCE: a base whose issuance needs `id = g_1^usk`
/// ([`SigmaFriendlyCredentialBase::REQUIRES_DLOG_IDENTITY`], i.e. `Σ-EQ`) is compatible only
/// with parameters under which `Tag(K, c_0) = g_1^K` (proof sketch of the Lemma on `Σ-EQ`,
/// §3.2.3: "compatible with `Tag_DDH` under `htag(c_0) = g_1`, not with `Tag_DY`").
///
/// The type-level constant [`PCSTag::IDENTITY_IS_DLOG`] is only a necessary condition: it
/// vouches for instances built by [`PCSTag::setup`], not for a `Tag_DDH` without the programmed
/// point or with another one, which is what a `pp` assembled from parts or decoded from the
/// wire may contain. Run this check in `Setup` AND wherever a `pp` is accepted from outside.
/// (Implementation note: under an incompatible instance the helper of `Σ-EQ` would sign
/// `(g_1, id, g_1^φ)` with `id = Tag(usk, c_0) ≠ g_1^usk`, which is not the holder's message
/// `Enc_Σ(usk, φ) = (g_1, g_1^usk, g_1^φ)`: honest users would end up without a usable
/// credential, and nothing would say why.)
///
/// # Degenerate tag parameters
///
/// Implementation note, not part of the paper's `Setup`, whose `pp_Tag` is always freshly
/// generated. Before anything else the check asks [`PCSTag::is_well_formed`] and refuses a
/// degenerate instance, whatever the base is. Under such an instance (a `Tag_DY` whose
/// generator is the identity, which only decoding WITHOUT validation produces) `TagEval` is `⊥`
/// at every point, so the `UKeyGen` loop of the construction box ("if `id = ⊥`, restart") would
/// never terminate. The rule for every caller, in this crate and outside it: a loop that
/// restarts on `⊥` runs only under a tag instance that has passed this check.
///
/// # Errors
/// [`Error::DegenerateInput`]`("pp_Tag")` for a degenerate tag instance;
/// [`Error::IncompatibleBaseAndTag`] for a well-formed one that the base cannot be combined
/// with.
pub fn check_compatibility<E, B, T>(tag: &T, c0: &E::ScalarField) -> Result<(), Error>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    compatible::<E::G1, T>(B::REQUIRES_DLOG_IDENTITY, tag, c0)
}

/// [`check_compatibility`] for a designated-verifier base over the group `G`, including its
/// refusal of degenerate tag parameters.
///
/// # Errors
/// [`Error::DegenerateInput`]`("pp_Tag")` for a degenerate tag instance;
/// [`Error::IncompatibleBaseAndTag`] for a well-formed one that the base cannot be combined
/// with.
pub fn check_dv_compatibility<G, B, T>(tag: &T, c0: &G::ScalarField) -> Result<(), Error>
where
    G: PrimeGroup,
    B: SigmaFriendlyDVCredentialBase<G>,
    T: PCSTag<G>,
{
    compatible::<G, T>(B::REQUIRES_DLOG_IDENTITY, tag, c0)
}

fn compatible<G: PrimeGroup, T: PCSTag<G>>(
    requires_dlog_identity: bool,
    tag: &T,
    c0: &G::ScalarField,
) -> Result<(), Error> {
    // First: a degenerate instance is no `pp_Tag` at all, for any base. This is what keeps every
    // restart loop behind this check from spinning forever on decoded parameters.
    if !tag.is_well_formed() {
        return Err(Error::DegenerateInput("pp_Tag"));
    }
    if requires_dlog_identity && !(T::IDENTITY_IS_DLOG && tag.identity_is_dlog(c0)) {
        return Err(Error::IncompatibleBaseAndTag);
    }
    Ok(())
}

/// A predicate credential system
/// `PCS = (Setup, HKeyGen, UKeyGen, Attest, VerifyAtt, Prove, Issue, Unblind, VerifyCred, VerifyProof)`
/// for a predicate family `F` and an authorization relation `R_PCS` (Def. "Predicate credential
/// system"), run by a helper and by users, where a user holding a credential may also act as an
/// attester.
///
/// The value implementing the trait *is* the public parameters `pp`: the paper assumes that
/// "`pp` is given implicitly to all algorithms", here it is `&self`. "The formats of identities,
/// credentials, attestations, proofs, and local state are left abstract": they are the
/// associated types. `⊥` is `Err(_)`; the three verifiers return `bool`, are deterministic,
/// never panic on adversarial input, and (implementation note) make no assumption about how
/// their inputs were built: an implementation re-validates what it receives (module docs,
/// "Rules the construction has to keep").
///
/// The paper asks for correctness (Def. "Correctness"), proof-gated issuance (Def. "Proof-gated
/// issuance": [`Self::issue`] outputs `⊥` whenever [`Self::verify_proof`] rejects), knowledge
/// soundness, credential unforgeability, attester anonymity and subject privacy.
///
/// # Encodings and the paper's sizes
///
/// Implementation note. Attestations and issuance proofs are canonically (de)serializable like
/// every public protocol object. A *derived* encoding is self-describing: each
/// [`FSProof`](crate::sigma::FSProof) carries an 8-byte length prefix for its responses and a
/// vector of `k` attestations another one, so at `k = 5` it is `8(k + 1) + 8 = 56` bytes longer
/// than the `|π|` of the paper's comparison table (§5.3), which counts group elements and scalars
/// only. The table's sizes are those of the fixed format of `VerifyProof` step 3 ("reject
/// malformed input"): the number of responses is a constant of the base
/// ([`SigmaFriendlyCredentialBase::POSSESSION_VARIABLES`],
/// [`SigmaFriendlyCredentialBase::ISSUANCE_VARIABLES`];
/// [`FSProof::serialize_compact`](crate::sigma::FSProof::serialize_compact)) and the number of
/// attestations is the threshold of the predicate `f_k`, which the verifier knows. An
/// implementation that wants the table's sizes writes that format (by hand for
/// [`Self::Attestation`], whose length is static, and with a decoder that takes `f_k` for
/// [`Self::IssuanceProof`]) and says which of the two encodings a size test measures. For
/// [`PCS`] that format is [`codec`]: `to_compact_bytes` / `from_compact_bytes`.
pub trait PredicateCredentialSystem: Sized {
    /// Deployment-specific inputs of `Setup`. The security parameter `1^λ` of the paper is fixed
    /// by the choice of groups (a type parameter of the implementation); what remains is, e.g.,
    /// a deployment label and the public attribute policy.
    type SetupParams;
    /// A predicate `f ∈ F`.
    type Predicate;
    /// The helper's verification key `hvk`.
    type HelperVerificationKey: Clone
        + Debug
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize;
    /// The helper's secret key `hsk`. Secret.
    type HelperSecretKey: Zeroize;
    /// A public identity `id`.
    type Identity: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// A user secret key `usk`. Secret.
    type UserSecretKey: Zeroize;
    /// A credential `cred`, bound to a user key and a predicate. Private to its holder.
    type Credential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// An attestation `att_j` for an identifier.
    type Attestation: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The authorization material `w` of the relation `R_PCS` (for the threshold construction a
    /// slice of attestations, hence `?Sized`).
    type Witness: ?Sized;
    /// An issuance proof `π`.
    type IssuanceProof: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The private local state `st_iss` that `Prove` hands to `Unblind`. Secret.
    type IssuanceState: Zeroize;
    /// A pre-credential `ĉred`.
    type PreCredential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;

    /// `Setup(1^λ) → pp`.
    ///
    /// Implementation note: Def. "Predicate credential system" calls `Setup` randomized; it
    /// takes no RNG here because the classical construction derives every parameter by hashing
    /// the deployment label (transparent setup, nothing to sample). An instantiation that needs
    /// coins receives them through [`Self::SetupParams`].
    ///
    /// # Errors
    /// If the building blocks are incompatible ([`check_compatibility`]) or their parameters
    /// cannot be generated.
    fn setup(params: Self::SetupParams) -> Result<Self, Error>;

    /// `HKeyGen(pp) → (hvk, hsk)`, run by the helper.
    fn helper_keygen<R: RngCore + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (Self::HelperVerificationKey, Self::HelperSecretKey);

    /// `UKeyGen(pp) → (id, usk)`, run by a user.
    ///
    /// # Errors
    /// Implementation note: the paper's `UKeyGen` has no `⊥` output (it restarts until `id` and
    /// `T_0` are defined). The `Err` case carries failures of the implementation only: the tag
    /// point `s = H_0(id)` of the restart test hashes the canonical encoding of `id`
    /// ([`h0_id`](crate::hash::h0_id), fallible because serializers are), and a loop that
    /// swallowed a persistent error would never terminate. It does not occur for the group
    /// elements of this crate.
    ///
    /// The restart loop itself terminates only under well-formed tag parameters: it runs behind
    /// [`check_compatibility`], which refuses a degenerate `pp_Tag` (module docs, "Rules the
    /// construction has to keep").
    fn user_keygen<R: RngCore + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Identity, Self::UserSecretKey), Error>;

    /// `Attest(hvk, usk_j, f_j, cred_j, id) → att_j / ⊥`, run by a user holding a credential
    /// `cred_j` bound to `(usk_j, f_j)`: an attestation for the identifier `id`.
    ///
    /// # Errors
    /// Where the paper outputs `⊥`.
    fn attest<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &Self::HelperVerificationKey,
        usk: &Self::UserSecretKey,
        f: &Self::Predicate,
        cred: &Self::Credential,
        id: &Self::Identity,
        rng: &mut R,
    ) -> Result<Self::Attestation, Error>;

    /// `VerifyAtt(hvk, id, att_j) → {0, 1}`: whether `att_j` is a valid attestation for `id`.
    fn verify_attestation(
        &self,
        hvk: &Self::HelperVerificationKey,
        id: &Self::Identity,
        att: &Self::Attestation,
    ) -> bool;

    /// `Prove(hvk, f, id, usk, w) → (π, st_iss) / ⊥`, run by a user on a witness with
    /// `((hvk, f, id), (usk, w)) ∈ R_PCS`.
    ///
    /// # Errors
    /// Where the paper outputs `⊥`, in particular when the witness does not satisfy the
    /// authorization relation.
    fn prove<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &Self::HelperVerificationKey,
        f: &Self::Predicate,
        id: &Self::Identity,
        usk: &Self::UserSecretKey,
        w: &Self::Witness,
        rng: &mut R,
    ) -> Result<(Self::IssuanceProof, Self::IssuanceState), Error>;

    /// `Issue(hvk, hsk, f, id, π) → ĉred / ⊥`, run by the helper. Proof-gated: outputs `⊥`
    /// whenever `VerifyProof(hvk, f, id, π) = 0`.
    ///
    /// # Errors
    /// Where the paper outputs `⊥`.
    fn issue<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &Self::HelperVerificationKey,
        hsk: &Self::HelperSecretKey,
        f: &Self::Predicate,
        id: &Self::Identity,
        proof: &Self::IssuanceProof,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error>;

    /// `Unblind(hvk, usk, f, ĉred, st_iss) → cred / ⊥`, run by the user. Deterministic.
    ///
    /// # Errors
    /// Where the paper outputs `⊥`, in particular when `st_iss` does not belong to `(usk, f)`.
    /// Implementation note: a publicly verifiable construction also fails closed, i.e. it
    /// returns [`Error::InvalidPreCredential`] when the unblinded credential does not pass
    /// [`Self::verify_cred`] (module docs, "Rules the construction has to keep"); the box
    /// returns the credential unverified.
    fn unblind(
        &self,
        hvk: &Self::HelperVerificationKey,
        usk: &Self::UserSecretKey,
        f: &Self::Predicate,
        pre: &Self::PreCredential,
        state: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error>;

    /// `VerifyCred(hvk, usk, f, cred) → {0, 1}`: whether `cred` is a helper credential bound to
    /// the user key `usk` and the predicate `f`.
    fn verify_cred(
        &self,
        hvk: &Self::HelperVerificationKey,
        usk: &Self::UserSecretKey,
        f: &Self::Predicate,
        cred: &Self::Credential,
    ) -> bool;

    /// `VerifyProof(hvk, f, id, π) → {0, 1}`: verifies an issuance proof for the statement
    /// `(hvk, f, id)`.
    fn verify_proof(
        &self,
        hvk: &Self::HelperVerificationKey,
        f: &Self::Predicate,
        id: &Self::Identity,
        proof: &Self::IssuanceProof,
    ) -> bool;
}
