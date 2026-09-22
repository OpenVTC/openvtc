//! Non-adaptive key-injective pseudorandom functions, the *tags* of the construction (paper
//! §3.1, Defs. "Non-adaptive key-injective pseudorandom function" and "Sigma-friendly
//! non-adaptive key-injective PRF").
//!
//! Every public value of a user is a tag evaluation under its secret key `usk`: the identifier
//! is `id = Tag(usk, c_0)`, an attestation for `id` carries `T_j = Tag(usk_j, H_0(id))`, and an
//! issuance proof carries the self-exclusion tag `T_0 = Tag(usk, H_0(id))` (§5.1, "Overview").
//!
//! ```math
//! id = \mathsf{Tag}(usk, c_0), \qquad T_j = \mathsf{Tag}\bigl(usk_j, H_0(id)\bigr), \qquad T_0 = \mathsf{Tag}\bigl(usk, H_0(id)\bigr)
//! ```
//!
//! This module holds the trait definitions and the stand-alone proof of `R_Tag`
//! ([`prove_tag`], [`verify_tag`]). The instantiations of the paper are
//!
//! * [`DDH`] = `Tag_DDH` (§3.1.1): key space `Z_p \ {0}`, `Tag(K, s) = htag(s)^K`,
//!   `ValidTag = [T ≠ 1]`, clause `T = htag(s)^K` (base `htag(s)`, target `T`); with the
//!   programmed point `htag(c_0) = g_1` of Remark "Identity point" the identifier is
//!   `id = g_1^usk`.
//! * [`DY`] = `Tag_DY` (§3.1.2): key space `Z_p`, `Tag(K, s) = g_1^{1/(K+s)}`, `⊥` iff
//!   `K + s = 0`, `ValidTag = [T ≠ 1]`, clause `T^K = g_1 T^{-s}` (base `T`, target
//!   `g_1 − s·T`).

pub mod ddh;
pub mod dy;

use core::fmt::Debug;

use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub use self::{ddh::DDH, dy::DY};
use crate::{
    error::Error,
    hash::Transcript,
    sigma::{FSProof, GroupRelation, LinearEquation, ScalarVar, Witness, fiat_shamir},
};

/// The scalar field of the group a sigma-friendly tag lives in; its key and input space.
pub type Scalar<T> = <<T as SigmaFriendlyKIPRF>::Group as PrimeGroup>::ScalarField;

/// A non-adaptive key-injective PRF `(TagKeyGen, TagEval)` with key space `K`, domain `X` and
/// range `Y` (Def. "Non-adaptive key-injective pseudorandom function").
///
/// The paper requires (i) *key injectivity*: `Tag(K, s) ≠ Tag(K', s)` for distinct keys at every
/// point where both are defined, and (ii) *non-adaptive pseudorandomness* at points fixed
/// independently of the key. An instance (`&self`) carries the public parameters of the
/// function (generators, the hash-to-group oracle, programmed points).
pub trait KIPRF {
    /// The key space `K`. A key is secret: hold it in a container that wipes it on drop.
    type Key: Zeroize;
    /// The domain `X` of evaluation points.
    type Input;
    /// The range `Y`.
    type Output: PartialEq;

    /// `TagKeyGen(1^λ) → K`.
    fn keygen<R: RngCore + CryptoRng + ?Sized>(&self, rng: &mut R) -> Self::Key;

    /// `TagEval(K, s) → y / ⊥`, written `Tag(K, s)`. Deterministic. `None` is `⊥`: the point
    /// lies outside the key-dependent domain `X_K` of a partial-domain instantiation.
    ///
    /// Implementation note: a key outside the key space (e.g. `0` for `Tag_DDH`, whose key
    /// space is `Z_p \ {0}`) must also evaluate to `None`; its "tag" would be the identity.
    fn eval(&self, key: &Self::Key, input: &Self::Input) -> Option<Self::Output>;
}

/// A KI-PRF whose relation
/// `R_Tag = { ((T, s), K) : T = Tag(K, s) ∧ ValidTag(T, s) = 1 }`
/// has a witness-preserving AND-composable sigma protocol (Def. "Sigma-friendly non-adaptive
/// key-injective PRF").
///
/// Here this means: keys and points are scalars of a prime-order group, tags are group
/// elements, and `T = Tag(K, s)` is equivalent (given `ValidTag`) to linear equations in the
/// single witness `K`, which the proof layer composes with other clauses sharing `K = usk`.
pub trait SigmaFriendlyKIPRF:
    KIPRF<Key = Scalar<Self>, Input = Scalar<Self>, Output = <Self as SigmaFriendlyKIPRF>::Group>
{
    /// The prime-order group of the tags; `G_1` in the pairing-based construction.
    type Group: PrimeGroup;

    /// The public validity predicate `ValidTag(T, s)`: accepts every honestly generated, defined
    /// tag and rejects every encoding that would make `R_Tag` vacuous (`T = 1` for both
    /// instantiations of the paper). The verifier evaluates it as a public pre-check; the sigma
    /// protocol does not enforce it.
    fn valid_tag(&self, tag: &Self::Group, input: &Scalar<Self>) -> bool;

    /// The linear clauses of `R_Tag` for the public statement `(tag, input)`, with the key as
    /// the witness variable `key` (shared with every other clause that uses the same variable).
    ///
    /// For every `(tag, input)` with `valid_tag(tag, input)`, a scalar `K` satisfies the
    /// returned equations if and only if `tag = Tag(K, input)`.
    fn tag_equations(
        &self,
        key: ScalarVar,
        tag: &Self::Group,
        input: &Scalar<Self>,
    ) -> Vec<LinearEquation<Self::Group>>;
}

/// The glue the credential system needs from a tag over the group `G` (`G = E::G1` for the
/// pairing-based construction of §5.1, the MAC group for its designated-verifier variant).
///
/// The tag instance is part of the public parameters `pp = (pp_Σ, pp_Tag, EncPred, H_0, H_1,
/// c_0)` (construction box, `Setup`), hence the serialization bounds.
pub trait PCSTag<G: PrimeGroup>:
    SigmaFriendlyKIPRF<Group = G>
    + Clone
    + Debug
    + PartialEq
    + Eq
    + CanonicalSerialize
    + CanonicalDeserialize
{
    /// `true` iff every instance built by [`Self::setup`] makes the identifier a plain discrete
    /// logarithm, `Tag(K, c_0) = g^K` for the standard generator `g` of `G`. Holds for `Tag_DDH`
    /// with the programmed point `htag(c_0) = g_1` (Remark "Identity point"), not for `Tag_DY`.
    /// `Σ-EQ` requires it: its helper builds the signed vector `(g_1, id, g_1^φ)` from the
    /// public `id`.
    ///
    /// This is a promise about the TYPE and about `setup`. It says nothing about an instance
    /// obtained in another way (a constructor that programs no point or another point, a `pp`
    /// decoded from the wire): for those, ask [`Self::identity_is_dlog`].
    const IDENTITY_IS_DLOG: bool;

    /// `pp_Tag` for the deployment label `domain` and the identity point `c_0` (construction
    /// box, `Setup` steps 1 and 4: when [`Self::IDENTITY_IS_DLOG`] the tag programs
    /// `htag(c_0) := g`).
    ///
    /// # Errors
    /// [`Error::HashToCurve`] if the hash-to-group oracle cannot be instantiated.
    fn setup(domain: &[u8], c0: G::ScalarField) -> Result<Self, Error>;

    /// Whether THIS instance satisfies `Tag(K, c_0) = g^K` for every key `K`, at the given
    /// identity point `c_0`: the value-level counterpart of [`Self::IDENTITY_IS_DLOG`]
    /// (proof sketch of the Lemma on `Σ-EQ`, §3.2.3: compatible "under `htag(c_0) = g_1`", which
    /// is a property of the parameters, not of the tag family). Must be `false` whenever the
    /// constant is.
    ///
    /// Whoever builds the public parameters from parts or decodes them checks this when the
    /// credential base requires it; see [`check_compatibility`](crate::pcs::check_compatibility).
    fn identity_is_dlog(&self, c0: &G::ScalarField) -> bool;

    /// Whether THIS instance is a usable `pp_Tag`. `false` for a DEGENERATE instance: one under
    /// which `TagEval` is `⊥` at every point (and `ValidTag` rejects every tag), such as a
    /// `Tag_DY` instance whose generator is the identity. Deterministic; costs no group
    /// operation; never panics.
    ///
    /// Implementation note, not an algorithm of the paper, whose `pp_Tag` is always an output of
    /// `Setup`. Every instance built by [`Self::setup`] is well formed. The question arises for
    /// an instance that was assembled or decoded in another way, in particular WITHOUT
    /// validation (`deserialize_*_unchecked`), and it is a question of LIVENESS: verifiers are
    /// protected in any case, because [`SigmaFriendlyKIPRF::valid_tag`] of a degenerate instance
    /// rejects everything, but `UKeyGen` of the construction box restarts while
    /// `Tag(usk, c_0) = ⊥` or `Tag(usk, H_0(id)) = ⊥`, and under a degenerate instance such a
    /// loop never terminates. Generic code cannot see the inherent checks of an instantiation;
    /// this hook is how it asks. [`check_compatibility`](crate::pcs::check_compatibility) and
    /// [`check_dv_compatibility`](crate::pcs::check_dv_compatibility) return
    /// [`Error::DegenerateInput`] for an instance that fails it, and every restart loop runs
    /// behind one of them.
    ///
    /// Contract for implementors: if this returns `true`, then for every point `s` at most ONE
    /// key `K` that [`KIPRF::keygen`] can output has `eval(K, s) = None` (none for `Tag_DDH`,
    /// the key `K = −s` for `Tag_DY`). For a uniform key, one iteration of the `UKeyGen` loop
    /// then restarts with probability about `2/p`: at most one key is undefined at the fixed
    /// point `c_0`, and the second point `H_0(id)` depends on the key only through the random
    /// oracle `H_0` (an estimate in the random-oracle model, not a claim of the paper).
    fn is_well_formed(&self) -> bool;
}

// ---------------------------------------------------------------------------------------------
// The stand-alone sigma protocol for R_Tag
// ---------------------------------------------------------------------------------------------

/// Oracle suffix of the Fiat-Shamir context of a stand-alone tag proof.
const TAG_PROOF_SUFFIX: &[u8] = b"/TAG-PROOF";

/// The statement `((T, s), ·) ∈ R_Tag` as a relation in the single witness `K`: a fresh
/// [`GroupRelation`] holding [`SigmaFriendlyKIPRF::tag_equations`], and the variable of `K`
/// (index 0).
///
/// `ValidTag(T, s)` is NOT part of the linear relation; [`verify_tag`] evaluates it as the
/// public pre-check of Def. "Sigma-friendly non-adaptive key-injective PRF".
///
/// # Errors
/// Propagates [`Error::UnallocatedVariable`] from a tag that returns malformed equations (none
/// of this crate does).
pub fn tag_relation<T: SigmaFriendlyKIPRF>(
    prf: &T,
    tag: &T::Group,
    input: &Scalar<T>,
) -> Result<(GroupRelation<T::Group>, ScalarVar), Error> {
    let mut rel = GroupRelation::new();
    let key = rel.alloc_scalar();
    for equation in prf.tag_equations(key, tag, input) {
        rel.add_equation(equation)?;
    }
    Ok((rel, key))
}

/// `ctx' = (pp_Tag, T, s, ctx)`. Implementation notes:
///
/// * `H_1` has no deployment input of its own (see [`crate::hash`]), so a proof is tied to a
///   deployment only through its context. The parameters `pp_Tag` (for `Tag_DDH`: the
///   deployment label of `htag` and the programmed point) are therefore part of it. Without
///   them a proof of `id = g^usk` at the programmed point, whose base `g` is the same in every
///   deployment, would verify under every deployment that uses the same `c_0`.
/// * Fiat-Shamir already absorbs every base and target of the statement; naming `(T, s)` as
///   well makes the binding to the evaluation point independent of how an instantiation encodes
///   `s` into its equations.
fn tag_proof_context<T: SigmaFriendlyKIPRF + CanonicalSerialize>(
    prf: &T,
    tag: &T::Group,
    input: &Scalar<T>,
    ctx: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut transcript = Transcript::new(TAG_PROOF_SUFFIX);
    transcript.append_serializable(b"pp-tag", prf)?;
    transcript.append_serializable(b"tag", tag)?;
    transcript.append_serializable(b"input", input)?;
    transcript.append_bytes(b"ctx", ctx);
    Ok(transcript.digest().to_vec())
}

/// `π ← zkPoK_ctx{ ((T, s), K) ∈ R_Tag }`: a stand-alone Fiat-Shamir proof of knowledge of the
/// key behind a tag (Def. "Sigma-friendly non-adaptive key-injective PRF").
///
/// The credential system never uses this proof on its own; it composes the same equations with
/// the clauses of a credential base under one shared variable `usk`. The stand-alone form
/// exists for applications and for the test harness. The proof is bound to the parameters
/// `pp_Tag` (hence the serialization bound), to `(T, s)` and to `ctx`.
///
/// # Errors
/// [`Error::InvalidTag`] if `ValidTag(T, s) = 0`; [`Error::WitnessDoesNotSatisfyRelation`] if
/// `T ≠ Tag(K, s)`.
pub fn prove_tag<T, R>(
    prf: &T,
    key: &Scalar<T>,
    tag: &T::Group,
    input: &Scalar<T>,
    ctx: &[u8],
    rng: &mut R,
) -> Result<FSProof<Scalar<T>>, Error>
where
    T: SigmaFriendlyKIPRF + CanonicalSerialize,
    R: RngCore + CryptoRng + ?Sized,
{
    if !prf.valid_tag(tag, input) {
        return Err(Error::InvalidTag);
    }
    let (rel, _) = tag_relation(prf, tag, input)?;
    let witness = Witness::from(vec![*key]);
    fiat_shamir::prove(
        &rel,
        &witness,
        &tag_proof_context(prf, tag, input, ctx)?,
        rng,
    )
}

/// Verifies a proof of [`prove_tag`] for the parameters `prf`, the public statement `(T, s)` and
/// the context `ctx`: the public pre-check `ValidTag(T, s)`, then Fiat-Shamir verification of
/// the tag equations. Never panics.
#[must_use]
pub fn verify_tag<T: SigmaFriendlyKIPRF + CanonicalSerialize>(
    prf: &T,
    tag: &T::Group,
    input: &Scalar<T>,
    ctx: &[u8],
    proof: &FSProof<Scalar<T>>,
) -> bool {
    if !prf.valid_tag(tag, input) {
        return false;
    }
    let (Ok((rel, _)), Ok(full_ctx)) = (
        tag_relation(prf, tag, input),
        tag_proof_context(prf, tag, input, ctx),
    ) else {
        return false;
    };
    fiat_shamir::verify(&rel, &full_ctx, proof)
}
