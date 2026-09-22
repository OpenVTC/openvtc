//! Credential bases (paper §3.2): a signature scheme with encoded (blind) issuance and
//! unlinkable shows, plus the sigma-friendly add-on that lets a holder prove possession.
//!
//! This module holds the trait definitions, the instantiations (one submodule each) and the
//! stand-alone possession proof ([`possess`], [`verify_possess`]):
//!
//! | paper | trait |
//! |---|---|
//! | Def. "Credential base": `Σ = (SIG, ReRand, BlindIssue, Unblind)` with the maps `Enc_Σ`, `Com_vk` | [`CredentialBase`] |
//! | Def. "Sigma-friendly credential base": `VerifyPossess`, `R_Possess` | [`SigmaFriendlyCredentialBase`] |
//! | Def. "Designated-verifier credential base" (MAC, secret `dvk`) | [`DVCredentialBase`] |
//! | Def. "Sigma-friendly designated-verifier credential base" | [`SigmaFriendlyDVCredentialBase`] |
//!
//! A base is a *type-level* scheme: all algorithms are associated functions that take the
//! public parameters `pp` explicitly. The instantiations of the paper are [`PS`] = `Σ-PS`
//! (§3.2.1), [`BBS`] = `Σ-BBS` (§3.2.2), [`EQ`] = `Σ-EQ` (§3.2.3) and the
//! designated-verifier [`MAC`] = `Σ-MAC` (§3.2.4). The sigma-friendly traits are shaped so
//! that all four fit:
//!
//! | | `m_hid = (usk, m_aux)` | `ρ` (issuance state) | `C` on the wire | `ω` (show state) | possession clauses |
//! |---|---|---|---|---|---|
//! | `Σ-PS` | `m_aux = ∅` | `ρ ← Z_p` | `C = g_1^ρ Y_1^usk` | `∅` | one `G_T` clause in `usk` |
//! | `Σ-BBS` | `m_aux = ρ` | the same `ρ` | `C = h_0 h_1^usk h_2^φ h_3^ρ` | `(e, r_1, r_3)` | two `G_1` clauses in `(usk, e, ρ, r_1, r_3)`, public pairing check |
//! | `Σ-EQ` | `m_aux = ∅` | `∅` | nothing: `C := id` | `∅` | one `G_1` clause in `usk`, no opening clause |
//! | `Σ-MAC` | `m_aux = ∅` | `ρ ← Z_q` | `C = g^usk h^ρ` | `∅` | one clause whose target the verifier derives from `dvk` |
//!
//! # What the verifiers re-impose
//!
//! Decoding accepts the identity point and the zero scalar, for shown credentials and for keys
//! alike. Two hooks keep a relation from becoming vacuous (Def. "Sigma-friendly credential
//! base": `VerifyPossess` "includes every public validity check needed to prevent a vacuous
//! relation"):
//!
//! * [`SigmaFriendlyCredentialBase::verify_possess_public`] holds ALL witness-independent checks
//!   of the possession verifier, on `cred*` (`σ'_1 ≠ 1`, ...) **and on `vk`**, which is part of
//!   the statement of `R_Possess`: a key component under which the clauses no longer depend on
//!   a certified value (`Ỹ_1 = 1` for `Σ-PS`, `X̃_2 = 1` for `Σ-EQ`) is rejected there, and so
//!   is a generator of `pp_Σ` that is the identity (`h_1 = 1` for `Σ-BBS`). The
//!   designated-verifier base has a keyless public check (`U' ≠ 1`); its key-side conditions
//!   (`y_1 ≠ 0`, `y_2 ≠ 0` for `Σ-MAC`) are enforced where the key is used, by
//!   [`SigmaFriendlyDVCredentialBase::possession_clauses_verifier`].
//! * [`CredentialBase::is_well_formed_key`] is the complete membership test "`vk` is in the
//!   range of `KeyGen`", to be run once by whoever accepts a key it did not generate
//!   (implementation note; the paper only ever considers keys output by `KeyGen`).
//!
//! # Proof sizes
//!
//! The number of witness variables a base adds to `R_att` and to `R_issue` is a constant of the
//! base ([`SigmaFriendlyCredentialBase::POSSESSION_VARIABLES`],
//! [`SigmaFriendlyCredentialBase::ISSUANCE_VARIABLES`]), so an attestation proof always has
//! `1 + POSSESSION_VARIABLES` responses and `π_0` has `1 + ISSUANCE_VARIABLES` (the `1` is the
//! shared `usk`; the tag clauses add no variable). This is what makes the fixed-format
//! encoding [`FSProof::serialize_compact`] decodable without a length prefix, and it is how the
//! byte sizes of the paper's comparison table (§5.3) are reached: the derived canonical encoding of
//! an [`FSProof`] is 8 bytes longer (the length prefix of its response vector).
//!
//! # Bounds
//!
//! The implementing type is a marker, e.g. `PS<E>(PhantomData<E>)`. The traits nevertheless
//! require it to be `Clone + Debug + PartialEq + Eq`, for one reason only: `#[derive(..)]` on a
//! protocol object that is generic over the base (an attestation, a credential) puts these
//! bounds on the type parameter itself.
//!
//! Public protocol objects are `Clone + Debug + PartialEq + Eq + CanonicalSerialize +
//! CanonicalDeserialize`. Secret material is [`Zeroize`]; implementations should additionally
//! wipe structs on drop, keep them non-`Copy`, and redact them in `Debug`. The unit type `()`
//! satisfies every bound and is the natural choice for an empty component (`∅`).

pub mod bbs;
#[cfg(any(test, feature = "test-utils"))]
pub mod conformance;
pub mod eq;
pub mod mac;
pub mod ps;

use core::fmt::Debug;

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub use self::{bbs::BBS, eq::EQ, mac::MAC, ps::PS};
use crate::{
    error::Error,
    hash::Transcript,
    sigma::{
        FSProof, GroupRelation, LinearRelation, PairingRelation, ScalarVar, Witness, fiat_shamir,
        pairing_product,
    },
};

/// Whether `∏_k e(P_k, Q_k) = 1`, evaluated as ONE pairing product (one Miller loop per pair,
/// one final exponentiation). This is how the bases check their verification equations: e.g.
/// `e(σ_1, X̃ Ỹ_1^{m_1} Ỹ_2^{m_2}) = e(σ_2, g̃)` is the product over
/// `[(σ_1, X̃ Ỹ_1^{m_1} Ỹ_2^{m_2}), (σ_2^{-1}, g̃)]`.
///
/// Never panics; an undefined product counts as "not the identity".
#[must_use]
pub fn pairing_product_is_identity<E: Pairing>(pairs: &[(E::G1, E::G2)]) -> bool {
    pairing_product::<E>(pairs).is_ok_and(|product| product.is_zero())
}

/// A credential base `Σ = (SIG, ReRand, BlindIssue, Unblind)` built from a signature scheme
/// `SIG = (KeyGen, Sign, Verify)`, with the deterministic message map
/// `Enc_Σ : M_hid × M_pub → M_Σ` and the issuance-encoding map
/// `Com_vk : M_hid × M_pub × R_Σ → C_Σ` (§3.2 and Def. "Credential base").
///
/// The paper requires correctness of the encoded-issuance flow
/// (`Verify(vk, Enc_Σ(m_hid, m_pub), Unblind(vk, m, BlindIssue(sk, Com(m_hid, m_pub; r), m_pub), r)) = 1`),
/// issuance indistinguishability, unforgeability, show unlinkability (strong or weak) and
/// one-more issuance unforgeability.
pub trait CredentialBase: Clone + Debug + PartialEq + Eq {
    /// Public parameters `pp_Σ`; transparent (hash-derived), so there is no trapdoor.
    type PublicParams: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The signing key `sk`. Secret.
    type SigningKey: Zeroize + CanonicalSerialize + CanonicalDeserialize;
    /// The verification key `vk`.
    type VerificationKey: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The hidden certified message `m_hid ∈ M_hid`. Secret: it contains `usk`.
    type HiddenMessage: Zeroize;
    /// The disclosed certified message `m_pub ∈ M_pub`.
    type PublicMessage: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The message `m = Enc_Σ(m_hid, m_pub) ∈ M_Σ` signed by the underlying scheme. Secret in
    /// general: it determines `m_hid`.
    type Message: Zeroize;
    /// The local issuance state `r ∈ R_Σ` the user keeps between `Com` and `Unblind`. Secret.
    type IssuanceState: Zeroize + CanonicalSerialize + CanonicalDeserialize;
    /// The issuance encoding `C ∈ C_Σ`.
    type IssuanceEncoding: Clone
        + Debug
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize;
    /// A credential `cred`: a signature on `m`.
    type Credential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// A blinded pre-credential `ĉred`, the output of `BlindIssue`.
    type PreCredential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The public credential encoding `cred*` output by `ReRand`. Its format may differ from
    /// that of `cred` (`Σ-BBS`, `Σ-EQ`).
    type ShownCredential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The private local state `ω` output by `ReRand`. Secret.
    type ShowState: Zeroize;

    /// Generates `pp_Σ` for the deployment label `domain` (construction box, `Setup` step 1).
    ///
    /// # Errors
    /// [`Error::HashToCurve`] if hash-derived generators cannot be computed. Implementation
    /// note: [`Error::LengthMismatch`] / [`Error::DegenerateInput`] if a hash-to-group oracle
    /// breaks its contract and returns too few generators or the identity (`Σ-BBS`).
    fn setup(domain: &[u8]) -> Result<Self::PublicParams, Error>;

    /// `KeyGen(pp) → (vk, sk)`.
    fn keygen<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::VerificationKey, Self::SigningKey);

    /// Whether `vk` is a well-formed verification key, i.e. lies in the range of `KeyGen(pp)`.
    /// Deterministic; never panics.
    ///
    /// Implementation note (not an algorithm of the paper, whose statements are about keys
    /// output by `KeyGen`): validated decoding accepts the identity point, so a key that comes
    /// from the wire can have components under which the scheme certifies nothing, e.g. `Ỹ_1 = 1`
    /// for `Σ-PS` (a credential is then independent of `usk`) or `X̃_2 = 1` for `Σ-EQ`. Whoever
    /// accepts an `hvk` it did not generate itself runs this check once and treats a failure as
    /// [`Error::InvalidKey`]. Independently of it,
    /// [`SigmaFriendlyCredentialBase::verify_possess_public`] re-imposes the conditions that the
    /// possession relation needs on every call.
    fn is_well_formed_key(pp: &Self::PublicParams, vk: &Self::VerificationKey) -> bool;

    /// `Sign(sk, m) → cred`.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if `m ∉ M_Σ`; [`Error::InvalidKey`] where an instantiation
    /// refuses a (decoded) signing key outside its key space.
    fn sign<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        m: &Self::Message,
        rng: &mut R,
    ) -> Result<Self::Credential, Error>;

    /// `Verify(vk, m, cred) → {0, 1}`. Deterministic; includes every non-degeneracy check of the
    /// instantiation (`σ_1 ≠ 1`, `A ≠ 1`, ...). Never panics.
    fn verify(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
    ) -> bool;

    /// The message map `Enc_Σ(m_hid, m_pub) → m`.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if the pair has no encoding in `M_Σ` (e.g. `φ = 0` for `Σ-EQ`,
    /// whose message components must not be the identity).
    fn encode_message(
        pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
    ) -> Result<Self::Message, Error>;

    /// The issuance-encoding map `Com_vk(m_hid, m_pub; r) → C`. Deterministic.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if the inputs have no issuance encoding.
    fn issuance_encoding(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
        r: &Self::IssuanceState,
    ) -> Result<Self::IssuanceEncoding, Error>;

    /// `ReRand(vk, m, cred) → (cred*, ω)`.
    ///
    /// # Errors
    /// [`Error::InvalidCredential`] where the instantiation outputs `⊥` (`Σ-EQ` re-randomizes
    /// verifying credentials only), and, as an implementation note, for an input that is
    /// degenerate on its face and whose shown form every possession verifier would reject
    /// (`σ_1 = 1` for `Σ-PS`; `A = 1` or `B(m) = 1` for `Σ-BBS`).
    fn rerand<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
        rng: &mut R,
    ) -> Result<(Self::ShownCredential, Self::ShowState), Error>;

    /// `BlindIssue(sk, C, m_pub) → ĉred`. The signer sees only `C` and `m_pub`.
    ///
    /// Note for implementors: the point at which `m_pub = φ` enters differs per base. `Σ-PS` and
    /// `Σ-MAC` add it here, `Σ-BBS` already has it inside `C` and must not add it again, `Σ-EQ`
    /// builds the signed vector `(g_1, C, g_1^φ)` here.
    ///
    /// # Errors
    /// [`Error::InvalidIssuanceEncoding`] / [`Error::InvalidMessage`] where the instantiation
    /// outputs `⊥`; [`Error::InvalidKey`] where it refuses a (decoded) signing key outside its
    /// key space.
    fn blind_issue<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        c: &Self::IssuanceEncoding,
        m_pub: &Self::PublicMessage,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error>;

    /// `Unblind(vk, m, ĉred, r) → cred`. Deterministic.
    ///
    /// As in the boxes of the instantiations of this crate (`Σ-PS`, `Σ-BBS`, `Σ-EQ`), `Unblind`
    /// removes the blinding and does NOT verify the result: only what is malformed on its face
    /// is refused (an identity component that no honest signer outputs; no group operation).
    /// Whether `cred` is a signature on `m` under `vk` is [`Self::verify`]. Implementation note:
    /// the construction runs that check once, in its own `Unblind`, for every base, and fails
    /// closed there (module docs of [`crate::pcs`], "Rules the construction has to keep"). A
    /// caller that uses a base directly does the same.
    ///
    /// # Errors
    /// [`Error::InvalidPreCredential`] if the pre-credential is malformed;
    /// [`Error::InvalidMessage`] if the issuance state `r` does not belong to `m` (`Σ-BBS`,
    /// where `r` is the component `ρ` of `m`; implementation note).
    fn unblind(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        pre: &Self::PreCredential,
        r: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error>;
}

/// [`Error::UnallocatedVariable`] unless the caller's variable `var` belongs to `rel`.
///
/// For the clause builders of the bases, which allocate variables of their own BEFORE they add
/// an equation. The check that a relation runs on every equation comes too late for them: a
/// foreign handle whose index equals the number of variables allocated so far would silently
/// alias the first fresh variable (`ρ`, say) instead of `usk`, and the clause `C = g^ρ Y^usk`
/// would turn into `C = (g Y)^ρ` without any error. Calling this first also leaves the relation
/// untouched on error.
pub(crate) fn ensure_allocated<R: LinearRelation>(rel: &R, var: ScalarVar) -> Result<(), Error> {
    let allocated = rel.num_scalars();
    if var.index() < allocated {
        Ok(())
    } else {
        Err(Error::UnallocatedVariable {
            index: var.index(),
            allocated,
        })
    }
}

/// The sigma-friendly add-on of a publicly verifiable, pairing-based credential base (Def.
/// "Sigma-friendly credential base"), in the form the construction of §5.1 consumes it.
///
/// The possession relation is
/// `R_Possess = { ((vk, cred*, m_pub), (m_hid, ω)) : VerifyPossess(vk, cred*, m_pub; m_hid, ω) = 1 }`.
/// `VerifyPossess` splits into
///
/// * its **witness-independent checks** ([`Self::verify_possess_public`]), which "prevent a
///   vacuous relation" and which the sigma-protocol verifier "performs directly", and
/// * **linear clauses** ([`Self::possession_clauses`]) over the witness `(m_hid, ω)`, appended
///   to a [`PairingRelation`] in which the component `usk` of `m_hid` is an existing variable
///   shared with the tag clauses (witness-preserving AND composition).
///
/// A verifier MUST run the public checks before it gives any meaning to a proof for the
/// clauses: with a degenerate `cred*` (e.g. `σ'_1 = 1`) the clauses hold for every `usk`.
///
/// The second half of the trait describes the base-specific parts of `R_issue` and of the
/// `(m_aux, ρ)` display of §5.1: `m_hid = (usk, m_aux)`, how `Prove` samples `(m_aux, ρ)`,
/// whether `C` travels inside `π`, and the opening clause `C = Com(m_hid, φ; ρ)`.
pub trait SigmaFriendlyCredentialBase<E: Pairing>:
    CredentialBase<PublicMessage = E::ScalarField>
{
    /// The base-specific hidden component `m_aux` of `m_hid = (usk, m_aux)`, which the holder
    /// keeps next to `cred_Σ` (the PCS credential is `cred = (cred_Σ, m_aux)`): `()` for `Σ-PS`
    /// and `Σ-EQ`, the scalar `ρ` for `Σ-BBS`. Secret.
    type Aux: Clone + Debug + PartialEq + Eq + Zeroize + CanonicalSerialize + CanonicalDeserialize;
    /// What travels inside an issuance proof `π` for the issuance encoding: `C` itself
    /// (`Σ-PS`, `Σ-BBS`), or `()` when the verifier reconstructs `C` from public input (`Σ-EQ`).
    type WireEncoding: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;

    /// `true` iff issuance needs `id = g_1^usk` (`Σ-EQ`: `C := id`), i.e. a tag instance with
    /// [`PCSTag::identity_is_dlog`](crate::kiprf::PCSTag::identity_is_dlog); see
    /// [`check_compatibility`](crate::pcs::check_compatibility).
    const REQUIRES_DLOG_IDENTITY: bool;

    /// The number of witness variables [`Self::possession_clauses`] allocates (the components
    /// `(m_aux, ω)` of the witness of `R_Possess`; the shared `usk` is not counted): `0` for
    /// `Σ-PS` and `Σ-EQ`, `4` for `Σ-BBS` (`e, ρ, r_1, r_3`). An attestation proof therefore has
    /// exactly `1 + POSSESSION_VARIABLES` responses, which fixes its compact encoding
    /// ([`FSProof::deserialize_compact`]) without a length on the wire.
    const POSSESSION_VARIABLES: usize;

    /// The number of witness variables [`Self::issuance_clauses`] allocates (the issuance
    /// state `ρ`; `usk` is not counted): `1` for `Σ-PS` and `Σ-BBS`, `0` for `Σ-EQ`. The proof
    /// `π_0` of `R_issue` therefore has exactly `1 + ISSUANCE_VARIABLES` responses.
    const ISSUANCE_VARIABLES: usize;

    /// `m_hid := (usk, m_aux)` (construction box, `Attest` step 7, `Prove` step 8).
    fn hidden_message(usk: &E::ScalarField, aux: &Self::Aux) -> Self::HiddenMessage;

    /// Parses `m_hid` as `(usk, m_aux)` (construction box, `Unblind` steps 2 and 5).
    fn split_hidden_message(m_hid: &Self::HiddenMessage) -> (E::ScalarField, Self::Aux);

    /// Samples the base-specific pair `(m_aux, ρ)` of `Prove` step 7: `(∅, r)` for `Σ-PS`,
    /// `(r, r)` for `Σ-BBS` (the same `r` is certified and is the issuance state), `(∅, ∅)` for
    /// `Σ-EQ`.
    fn sample_issuance<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::Aux, Self::IssuanceState);

    /// The part of `C` that is serialized into `π` (`Prove` steps 12-13).
    fn encoding_to_wire(c: &Self::IssuanceEncoding) -> Self::WireEncoding;

    /// Recovers `C` on the verifier's side from the wire value and the public identifier
    /// (`VerifyProof` steps 1-2): the transmitted `C`, or `C := id` for `Σ-EQ`. `None` rejects
    /// an inadmissible encoding.
    fn encoding_from_wire(
        pp: &Self::PublicParams,
        wire: &Self::WireEncoding,
        id: &E::G1,
    ) -> Option<Self::IssuanceEncoding>;

    /// ALL witness-independent checks of `VerifyPossess(vk, cred*, m_pub; ·)`:
    /// `σ'_1 ≠ 1` (`Σ-PS`); `Ā ≠ 1`, `D ≠ 1` and `e(Ā, X̃) = e(B̄, g̃)` (`Σ-BBS`); `M'_1 ≠ 1`,
    /// `Verify(vk, M', cred') = 1` and `M'_3 = (M'_1)^φ` (`Σ-EQ`). Never panics.
    ///
    /// The statement of `R_Possess` contains `vk`, and "every public validity check needed to
    /// prevent a vacuous relation" (Def. "Sigma-friendly credential base") includes the key:
    /// the implementation also rejects a `vk` under which the clauses do not depend on a
    /// certified value, e.g. `Ỹ_1 = 1` or `Ỹ_2 = 1` for `Σ-PS` (the clause would hold for every
    /// `usk`, resp. every `φ`) and `X̃_i = 1` for `Σ-EQ`. The same holds for parameters the
    /// clauses are built from: `Σ-BBS` rejects a `pp` with an identity generator (with `h_1 = 1`
    /// its clauses would hold next to a tag under every key). Implementation note: the paper's
    /// boxes list the checks on `cred*` only, because they assume `vk ← KeyGen` and honestly
    /// generated parameters.
    fn verify_possess_public(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        m_pub: &E::ScalarField,
    ) -> bool;

    /// Appends the linear clauses of `R_Possess` for the public statement `(vk, cred*, m_pub)`
    /// to `rel`. `usk` is the already allocated variable of the shared component of `m_hid`;
    /// the variables of the remaining witness components `(m_aux, ω)` are allocated here and
    /// returned, in the order in which [`Self::possession_witness`] lists their values.
    ///
    /// Depends on public data only, so prover and verifier build the identical statement.
    /// Always allocates exactly [`Self::POSSESSION_VARIABLES`] variables.
    ///
    /// Note for implementors: check that `usk` belongs to `rel` BEFORE allocating a variable
    /// (a foreign handle could otherwise alias a fresh variable), and leave `rel` untouched on
    /// error.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`.
    fn possession_clauses(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error>;

    /// The values of the variables allocated by [`Self::possession_clauses`], taken from the
    /// witness `(m_hid, ω)`; `usk` itself is not included.
    fn possession_witness(
        m_hid: &Self::HiddenMessage,
        show_state: &Self::ShowState,
    ) -> Witness<E::ScalarField>;

    /// Appends the opening clause `C = Com(m_hid, m_pub; ρ)` of `R_issue` to `rel` and returns
    /// the variables it allocated (beyond `usk`): always exactly [`Self::ISSUANCE_VARIABLES`].
    /// No clause and no variable for `Σ-EQ`, whose `C = id` is already bound by the identifier
    /// clause of `R_issue`.
    ///
    /// The note for implementors of [`Self::possession_clauses`] applies here as well.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`; [`Error::InvalidKey`]
    /// if `vk` makes the opening clause independent of `usk` (`Y_1 = 1` for `Σ-PS`;
    /// implementation note, cf. [`CredentialBase::is_well_formed_key`]);
    /// [`Error::DegenerateInput`] if `pp` does (a `pp` of `Σ-BBS` with an identity generator;
    /// implementation note). Nothing is appended and nothing is allocated on error.
    fn issuance_clauses(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        c: &Self::IssuanceEncoding,
        m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error>;

    /// The values of the variables allocated by [`Self::issuance_clauses`], taken from the
    /// witness `(m_hid, ρ)`; `usk` itself is not included.
    fn issuance_witness(
        m_hid: &Self::HiddenMessage,
        r: &Self::IssuanceState,
    ) -> Witness<E::ScalarField>;
}

// ---------------------------------------------------------------------------------------------
// The stand-alone sigma protocol for R_Possess
// ---------------------------------------------------------------------------------------------

/// Oracle suffix of the Fiat-Shamir context of a stand-alone possession proof.
const POSSESS_SUFFIX: &[u8] = b"/POSSESS";

/// The clauses of `R_Possess` for the public statement `(vk, cred*, m_pub)` in a fresh
/// [`PairingRelation`] whose variable 0 is `usk` (returned), followed by the variables of
/// [`SigmaFriendlyCredentialBase::possession_clauses`]. The matching witness vector is `usk`
/// followed by [`SigmaFriendlyCredentialBase::possession_witness`].
///
/// The construction of §5.1 extends exactly this relation by the tag clause on the same
/// variable `usk` to obtain `R_att`. The witness-independent checks of `VerifyPossess` are NOT
/// part of it ([`SigmaFriendlyCredentialBase::verify_possess_public`]).
///
/// # Errors
/// Propagates the errors of [`SigmaFriendlyCredentialBase::possession_clauses`];
/// [`Error::LengthMismatch`] if a base allocates another number of variables than its
/// [`SigmaFriendlyCredentialBase::POSSESSION_VARIABLES`] (none of this crate does; fixed-format
/// decoding of attestations relies on the constant).
pub fn possession_relation<E, B>(
    pp: &B::PublicParams,
    vk: &B::VerificationKey,
    shown: &B::ShownCredential,
    m_pub: &E::ScalarField,
) -> Result<(PairingRelation<E>, ScalarVar), Error>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
{
    let mut rel = PairingRelation::new();
    let usk = rel.alloc_scalar();
    let allocated = B::possession_clauses(pp, vk, shown, m_pub, &mut rel, usk)?;
    if allocated.len() != B::POSSESSION_VARIABLES {
        return Err(Error::LengthMismatch {
            expected: B::POSSESSION_VARIABLES,
            actual: allocated.len(),
        });
    }
    Ok((rel, usk))
}

/// The witness vector of [`possession_relation`] (and of `R_att`, which adds no variable):
/// `usk` followed by [`SigmaFriendlyCredentialBase::possession_witness`], built in ONE
/// allocation of `1 + POSSESSION_VARIABLES` scalars that is wiped on drop.
#[must_use]
pub fn possession_witness_vector<E, B>(
    m_hid: &B::HiddenMessage,
    show_state: &B::ShowState,
) -> Witness<E::ScalarField>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
{
    shared_then::<E, B>(
        m_hid,
        1 + B::POSSESSION_VARIABLES,
        &B::possession_witness(m_hid, show_state),
    )
}

/// The witness vector of `R_issue`: `usk` followed by
/// [`SigmaFriendlyCredentialBase::issuance_witness`], built in ONE allocation of
/// `1 + ISSUANCE_VARIABLES` scalars that is wiped on drop.
#[must_use]
pub fn issuance_witness_vector<E, B>(
    m_hid: &B::HiddenMessage,
    r: &B::IssuanceState,
) -> Witness<E::ScalarField>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
{
    shared_then::<E, B>(
        m_hid,
        1 + B::ISSUANCE_VARIABLES,
        &B::issuance_witness(m_hid, r),
    )
}

/// `usk` (the shared first component of `m_hid`) followed by `rest`. The local copies of the
/// secret components are wiped; see the limitations in the crate docs on what that can and
/// cannot guarantee for `Copy` field elements.
fn shared_then<E, B>(
    m_hid: &B::HiddenMessage,
    capacity: usize,
    rest: &[E::ScalarField],
) -> Witness<E::ScalarField>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
{
    let mut witness = Witness::with_capacity(capacity.max(1 + rest.len()));
    let (mut usk, mut aux) = B::split_hidden_message(m_hid);
    witness.push(usk);
    usk.zeroize();
    aux.zeroize();
    witness.extend_from_slice(rest);
    witness
}

/// `ctx' = (pp, vk, cred*, m_pub, ctx)`: the complete public statement of `R_Possess` next to
/// the caller's context. Implementation note: Fiat-Shamir already absorbs every base and target
/// of the clauses; naming the statement as well keeps the binding independent of how a base
/// encodes `vk` and `m_pub` into its clauses.
fn possess_context<E, B>(
    pp: &B::PublicParams,
    vk: &B::VerificationKey,
    shown: &B::ShownCredential,
    m_pub: &E::ScalarField,
    ctx: &[u8],
) -> Result<Vec<u8>, Error>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
{
    let mut transcript = Transcript::new(POSSESS_SUFFIX);
    transcript.append_serializable(b"pp", pp)?;
    transcript.append_serializable(b"vk", vk)?;
    transcript.append_serializable(b"cred*", shown)?;
    transcript.append_serializable(b"m_pub", m_pub)?;
    transcript.append_bytes(b"ctx", ctx);
    Ok(transcript.digest().to_vec())
}

/// `Possess(vk, cred*, m_pub; m_hid, ω) → Π` (Def. "Sigma-friendly credential base"): a
/// stand-alone Fiat-Shamir proof of knowledge of the hidden message certified by the shown
/// credential `cred*`, bound to the context `ctx`.
///
/// The credential system never uses this proof on its own; it composes the same clauses with
/// the tag clause under one shared variable `usk`. The stand-alone form exists for
/// applications and for the test harness.
///
/// # Errors
/// [`Error::InvalidKey`] if `vk` is not well formed; [`Error::InvalidCredential`] if `cred*`
/// fails the public checks of `VerifyPossess`; [`Error::WitnessDoesNotSatisfyRelation`] if
/// `(m_hid, ω)` is not a witness.
// The parameter list is the paper's `Possess(vk, cred*, m_pub; m_hid, ω)` plus `pp`, the
// context and the RNG.
#[allow(clippy::too_many_arguments)]
pub fn possess<E, B, R>(
    pp: &B::PublicParams,
    vk: &B::VerificationKey,
    shown: &B::ShownCredential,
    m_pub: &E::ScalarField,
    m_hid: &B::HiddenMessage,
    show_state: &B::ShowState,
    ctx: &[u8],
    rng: &mut R,
) -> Result<FSProof<E::ScalarField>, Error>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    R: RngCore + CryptoRng + ?Sized,
{
    if !B::is_well_formed_key(pp, vk) {
        return Err(Error::InvalidKey);
    }
    if !B::verify_possess_public(pp, vk, shown, m_pub) {
        return Err(Error::InvalidCredential);
    }
    let (rel, _) = possession_relation::<E, B>(pp, vk, shown, m_pub)?;
    let witness = possession_witness_vector::<E, B>(m_hid, show_state);
    let full_ctx = possess_context::<E, B>(pp, vk, shown, m_pub, ctx)?;
    fiat_shamir::prove(&rel, &witness, &full_ctx, rng)
}

/// `VerifyPossess` as run by the sigma-protocol verifier (Def. "Sigma-friendly credential
/// base"): first ALL witness-independent checks
/// ([`SigmaFriendlyCredentialBase::verify_possess_public`]), then Fiat-Shamir verification of
/// the clauses for the statement `(vk, cred*, m_pub)` and the context `ctx`. Never panics.
#[must_use]
pub fn verify_possess<E, B>(
    pp: &B::PublicParams,
    vk: &B::VerificationKey,
    shown: &B::ShownCredential,
    m_pub: &E::ScalarField,
    ctx: &[u8],
    proof: &FSProof<E::ScalarField>,
) -> bool
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
{
    if !B::verify_possess_public(pp, vk, shown, m_pub) {
        return false;
    }
    let (Ok((rel, _)), Ok(full_ctx)) = (
        possession_relation::<E, B>(pp, vk, shown, m_pub),
        possess_context::<E, B>(pp, vk, shown, m_pub, ctx),
    ) else {
        return false;
    };
    fiat_shamir::verify(&rel, &full_ctx, proof)
}

/// A designated-verifier credential base `(MAC, ReRand, BlindIssue, Unblind)` built from a MAC
/// `(KeyGen, Sign, Verify)` with the public issuance-encoding map `Com_pp` (Def.
/// "Designated-verifier credential base").
///
/// It mirrors [`CredentialBase`] with the changes the paper lists: `KeyGen` returns the single
/// key `dvk`, which stays secret with the designated verifier and is used for signing,
/// verification and blind issuance; `ReRand`, `Unblind` and `Com` take `pp` in place of `vk`.
/// A user cannot verify its own credential.
pub trait DVCredentialBase: Clone + Debug + PartialEq + Eq {
    /// Public parameters `pp` (group generators).
    type PublicParams: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The key `dvk`, retained by the designated verifier. Secret.
    type DVKey: Zeroize + CanonicalSerialize + CanonicalDeserialize;
    /// The hidden certified message `m_hid`. Secret: it contains `usk`.
    type HiddenMessage: Zeroize;
    /// The disclosed certified message `m_pub`.
    type PublicMessage: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The authenticated message `m = Enc_Σ(m_hid, m_pub)`. Secret in general.
    type Message: Zeroize;
    /// The local issuance state `r`. Secret.
    type IssuanceState: Zeroize + CanonicalSerialize + CanonicalDeserialize;
    /// The issuance encoding `C = Com_pp(m_hid, m_pub; r)`.
    type IssuanceEncoding: Clone
        + Debug
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize;
    /// A credential `cred`: a MAC on `m`.
    type Credential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// A blinded pre-credential `ĉred`.
    type PreCredential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The public credential encoding `cred*`.
    type ShownCredential: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;
    /// The private local state `ω` of `ReRand`. Secret.
    type ShowState: Zeroize;

    /// Generates `pp` for the deployment label `domain`.
    ///
    /// # Errors
    /// [`Error::HashToCurve`] if hash-derived generators cannot be computed.
    fn setup(domain: &[u8]) -> Result<Self::PublicParams, Error>;

    /// `KeyGen(pp) → dvk`.
    fn keygen<R: RngCore + CryptoRng + ?Sized>(pp: &Self::PublicParams, rng: &mut R)
    -> Self::DVKey;

    /// Whether `dvk` is a well-formed key, i.e. lies in the range of `KeyGen(pp)`
    /// (`y_1 ≠ 0 ∧ y_2 ≠ 0` for `Σ-MAC`, whose `KeyGen` samples both from `Z_q^*`).
    /// Deterministic; never panics.
    /// Implementation note, the mirror of [`CredentialBase::is_well_formed_key`]: decoding
    /// accepts the zero scalar, so a key that was stored and read back is checked before it is
    /// used.
    fn is_well_formed_key(pp: &Self::PublicParams, dvk: &Self::DVKey) -> bool;

    /// `Sign(dvk, m) → cred`.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if `m ∉ M_Σ`; [`Error::InvalidKey`] if `dvk` is not well formed;
    /// [`Error::DegenerateInput`] for (decoded) parameters `pp` that are degenerate on their
    /// face (`Σ-MAC`: `g = 1`, `h = 1` or `g = h`; implementation note).
    fn sign<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        m: &Self::Message,
        rng: &mut R,
    ) -> Result<Self::Credential, Error>;

    /// `Verify(dvk, m, cred) → {0, 1}`. Deterministic, keyed. Never panics.
    fn verify(
        pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        m: &Self::Message,
        cred: &Self::Credential,
    ) -> bool;

    /// The message map `Enc_Σ(m_hid, m_pub) → m`.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if the pair has no encoding in `M_Σ`.
    fn encode_message(
        pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
    ) -> Result<Self::Message, Error>;

    /// The public issuance-encoding map `Com_pp(m_hid, m_pub; r) → C`.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if the inputs have no issuance encoding;
    /// [`Error::DegenerateInput`] for (decoded) parameters `pp` that are degenerate on their
    /// face, under which `C` would not hide or not bind `m_hid` (implementation note).
    fn issuance_encoding(
        pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
        r: &Self::IssuanceState,
    ) -> Result<Self::IssuanceEncoding, Error>;

    /// `ReRand(pp, m, cred) → (cred*, ω)`. Keyless: the holder cannot verify `cred` first.
    ///
    /// # Errors
    /// [`Error::InvalidCredential`] for a credential that is degenerate on its face.
    fn rerand<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        m: &Self::Message,
        cred: &Self::Credential,
        rng: &mut R,
    ) -> Result<(Self::ShownCredential, Self::ShowState), Error>;

    /// `BlindIssue(dvk, C, m_pub) → ĉred`.
    ///
    /// # Errors
    /// [`Error::InvalidIssuanceEncoding`] where the instantiation outputs `⊥`;
    /// [`Error::InvalidKey`] if `dvk` is not well formed; [`Error::DegenerateInput`] for
    /// (decoded) parameters `pp` that are degenerate on their face (implementation note).
    fn blind_issue<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        c: &Self::IssuanceEncoding,
        m_pub: &Self::PublicMessage,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error>;

    /// `Unblind(pp, m, ĉred, r) → cred`. Deterministic. The result is not verified and cannot
    /// be: only the holder of `dvk` can run [`Self::verify`] ("a malicious issuer can instead
    /// return an unusable pre-credential, causing denial of service", after Def.
    /// "Designated-verifier credential base").
    ///
    /// # Errors
    /// [`Error::InvalidPreCredential`] if the pre-credential is malformed on its face.
    fn unblind(
        pp: &Self::PublicParams,
        m: &Self::Message,
        pre: &Self::PreCredential,
        r: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error>;
}

/// The sigma-friendly add-on of a designated-verifier base over a prime-order group `G` (Def.
/// "Sigma-friendly designated-verifier credential base"): "the prover uses only public
/// parameters, `(cred*, m_pub)`, and witness `(m_hid, ω)`, while the verifier additionally uses
/// `dvk`".
///
/// # Prover and verifier build the statement differently
///
/// With compact Fiat-Shamir proofs both parties must hash the *same* statement and recompute the
/// *same* commitment, yet the paper's `Σ-MAC` relation `V'(U')^{-x-y_2φ} = (U')^{y_1·usk}` has a
/// base and a target that only the key holder can compute. Both sides therefore use the
/// equivalent clause `X = (U')^usk` of `Possess` step 2:
///
/// * the **prover** computes the target `X := (U')^usk` from its witness
///   ([`Self::possession_clauses_prover`], which never sees `dvk`);
/// * the **verifier** derives the same target from `dvk` as
///   `X = (V'(U')^{-x-y_2φ})^{1/y_1}` ([`Self::possession_clauses_verifier`]; `y_1 ≠ 0` by
///   `KeyGen`).
///
/// For an honestly re-randomized credential both targets coincide, and a proof of knowledge of
/// `usk` with `X = (U')^usk` for the verifier's `X` is exactly the paper's relation.
///
/// # The verifier's statement is secret
///
/// **WARNING** (second remark after the box `Σ-MAC`). What
/// [`Self::possession_clauses_verifier`] appends to a relation is derived from `dvk` and from
/// the attacker-chosen `(cred*, m_pub)`, and it must NEVER leave the verifier: for `Σ-MAC` three
/// such targets give a universal forgery (module docs of [`mac`], "The verifier's statement is
/// secret"; the unit tests mount it). This is not an artefact of the clause `X = (U')^usk`:
/// base and target of the relation displayed in the box are key-derived on the verifier's side
/// as well. Handle the relation like `dvk` itself: never log it ([`GroupRelation`] is `Debug`),
/// serialize it, return it or put it into an error, for accepted and for rejected shows alike.
/// Its only use is as the input of the Fiat-Shamir verifier, of which one bit comes out. A layer
/// that composes the verifier's clauses with tag clauses (the designated-verifier construction)
/// keeps the same discipline and exposes no keyed relation builder outside test builds.
pub trait SigmaFriendlyDVCredentialBase<G: PrimeGroup>:
    DVCredentialBase<PublicMessage = G::ScalarField>
{
    /// The base-specific hidden component `m_aux` of `m_hid = (usk, m_aux)`; `()` for `Σ-MAC`.
    type Aux: Clone + Debug + PartialEq + Eq + Zeroize + CanonicalSerialize + CanonicalDeserialize;
    /// What travels inside an issuance proof `π` for the issuance encoding `C`.
    type WireEncoding: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;

    /// `true` iff issuance needs `id = g^usk`; `false` for `Σ-MAC`.
    const REQUIRES_DLOG_IDENTITY: bool;

    /// The number of witness variables the possession clauses allocate, the same on the
    /// prover's and on the verifier's side (`usk` is not counted): `0` for `Σ-MAC`. An
    /// attestation proof has exactly `1 + POSSESSION_VARIABLES` responses.
    const POSSESSION_VARIABLES: usize;

    /// The number of witness variables [`Self::issuance_clauses`] allocates (`usk` is not
    /// counted): `1` for `Σ-MAC` (`ρ`). `π_0` has exactly `1 + ISSUANCE_VARIABLES` responses.
    const ISSUANCE_VARIABLES: usize;

    /// `m_hid := (usk, m_aux)`.
    fn hidden_message(usk: &G::ScalarField, aux: &Self::Aux) -> Self::HiddenMessage;

    /// Parses `m_hid` as `(usk, m_aux)`.
    fn split_hidden_message(m_hid: &Self::HiddenMessage) -> (G::ScalarField, Self::Aux);

    /// Samples the base-specific pair `(m_aux, ρ)` of `Prove` step 7: `(∅, r)`, `r ← Z_q`, for
    /// `Σ-MAC`.
    fn sample_issuance<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::Aux, Self::IssuanceState);

    /// The part of `C` that is serialized into `π`.
    fn encoding_to_wire(c: &Self::IssuanceEncoding) -> Self::WireEncoding;

    /// Recovers `C` on the verifier's side; `None` rejects an inadmissible encoding.
    fn encoding_from_wire(
        pp: &Self::PublicParams,
        wire: &Self::WireEncoding,
        id: &G,
    ) -> Option<Self::IssuanceEncoding>;

    /// The witness-independent checks of the possession verifier that need no key (`U' ≠ 1` for
    /// `Σ-MAC`). A prover-side party can run them too. Never panics.
    fn verify_possess_public(
        pp: &Self::PublicParams,
        shown: &Self::ShownCredential,
        m_pub: &G::ScalarField,
    ) -> bool;

    /// PROVER side: appends the possession clauses to `rel`, computing key-dependent targets
    /// from the witness `(m_hid, ω)`. Returns the variables allocated beyond `usk` (exactly
    /// [`Self::POSSESSION_VARIABLES`]), in the order of [`Self::possession_witness`].
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`.
    fn possession_clauses_prover(
        pp: &Self::PublicParams,
        shown: &Self::ShownCredential,
        m_pub: &G::ScalarField,
        m_hid: &Self::HiddenMessage,
        show_state: &Self::ShowState,
        rel: &mut GroupRelation<G>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error>;

    /// VERIFIER side: appends the possession clauses to `rel`, deriving key-dependent targets
    /// from `dvk`, and returns the variables allocated beyond `usk` (exactly
    /// [`Self::POSSESSION_VARIABLES`]). For an honest `cred*` the statement equals the prover's.
    /// SECRET: after this call `rel` must never leave the verifier (trait docs, "The verifier's
    /// statement is secret").
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`; [`Error::InvalidKey`]
    /// if `dvk` is not well formed (`Σ-MAC`: `y_1 = 0`, which must not be inverted, or
    /// `y_2 = 0`, under which the clause would not depend on `m_pub`).
    fn possession_clauses_verifier(
        pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        shown: &Self::ShownCredential,
        m_pub: &G::ScalarField,
        rel: &mut GroupRelation<G>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error>;

    /// The values of the variables allocated by the possession clauses; `usk` is not included.
    fn possession_witness(
        m_hid: &Self::HiddenMessage,
        show_state: &Self::ShowState,
    ) -> Witness<G::ScalarField>;

    /// Appends the opening clause `C = Com_pp(m_hid, m_pub; ρ)` of `R_issue` (`C = g^usk h^ρ`
    /// for `Σ-MAC`) and returns the variables it allocated beyond `usk` (exactly
    /// [`Self::ISSUANCE_VARIABLES`]). Keyless.
    ///
    /// Note for implementors: check that `usk` belongs to `rel` BEFORE allocating a variable
    /// (a foreign handle could otherwise alias a fresh variable), and leave `rel` untouched on
    /// error.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`;
    /// [`Error::DegenerateInput`] for (decoded) parameters `pp` under which the clause would not
    /// bind `usk` (implementation note). Nothing is appended and nothing is allocated on error.
    fn issuance_clauses(
        pp: &Self::PublicParams,
        c: &Self::IssuanceEncoding,
        m_pub: &G::ScalarField,
        rel: &mut GroupRelation<G>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error>;

    /// The values of the variables allocated by [`Self::issuance_clauses`]; `usk` is not
    /// included.
    fn issuance_witness(
        m_hid: &Self::HiddenMessage,
        r: &Self::IssuanceState,
    ) -> Witness<G::ScalarField>;
}
