//! The modular threshold predicate credential construction (paper §5.1, protocol box "Modular
//! threshold predicate credential construction"), generic over the pairing `E`, a sigma-friendly
//! credential base `B`, a sigma-friendly tag `T` over `G_1`, and a public attribute policy `P`.
//!
//! | paper (protocol box) | here |
//! |---|---|
//! | `Setup(1^λ) → pp` | [`PredicateCredentialSystem::setup`]; [`PCS::from_public_parameters`] for a received `pp` |
//! | `HKeyGen`, `UKeyGen` | [`PredicateCredentialSystem::helper_keygen`], [`PredicateCredentialSystem::user_keygen`] |
//! | `Attest`, `VerifyAtt` | [`PredicateCredentialSystem::attest`], [`PredicateCredentialSystem::verify_attestation`] ([`PCS::check_attestation`] names the reason) |
//! | `Prove`, `VerifyProof` | [`PredicateCredentialSystem::prove`], [`PredicateCredentialSystem::verify_proof`] ([`PCS::check_proof`] names the reason) |
//! | `Issue`, `Unblind`, `VerifyCred` | [`PredicateCredentialSystem::issue`], [`PredicateCredentialSystem::unblind`], [`PredicateCredentialSystem::verify_cred`] |
//! | the auxiliary routine `CheckAtts_P` | run by `prove` and by `check_proof`, exactly as displayed |
//! | `R_att`, `R_issue` (§5.1, "Building blocks") | [`PCS::attestation_relation`], [`PCS::issuance_relation`], with the witnesses [`PCS::attestation_witness`], [`PCS::issuance_witness`] |
//! | `ctx_j`, `ctx_0` | [`PCS::attestation_context`], [`PCS::issuance_context`] |
//! | root credentials (Remark "Chaining and the base case") | [`PCS::root_request`], [`PCS::verify_root_request`], [`PCS::issue_root`] |
//!
//! # In formulas
//!
//! Every public value of a user is a tag under its key: $`id = \mathsf{Tag}(usk, c_0)`$, an attestation
//! for $`id`$ carries $`T_j = \mathsf{Tag}(usk_j, s)`$ and an issuance proof carries
//! $`T_0 = \mathsf{Tag}(usk, s)`$, at the point $`s = H_0(id)`$. The two relations of §5.1, in which the
//! same component $`usk`$ of $`m_{\mathsf{hid}}`$ is shared by all clauses:
//!
//! ```math
//! \begin{aligned}
//! R_{\mathsf{att}} = \Bigl\{\, \bigl((vk, cred^{*}, \varphi, T, s),\ (m_{\mathsf{hid}}, \omega)\bigr) \;:\;\ & \bigl((vk, cred^{*}, \varphi),\ (m_{\mathsf{hid}}, \omega)\bigr) \in R_{\mathsf{Possess}} \\
//! & \wedge\ \bigl((T, s),\ usk\bigr) \in R_{\mathsf{Tag}} \,\Bigr\} \\[0.6em]
//! R_{\mathsf{issue}} = \Bigl\{\, \bigl((vk, C, \varphi, id, T_0, c_0, s),\ (m_{\mathsf{hid}}, \rho)\bigr) \;:\;\ & C = \mathsf{Com}(m_{\mathsf{hid}}, \varphi; \rho) \ \wedge\ \bigl((id, c_0),\ usk\bigr) \in R_{\mathsf{Tag}} \\
//! & \wedge\ \bigl((T_0, s),\ usk\bigr) \in R_{\mathsf{Tag}} \,\Bigr\}
//! \end{aligned}
//! ```
//!
//! `CheckAtts_P` accepts $`k`$ attestations iff each one verifies, the tags $`T_1, \dots, T_k`$ are
//! pairwise distinct, $`T_0 \notin \{T_1, \dots, T_k\}`$ and $`P(\varphi_1, \dots, \varphi_k) = 1`$.
//!
//! # What the paper claims, and under which hypotheses
//!
//! For a correct credential base and a sigma-friendly non-adaptive KI-PRF the construction is
//! correct and has proof-gated issuance (Theorem "Correctness and proof-gated issuance"; the
//! probability is `1` for `Tag_DDH` with `Σ-PS` and `Σ-EQ`, `1 − 1/p` with `Σ-BBS`, whose
//! `BlindIssue` returns `⊥` on the one `ρ` with `C = 1`, and `1 − k/p` for `Tag_DY`, whose
//! `Attest` outputs `⊥` when `usk_j = −H_0(id)`). In the random-oracle model the paper further states Theorems "Knowledge
//! soundness", "Credential unforgeability", "Predicate soundness", "Attester anonymity" and
//! "Subject privacy", each under the hypotheses on `Σ`, `Tag` and the sigma protocols listed
//! there. This crate compiles the proofs with PLAIN Fiat-Shamir. Remark "Concurrent issuance"
//! takes straight-line extractable proofs as the default instantiation and says of this case:
//! "With plain Fiat-Shamir the theorems still hold for sequential issuance and constant `k`,
//! with the losses just described." The code does not enforce sequential issuance.
//!
//! Implementation note on correctness: one more event of probability `1/p` ends in `⊥` here,
//! `EncPred(f) = 0` ([`enc_pred`]; `Σ-EQ` has no message for it). Def. "Correctness" asks for
//! `1 − negl`, so nothing changes for the theorem itself.
//!
//! # Implementation notes
//!
//! How the code realizes the box, and what it adds. None of it changes what honest parties
//! compute.
//!
//! * **Threshold at least one.** The predicate family is `F = {f_k}_{k ≥ 1}`: `CheckAtts_P`
//!   would accept the empty list for `k = 0`. `prove`, `verify_proof` and `issue` reject
//!   threshold 0 ([`Error::ZeroThreshold`], the "`f_k ∉ F`" of `VerifyProof` step 3); here a
//!   threshold-0 predicate is a ROOT predicate `f_root ∉ F`, served by the root path only.
//! * **Root credentials.** Remark "Chaining and the base case": the user "sends the root
//!   request `(C, T_0, π_0)`", computed "as in `Prove`, with the empty list of attestations" and
//!   under a context of its own, `ctx_root`. This is [`RootRequest`], [`PCS::root_request`],
//!   [`PCS::verify_root_request`] and [`PCS::issue_root`]. The helper calls `issue_root` ONLY
//!   after its out-of-band admission check: the request proves that `C` and `id` are under one
//!   key, not that the key should be admitted, and `f_root` "is fixed by the issuer, never named
//!   by the requester". `unblind` and `verify_cred` are shared with the ordinary path.
//! * **Exactly `k` attestations.** `VerifyProof` step 3 rejects "a number of attestations in `π`
//!   other than the threshold `k` of `f_k`" ([`Error::WrongAttestationCount`]). `EncPred(f_k)`
//!   is a hash and would not tell the helper the threshold, so `f_k` itself is part of `ctx_0`.
//! * **Received objects are re-validated.** In the paper `id`, `T_j`, `T_0`, `C`, `cred*`,
//!   `ĉred`, `hvk` are group elements by definition. A value of type `E::G1` is one only if
//!   whoever built it made sure (validated decoding does; unvalidated or uncompressed decoding
//!   and hand-built values do not). No algorithm here depends on that: every algorithm that
//!   consumes an object of another party first runs `ark_serialize::Valid::check` on it, i.e.
//!   checks that EVERY group element is on its curve and in the prime-order subgroup, and
//!   outputs `⊥` otherwise ([`Error::InvalidGroupElement`]; `false` for the three verifiers):
//!   `VerifyAtt` (`hvk`, `id`, `att_j`), `VerifyProof` and `Issue` (`hvk`, `id`, all of `π`),
//!   the root path (`hvk`, `id`, the request), `Prove` (`hvk`, the attestations), `Attest`
//!   (`id`), `Unblind` (`hvk`, `ĉred`), `VerifyCred` (`hvk`, `cred`). This is load-bearing and
//!   not a formality. Pairing equations do not see a component of small order in a `G_1`
//!   argument, and the Schnorr clause of a tag `T' = T + P_3` with `P_3` of order 3 (the
//!   cofactor of BLS12-381 `G_1` is divisible by 3) verifies for a guessed `c mod 3`, i.e. after
//!   three attempts on average. `T'` is a different point than `T`, so ONE attester would pass
//!   the distinctness check of `CheckAtts_P` as two, and a requester with `T_0' = T_0 + P_3`
//!   would pass the self-exclusion check with its own attestation
//!   (`tests/pcs_review_regressions.rs` mounts both against every base).
//! * **Keys and identifiers are checked.** `hvk ∉ V_pp` is malformed input for `VerifyAtt`,
//!   `VerifyProof`, `Unblind` and `VerifyCred` (the box): every verifier runs
//!   [`CredentialBase::is_well_formed_key`](crate::cred::CredentialBase::is_well_formed_key),
//!   the membership test for the range of `KeyGen`, once per call and not once per attestation,
//!   because a credential under a key that certifies nothing is not "bound to the user key".
//!   In addition an identifier has to be an admissible tag encoding, `ValidTag(id, c_0) = 1`,
//!   for `attest` and `verify_attestation` as well, not only where `R_issue` contains
//!   `((id, c_0), usk) ∈ R_Tag`.
//! * **`Prove` checks `id = Tag(usk, c_0)`** ([`Error::IdentifierMismatch`]) right after its
//!   checks of the threshold, of the number of attestations and of `hvk`, and before it
//!   evaluates `CheckAtts_P`. Together with `T_0 ≠ ⊥` (step 6 of the box) this is the first
//!   condition of `R_PCS`, `(id, usk) ∈ supp(UKeyGen(pp))`. `Prove`
//!   builds `R_issue` and `ctx_0` from the statement exactly as the verifier will reconstruct
//!   it from `(π, id)`, with the same code.
//! * **`Issue` compares the two copies of `hvk`** (its argument and the one inside
//!   `hsk = (sk, hvk)`), and returns [`Error::InvalidKey`] if they differ.
//! * **A helper key belongs to ONE deployment.** `HKeyGen` records the digest of `pp` inside
//!   `hsk` ([`HelperSecretKey`]), and `Issue` and the root path return [`Error::InvalidKey`]
//!   under another `pp`. A credential of `Σ-PS` or `Σ-EQ` is a signature under `hvk` and
//!   nothing else (`pp_Σ` is empty), so a key that served two deployment labels would certify,
//!   in each of them, endorsers of the other; under the default policy `P ≡ 1`, which accepts
//!   ANY disclosed label `φ_j`, they would count (`docs/operating-a-helper.md`).
//! * **`Unblind` fails closed** (module docs of [`crate::pcs`], "Rules the construction has to
//!   keep"): it returns [`Error::InvalidPreCredential`] unless the credential it is about to
//!   return passes `VerifyCred`.
//! * **`UKeyGen` is guarded and bounded.** The loop of the box restarts while a tag is `⊥`. A
//!   [`PCS`] only exists for tag parameters that passed [`check_compatibility`], and the loop
//!   gives up after [`MAX_KEYGEN_ATTEMPTS`] restarts, each of which has probability about `2/p`
//!   under well-formed parameters.
//! * **Standing endorsements.** As in the paper, "a set `{att_j}` collected once remains valid
//!   indefinitely and may be presented in any number of later issuance requests for that
//!   identifier, under any predicate `f`" (Remark "Attestations are standing endorsements").
//!   Neither of the two remedies of that Remark is implemented.
//!
//! # Example
//!
//! Two root members endorse a newcomer, who obtains a credential for the threshold predicate
//! `f_2` and can endorse others from then on:
//!
//! ```
//! use ark_bls12_381::{Bls12_381, G1Projective};
//! use predicate_credential_system::{
//!     cred::PS,
//!     hash::bls12_381::G1Hasher,
//!     kiprf::DDH,
//!     pcs::{PCS, Predicate, PredicateCredentialSystem, SetupParams},
//! };
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type Scheme = PCS<Bls12_381, PS<Bls12_381>, DDH<G1Projective, G1Hasher>>;
//!
//! let mut rng = StdRng::seed_from_u64(1);
//! let pcs = Scheme::setup(SetupParams::new(b"example deployment".to_vec()))?;
//! let (hvk, hsk) = pcs.helper_keygen(&mut rng);
//! let f_root = Predicate::root(b"founders".to_vec());
//! let f = Predicate::new(2, b"members".to_vec());
//!
//! // Root credentials: the helper admits two founders out of band. It never sees a user key.
//! let mut founders = Vec::new();
//! for _ in 0..2 {
//!     let (id_j, usk_j) = pcs.user_keygen(&mut rng)?;
//!     let (request, state) = pcs.root_request(&hvk, &f_root, &id_j, &usk_j, &mut rng)?;
//!     let pre = pcs.issue_root(&hvk, &hsk, &f_root, &id_j, &request, &mut rng)?;
//!     let cred_j = pcs.unblind(&hvk, &usk_j, &f_root, &pre, &state)?;
//!     founders.push((usk_j, cred_j));
//! }
//!
//! // A newcomer collects one attestation per founder for its identifier ...
//! let (id, usk) = pcs.user_keygen(&mut rng)?;
//! let mut attestations = Vec::new();
//! for (usk_j, cred_j) in &founders {
//!     let att = pcs.attest(&hvk, usk_j, &f_root, cred_j, &id, &mut rng)?;
//!     assert!(pcs.verify_attestation(&hvk, &id, &att));
//!     attestations.push(att);
//! }
//! // ... proves that it holds them, and the helper issues on the proof alone.
//! let (proof, state) = pcs.prove(&hvk, &f, &id, &usk, &attestations, &mut rng)?;
//! assert!(pcs.verify_proof(&hvk, &f, &id, &proof));
//! let pre = pcs.issue(&hvk, &hsk, &f, &id, &proof, &mut rng)?;
//! let cred = pcs.unblind(&hvk, &usk, &f, &pre, &state)?;
//! assert!(pcs.verify_cred(&hvk, &usk, &f, &cred));
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

use core::fmt;
use std::collections::HashSet;

use ark_ec::{CurveGroup, pairing::Pairing};
use ark_serialize::Valid;
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use super::{
    PredicateCredentialSystem, check_compatibility,
    predicate::{AcceptAll, AllowList, AttributePolicy, Predicate, enc_pred},
    types::{
        Attestation, Credential, HelperSecretKey, IssuanceProof, IssuanceState, PublicParameters,
        RootRequest, SetupParams, UserSecretKey,
    },
};
use crate::{
    cred::{
        SigmaFriendlyCredentialBase, issuance_witness_vector, possession_relation,
        possession_witness_vector,
    },
    error::Error,
    hash::{h0_id, h0_identity_point},
    kiprf::PCSTag,
    sigma::{FSProof, PairingRelation, Witness, fiat_shamir},
};

/// Upper bound on the restarts of the `UKeyGen` loop (construction box, `UKeyGen` steps 3 and
/// 5). Under well-formed tag parameters one attempt restarts with probability about `2/p` (the
/// contract of [`PCSTag::is_well_formed`]), so running into the bound means broken parameters.
pub const MAX_KEYGEN_ATTEMPTS: usize = 64;

/// Re-validation of an object that comes from another party: every group element in it is on
/// its curve and in the prime-order subgroup (`ark_serialize::Valid::check`, which is what
/// validated decoding runs). `what` names the argument in the error.
///
/// Implementation note (module docs, "Received objects are re-validated"): the paper's
/// elements are group elements by definition; this is where the code makes them so, whatever
/// way the caller obtained the value.
fn validate<V: Valid + ?Sized>(value: &V, what: &'static str) -> Result<(), Error> {
    value.check().map_err(|_| Error::InvalidGroupElement(what))
}

/// [`validate`] for a sequence, as ONE batch (one batch normalization per field).
fn validate_all<'a, V: Valid + 'a>(
    values: impl Iterator<Item = &'a V> + Send,
    what: &'static str,
) -> Result<(), Error> {
    V::batch_check(values).map_err(|_| Error::InvalidGroupElement(what))
}

/// The modular threshold predicate credential construction of §5.1: a predicate credential
/// system for the threshold predicates [`Predicate`] and the authorization relation of Def.
/// "Threshold authorization relation" with the public attribute policy `P`.
///
/// A value of this type *is* the public parameters `pp` together with the policy; the ten
/// algorithms are the methods of [`PredicateCredentialSystem`]. See the [module docs](self) for
/// the map to the protocol box, the claims of the paper and the implementation notes.
///
/// Compatible instantiations: [`PS`](crate::cred::PS) and
/// [`BBS`](crate::cred::BBS) with [`DDH`](crate::kiprf::DDH) or
/// [`DY`](crate::kiprf::DY), and [`EQ`](crate::cred::EQ) with
/// `DDH`. `Setup` refuses `Σ-EQ` with `Tag_DY`.
#[derive(Clone)]
pub struct PCS<E, B, T, P = AcceptAll>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    pub(super) pp: PublicParameters<E, B, T>,
    /// [`PublicParameters::digest`], computed once; it leads every Fiat-Shamir context.
    pub(super) pp_digest: [u8; 32],
    pub(super) policy: P,
}

impl<E, B, T, P> fmt::Debug for PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PCS")
            .field("pp", &self.pp)
            .field("pp_digest", &self.pp_digest)
            .finish_non_exhaustive()
    }
}

/// The verifier's view of the statement of `R_issue`, shared by `Prove`, `VerifyProof` and the
/// root path.
struct IssuanceStatement<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    /// `s = H_0(id)`.
    s: E::ScalarField,
    /// `C`: parsed from the wire, or `C := id` for `Σ-EQ`.
    c: B::IssuanceEncoding,
    /// `R_issue` for `(vk, C, φ, id, T_0, c_0, s)`.
    relation: PairingRelation<E>,
}

/// What `Prove` steps 3-11 and 14 produce: the parts `(C, T_0, π_0)` of `π` and `st_iss`.
struct IssuanceParts<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    /// What travels for `C`.
    encoding: B::WireEncoding,
    /// `T_0 = Tag(usk, H_0(id))`.
    t0: E::G1,
    /// `π_0`.
    proof: FSProof<E::ScalarField>,
    /// `st_iss = (m_hid, φ, ρ)`.
    state: IssuanceState<E, B>,
}

// ---------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------

impl<E, B, T, P> PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    /// `Setup` steps 1-5 for the deployment `label`, without any check.
    fn derive_parameters(label: &[u8]) -> Result<PublicParameters<E, B, T>, Error> {
        // 2. Fix EncPred and the random oracles H_0, H_1: fixed functions of the label.
        // 3. c_0 := H_0("identity")   (before step 1, because pp_Tag depends on it)
        let c0: E::ScalarField = h0_identity_point(label);
        // 1. Generate [...] algebraic parameters pp_Σ and pp_Tag.
        let pp_sigma = B::setup(label)?;
        // 4. For Σ-EQ with Tag_DDH, set H_2(c_0) := g_1. (`PCSTag::setup` of `Tag_DDH` programs
        //    the point for every base, following Remark "Identity point".)
        let pp_tag = T::setup(label, c0)?;
        // 5. pp := (pp_Σ, pp_Tag, EncPred, H_0, H_1, c_0)
        Ok(PublicParameters {
            label: label.to_vec(),
            pp_sigma,
            pp_tag,
            c0,
        })
    }

    /// The checks every constructor runs: "compatible" of `Setup` step 1 and the
    /// well-formedness of `pp_Tag` ([`check_compatibility`]); then the digest of `pp`.
    fn assemble(pp: PublicParameters<E, B, T>, policy: P) -> Result<Self, Error> {
        check_compatibility::<E, B, T>(&pp.pp_tag, &pp.c0)?;
        let pp_digest = pp.digest()?;
        Ok(Self {
            pp,
            pp_digest,
            policy,
        })
    }

    /// Rebuilds the system from RECEIVED public parameters (decoded from the wire, read from a
    /// file) and the verifier's own policy.
    ///
    /// Implementation note. `Setup` is transparent: `pp` is a deterministic function of the
    /// deployment label. A received `pp` is therefore accepted only if it passes the checks of
    /// `Setup` AND equals what `Setup` derives from the label it carries. Parameters that are
    /// merely well formed are not good enough: generators of `Σ-BBS` with a known
    /// discrete-logarithm relation look like any others, and whoever knows such a relation
    /// attests under arbitrary keys with one credential (proof sketch of the Lemma on `Σ-BBS`;
    /// module docs of [`crate::cred::bbs`], "The possession proof").
    ///
    /// # Errors
    /// [`Error::DegenerateInput`]`("pp_Tag")` and [`Error::IncompatibleBaseAndTag`] as for
    /// `Setup` ([`check_compatibility`]); [`Error::InvalidPublicParameters`] if `c_0`, `pp_Tag`
    /// or `pp_Σ` is not the value derived from the label; the errors of `Setup` itself.
    pub fn from_public_parameters(pp: PublicParameters<E, B, T>, policy: P) -> Result<Self, Error> {
        check_compatibility::<E, B, T>(&pp.pp_tag, &pp.c0)?;
        let derived = Self::derive_parameters(&pp.label)?;
        if pp.c0 != derived.c0 {
            return Err(Error::InvalidPublicParameters(
                "c_0 is not H_0(\"identity\")",
            ));
        }
        if pp.pp_tag != derived.pp_tag {
            return Err(Error::InvalidPublicParameters(
                "pp_Tag is not derived from the label",
            ));
        }
        if pp.pp_sigma != derived.pp_sigma {
            return Err(Error::InvalidPublicParameters(
                "pp_Σ is not derived from the label",
            ));
        }
        Self::assemble(pp, policy)
    }

    /// `Setup` for base parameters `pp_Σ` that are NOT the ones [`CredentialBase::setup`] derives
    /// from the label, e.g. the IETF-compatible generators of `Σ-BBS`
    /// ([`BBSPublicParams::ietf`](crate::cred::bbs::BBSPublicParams::ietf)), which depend on the
    /// helper's key and therefore exist only after it. `c_0` and `pp_Tag` are derived from the
    /// label as in `Setup`; `pp_Σ` enters the digest of `pp`, so every proof is bound to it.
    ///
    /// Implementation note, and a WARNING. The soundness of a base rests on how its parameters
    /// were generated: whoever knows a discrete-logarithm relation among the generators of
    /// `Σ-BBS` attests under arbitrary keys with one credential. Pass only parameters that are
    /// transparently derived and that YOU computed; never parameters chosen by another party.
    /// For parameters received from outside use [`Self::from_public_parameters_with_base`].
    ///
    /// # Errors
    /// As `Setup`: [`check_compatibility`] and the errors of the derivation of `pp_Tag`.
    ///
    /// [`CredentialBase::setup`]: crate::cred::CredentialBase::setup
    pub fn setup_with_base_parameters(
        label: impl Into<Vec<u8>>,
        pp_sigma: B::PublicParams,
        policy: P,
    ) -> Result<Self, Error> {
        let mut pp = Self::derive_parameters(&label.into())?;
        pp.pp_sigma = pp_sigma;
        Self::assemble(pp, policy)
    }

    /// [`Self::from_public_parameters`] for a system that was set up with
    /// [`Self::setup_with_base_parameters`]: the received `pp` is accepted only if `c_0` and
    /// `pp_Tag` are the values derived from its label AND its `pp_Σ` equals `expected`, the base
    /// parameters the caller derived on its own (for `Σ-BBS` in its IETF form: from the
    /// helper's key and the header).
    ///
    /// # Errors
    /// As [`Self::from_public_parameters`], with [`Error::InvalidPublicParameters`] if `pp_Σ`
    /// differs from `expected`.
    pub fn from_public_parameters_with_base(
        pp: PublicParameters<E, B, T>,
        expected: &B::PublicParams,
        policy: P,
    ) -> Result<Self, Error> {
        check_compatibility::<E, B, T>(&pp.pp_tag, &pp.c0)?;
        let derived = Self::derive_parameters(&pp.label)?;
        if pp.c0 != derived.c0 {
            return Err(Error::InvalidPublicParameters(
                "c_0 is not H_0(\"identity\")",
            ));
        }
        if pp.pp_tag != derived.pp_tag {
            return Err(Error::InvalidPublicParameters(
                "pp_Tag is not derived from the label",
            ));
        }
        if &pp.pp_sigma != expected {
            return Err(Error::InvalidPublicParameters(
                "pp_Σ is not the expected base parameters",
            ));
        }
        Self::assemble(pp, policy)
    }

    /// The public parameters `pp`, e.g. to publish them ([`PublicParameters`] is canonically
    /// serializable; [`Self::from_public_parameters`] is the way back).
    #[must_use]
    pub fn public_parameters(&self) -> &PublicParameters<E, B, T> {
        &self.pp
    }

    /// The deployment label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.pp.label
    }

    /// `pp_Σ`.
    #[must_use]
    pub fn base_parameters(&self) -> &B::PublicParams {
        &self.pp.pp_sigma
    }

    /// `pp_Tag`: the tag function.
    #[must_use]
    pub fn tag(&self) -> &T {
        &self.pp.pp_tag
    }

    /// The identity point `c_0 = H_0("identity")`.
    #[must_use]
    pub fn identity_point(&self) -> &E::ScalarField {
        &self.pp.c0
    }

    /// The digest of `pp` that leads every Fiat-Shamir context ([`PublicParameters::digest`]).
    #[must_use]
    pub fn parameters_digest(&self) -> &[u8; 32] {
        &self.pp_digest
    }

    /// The public attribute policy `P`.
    #[must_use]
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// `φ = EncPred(f) = H_0("predicate" ‖ ⟨f⟩)` in this deployment ([`enc_pred`]).
    ///
    /// # Errors
    /// [`Error::DegenerateInput`] if `EncPred(f) = 0`.
    pub fn enc_pred(&self, f: &Predicate) -> Result<E::ScalarField, Error> {
        enc_pred(&self.pp.label, f)
    }

    /// The attribute policy that admits exactly the attesters whose credentials were issued
    /// under one of `predicates` IN THIS DEPLOYMENT: the allow list over `EncPred(f)` for the
    /// label of this `pp` ([`AllowList::from_predicates`] with the right deployment label filled
    /// in). Hand it to [`Self::from_public_parameters`] (or to `Setup`) to obtain the verifier
    /// that enforces it; leaving a root predicate off the list means that root credentials do
    /// not count toward a threshold.
    ///
    /// Implementation note: under `P ≡ 1` ([`AcceptAll`], the default) a credential under `hvk`
    /// counts whatever label `φ_j` it discloses. A helper that serves a closed set of predicates
    /// says so with this policy (`docs/operating-a-helper.md`).
    ///
    /// # Errors
    /// [`Error::DegenerateInput`] if `EncPred(f) = 0` for one of the predicates.
    pub fn allow_list<'a>(
        &self,
        predicates: impl IntoIterator<Item = &'a Predicate>,
    ) -> Result<AllowList<E::ScalarField>, Error> {
        AllowList::from_predicates(&self.pp.label, predicates)
    }

    /// `s = H_0(id)`, the point at which the tags of the attesters of `id`, and the
    /// self-exclusion tag of `id`, are evaluated.
    ///
    /// # Errors
    /// [`Error::Serialization`] if `id` cannot be serialized (it can).
    pub fn tag_point(&self, id: &E::G1) -> Result<E::ScalarField, Error> {
        h0_id(&self.pp.label, id)
    }

    /// `UKeyGen` steps 2-5 for a GIVEN key: `id = Tag(usk, c_0)`, provided that `id` and
    /// `T_0 = Tag(usk, H_0(id))` are defined, i.e. `(id, usk) ∈ supp(UKeyGen(pp))`.
    ///
    /// # Errors
    /// [`Error::UndefinedTag`] if one of the two evaluations is `⊥` (the key `0` for `Tag_DDH`;
    /// `usk ∈ {−c_0, −H_0(id)}` for `Tag_DY`).
    pub fn identity(&self, usk: &UserSecretKey<E>) -> Result<E::G1, Error> {
        // 2. id ← Tag(usk, c_0)       3. if id = ⊥ ...
        let id = self
            .pp
            .pp_tag
            .eval(&usk.0, &self.pp.c0)
            .ok_or(Error::UndefinedTag)?;
        // 4. T_0 ← Tag(usk, H_0(id))  5. if T_0 = ⊥ ...
        let s = self.tag_point(&id)?;
        self.pp.pp_tag.eval(&usk.0, &s).ok_or(Error::UndefinedTag)?;
        Ok(id)
    }
}

// ---------------------------------------------------------------------------------------------
// The relations R_att and R_issue
// ---------------------------------------------------------------------------------------------

impl<E, B, T, P> PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    /// `R_att` for the public statement `(vk, cred*, φ, T, s)` (§5.1, "Building blocks"): the
    /// clauses of `R_Possess` for `(vk, cred*, φ)` and the clause of `R_Tag` for `(T, s)`, where
    /// "the same component `usk` of `m_hid` is shared by all clauses".
    ///
    /// Variable 0 is the shared `usk`; the variables of the possession clauses follow
    /// ([`SigmaFriendlyCredentialBase::POSSESSION_VARIABLES`] many); the tag clause adds none.
    /// The matching witness is [`Self::attestation_witness`]. The public pre-checks of the
    /// statement (`ValidTag`, the public checks of `VerifyPossess`) are NOT part of the linear
    /// relation; [`Self::check_attestation`] runs them.
    ///
    /// Public so that a harness can run the interactive protocol of [`crate::sigma`], its
    /// simulator and its extractor on exactly the relation the attestation proofs use.
    ///
    /// # Errors
    /// Propagates the errors of the clause builders of the base.
    pub fn attestation_relation(
        &self,
        hvk: &B::VerificationKey,
        shown: &B::ShownCredential,
        phi: &E::ScalarField,
        tag: &E::G1,
        s: &E::ScalarField,
    ) -> Result<PairingRelation<E>, Error> {
        // ((vk, cred*, φ), (m_hid, ω)) ∈ R_Possess, with usk as variable 0
        let (mut relation, usk) = possession_relation::<E, B>(&self.pp.pp_sigma, hvk, shown, phi)?;
        // ∧ ((T, s), usk) ∈ R_Tag, on the SAME variable
        for equation in self.pp.pp_tag.tag_equations(usk, tag, s) {
            relation.add_g1(equation)?;
        }
        Ok(relation)
    }

    /// The witness `(m_hid, ω)` of `R_att`, in the variable order of
    /// [`Self::attestation_relation`]: `usk`, then the values of the possession variables.
    #[must_use]
    pub fn attestation_witness(
        m_hid: &B::HiddenMessage,
        show_state: &B::ShowState,
    ) -> Witness<E::ScalarField> {
        possession_witness_vector::<E, B>(m_hid, show_state)
    }

    /// `R_issue` for the public statement `(vk, C, φ, id, T_0, c_0, s)` (§5.1, "Building
    /// blocks"): the opening clause `C = Com(m_hid, φ; ρ)`, the clause of `R_Tag` for
    /// `(id, c_0)` and the clause of `R_Tag` for `(T_0, s)`, in this order, where "the same
    /// component `usk` of `m_hid` is shared by all clauses". For `Σ-EQ` "the duplicate opening
    /// clause is omitted": `C = id` is bound by the identifier clause.
    ///
    /// Variable 0 is the shared `usk`; the variables of the opening clause follow
    /// ([`SigmaFriendlyCredentialBase::ISSUANCE_VARIABLES`] many). The matching witness is
    /// [`Self::issuance_witness`] ([`IssuanceState::witness`] for the state `Prove` returned).
    /// `c_0` is taken from `pp`. The relation is the same for issuance proofs and for root
    /// requests; their contexts differ.
    ///
    /// # Errors
    /// Propagates the errors of the clause builder of the base; [`Error::LengthMismatch`] if a
    /// base allocates another number of variables than its `ISSUANCE_VARIABLES` (none of this
    /// crate does; the fixed format of `π_0` relies on the constant).
    pub fn issuance_relation(
        &self,
        hvk: &B::VerificationKey,
        c: &B::IssuanceEncoding,
        phi: &E::ScalarField,
        id: &E::G1,
        t0: &E::G1,
        s: &E::ScalarField,
    ) -> Result<PairingRelation<E>, Error> {
        let mut relation = PairingRelation::new();
        let usk = relation.alloc_scalar();
        // C = Com(m_hid, φ; ρ)
        let allocated = B::issuance_clauses(&self.pp.pp_sigma, hvk, c, phi, &mut relation, usk)?;
        if allocated.len() != B::ISSUANCE_VARIABLES {
            return Err(Error::LengthMismatch {
                expected: B::ISSUANCE_VARIABLES,
                actual: allocated.len(),
            });
        }
        // ∧ ((id, c_0), usk) ∈ R_Tag  ∧ ((T_0, s), usk) ∈ R_Tag, on the SAME variable
        let tag = &self.pp.pp_tag;
        for equation in tag
            .tag_equations(usk, id, &self.pp.c0)
            .into_iter()
            .chain(tag.tag_equations(usk, t0, s))
        {
            relation.add_g1(equation)?;
        }
        Ok(relation)
    }

    /// The witness `(m_hid, ρ)` of `R_issue`, in the variable order of
    /// [`Self::issuance_relation`]: `usk`, then the values of the opening variables.
    #[must_use]
    pub fn issuance_witness(
        m_hid: &B::HiddenMessage,
        rho: &B::IssuanceState,
    ) -> Witness<E::ScalarField> {
        issuance_witness_vector::<E, B>(m_hid, rho)
    }

    /// `vk := hvk` (step 1 of `VerifyAtt`, `Prove`, `Unblind` and `VerifyCred`; `VerifyProof`
    /// and the root path use `hvk` as well). Implementation note: `hvk` is part of every
    /// statement. Its components have to be group elements ([`validate`];
    /// [`Error::InvalidGroupElement`]), and it has to lie in the range of `KeyGen`
    /// ([`CredentialBase::is_well_formed_key`](crate::cred::CredentialBase::is_well_formed_key),
    /// [`Error::InvalidKey`]; for `Σ-PS` this is a pairing product). Every algorithm runs both
    /// ONCE per call.
    fn check_key(&self, hvk: &B::VerificationKey) -> Result<(), Error> {
        validate(hvk, "hvk")?;
        if B::is_well_formed_key(&self.pp.pp_sigma, hvk) {
            Ok(())
        } else {
            Err(Error::InvalidKey)
        }
    }

    /// `VerifyCred` steps 2-6 (construction box), for an `hvk` that passed [`Self::check_key`].
    fn credential_verifies(
        &self,
        hvk: &B::VerificationKey,
        usk: &UserSecretKey<E>,
        f: &Predicate,
        cred: &Credential<E, B>,
    ) -> bool {
        // 2. φ := EncPred(f)
        let Ok(phi) = self.enc_pred(f) else {
            return false;
        };
        // 3. Parse cred as (cred_Σ, m_aux).
        let (cred_sigma, aux) = (&cred.cred, &cred.aux);
        // 4. m_hid := (usk, m_aux)
        let m_hid = Zeroizing::new(B::hidden_message(&usk.0, aux));
        // 5. m := Enc_Σ(m_hid, φ)
        let Ok(m) = B::encode_message(&self.pp.pp_sigma, &m_hid, &phi) else {
            return false;
        };
        let m = Zeroizing::new(m);
        // 6. Return Σ.Verify(vk, m, cred_Σ).
        B::verify(&self.pp.pp_sigma, hvk, &m, cred_sigma)
    }

    /// The public part of `VerifyProof` that does not depend on the attestations, shared with
    /// `Prove` (which thereby proves about exactly what the verifier will reconstruct) and with
    /// the root path: `φ`, `s`, the public pre-checks `ValidTag(id, c_0)` and `ValidTag(T_0, s)`
    /// of the two tag clauses, `C`, and `R_issue`. The caller has checked `hvk`
    /// ([`Self::check_key`]).
    fn issuance_statement(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        encoding: &B::WireEncoding,
        t0: &E::G1,
    ) -> Result<IssuanceStatement<E, B>, Error> {
        let phi = self.enc_pred(f)?;
        let s = self.tag_point(id)?;
        if !self.pp.pp_tag.valid_tag(id, &self.pp.c0) || !self.pp.pp_tag.valid_tag(t0, &s) {
            return Err(Error::InvalidTag);
        }
        // For Σ-EQ set C := id; otherwise C is the one parsed from π.
        let c = B::encoding_from_wire(&self.pp.pp_sigma, encoding, id)
            .ok_or(Error::InvalidIssuanceEncoding)?;
        let relation = self.issuance_relation(hvk, &c, &phi, id, t0, &s)?;
        Ok(IssuanceStatement { s, c, relation })
    }
}

// ---------------------------------------------------------------------------------------------
// Verification with reasons, CheckAtts_P
// ---------------------------------------------------------------------------------------------

impl<E, B, T, P> PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
    P: AttributePolicy<E::ScalarField>,
{
    /// `VerifyAtt(hvk, id, att_j)` with the reason for a rejection: `Ok(())` iff
    /// [`PredicateCredentialSystem::verify_attestation`] returns `true`. A function of public
    /// data; never panics.
    ///
    /// Implementation note: the verdict does not depend on how `hvk`, `id` and `att_j` were
    /// built. All three are re-validated first (every group element on its curve and in the
    /// prime-order subgroup), so a value that was decoded without validation or assembled by
    /// hand is judged like one that came through
    /// [`Attestation::from_compact_bytes`] (module docs, "Received objects are re-validated").
    ///
    /// # Errors
    /// [`Error::InvalidGroupElement`] if `hvk`, `id` or `att_j` contains a value that is not an
    /// element of its group; [`Error::InvalidKey`] if `hvk` is not well formed;
    /// [`Error::InvalidTag`] if `ValidTag(id, c_0) = 0` or `ValidTag(T_j, s) = 0`;
    /// [`Error::InvalidCredential`] if `cred*_j` fails the public checks of `VerifyPossess`;
    /// [`Error::InvalidProof`] if `π_j` does not verify for the rebuilt context.
    pub fn check_attestation(
        &self,
        hvk: &B::VerificationKey,
        id: &E::G1,
        att: &Attestation<E, B>,
    ) -> Result<(), Error> {
        // 1. vk := hvk   (implementation note: hvk has to lie in the range of KeyGen)
        self.check_key(hvk)?;
        // 3. Reject malformed input: id and every element of att_j are group elements
        //    (implementation note: whatever way they were built) ...
        validate(id, "id")?;
        validate(att, "att")?;
        // ... and an identifier is an admissible tag encoding.
        if !self.pp.pp_tag.valid_tag(id, &self.pp.c0) {
            return Err(Error::InvalidTag);
        }
        // 4. s := H_0(id)
        let s = self.tag_point(id)?;
        self.check_attestation_at(hvk, id, &s, att, None)
    }

    /// [`PCS::check_attestation`] under an application context `app_j`: the attestation must
    /// have been made by [`PCS::attest_in_context`] with the same bytes
    /// ([`PCS::attestation_context_with_app`]). The verifier supplies `app_j` from its own copy
    /// of the public data. Implementation note, not in the paper.
    ///
    /// # Errors
    /// As [`PCS::check_attestation`]; [`Error::InvalidProof`] also when `app_j` differs from
    /// the context the attestation was made under.
    pub fn check_attestation_in_context(
        &self,
        hvk: &B::VerificationKey,
        id: &E::G1,
        att: &Attestation<E, B>,
        app: &[u8],
    ) -> Result<(), Error> {
        self.check_key(hvk)?;
        validate(id, "id")?;
        validate(att, "att")?;
        if !self.pp.pp_tag.valid_tag(id, &self.pp.c0) {
            return Err(Error::InvalidTag);
        }
        let s = self.tag_point(id)?;
        self.check_attestation_at(hvk, id, &s, att, Some(app))
    }

    /// `VerifyAtt` steps 2-6 for a well-formed `hvk`, an admissible `id`, `s = H_0(id)` and a
    /// RE-VALIDATED `att_j` (the callers of `CheckAtts_P` establish the four once for all `k`
    /// attestations; [`validate`]).
    fn check_attestation_at(
        &self,
        hvk: &B::VerificationKey,
        id: &E::G1,
        s: &E::ScalarField,
        att: &Attestation<E, B>,
        app: Option<&[u8]>,
    ) -> Result<(), Error> {
        // 2. Parse att_j as (T_j, cred*_j, φ_j, π_j).
        // 3. Reject malformed input: the elements are decoded with validation, and a π_j with
        //    another number of responses than R_att has variables is rejected by Verify_FS.
        // 6. [ValidTag(T_j, s) ∧ ...
        if !self.pp.pp_tag.valid_tag(&att.tag, s) {
            return Err(Error::InvalidTag);
        }
        // ... "the Fiat-Shamir verifier includes the public checks of VerifyPossess"
        if !B::verify_possess_public(&self.pp.pp_sigma, hvk, &att.shown, &att.phi) {
            return Err(Error::InvalidCredential);
        }
        // 5. ctx_j := (pp, hvk, id, φ_j, T_j, cred*_j [, app_j]), REBUILT from the public
        //    statement
        let ctx =
            self.attestation_context_with_app(hvk, id, &att.phi, &att.tag, &att.shown, app)?;
        // 6. ... ∧ Verify_FS(ctx_j, π_j)]
        let relation = self.attestation_relation(hvk, &att.shown, &att.phi, &att.tag, s)?;
        if fiat_shamir::verify(&relation, &ctx, &att.proof) {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    /// The auxiliary routine `CheckAtts_P(hvk, id, T_0, (att_j)_{j ∈ [k]})` of §5.1, for a
    /// well-formed `hvk`, an admissible `id`, `s = H_0(id)`, and attestations and a `T_0` that
    /// the caller has re-validated ([`validate`]): the comparison of tags below is a comparison
    /// of GROUP ELEMENTS, and it means "distinct keys" only for elements of the prime-order
    /// group (key injectivity of `Tag` is a statement about those).
    fn check_atts(
        &self,
        hvk: &B::VerificationKey,
        id: &E::G1,
        s: &E::ScalarField,
        t0: &E::G1,
        attestations: &[Attestation<E, B>],
        att_apps: Option<&[&[u8]]>,
    ) -> Result<(), Error> {
        // Implementation note: one application context per attestation, or none at all.
        if let Some(att_apps) = att_apps
            && att_apps.len() != attestations.len()
        {
            return Err(Error::WrongAttestationCount {
                expected: attestations.len(),
                actual: att_apps.len(),
            });
        }
        // 1.-6. for j ∈ [k]: if VerifyAtt(hvk, id, att_j) = 0 return 0; parse att_j
        for (j, att) in attestations.iter().enumerate() {
            let app = att_apps.map(|apps| apps[j]);
            if self.check_attestation_at(hvk, id, s, att, app).is_err() {
                return Err(Error::InvalidAttestation);
            }
        }
        // Tags are compared as normalized points (one batch inversion for all of them).
        let mut points: Vec<E::G1> = attestations.iter().map(|att| att.tag).collect();
        points.push(*t0);
        let points = E::G1::normalize_batch(&points);
        let Some((t0, tags)) = points.split_last() else {
            return Err(Error::InvalidTag);
        };
        // 7.-9. if |{T_j : j ∈ [k]}| ≠ k return 0
        let distinct: HashSet<&E::G1Affine> = tags.iter().collect();
        if distinct.len() != attestations.len() {
            return Err(Error::DuplicateAttester);
        }
        // 10.-12. if T_0 ∈ {T_j : j ∈ [k]} return 0
        if distinct.contains(t0) {
            return Err(Error::SelfAttestation);
        }
        // 13. return P((φ_j)_{j ∈ [k]})
        let phis: Vec<E::ScalarField> = attestations.iter().map(|att| att.phi).collect();
        if self.policy.accepts(&phis) {
            Ok(())
        } else {
            Err(Error::PolicyRejected)
        }
    }

    /// `VerifyProof(hvk, f_k, id, π)` with the reason for a rejection: `Ok(())` iff
    /// [`PredicateCredentialSystem::verify_proof`] returns `true`. A function of public data;
    /// never panics.
    ///
    /// Implementation note: the verdict does not depend on how `hvk`, `id` and `π` were built.
    /// They are re-validated before anything is computed from them (every group element of
    /// `hvk`, of `id`, of `C`, `T_0` and of all `k` attestations is on its curve and in the
    /// prime-order subgroup), so a value that was decoded without validation or assembled by
    /// hand is judged like one that came through [`IssuanceProof::from_compact_bytes`] (module
    /// docs, "Received objects are re-validated"). The distinctness and self-exclusion checks
    /// of `CheckAtts_P` would be meaningless without it.
    ///
    /// # Errors
    /// [`Error::ZeroThreshold`] for a root predicate; [`Error::WrongAttestationCount`] unless
    /// `π` carries exactly `f.threshold` attestations; [`Error::InvalidGroupElement`] if `hvk`,
    /// `id` or `π` contains a value that is not an element of its group; [`Error::InvalidKey`],
    /// [`Error::InvalidTag`] (`id` or `T_0`), [`Error::InvalidIssuanceEncoding`] for an
    /// inadmissible statement; [`Error::InvalidAttestation`], [`Error::DuplicateAttester`],
    /// [`Error::SelfAttestation`], [`Error::PolicyRejected`] from `CheckAtts_P`;
    /// [`Error::InvalidProof`] if `π_0` does not verify for the rebuilt context. Implementation
    /// note: [`Error::DegenerateInput`] in the event `EncPred(f) = 0` (probability `1/p`);
    /// [`Error::Serialization`] if an element cannot be serialized into a context (it can).
    pub fn check_proof(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        proof: &IssuanceProof<E, B>,
    ) -> Result<(), Error> {
        self.check_proof_at(hvk, f, id, proof, None, None)
    }

    /// [`PCS::check_proof`] under application contexts: `att_apps[j]` is the context the
    /// `j`-th attestation was made under ([`PCS::attest_in_context`]) and `app` the proof's own
    /// context, e.g. the verifier's single-use challenge. The proof must have been made by
    /// [`PCS::prove_in_context`] with the same bytes; the verifier supplies all of them from
    /// its own copy of the public data. Implementation note, not in the paper.
    ///
    /// # Errors
    /// As [`PCS::check_proof`]; [`Error::WrongAttestationCount`] if `att_apps` does not have
    /// one entry per attestation; [`Error::InvalidAttestation`] if an attestation does not
    /// verify under its context; [`Error::InvalidProof`] if `π_0` does not verify under `app`.
    pub fn check_proof_in_context(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        proof: &IssuanceProof<E, B>,
        att_apps: &[&[u8]],
        app: &[u8],
    ) -> Result<(), Error> {
        self.check_proof_at(hvk, f, id, proof, Some(att_apps), Some(app))
    }

    /// `VerifyProof` with optional application contexts (shared by the two entry points above).
    fn check_proof_at(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        proof: &IssuanceProof<E, B>,
        att_apps: Option<&[&[u8]]>,
        app: Option<&[u8]>,
    ) -> Result<(), Error> {
        // Implementation note: f_0 is not a predicate of the ordinary path.
        if f.is_root() {
            return Err(Error::ZeroThreshold);
        }
        // 1./2. Parse π as ((att_j)_{j ∈ [k]}, [C,] T_0, π_0): T_0 is a mandatory field.
        // 3. Reject malformed input: EXACTLY k = f.threshold attestations.
        let actual = proof.attestations.len();
        if u32::try_from(actual).ok() != Some(f.threshold) {
            return Err(Error::WrongAttestationCount {
                expected: usize::try_from(f.threshold).unwrap_or(usize::MAX),
                actual,
            });
        }
        self.check_key(hvk)?;
        //    ... and (implementation note) id and EVERY element of π, the k attestations
        //    included, is a group element, whatever way the proof was built.
        validate(id, "id")?;
        validate(proof, "π")?;
        // 1. For Σ-EQ set C := id. Also: φ, s, ValidTag(id, c_0), ValidTag(T_0, s).
        let statement = self.issuance_statement(hvk, f, id, &proof.encoding, &proof.t0)?;
        // 5. If CheckAtts_P(hvk, id, T_0, (att_j)_j) = 0, return 0.
        //    (implementation note: first, so that a wrong number of application contexts is
        //    reported as such before any context is built)
        self.check_atts(
            hvk,
            id,
            &statement.s,
            &proof.t0,
            &proof.attestations,
            att_apps,
        )?;
        // 4. ctx_0 := (pp, hvk, f_k, id, C, T_0, (att_j)_j [, (app_j)_j, app_0]), REBUILT from
        //    the public statement
        let ctx = self.issuance_context_with_app(
            hvk,
            f,
            id,
            &statement.c,
            &proof.t0,
            &proof.attestations,
            att_apps,
            app,
        )?;
        // 6. Return Verify_FS(ctx_0, π_0).
        if fiat_shamir::verify(&statement.relation, &ctx, &proof.proof) {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    /// `Prove` steps 1, 3-11 and 14 (construction box), shared with the root path. For
    /// `Some(attestations)` this is `Prove` proper: `CheckAtts_P` in step 6 and the context
    /// `ctx_0`. For `None` it is the root request: no attestations, hence no `CheckAtts_P`, and
    /// the context of [`Self::root_context`].
    #[allow(clippy::too_many_arguments)]
    fn prove_issuance<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        usk: &UserSecretKey<E>,
        attestations: Option<&[Attestation<E, B>]>,
        att_apps: Option<&[&[u8]]>,
        app: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<IssuanceParts<E, B>, Error> {
        // 1. vk := hvk   (implementation note: well formed; CheckAtts_P presupposes it)
        self.check_key(hvk)?;
        // The first condition of R_PCS: (id, usk) ∈ supp(UKeyGen(pp)). (Implementation note: the
        // box presupposes it. It also makes `id` an admissible identifier, ValidTag(id, c_0).)
        if self.pp.pp_tag.eval(&usk.0, &self.pp.c0) != Some(*id) {
            return Err(Error::IdentifierMismatch);
        }
        // 3. φ := EncPred(f_k)
        let phi = self.enc_pred(f)?;
        // 4. s := H_0(id)
        let s = self.tag_point(id)?;
        // 5. T_0 ← Tag(usk, s)
        // 6. If T_0 = ⊥ or CheckAtts_P(hvk, id, T_0, (att_j)_j) = 0, return ⊥.
        let t0 = self.pp.pp_tag.eval(&usk.0, &s).ok_or(Error::UndefinedTag)?;
        if let Some(attestations) = attestations {
            self.check_atts(hvk, id, &s, &t0, attestations, att_apps)?;
        }
        // 7. Generate the base-specific pair (m_aux, ρ).
        let (mut aux, rho) = B::sample_issuance(&self.pp.pp_sigma, rng);
        // 8. m_hid := (usk, m_aux)       14. st_iss := (m_hid, φ, ρ), wiped on every exit
        let state = IssuanceState {
            m_hid: B::hidden_message(&usk.0, &aux),
            phi,
            rho,
        };
        aux.zeroize();
        // 9. C ← Com(m_hid, φ; ρ)
        let c = B::issuance_encoding(&self.pp.pp_sigma, hvk, &state.m_hid, &phi, &state.rho)?;
        let encoding = B::encoding_to_wire(&c);
        // Implementation note: relation and context are built from the statement as the VERIFIER
        // will reconstruct it from (π, id), with the same code (for Σ-EQ its C is `id`). This
        // also refuses, as the verifier would, an inadmissible C (Σ-BBS: C = 1).
        let statement = self.issuance_statement(hvk, f, id, &encoding, &t0)?;
        // 10. ctx_0 := (pp, hvk, f_k, id, C, T_0, (att_j)_j)
        let c = &statement.c;
        let ctx = match attestations {
            Some(attestations) => {
                self.issuance_context_with_app(hvk, f, id, c, &t0, attestations, att_apps, app)?
            }
            None => self.root_context(hvk, f, id, c, &t0)?,
        };
        // 11. π_0 ← zkPoK_{ctx_0}{ ((vk, C, φ, id, T_0, c_0, s), (m_hid, ρ)) ∈ R_issue }
        let witness = Self::issuance_witness(&state.m_hid, &state.rho);
        let proof = fiat_shamir::prove(&statement.relation, &witness, &ctx, rng)?;
        Ok(IssuanceParts {
            encoding,
            t0,
            proof,
            state,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Application contexts (implementation note, not in the paper)
// ---------------------------------------------------------------------------------------------

impl<E, B, T, P> PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
    P: AttributePolicy<E::ScalarField>,
{
    /// `Attest` under an application context `app_j`: the caller's bytes enter `ctx_j` as one
    /// more framed item ([`PCS::attestation_context_with_app`]), so the attestation is bound to
    /// them. A deployment puts there what its verifier checks per attestation: statement
    /// metadata, a validity window, a serial. Verify with
    /// [`PCS::check_attestation_in_context`], and inside a proof with
    /// [`PCS::prove_in_context`] / [`PCS::check_proof_in_context`].
    ///
    /// The tag is unchanged: it depends on `usk_j` and `id` only, so two attestations of one
    /// holder for one `id` under different contexts still carry the same tag and still count
    /// once.
    ///
    /// # Errors
    /// As [`PredicateCredentialSystem::attest`].
    #[allow(clippy::too_many_arguments)]
    pub fn attest_in_context<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        usk: &UserSecretKey<E>,
        f: &Predicate,
        cred: &Credential<E, B>,
        id: &E::G1,
        app: &[u8],
        rng: &mut R,
    ) -> Result<Attestation<E, B>, Error> {
        self.attest_at(hvk, usk, f, cred, id, Some(app), rng)
    }

    /// `Prove` under application contexts: `att_apps[j]` is the context the `j`-th attestation
    /// of `w` was made under, and `app` is the proof's own context (e.g. the verifier's
    /// single-use challenge and an audience). `π_0` is bound to all of them
    /// ([`PCS::issuance_context_with_app`]). Verify with [`PCS::check_proof_in_context`].
    ///
    /// # Errors
    /// As [`PredicateCredentialSystem::prove`]; [`Error::WrongAttestationCount`] if `att_apps`
    /// does not have one entry per attestation; [`Error::InvalidAttestation`] if an attestation
    /// does not verify under its context.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn prove_in_context<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        usk: &UserSecretKey<E>,
        w: &[Attestation<E, B>],
        att_apps: &[&[u8]],
        app: &[u8],
        rng: &mut R,
    ) -> Result<(IssuanceProof<E, B>, IssuanceState<E, B>), Error> {
        if f.is_root() {
            return Err(Error::ZeroThreshold);
        }
        if u32::try_from(w.len()).ok() != Some(f.threshold) {
            return Err(Error::WrongAttestationCount {
                expected: usize::try_from(f.threshold).unwrap_or(usize::MAX),
                actual: w.len(),
            });
        }
        validate_all(w.iter(), "att")?;
        let parts =
            self.prove_issuance(hvk, f, id, usk, Some(w), Some(att_apps), Some(app), rng)?;
        let proof = IssuanceProof {
            attestations: w.to_vec(),
            encoding: parts.encoding,
            t0: parts.t0,
            proof: parts.proof,
        };
        Ok((proof, parts.state))
    }

    /// `Issue` gated on [`PCS::check_proof_in_context`] instead of `VerifyProof`: as
    /// [`PredicateCredentialSystem::issue`] in every other respect (`f` is the HELPER's input).
    ///
    /// # Errors
    /// As [`PredicateCredentialSystem::issue`].
    #[allow(clippy::too_many_arguments)]
    pub fn issue_in_context<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        hsk: &HelperSecretKey<B>,
        f: &Predicate,
        id: &E::G1,
        proof: &IssuanceProof<E, B>,
        att_apps: &[&[u8]],
        app: &[u8],
        rng: &mut R,
    ) -> Result<B::PreCredential, Error> {
        if hsk.hvk != *hvk || hsk.pp_digest != self.pp_digest {
            return Err(Error::InvalidKey);
        }
        if f.is_root() {
            return Err(Error::ZeroThreshold);
        }
        if self
            .check_proof_in_context(hvk, f, id, proof, att_apps, app)
            .is_err()
        {
            return Err(Error::InvalidProof);
        }
        let c = B::encoding_from_wire(&self.pp.pp_sigma, &proof.encoding, id)
            .ok_or(Error::InvalidIssuanceEncoding)?;
        let phi = self.enc_pred(f)?;
        B::blind_issue(&self.pp.pp_sigma, &hsk.sk, &c, &phi, rng)
    }

    /// `Attest` (construction box) with an optional application context; the body of both
    /// [`PredicateCredentialSystem::attest`] (`None`) and [`PCS::attest_in_context`].
    #[allow(clippy::too_many_arguments)]
    fn attest_at<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        usk: &UserSecretKey<E>,
        f: &Predicate,
        cred: &Credential<E, B>,
        id: &E::G1,
        app: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<Attestation<E, B>, Error> {
        // 1. vk := hvk
        // 2. Parse cred_j as (cred_Σ,j, m_aux,j).

        let (cred_sigma, aux) = (&cred.cred, &cred.aux);
        // 3. φ_j := EncPred(f_j)
        let phi = self.enc_pred(f)?;
        // 4. s := H_0(id)   (implementation note: id, which comes from the subject, has to be a
        //    group element and an admissible identifier)
        validate(id, "id")?;
        if !self.pp.pp_tag.valid_tag(id, &self.pp.c0) {
            return Err(Error::InvalidTag);
        }
        let s = self.tag_point(id)?;
        // 5. T_j ← Tag(usk_j, s)
        // 6. If T_j = ⊥, return ⊥.
        let tag = self.pp.pp_tag.eval(&usk.0, &s).ok_or(Error::UndefinedTag)?;
        // 7. m_hid,j := (usk_j, m_aux,j)
        let m_hid = Zeroizing::new(B::hidden_message(&usk.0, aux));
        // 8. m_j := Enc_Σ(m_hid,j, φ_j)
        let m = Zeroizing::new(B::encode_message(&self.pp.pp_sigma, &m_hid, &phi)?);
        // 9. (cred*_j, ω_j) ← Σ.ReRand(vk, m_j, cred_Σ,j)
        let (shown, omega) = B::rerand(&self.pp.pp_sigma, hvk, &m, cred_sigma, rng)?;
        let omega = Zeroizing::new(omega);
        // 10. ctx_j := (pp, hvk, id, φ_j, T_j, cred*_j [, app_j])
        let ctx = self.attestation_context_with_app(hvk, id, &phi, &tag, &shown, app)?;
        // 11. π_j ← zkPoK_{ctx_j}{ ((vk, cred*_j, φ_j, T_j, s), (m_hid,j, ω_j)) ∈ R_att }
        let relation = self.attestation_relation(hvk, &shown, &phi, &tag, &s)?;
        let witness = Self::attestation_witness(&m_hid, &omega);
        let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng)?;
        // 12. Return att_j = (T_j, cred*_j, φ_j, π_j).
        Ok(Attestation {
            tag,
            shown,
            phi,
            proof,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Root credentials (Remark "Chaining and the base case")
// ---------------------------------------------------------------------------------------------

impl<E, B, T, P> PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
    P: AttributePolicy<E::ScalarField>,
{
    /// USER: the request for a root credential under the root predicate `f_root`: the issuance
    /// encoding `C`, the tag `T_0` and a proof for `R_issue`, exactly as `Prove` computes them
    /// for zero attestations, but under [`Self::root_context`]. Returns the request and the
    /// issuance state for [`PredicateCredentialSystem::unblind`].
    ///
    /// This is the root request of Remark "Chaining and the base case" (module docs, "Root
    /// credentials"). `(id, usk)` is the user's own key pair.
    ///
    /// # Errors
    /// [`Error::NotARootPredicate`] unless `f_root.threshold = 0`;
    /// [`Error::IdentifierMismatch`] if `id ≠ Tag(usk, c_0)`; [`Error::InvalidKey`] if `hvk` is
    /// not well formed; otherwise as [`PredicateCredentialSystem::prove`].
    // The return type mirrors `Prove → (π, st_iss) / ⊥`.
    #[allow(clippy::type_complexity)]
    pub fn root_request<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        f_root: &Predicate,
        id: &E::G1,
        usk: &UserSecretKey<E>,
        rng: &mut R,
    ) -> Result<(RootRequest<E, B>, IssuanceState<E, B>), Error> {
        if !f_root.is_root() {
            return Err(Error::NotARootPredicate);
        }
        // `Prove` for zero attestations, under the root context
        let parts = self.prove_issuance(hvk, f_root, id, usk, None, None, None, rng)?;
        Ok((
            RootRequest {
                encoding: parts.encoding,
                t0: parts.t0,
                proof: parts.proof,
            },
            parts.state,
        ))
    }

    /// Verification of a root request with the reason for a rejection: `Ok(())` iff
    /// [`Self::verify_root_request`] returns `true`. It says that `C`, `id` and `T_0` are under
    /// one key which the requester knows; it does NOT say that the requester should be admitted.
    ///
    /// Implementation note: as for [`Self::check_proof`], `hvk`, `id` and the request are
    /// re-validated first; the verdict does not depend on how they were built.
    ///
    /// # Errors
    /// [`Error::NotARootPredicate`] unless `f_root.threshold = 0`;
    /// [`Error::InvalidGroupElement`] if `hvk`, `id` or the request contains a value that is not
    /// an element of its group; [`Error::InvalidKey`], [`Error::InvalidTag`],
    /// [`Error::InvalidIssuanceEncoding`] for an inadmissible statement; [`Error::InvalidProof`]
    /// if the proof does not verify for the rebuilt root context.
    pub fn check_root_request(
        &self,
        hvk: &B::VerificationKey,
        f_root: &Predicate,
        id: &E::G1,
        request: &RootRequest<E, B>,
    ) -> Result<(), Error> {
        if !f_root.is_root() {
            return Err(Error::NotARootPredicate);
        }
        self.check_key(hvk)?;
        validate(id, "id")?;
        validate(request, "root request")?;
        let statement = self.issuance_statement(hvk, f_root, id, &request.encoding, &request.t0)?;
        let ctx = self.root_context(hvk, f_root, id, &statement.c, &request.t0)?;
        if fiat_shamir::verify(&statement.relation, &ctx, &request.proof) {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    /// Whether `request` is a valid root request for the statement `(hvk, f_root, id)`.
    /// Deterministic; never panics.
    #[must_use]
    pub fn verify_root_request(
        &self,
        hvk: &B::VerificationKey,
        f_root: &Predicate,
        id: &E::G1,
        request: &RootRequest<E, B>,
    ) -> bool {
        self.check_root_request(hvk, f_root, id, request).is_ok()
    }

    /// HELPER: issues the pre-credential of a root credential, `BlindIssue(sk, C, EncPred(f_root))`
    /// for the `C` of a verified root request. The helper does not see `usk`.
    ///
    /// **To be called only after the helper's out-of-band admission check of `id`** (Remark
    /// "Chaining and the base case": "The security model treats these root credentials as an
    /// explicit initial condition."). Nothing in a root request authorizes it. The user finishes
    /// with [`PredicateCredentialSystem::unblind`] and the state of [`Self::root_request`].
    ///
    /// Choose `f_root` yourself: a root credential is as good as the out-of-band check behind
    /// it, and a requester that names its own root predicate names its own admission class
    /// (`docs/operating-a-helper.md`).
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if `hvk` is not the key inside `hsk`, or if `hsk` belongs to another
    /// deployment (implementation note: [`HelperSecretKey`] records the digest of its `pp`);
    /// [`Error::NotARootPredicate`] unless `f_root.threshold = 0`; [`Error::InvalidProof`] if
    /// [`Self::verify_root_request`] rejects; the errors of `BlindIssue`.
    pub fn issue_root<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &B::VerificationKey,
        hsk: &HelperSecretKey<B>,
        f_root: &Predicate,
        id: &E::G1,
        request: &RootRequest<E, B>,
        rng: &mut R,
    ) -> Result<B::PreCredential, Error> {
        if hsk.hvk != *hvk || hsk.pp_digest != self.pp_digest {
            return Err(Error::InvalidKey);
        }
        if !f_root.is_root() {
            return Err(Error::NotARootPredicate);
        }
        if !self.verify_root_request(hvk, f_root, id, request) {
            return Err(Error::InvalidProof);
        }
        let c = B::encoding_from_wire(&self.pp.pp_sigma, &request.encoding, id)
            .ok_or(Error::InvalidIssuanceEncoding)?;
        let phi = self.enc_pred(f_root)?;
        B::blind_issue(&self.pp.pp_sigma, &hsk.sk, &c, &phi, rng)
    }
}

// ---------------------------------------------------------------------------------------------
// The ten algorithms of the protocol box
// ---------------------------------------------------------------------------------------------

impl<E, B, T, P> PredicateCredentialSystem for PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
    P: AttributePolicy<E::ScalarField>,
{
    type SetupParams = SetupParams<P>;
    type Predicate = Predicate;
    /// `hvk := vk`.
    type HelperVerificationKey = B::VerificationKey;
    /// `hsk := (sk, hvk)`.
    type HelperSecretKey = HelperSecretKey<B>;
    /// `id = Tag(usk, c_0) ∈ G_1`.
    type Identity = E::G1;
    type UserSecretKey = UserSecretKey<E>;
    /// `cred = (cred_Σ, m_aux)`.
    type Credential = Credential<E, B>;
    /// `att_j = (T_j, cred*_j, φ_j, π_j)`.
    type Attestation = Attestation<E, B>;
    /// `w = (att_j)_{j ∈ [k]}`.
    type Witness = [Attestation<E, B>];
    /// `π = ((att_j)_{j ∈ [k]}, C, T_0, π_0)`.
    type IssuanceProof = IssuanceProof<E, B>;
    /// `st_iss = (m_hid, φ, ρ)`.
    type IssuanceState = IssuanceState<E, B>;
    type PreCredential = B::PreCredential;

    /// `Setup(1^λ) → pp` (construction box). Transparent: every parameter is derived from the
    /// deployment label `params.label`; the security parameter is fixed by the choice of `E`.
    ///
    /// # Errors
    /// [`Error::IncompatibleBaseAndTag`] for a base that needs `id = g_1^usk` with a tag that
    /// does not provide it (`Σ-EQ` with `Tag_DY`); [`Error::DegenerateInput`] for degenerate
    /// parameters; [`Error::HashToCurve`] if hash-derived parameters cannot be computed.
    fn setup(params: Self::SetupParams) -> Result<Self, Error> {
        // 1.-5. derive pp; "compatible" of step 1 is checked on the derived instance
        let pp = Self::derive_parameters(&params.label)?;
        // 6. Return pp.
        Self::assemble(pp, params.policy)
    }

    /// `HKeyGen(pp) → (hvk, hsk)` (construction box). Implementation note: `hsk` also records
    /// the digest of THIS `pp`; `Issue` and the root path refuse it under any other
    /// ([`HelperSecretKey`]). One key pair per deployment label.
    fn helper_keygen<R: RngCore + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (Self::HelperVerificationKey, Self::HelperSecretKey) {
        // 1. (vk, sk) ← Σ.KeyGen(pp)
        let (vk, sk) = B::keygen(&self.pp.pp_sigma, rng);
        // 2. hvk := vk      3. hsk := (sk, hvk)   (implementation note: and the digest of pp)
        let hsk = HelperSecretKey {
            sk,
            hvk: vk.clone(),
            pp_digest: self.pp_digest,
        };
        // 4. Return (hvk, hsk).
        (vk, hsk)
    }

    /// `UKeyGen(pp) → (id, usk)` (construction box). "For `Tag_DY`, the resampling in `UKeyGen`
    /// excludes its two then-known undefined points" (§5.1).
    ///
    /// # Errors
    /// Implementation note (the box has no `⊥`): [`Error::DegenerateInput`] if `pp_Tag` is
    /// degenerate or no key with defined tags was found in [`MAX_KEYGEN_ATTEMPTS`] attempts.
    /// Under well-formed parameters one attempt restarts with probability about `2/p` (an
    /// estimate in the random-oracle model, see [`PCSTag::is_well_formed`]), so the distribution
    /// of the output differs from that of the unbounded loop by about `(2/p)^64`.
    fn user_keygen<R: RngCore + CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Identity, Self::UserSecretKey), Error> {
        // The guard of the restart loop: under degenerate parameters every evaluation is ⊥.
        if !self.pp.pp_tag.is_well_formed() {
            return Err(Error::DegenerateInput("pp_Tag"));
        }
        for _ in 0..MAX_KEYGEN_ATTEMPTS {
            // 1. usk ← TagKeyGen(1^λ)
            let usk = UserSecretKey(self.pp.pp_tag.keygen(rng));
            // 2. id ← Tag(usk, c_0)         3. If id = ⊥, restart.
            // 4. T_0 ← Tag(usk, H_0(id))    5. If T_0 = ⊥, restart.
            match self.identity(&usk) {
                // 6. Return (id, usk).
                Ok(id) => return Ok((id, usk)),
                Err(Error::UndefinedTag) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::DegenerateInput(
            "pp_Tag: UKeyGen found no key whose tags are defined",
        ))
    }

    /// `Attest(hvk, usk_j, f_j, cred_j, id) → att_j / ⊥` (construction box).
    ///
    /// The attestation "binds an identifier `id` and an attester key, but no session, epoch or
    /// predicate" (Remark "Attestations are standing endorsements"). Two attestations of one
    /// holder for one `id` carry the same tag: "an attester's tag for a fixed identifier is
    /// deterministic" (proof of Theorem "Attester anonymity").
    ///
    /// Implementation note: as in the box, `Attest` does not verify its own output, and it does
    /// not check `hvk` (a holder checks a helper key once, when it receives it; `Unblind` has).
    /// On a credential that does not belong to `(usk_j, f_j)`, `Σ-PS` and `Σ-EQ` make it fail
    /// (`R_att` has no witness, resp. `ReRand` outputs `⊥`); the weak base `Σ-BBS` re-randomizes
    /// under the CLAIMED message, and the result is an attestation that `VerifyAtt` rejects.
    ///
    /// # Errors
    /// [`Error::UndefinedTag`] if `T_j = ⊥` (`Tag_DY` with `usk_j = −H_0(id)`);
    /// [`Error::InvalidGroupElement`] if `id` is not an element of `G_1`, and
    /// [`Error::InvalidTag`] if `ValidTag(id, c_0) = 0` (implementation notes: what is not an
    /// identifier is not attested for);
    /// [`Error::InvalidCredential`] where `ReRand` outputs `⊥`;
    /// [`Error::WitnessDoesNotSatisfyRelation`] if `cred_j` is not a credential of
    /// `(usk_j, f_j)`; [`Error::DegenerateInput`] if `EncPred(f_j) = 0`.
    fn attest<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &Self::HelperVerificationKey,
        usk: &Self::UserSecretKey,
        f: &Self::Predicate,
        cred: &Self::Credential,
        id: &Self::Identity,
        rng: &mut R,
    ) -> Result<Self::Attestation, Error> {
        self.attest_at(hvk, usk, f, cred, id, None, rng)
    }

    /// `VerifyAtt(hvk, id, att_j) → {0, 1}` (construction box); [`PCS::check_attestation`] is
    /// the same algorithm with the reason for a rejection. Deterministic; never panics; makes no
    /// assumption about how its inputs were built (implementation note: it re-validates them).
    fn verify_attestation(
        &self,
        hvk: &Self::HelperVerificationKey,
        id: &Self::Identity,
        att: &Self::Attestation,
    ) -> bool {
        self.check_attestation(hvk, id, att).is_ok()
    }

    /// `Prove(hvk, f_k, id, usk, w) → (π, st_iss) / ⊥` (construction box).
    ///
    /// The helper learns from `π` the attestations (forwarded verbatim), `C` and `T_0`; Theorem
    /// "Subject privacy" is the paper's statement about what these reveal.
    ///
    /// # Errors
    /// [`Error::ZeroThreshold`] for a root predicate; [`Error::WrongAttestationCount`] unless
    /// `w` has exactly `f.threshold` attestations; [`Error::InvalidGroupElement`] if `hvk` or an
    /// attestation contains a value that is not an element of its group (implementation note:
    /// the attestations come from other parties, and the helper would reject the proof);
    /// [`Error::IdentifierMismatch`] if `id ≠ Tag(usk, c_0)`; [`Error::UndefinedTag`] if
    /// `T_0 = ⊥`; [`Error::InvalidKey`] if `hvk` is not well formed; where `CheckAtts_P`
    /// returns `0`:
    /// [`Error::InvalidAttestation`], [`Error::DuplicateAttester`], [`Error::SelfAttestation`]
    /// or [`Error::PolicyRejected`]; [`Error::InvalidIssuanceEncoding`] in the event that the
    /// sampled `C` is one the verifier refuses (`Σ-BBS`: `C = 1`, probability `1/p`).
    fn prove<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &Self::HelperVerificationKey,
        f: &Self::Predicate,
        id: &Self::Identity,
        usk: &Self::UserSecretKey,
        w: &Self::Witness,
        rng: &mut R,
    ) -> Result<(Self::IssuanceProof, Self::IssuanceState), Error> {
        // Implementation note: f_0 is not a predicate of the ordinary path.
        if f.is_root() {
            return Err(Error::ZeroThreshold);
        }
        // 2. Parse w as (att_j)_{j ∈ [k]}: exactly k = f.threshold attestations.
        if u32::try_from(w.len()).ok() != Some(f.threshold) {
            return Err(Error::WrongAttestationCount {
                expected: usize::try_from(f.threshold).unwrap_or(usize::MAX),
                actual: w.len(),
            });
        }
        //    (implementation note: the attestations come from other parties; every element of
        //    every att_j is a group element, as the verifier will require)
        validate_all(w.iter(), "att")?;
        // 1., 3.-11. and 14. (`prove_issuance`, shared with the root path)
        let parts = self.prove_issuance(hvk, f, id, usk, Some(w), None, None, rng)?;
        // 12. For Σ-EQ, π := ((att_j)_j, T_0, π_0).    (its `encoding` is `()`)
        // 13. Otherwise, π := ((att_j)_j, C, T_0, π_0).
        let proof = IssuanceProof {
            attestations: w.to_vec(),
            encoding: parts.encoding,
            t0: parts.t0,
            proof: parts.proof,
        };
        // 15. Return (π, st_iss).
        Ok((proof, parts.state))
    }

    /// `Issue(hvk, hsk, f_k, id, π) → ĉred / ⊥` (construction box). Proof-gated (Def.
    /// "Proof-gated issuance"): `⊥` whenever `VerifyProof(hvk, f_k, id, π) = 0`. "`Issue` must
    /// blind-sign the commitment carried by the verified `π`" (§5.5): the helper never sees
    /// `usk`.
    ///
    /// Implementation note: `f_k` is the HELPER's input. A helper serves a closed set of
    /// predicates that it has decided on; a requester that may name `f` itself names its own
    /// threshold (`docs/operating-a-helper.md`).
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if `hvk` is not the key inside `hsk`, or if `hsk` belongs to another
    /// deployment (implementation note: [`HelperSecretKey`] records the digest of its `pp`);
    /// [`Error::ZeroThreshold`] for a root predicate; [`Error::InvalidProof`] if `VerifyProof`
    /// rejects, whatever the reason ([`PCS::check_proof`] names it; a `π` with a value that is
    /// not a group element is one of them); the errors of `BlindIssue`.
    fn issue<R: RngCore + CryptoRng + ?Sized>(
        &self,
        hvk: &Self::HelperVerificationKey,
        hsk: &Self::HelperSecretKey,
        f: &Self::Predicate,
        id: &Self::Identity,
        proof: &Self::IssuanceProof,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error> {
        // 1. Parse hsk as (sk, hvk).   (implementation note: the two copies of hvk agree, and
        //    hsk was generated under THIS pp)
        if hsk.hvk != *hvk || hsk.pp_digest != self.pp_digest {
            return Err(Error::InvalidKey);
        }
        if f.is_root() {
            return Err(Error::ZeroThreshold);
        }
        // 2. If VerifyProof(hvk, f_k, id, π) = 0, return ⊥.
        if !self.verify_proof(hvk, f, id, proof) {
            return Err(Error::InvalidProof);
        }
        // 3. For Σ-EQ, set C := id.    4. Otherwise, parse C from π.
        let c = B::encoding_from_wire(&self.pp.pp_sigma, &proof.encoding, id)
            .ok_or(Error::InvalidIssuanceEncoding)?;
        // 5. φ := EncPred(f_k)
        let phi = self.enc_pred(f)?;
        // 6. ĉred ← Σ.BlindIssue(sk, C, φ)      7. Return ĉred.
        B::blind_issue(&self.pp.pp_sigma, &hsk.sk, &c, &phi, rng)
    }

    /// `Unblind(hvk, usk, f_k, ĉred, st_iss) → cred / ⊥` (construction box), failing closed.
    /// Shared by the ordinary path and the root path.
    ///
    /// # Errors
    /// [`Error::IssuanceStateMismatch`] if `st_iss` does not belong to `(usk, f_k)` (step 2);
    /// [`Error::InvalidKey`] if `hvk` is not well formed; [`Error::InvalidGroupElement`] if
    /// `hvk` or `ĉred` contains a value that is not an element of its group (implementation
    /// note: `ĉred` comes from the helper, and `Unblind` multiplies its elements by the secret
    /// `ρ`); the errors of the base's `Unblind`;
    /// implementation note: [`Error::InvalidPreCredential`] if the unblinded credential does
    /// not pass `VerifyCred` (the box returns it unverified).
    fn unblind(
        &self,
        hvk: &Self::HelperVerificationKey,
        usk: &Self::UserSecretKey,
        f: &Self::Predicate,
        pre: &Self::PreCredential,
        state: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error> {
        // 1. vk := hvk   (implementation note: the final check presupposes a well-formed key,
        //    and ĉred, which comes from the helper, consists of group elements)
        self.check_key(hvk)?;
        validate(pre, "ĉred")?;
        // 2. Parse st_iss as (m_hid, φ, ρ) and check that the first component of m_hid is usk
        //    and that φ = EncPred(f_k); return ⊥ otherwise.
        //    (One call splits m_hid: this is also step 5, "parse m_hid as (usk, m_aux)".)
        let phi = self.enc_pred(f)?;
        let (mut usk_in_state, aux) = B::split_hidden_message(&state.m_hid);
        let aux = Zeroizing::new(aux);
        let belongs = usk_in_state == usk.0 && state.phi == phi;
        usk_in_state.zeroize();
        if !belongs {
            return Err(Error::IssuanceStateMismatch);
        }
        // 3. m := Enc_Σ(m_hid, φ)
        let m = Zeroizing::new(B::encode_message(
            &self.pp.pp_sigma,
            &state.m_hid,
            &state.phi,
        )?);
        // 4. cred_Σ ← Σ.Unblind(vk, m, ĉred, ρ)
        let cred_sigma = B::unblind(&self.pp.pp_sigma, hvk, &m, pre, &state.rho)?;
        // 5. Parse m_hid as (usk, m_aux).      6. cred := (cred_Σ, m_aux)
        let cred = Credential {
            cred: cred_sigma,
            aux: (*aux).clone(),
        };
        // Fail closed: VerifyCred (hvk was checked in step 1). A wrong answer of the helper is
        // noticed here, not at the first Attest.
        if !self.credential_verifies(hvk, usk, f, &cred) {
            return Err(Error::InvalidPreCredential);
        }
        // 7. Return cred.
        Ok(cred)
    }

    /// `VerifyCred(hvk, usk, f, cred) → {0, 1}` (construction box). Deterministic; never panics.
    /// Implementation notes: `false` under an `hvk` that is not well formed, and `false` if
    /// `hvk` or `cred` contains a value that is not an element of its group. (A pairing equation
    /// does not see a component of small order in a `G_1` argument: without the check a
    /// credential `(σ_1 + P_3, σ_2)` would "verify" next to `(σ_1, σ_2)`.)
    fn verify_cred(
        &self,
        hvk: &Self::HelperVerificationKey,
        usk: &Self::UserSecretKey,
        f: &Self::Predicate,
        cred: &Self::Credential,
    ) -> bool {
        // 1. vk := hvk
        // 2.-6.
        self.check_key(hvk).is_ok()
            && validate(cred, "cred").is_ok()
            && self.credential_verifies(hvk, usk, f, cred)
    }

    /// `VerifyProof(hvk, f_k, id, π) → {0, 1}` (construction box); [`PCS::check_proof`] is the
    /// same algorithm with the reason for a rejection. Deterministic; never panics; makes no
    /// assumption about how its inputs were built (implementation note: it re-validates them).
    fn verify_proof(
        &self,
        hvk: &Self::HelperVerificationKey,
        f: &Self::Predicate,
        id: &Self::Identity,
        proof: &Self::IssuanceProof,
    ) -> bool {
        self.check_proof(hvk, f, id, proof).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use ark_ec::PrimeGroup;
    use ark_ff::{One, UniformRand, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        cred::{CredentialBase, conformance::Forgery},
        hash::{HashToGroup, bls12_381::G1Hasher},
        kiprf::{KIPRF, SigmaFriendlyKIPRF},
        pcs::test_support::{
            BBS, DDH, DY, E, Fixture, G1, G2, PS, RandomShown, SPSEQ, random_attestation,
            random_proof, random_root_request,
        },
        serialization::WireFormat,
        sigma::{LinearEquation, LinearRelation, ScalarVar, commit, extract, respond, verify},
    };

    type Fr = ark_bls12_381::Fr;

    fn setup<B, T>(label: &[u8]) -> Result<PCS<E, B, T>, Error>
    where
        B: SigmaFriendlyCredentialBase<E>,
        T: PCSTag<G1>,
    {
        PCS::setup(SetupParams::new(label.to_vec()))
    }

    // ----- Setup ---------------------------------------------------------------------------------

    #[test]
    fn setup_is_transparent_and_refuses_incompatible_pairs() {
        let label = b"construction/setup";
        let pcs = setup::<BBS, DDH>(label).unwrap();
        // pp is a function of the label: c_0 = H_0("identity"), pp_Σ and pp_Tag as derived by the
        // base and the tag, with H_2(c_0) = g_1 programmed
        assert_eq!(pcs.label(), label);
        assert_eq!(*pcs.identity_point(), h0_identity_point::<Fr>(label));
        assert_eq!(pcs.base_parameters(), &BBS::setup(label).unwrap());
        assert_eq!(
            pcs.tag(),
            &DDH::setup(label, *pcs.identity_point()).unwrap()
        );
        assert_eq!(pcs.tag().htag(pcs.identity_point()), G1::generator());
        let again = setup::<BBS, DDH>(label).unwrap();
        assert_eq!(again.public_parameters(), pcs.public_parameters());
        assert_eq!(again.parameters_digest(), pcs.parameters_digest());
        let other = setup::<BBS, DDH>(b"construction/setup2").unwrap();
        assert_ne!(other.public_parameters(), pcs.public_parameters());
        assert_ne!(other.parameters_digest(), pcs.parameters_digest());
        assert!(format!("{pcs:?}").starts_with("PCS {"));

        // every compatible pair, and the one incompatible pair
        assert!(setup::<PS, DDH>(label).is_ok());
        assert!(setup::<PS, DY>(label).is_ok());
        assert!(setup::<BBS, DY>(label).is_ok());
        assert!(setup::<SPSEQ, DDH>(label).is_ok());
        assert_eq!(
            setup::<SPSEQ, DY>(label).err(),
            Some(Error::IncompatibleBaseAndTag)
        );
    }

    /// `pp` is accepted from outside only if it is what `Setup` derives from its own label.
    #[test]
    fn received_parameters_must_be_the_derived_ones() {
        let label = b"construction/received";
        let pcs = setup::<BBS, DDH>(label).unwrap();
        let pp = pcs.public_parameters().clone();

        // the way over the wire
        let bytes = pp.to_bytes().unwrap();
        let received = PublicParameters::<E, BBS, DDH>::from_bytes(&bytes).unwrap();
        let rebuilt = PCS::from_public_parameters(received, AcceptAll).unwrap();
        assert_eq!(rebuilt.public_parameters(), &pp);
        assert_eq!(rebuilt.parameters_digest(), pcs.parameters_digest());

        let invalid =
            |pp: PublicParameters<E, BBS, DDH>| match PCS::from_public_parameters(pp, AcceptAll) {
                Err(Error::InvalidPublicParameters(what)) => what,
                other => panic!("accepted or refused for another reason: {other:?}"),
            };
        // another label on the same parameters; another c_0
        let mut bad = pp.clone();
        bad.label = b"construction/other".to_vec();
        assert!(invalid(bad).starts_with("c_0"));
        let mut bad = pp.clone();
        bad.c0 += Fr::one();
        assert!(invalid(bad).starts_with("c_0"));
        // generators that are not the hash-derived ones: a known discrete-logarithm relation
        // among them is what breaks Σ-BBS, and nothing about them looks wrong
        let mut bad = pp.clone();
        bad.pp_sigma.h3 = bad.pp_sigma.h1 * Fr::from(2u64);
        assert!(bad.pp_sigma.is_well_formed());
        assert!(invalid(bad).starts_with("pp_Σ"));
        let mut bad = pp.clone();
        bad.pp_sigma = BBS::setup(b"construction/other").unwrap();
        assert!(invalid(bad).starts_with("pp_Σ"));
        // a tag of another deployment, a tag without the programmed point
        let mut bad = pp.clone();
        bad.pp_tag = DDH::setup(b"construction/other", pp.c0).unwrap();
        assert!(invalid(bad).starts_with("pp_Tag"));
        let mut bad = pp.clone();
        bad.pp_tag = DDH::new(G1Hasher::new(label).unwrap());
        assert!(invalid(bad).starts_with("pp_Tag"));

        // the checks of Setup come first: Σ-EQ without the programmed point, and with Tag_DY
        let eq = setup::<SPSEQ, DDH>(label).unwrap();
        let mut bad = eq.public_parameters().clone();
        bad.pp_tag = DDH::new(G1Hasher::new(label).unwrap());
        assert_eq!(
            PCS::from_public_parameters(bad, AcceptAll).err(),
            Some(Error::IncompatibleBaseAndTag)
        );
        let bad = PublicParameters::<E, SPSEQ, DY> {
            label: label.to_vec(),
            pp_sigma: (),
            pp_tag: DY::new(),
            c0: pp.c0,
        };
        assert_eq!(
            PCS::from_public_parameters(bad, AcceptAll).err(),
            Some(Error::IncompatibleBaseAndTag)
        );
        // degenerate tag parameters (only decoding WITHOUT validation produces them)
        let bad = PublicParameters::<E, PS, DY> {
            label: label.to_vec(),
            pp_sigma: (),
            pp_tag: degenerate_dy(),
            c0: pp.c0,
        };
        assert_eq!(
            PCS::from_public_parameters(bad, AcceptAll).err(),
            Some(Error::DegenerateInput("pp_Tag"))
        );
        // ... and validated decoding of pp refuses them in the first place
        let mut bytes = setup::<PS, DY>(label)
            .unwrap()
            .public_parameters()
            .to_bytes()
            .unwrap();
        let tag_at = 8 + label.len();
        bytes[tag_at..tag_at + 48].copy_from_slice(&G1::zero().to_bytes().unwrap());
        assert!(PublicParameters::<E, PS, DY>::from_bytes(&bytes).is_err());
    }

    // ----- UKeyGen -------------------------------------------------------------------------------

    fn degenerate_dy() -> crate::kiprf::DY<G1> {
        let bytes = G1::zero().to_bytes().unwrap();
        let tag = crate::kiprf::DY::<G1>::deserialize_compressed_unchecked(&bytes[..]).unwrap();
        assert!(!PCSTag::<G1>::is_well_formed(&tag));
        tag
    }

    #[test]
    fn user_keygen_returns_keys_of_the_support() {
        let mut rng = StdRng::seed_from_u64(0xc025_0001);
        let ddh = setup::<PS, DDH>(b"construction/ukeygen").unwrap();
        let dy = setup::<PS, DY>(b"construction/ukeygen").unwrap();
        for _ in 0..8 {
            // Tag_DDH: id = g_1^usk with usk ≠ 0 (Remark "Identity point")
            let (id, usk) = ddh.user_keygen(&mut rng).unwrap();
            assert!(!usk.expose_scalar().is_zero());
            assert_eq!(id, G1::generator() * usk.expose_scalar());
            assert_eq!(ddh.identity(&usk), Ok(id));
            // Tag_DY: id = g_1^{1/(usk + c_0)}, and T_0 is defined as well
            let (id, usk) = dy.user_keygen(&mut rng).unwrap();
            assert_eq!(
                id * (*usk.expose_scalar() + dy.identity_point()),
                G1::generator()
            );
            let s = dy.tag_point(&id).unwrap();
            assert!(dy.tag().eval(usk.expose_scalar(), &s).is_some());
        }
        // keys outside the support
        let zero = UserSecretKey::<E>::from_scalar(Fr::zero());
        assert_eq!(ddh.identity(&zero), Err(Error::UndefinedTag));
        assert!(dy.identity(&zero).is_ok());
        let minus_c0 = UserSecretKey::<E>::from_scalar(-*dy.identity_point());
        assert_eq!(dy.identity(&minus_c0), Err(Error::UndefinedTag));
    }

    thread_local! {
        /// Calls of `LyingTag::keygen` on this thread (every test runs on its own thread).
        static LYING_KEYGEN_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// A broken tag: it CLAIMS to be well formed, and it is undefined everywhere
    /// (`defined_at = None`) or everywhere but at ONE point (`K ↦ g_1^K` there). The guard of
    /// the `UKeyGen` loop cannot catch it; the bound has to. Its `keygen` panics once it is
    /// called more often than the bound allows, so a loop without a bound FAILS instead of
    /// hanging.
    #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
    struct LyingTag {
        defined_at: Option<Fr>,
    }

    impl KIPRF for LyingTag {
        type Key = Fr;
        type Input = Fr;
        type Output = G1;

        fn keygen<R: RngCore + CryptoRng + ?Sized>(&self, rng: &mut R) -> Fr {
            let calls = LYING_KEYGEN_CALLS.with(|c| {
                c.set(c.get() + 1);
                c.get()
            });
            assert!(
                calls <= MAX_KEYGEN_ATTEMPTS,
                "the UKeyGen loop is not bounded"
            );
            Fr::rand(rng)
        }

        fn eval(&self, key: &Fr, input: &Fr) -> Option<G1> {
            (self.defined_at == Some(*input)).then(|| G1::generator() * key)
        }
    }

    impl SigmaFriendlyKIPRF for LyingTag {
        type Group = G1;

        fn valid_tag(&self, _tag: &G1, _input: &Fr) -> bool {
            false
        }

        fn tag_equations(
            &self,
            _key: ScalarVar,
            _tag: &G1,
            _input: &Fr,
        ) -> Vec<LinearEquation<G1>> {
            Vec::new()
        }
    }

    impl PCSTag<G1> for LyingTag {
        const IDENTITY_IS_DLOG: bool = false;

        fn setup(_domain: &[u8], _c0: Fr) -> Result<Self, Error> {
            Ok(Self { defined_at: None })
        }

        fn identity_is_dlog(&self, _c0: &Fr) -> bool {
            false
        }

        fn is_well_formed(&self) -> bool {
            true
        }
    }

    #[test]
    fn user_keygen_is_guarded_and_bounded() {
        let mut rng = StdRng::seed_from_u64(0xc025_0002);
        // the bound (the documented value): exactly MAX_KEYGEN_ATTEMPTS attempts, then ⊥
        assert_eq!(MAX_KEYGEN_ATTEMPTS, 64);
        let lying = setup::<PS, LyingTag>(b"construction/lying").unwrap();
        assert_eq!(
            lying.user_keygen(&mut rng).err(),
            Some(Error::DegenerateInput(
                "pp_Tag: UKeyGen found no key whose tags are defined"
            ))
        );
        assert_eq!(LYING_KEYGEN_CALLS.with(Cell::get), MAX_KEYGEN_ATTEMPTS);

        // UKeyGen steps 4-5: a key whose identifier is defined and whose self-exclusion tag
        // T_0 = Tag(usk, H_0(id)) is NOT is no key either. (For Tag_DY that is usk = −H_0(id).)
        LYING_KEYGEN_CALLS.with(|c| c.set(0));
        let half = PCS::<E, PS, LyingTag> {
            pp: PublicParameters {
                pp_tag: LyingTag {
                    defined_at: Some(lying.pp.c0),
                },
                ..lying.pp.clone()
            },
            pp_digest: lying.pp_digest,
            policy: AcceptAll,
        };
        let usk = UserSecretKey::<E>::from_scalar(Fr::from(5u64));
        assert!(half.tag().eval(usk.expose_scalar(), &half.pp.c0).is_some());
        assert_eq!(half.identity(&usk), Err(Error::UndefinedTag));
        assert!(matches!(
            half.user_keygen(&mut rng),
            Err(Error::DegenerateInput(_))
        ));
        assert_eq!(LYING_KEYGEN_CALLS.with(Cell::get), MAX_KEYGEN_ATTEMPTS);

        // the guard: no constructor lets a degenerate pp_Tag through, and an instance that
        // holds one all the same (built field by field here) does not enter the loop
        let good = setup::<PS, DY>(b"construction/guard").unwrap();
        let degenerate = PCS::<E, PS, DY> {
            pp: PublicParameters {
                pp_tag: degenerate_dy(),
                ..good.pp.clone()
            },
            pp_digest: good.pp_digest,
            policy: AcceptAll,
        };
        assert_eq!(
            degenerate.user_keygen(&mut rng).err(),
            Some(Error::DegenerateInput("pp_Tag"))
        );
        assert!(good.user_keygen(&mut rng).is_ok());
    }

    // ----- R_att and R_issue ---------------------------------------------------------------------

    /// The public relation builders give exactly the relations of `π_j` and `π_0`: their shape,
    /// their witnesses, ONE variable for `usk`, and the interactive protocol with its extractor.
    #[test]
    fn relations_are_those_of_the_proofs() {
        fn check<B, T>(label: &[u8], seed: u64, att_equations: [usize; 2], issue_g1: usize)
        where
            B: SigmaFriendlyCredentialBase<E>,
            T: PCSTag<G1>,
        {
            let mut fixture = Fixture::<B, T>::new(label, seed);
            let holder = fixture.holder();
            let (id, usk) = fixture.pcs.user_keygen(&mut fixture.rng).unwrap();
            let (pcs, hvk, rng) = (&fixture.pcs, &fixture.hvk, &mut fixture.rng);
            let pp = pcs.base_parameters();
            let s = pcs.tag_point(&id).unwrap();

            // R_att, rebuilt by hand from the steps of Attest
            let phi = pcs.enc_pred(&fixture.f_root).unwrap();
            let tag = pcs.tag().eval(holder.usk.expose_scalar(), &s).unwrap();
            let m_hid = B::hidden_message(holder.usk.expose_scalar(), &holder.cred.aux);
            let m = B::encode_message(pp, &m_hid, &phi).unwrap();
            let (shown, omega) = B::rerand(pp, hvk, &m, &holder.cred.cred, rng).unwrap();
            let relation = pcs
                .attestation_relation(hvk, &shown, &phi, &tag, &s)
                .unwrap();
            assert_eq!(relation.num_scalars(), 1 + B::POSSESSION_VARIABLES);
            assert_eq!(
                [relation.g1_equations().len(), relation.gt_equations().len()],
                att_equations
            );
            let witness = PCS::<E, B, T>::attestation_witness(&m_hid, &omega);
            assert_eq!(witness[0], *holder.usk.expose_scalar());
            assert!(relation.is_satisfied_by(&witness));
            // the tag clause is the LAST G_1 equation and lives on variable 0, like the
            // possession clauses: one variable, one response
            let tag_clause = relation.g1_equations().last().unwrap();
            assert!(tag_clause.terms.iter().all(|(var, _)| var.index() == 0));
            assert_eq!(
                vec![tag_clause.clone()],
                pcs.tag().tag_equations(tag_clause.terms[0].0, &tag, &s)
            );
            // a proof made on this relation under ctx_j IS an attestation
            let ctx = pcs
                .attestation_context(hvk, &id, &phi, &tag, &shown)
                .unwrap();
            let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng).unwrap();
            let att = Attestation {
                tag,
                shown,
                phi,
                proof,
            };
            assert_eq!(pcs.check_attestation(hvk, &id, &att), Ok(()));
            // special soundness on exactly this relation: the extractor returns THE key
            let (a, state_1) = commit(&relation, &mut StdRng::seed_from_u64(seed)).unwrap();
            let (a_again, state_2) = commit(&relation, &mut StdRng::seed_from_u64(seed)).unwrap();
            assert_eq!(a, a_again);
            let (c_1, c_2) = (Fr::rand(rng), Fr::rand(rng));
            let z_1 = respond(state_1, &witness, &c_1).unwrap();
            let z_2 = respond(state_2, &witness, &c_2).unwrap();
            assert!(verify(&relation, &a, &c_1, &z_1));
            let extracted = extract(&relation, &a, (&c_1, &z_1), (&c_2, &z_2)).unwrap();
            assert_eq!(extracted[0], *holder.usk.expose_scalar());
            // another key in the place of usk satisfies no part of R_att
            let mut wrong = witness.to_vec();
            wrong[0] += Fr::one();
            assert!(!relation.is_satisfied_by(&wrong));

            // R_issue, from a real proof and its state
            let f = Predicate::new(1, b"members".to_vec());
            let (proof, state) = pcs.prove(hvk, &f, &id, &usk, &[att], rng).unwrap();
            let c = B::encoding_from_wire(pp, &proof.encoding, &id).unwrap();
            let phi = pcs.enc_pred(&f).unwrap();
            let relation = pcs
                .issuance_relation(hvk, &c, &phi, &id, &proof.t0, &s)
                .unwrap();
            assert_eq!(relation.num_scalars(), 1 + B::ISSUANCE_VARIABLES);
            assert_eq!(
                [relation.g1_equations().len(), relation.gt_equations().len()],
                [issue_g1, 0]
            );
            let witness = state.witness();
            assert_eq!(witness[0], *usk.expose_scalar());
            assert!(relation.is_satisfied_by(&witness));
            assert_eq!(
                &*witness,
                &*PCS::<E, B, T>::issuance_witness(&state.m_hid, &state.rho)
            );
            // the last two equations are the tag clauses of (id, c_0) and (T_0, s), in this order
            let equations = relation.g1_equations();
            let var = equations[issue_g1 - 1].terms[0].0;
            assert_eq!(var.index(), 0);
            assert_eq!(
                equations[issue_g1 - 2..].to_vec(),
                [
                    pcs.tag().tag_equations(var, &id, pcs.identity_point()),
                    pcs.tag().tag_equations(var, &proof.t0, &s)
                ]
                .concat()
            );
            let ctx = pcs
                .issuance_context(hvk, &f, &id, &c, &proof.t0, &proof.attestations)
                .unwrap();
            assert!(fiat_shamir::verify(&relation, &ctx, &proof.proof));
            // π_0 does not verify for the root context, nor a root request for ctx_0
            let root_ctx = pcs.root_context(hvk, &f, &id, &c, &proof.t0).unwrap();
            assert!(!fiat_shamir::verify(&relation, &root_ctx, &proof.proof));
            let mut wrong = witness.to_vec();
            wrong[0] += Fr::one();
            assert!(!relation.is_satisfied_by(&wrong));
        }
        // Σ-PS: one G_T possession clause; Σ-BBS: two G_1 clauses; Σ-EQ: one G_1 clause and no
        // opening clause. Plus one tag clause for R_att, two for R_issue.
        check::<PS, DDH>(b"construction/rel/ps", 0xc025_0011, [1, 1], 3);
        check::<PS, DY>(b"construction/rel/ps+dy", 0xc025_0012, [1, 1], 3);
        check::<BBS, DDH>(b"construction/rel/bbs", 0xc025_0013, [3, 0], 3);
        check::<SPSEQ, DDH>(b"construction/rel/eq", 0xc025_0014, [2, 0], 2);
    }

    // ----- the public pre-checks ---------------------------------------------------------------

    /// "Verification must re-impose what the algebra drops" (§5.5), at the level of `VerifyAtt`:
    /// a party WITHOUT any credential picks a key, a degenerate shown credential for which the
    /// clauses of `R_att` hold under that key, and proves `R_att` honestly under `ctx_j`. The
    /// Fiat-Shamir proof verifies; the public checks of `VerifyPossess` are the only thing in
    /// the way (attacks A1 / W4 of the reference implementations).
    #[test]
    fn credential_free_attestations_fail_the_public_checks_only() {
        fn check<B, T>(
            label: &[u8],
            seed: u64,
            forgeries: impl Fn(
                &B::PublicParams,
                &B::VerificationKey,
                &Fr,
                &Fr,
            ) -> Vec<Forgery<B::ShownCredential, Fr>>,
        ) where
            B: SigmaFriendlyCredentialBase<E>,
            T: PCSTag<G1>,
        {
            let mut fixture = Fixture::<B, T>::new(label, seed);
            let (pcs, hvk, rng) = (&fixture.pcs, &fixture.hvk, &mut fixture.rng);
            let (id, usk) = pcs.user_keygen(rng).unwrap();
            let s = pcs.tag_point(&id).unwrap();
            let phi = pcs.enc_pred(&fixture.f_root).unwrap();
            // the forger's key, which no credential certifies
            let key = pcs.tag().keygen(rng);
            let tag = pcs.tag().eval(&key, &s).unwrap();
            let mut satisfiable = 0;
            for forgery in forgeries(pcs.base_parameters(), hvk, &phi, &key) {
                let relation = pcs
                    .attestation_relation(hvk, &forgery.shown, &phi, &tag, &s)
                    .unwrap();
                let mut witness = vec![key];
                witness.extend(&forgery.extra_witness);
                if !relation.is_satisfied_by(&witness) {
                    continue;
                }
                satisfiable += 1;
                let ctx = pcs
                    .attestation_context(hvk, &id, &phi, &tag, &forgery.shown)
                    .unwrap();
                let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng).unwrap();
                assert!(fiat_shamir::verify(&relation, &ctx, &proof));
                assert!(pcs.tag().valid_tag(&tag, &s));
                let att = Attestation {
                    tag,
                    shown: forgery.shown,
                    phi,
                    proof,
                };
                assert_eq!(
                    pcs.check_attestation(hvk, &id, &att),
                    Err(Error::InvalidCredential)
                );
                assert!(!pcs.verify_attestation(hvk, &id, &att));
                // ... so nobody joins on it
                let f = Predicate::new(1, b"members".to_vec());
                assert_eq!(
                    pcs.prove(hvk, &f, &id, &usk, &[att], rng).err(),
                    Some(Error::InvalidAttestation)
                );
            }
            assert!(satisfiable > 0, "no forgery satisfies the clauses");
        }
        check::<PS, DDH>(
            b"construction/forgery/ps",
            0xc025_0031,
            crate::cred::ps::credential_free_forgeries,
        );
        check::<BBS, DY>(
            b"construction/forgery/bbs",
            0xc025_0032,
            crate::cred::bbs::credential_free_forgeries,
        );
        check::<SPSEQ, DDH>(
            b"construction/forgery/eq",
            0xc025_0033,
            crate::cred::eq::credential_free_forgeries,
        );
    }

    /// `ValidTag` is load-bearing (`T ≠ 1` "throughout", §5.5). For `Tag_DDH` the clause
    /// `T = H_2(s)^K` has the witness `K = 0` for `T = 1`, at EVERY point `s`.
    ///
    /// * A root request for `usk = 0` (hence `id = 1`, `T_0 = 1`) satisfies `R_issue`, and its
    ///   proof verifies under the root context: only `ValidTag` keeps the helper from
    ///   certifying the key `0`.
    /// * With a credential on the key `0` (signed directly here), `T_j = 1` is a "tag" for every
    ///   identifier: the attestation proof verifies and the public checks of `VerifyPossess`
    ///   pass. Only `ValidTag(T_j, s)` rejects it.
    #[test]
    fn the_identity_is_never_a_tag() {
        let mut fixture = Fixture::<PS, DDH>::new(b"construction/validtag", 0xc025_0041);
        let (pcs, hvk, hsk, rng) = (&fixture.pcs, &fixture.hvk, &fixture.hsk, &mut fixture.rng);
        let pp = pcs.base_parameters();
        let f_root = &fixture.f_root;
        let (zero, one) = (Fr::zero(), G1::zero());

        // the root request of the key 0
        let phi = pcs.enc_pred(f_root).unwrap();
        let s = pcs.tag_point(&one).unwrap();
        let rho = Fr::rand(rng);
        let c = PS::issuance_encoding(pp, hvk, &zero, &phi, &rho).unwrap();
        let relation = pcs
            .issuance_relation(hvk, &c, &phi, &one, &one, &s)
            .unwrap();
        let witness = PCS::<E, PS, DDH>::issuance_witness(&zero, &rho);
        assert!(relation.is_satisfied_by(&witness));
        let ctx = pcs.root_context(hvk, f_root, &one, &c, &one).unwrap();
        let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng).unwrap();
        assert!(fiat_shamir::verify(&relation, &ctx, &proof));
        let request = RootRequest::<E, PS> {
            encoding: c,
            t0: one,
            proof,
        };
        assert_eq!(
            pcs.check_root_request(hvk, f_root, &one, &request),
            Err(Error::InvalidTag)
        );
        assert_eq!(
            pcs.issue_root(hvk, hsk, f_root, &one, &request, rng).err(),
            Some(Error::InvalidProof)
        );
        // the honest algorithms refuse the key as well
        let usk_0 = UserSecretKey::<E>::from_scalar(zero);
        assert_eq!(pcs.identity(&usk_0), Err(Error::UndefinedTag));
        assert_eq!(
            pcs.root_request(hvk, f_root, &one, &usk_0, rng).err(),
            Some(Error::IdentifierMismatch)
        );

        // a credential on the key 0, from a signer that does not look, and T_j = 1
        let m = PS::encode_message(pp, &zero, &phi).unwrap();
        let cred = PS::sign(pp, &hsk.sk, &m, rng).unwrap();
        let (shown, ()) = PS::rerand(pp, hvk, &m, &cred, rng).unwrap();
        let (id, _) = pcs.user_keygen(rng).unwrap();
        let s = pcs.tag_point(&id).unwrap();
        let relation = pcs
            .attestation_relation(hvk, &shown, &phi, &one, &s)
            .unwrap();
        assert!(relation.is_satisfied_by(&[zero]));
        let ctx = pcs
            .attestation_context(hvk, &id, &phi, &one, &shown)
            .unwrap();
        let proof = fiat_shamir::prove(&relation, &[zero], &ctx, rng).unwrap();
        assert!(fiat_shamir::verify(&relation, &ctx, &proof));
        assert!(PS::verify_possess_public(pp, hvk, &shown, &phi));
        let att = Attestation::<E, PS> {
            tag: one,
            shown,
            phi,
            proof,
        };
        assert_eq!(
            pcs.check_attestation(hvk, &id, &att),
            Err(Error::InvalidTag)
        );
        // the honest Attest of that holder outputs ⊥
        let cred = Credential::<E, PS> { cred, aux: () };
        assert_eq!(
            pcs.attest(hvk, &usk_0, f_root, &cred, &id, rng).err(),
            Some(Error::UndefinedTag)
        );
    }

    /// Verifiers return `false`, and never panic, on well-typed garbage: random group elements
    /// and scalars, the identity everywhere, proofs with a wrong number of responses. Decoders
    /// return `Err` on random bytes.
    #[test]
    fn verifiers_reject_garbage_without_panicking() {
        fn check<B: RandomShown>(label: &[u8], seed: u64) {
            let fixture = Fixture::<B, DDH>::new(label, seed);
            let (pcs, hvk) = (&fixture.pcs, &fixture.hvk);
            let mut rng = StdRng::seed_from_u64(seed);
            let f = Predicate::new(2, b"members".to_vec());
            for id in [G1::rand(&mut rng), G1::zero(), G1::generator()] {
                let att = random_attestation::<B>(&mut rng);
                assert!(!pcs.verify_attestation(hvk, &id, &att));
                let mut proof = random_proof::<B>(2, &mut rng);
                assert!(!pcs.verify_proof(hvk, &f, &id, &proof));
                let mut request = random_root_request::<B>(&mut rng);
                assert!(!pcs.verify_root_request(hvk, &fixture.f_root, &id, &request));
                assert!(
                    pcs.issue(hvk, &fixture.hsk, &f, &id, &proof, &mut rng)
                        .is_err()
                );
                assert!(
                    pcs.issue_root(hvk, &fixture.hsk, &fixture.f_root, &id, &request, &mut rng)
                        .is_err()
                );

                // no responses at all, and far too many
                for responses in [Vec::new(), vec![Fr::one(); 64]] {
                    proof.proof.responses.clone_from(&responses);
                    proof.attestations[0].proof.responses.clone_from(&responses);
                    request.proof.responses = responses;
                    assert!(!pcs.verify_proof(hvk, &f, &id, &proof));
                    assert!(!pcs.verify_attestation(hvk, &id, &proof.attestations[0]));
                    assert!(!pcs.verify_root_request(hvk, &fixture.f_root, &id, &request));
                }
            }
            // random bytes are not an encoding of anything
            for len in [0usize, 1, 47, 48, 240, 416, 480, 1392, 4096] {
                let mut bytes = vec![0u8; len];
                rng.fill_bytes(&mut bytes);
                assert!(Attestation::<E, B>::from_compact_bytes(&bytes).is_err());
                assert!(IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f).is_err());
                assert!(IssuanceProof::<E, B>::from_bytes(&bytes).is_err());
                assert!(IssuanceState::<E, B>::from_bytes(&bytes).is_err());
                assert!(RootRequest::<E, B>::from_compact_bytes(&bytes).is_err());
            }
        }
        check::<PS>(b"construction/garbage/ps", 0xc025_0051);
        check::<BBS>(b"construction/garbage/bbs", 0xc025_0052);
        check::<SPSEQ>(b"construction/garbage/eq", 0xc025_0053);
    }

    /// Degenerate values in ONE position at a time of an otherwise HONEST proof: the encoding of
    /// the identity of `G_1` or of `G_2`, or the scalar `0` or `1`, is written over the compact
    /// encoding of a valid `k = 2` proof at every 16th offset. Whatever still decodes is a proof
    /// in which everything but one value (or one pair of neighbouring values) is honest, so the
    /// verifier gets past its first checks and the degenerate value is actually LOOKED AT.
    /// Every such proof is rejected, `Issue` outputs `⊥`, and nothing panics. (A proof with the
    /// identity in EVERY position would be rejected by the very first `ValidTag` and show
    /// nothing about the other positions.)
    #[test]
    fn single_degenerate_positions_are_rejected_without_panicking() {
        fn check<B, T>(label: &[u8], seed: u64) -> usize
        where
            B: SigmaFriendlyCredentialBase<E>,
            T: PCSTag<G1>,
        {
            let mut fixture = Fixture::<B, T>::new(label, seed);
            let (id, usk) = fixture.pcs.user_keygen(&mut fixture.rng).unwrap();
            let atts = fixture.attestations(2, &id);
            let (pcs, hvk, hsk, rng) = (&fixture.pcs, &fixture.hvk, &fixture.hsk, &mut fixture.rng);
            let f = Predicate::new(2, b"members".to_vec());
            let (proof, _) = pcs.prove(hvk, &f, &id, &usk, &atts, rng).unwrap();
            let bytes = proof.to_compact_bytes().unwrap();
            // control: the untouched bytes are a proof
            let decoded = IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f).unwrap();
            assert_eq!(pcs.check_proof(hvk, &f, &id, &decoded), Ok(()));

            let g1_identity = G1::zero().to_bytes().unwrap();
            let g2_identity = G2::zero().to_bytes().unwrap();
            let (zero, one) = (
                Fr::zero().to_bytes().unwrap(),
                Fr::one().to_bytes().unwrap(),
            );
            let mut looked_at = 0;
            for at in (0..bytes.len()).step_by(16) {
                for patch in [&g1_identity, &g2_identity, &zero, &one] {
                    let Some(end) = at
                        .checked_add(patch.len())
                        .filter(|end| *end <= bytes.len())
                    else {
                        continue;
                    };
                    let mut bad = bytes.clone();
                    bad[at..end].copy_from_slice(patch);
                    if bad == bytes {
                        continue;
                    }
                    let Ok(bad) = IssuanceProof::<E, B>::from_compact_bytes(&bad, &f) else {
                        continue;
                    };
                    looked_at += 1;
                    assert!(!pcs.verify_proof(hvk, &f, &id, &bad), "patch at {at}");
                    assert!(pcs.issue(hvk, hsk, &f, &id, &bad, rng).is_err());
                }
            }
            looked_at
        }
        // The numbers of patches that decoded (and were then rejected). They are deterministic
        // (seeded) and pinned, so that the test cannot silently turn vacuous.
        let looked_at = [
            check::<PS, DDH>(b"construction/patch/ps", 0xc025_0061),
            check::<PS, DY>(b"construction/patch/ps+dy", 0xc025_0062),
            check::<BBS, DDH>(b"construction/patch/bbs", 0xc025_0063),
            check::<BBS, DY>(b"construction/patch/bbs+dy", 0xc025_0064),
            check::<SPSEQ, DDH>(b"construction/patch/eq", 0xc025_0065),
        ];
        for count in looked_at {
            assert!(count >= 50, "{looked_at:?}");
        }
    }

    // ----- hvk -----------------------------------------------------------------------------------

    /// A helper key outside the range of `KeyGen` (`Ỹ_1 = 1` for `Σ-PS`: a credential under it
    /// does not depend on `usk` at all) is refused by every algorithm that takes the statement
    /// seriously, before anything else is looked at.
    #[test]
    fn a_malformed_helper_key_is_refused() {
        let mut fixture = Fixture::<PS, DDH>::new(b"construction/hvk", 0xc025_0021);
        let holder = fixture.holder();
        let (id, usk) = fixture.pcs.user_keygen(&mut fixture.rng).unwrap();
        let atts = fixture.attestations(1, &id);
        let (pcs, hvk, rng) = (&fixture.pcs, &fixture.hvk, &mut fixture.rng);
        let f = Predicate::new(1, b"members".to_vec());
        let (proof, state) = pcs.prove(hvk, &f, &id, &usk, &atts, rng).unwrap();
        let pre = pcs.issue(hvk, &fixture.hsk, &f, &id, &proof, rng).unwrap();
        let (request, _) = pcs
            .root_request(hvk, &fixture.f_root, &id, &usk, rng)
            .unwrap();

        let mut no_usk = hvk.clone();
        no_usk.y1_tilde = G2::zero();
        let mut inconsistent = hvk.clone();
        inconsistent.y1 = G1::generator();
        for bad in [&no_usk, &inconsistent] {
            assert!(!PS::is_well_formed_key(pcs.base_parameters(), bad));
            assert_eq!(
                pcs.check_attestation(bad, &id, &atts[0]),
                Err(Error::InvalidKey)
            );
            assert_eq!(
                pcs.check_proof(bad, &f, &id, &proof),
                Err(Error::InvalidKey)
            );
            assert_eq!(
                pcs.check_root_request(bad, &fixture.f_root, &id, &request),
                Err(Error::InvalidKey)
            );
            assert_eq!(
                pcs.prove(bad, &f, &id, &usk, &atts, rng).err(),
                Some(Error::InvalidKey)
            );
            assert_eq!(
                pcs.root_request(bad, &fixture.f_root, &id, &usk, rng).err(),
                Some(Error::InvalidKey)
            );
            assert_eq!(
                pcs.unblind(bad, &usk, &f, &pre, &state).err(),
                Some(Error::InvalidKey)
            );
            assert!(!pcs.verify_cred(bad, &holder.usk, &fixture.f_root, &holder.cred));
        }
        // control
        assert!(pcs.verify_cred(hvk, &holder.usk, &fixture.f_root, &holder.cred));
        assert!(pcs.unblind(hvk, &usk, &f, &pre, &state).is_ok());

        // Why VerifyCred looks at the key. A signing key with y_1 = 0 (decoding accepts it) has
        // Ỹ_1 = 1: the verification equation of Σ-PS then does not contain usk, and the base's
        // Verify, which follows its box, accepts ONE credential for EVERY user key.
        let pp = pcs.base_parameters();
        let mut sk_bytes = Fr::rand(rng).to_bytes().unwrap();
        sk_bytes.extend(Fr::zero().to_bytes().unwrap());
        sk_bytes.extend(Fr::rand(rng).to_bytes().unwrap());
        let sk = <PS as CredentialBase>::SigningKey::from_bytes(&sk_bytes).unwrap();
        let vk = sk.verification_key();
        assert!(vk.y1_tilde.is_zero() && !PS::is_well_formed_key(pp, &vk));
        let phi = pcs.enc_pred(&fixture.f_root).unwrap();
        let m = PS::encode_message(pp, holder.usk.expose_scalar(), &phi).unwrap();
        let cred = Credential::<E, PS> {
            cred: PS::sign(pp, &sk, &m, rng).unwrap(),
            aux: (),
        };
        let stranger = UserSecretKey::<E>::from_scalar(Fr::from(1234u64));
        let m_stranger = PS::encode_message(pp, stranger.expose_scalar(), &phi).unwrap();
        assert!(PS::verify(pp, &vk, &m, &cred.cred));
        assert!(PS::verify(pp, &vk, &m_stranger, &cred.cred));
        assert!(!pcs.verify_cred(&vk, &holder.usk, &fixture.f_root, &cred));
        assert!(!pcs.verify_cred(&vk, &stranger, &fixture.f_root, &cred));
    }
}
