//! `Σ-BBS`, the BBS credential base (paper §3.2.2, "The BBS instantiation", box "`Σ-BBS`
//! credential base").
//!
//! Setting: `M_Σ = Z_p^3`, the encoded message is `(usk, φ, ρ)` with the certified-message split
//! `m_hid = (usk, ρ)`, `m_pub = φ`. `h_0, h_1, h_2, h_3` are independent generators of `G_1` and
//! `B(m) = h_0 h_1^{m_1} h_2^{m_2} h_3^{m_3}`. The maps are `Enc_Σ((usk, ρ), φ) = (usk, φ, ρ)`
//! and `Com_vk((usk, ρ), φ; ρ) = h_0 h_1^usk h_2^φ h_3^ρ = B(usk, φ, ρ)`: "the same `ρ` is both
//! a certified hidden component and the local issuance state", and at the PCS layer it is
//! stored next to `(A, e)` as `m_aux`.
//!
//! | paper (box `Σ-BBS`) | here |
//! |---|---|
//! | `KeyGen(pp)`: `x ← Z_p`, `X̃ = g̃^x`, `vk = X̃`, `sk = x`; the generators `h_0, …, h_3` are taken from `pp` | [`CredentialBase::keygen`] (see "Generators") |
//! | `Sign(sk, m)`: `⊥` if `B(m) = 1`; `e ← Z_p \ {−x}`, `cred = (A, e)`, `A = B(m)^{1/(x+e)}` | [`CredentialBase::sign`] |
//! | `Verify`: `[A ≠ 1 ∧ e(A, X̃ g̃^e) = e(B(m), g̃)]` | [`CredentialBase::verify`], ONE pairing product |
//! | `ReRand(vk, m, (A, e))`: `r_1, r_2 ← Z_p^*`, `D = B(m)^{r_2}`, `Ā = A^{r_1 r_2}`, `B̄ = D^{r_1} Ā^{-e}`, `r_3 = r_2^{-1}`; `cred* = (Ā, B̄, D)`, `ω = (e, r_1, r_3)` | [`CredentialBase::rerand`] |
//! | `BlindIssue(sk, C, φ)`: `⊥` if `C = 1`; `e ← Z_p \ {−x}`, `ĉred = (C^{1/(x+e)}, e)` | [`CredentialBase::blind_issue`] |
//! | `Unblind(vk, (usk, φ, ρ), ĉred, ρ) = ĉred` | [`CredentialBase::unblind`] |
//! | `Possess` step 1: reject if `Ā = 1`, `D = 1` or `e(Ā, X̃) ≠ e(B̄, g̃)` | [`SigmaFriendlyCredentialBase::verify_possess_public`], ONE pairing product |
//! | `Possess` step 2: `B̄ = D^{r_1} Ā^{-e}` and `h_0 h_2^φ = D^{r_3} h_1^{-usk} h_3^{-ρ}` | [`SigmaFriendlyCredentialBase::possession_clauses`], two `G_1` clauses |
//! | §5.1: `(m_aux, ρ) = (r, r)`, `r ← Z_p`; opening clause `C = B(usk, φ, ρ)` of `R_issue` | [`SigmaFriendlyCredentialBase::sample_issuance`], [`SigmaFriendlyCredentialBase::issuance_clauses`] |
//!
//! Security (Lemma on `Σ-BBS`, §3.2.2): under `q`-SDH and the one-more security of
//! committed-message BBS issuance, `Σ-BBS` is a *weak* sigma-friendly credential base: `cred*`
//! is a blinded encoding, not a signature. The nonidentity checks exclude degenerate public
//! statements; the degenerate WITNESSES, which the proof sketch of the Lemma excludes
//! computationally, are spelled out under "The possession proof".
//!
//! # In formulas
//!
//! ```math
//! \begin{aligned}
//! B(m) &= h_0\, h_1^{m_1} h_2^{m_2} h_3^{m_3}, \qquad m = (usk, \varphi, \rho) \\
//! \mathsf{Sign}(x, m) &= (A, e), \qquad A = B(m)^{1/(x+e)}, \quad e \leftarrow \mathbb{Z}_p \setminus \{-x\} \\
//! \mathsf{Verify}\bigl(\tilde{X}, m, (A, e)\bigr) &= \bigl[\, A \neq 1 \;\wedge\; e\bigl(A,\ \tilde{X}\, \tilde{g}^{\,e}\bigr) = e\bigl(B(m), \tilde{g}\bigr) \,\bigr]
//! \end{aligned}
//! ```
//!
//! The show $`cred^{*} = (\bar{A}, \bar{B}, D)`$ with $`D = B(m)^{r_2}`$, $`\bar{A} = A^{r_1 r_2}`$,
//! $`\bar{B} = D^{r_1} \bar{A}^{-e}`$ and $`r_3 = r_2^{-1}`$:
//!
//! ```math
//! \begin{aligned}
//! \text{public checks:}\quad & \bar{A} \neq 1, \qquad D \neq 1, \qquad e(\bar{A}, \tilde{X}) = e(\bar{B}, \tilde{g}) \\
//! \text{proved:}\quad & \bar{B} = D^{r_1} \bar{A}^{-e} \quad\wedge\quad h_0\, h_2^{\varphi} = D^{r_3}\, h_1^{-usk}\, h_3^{-\rho}
//! \end{aligned}
//! ```
//!
//! # Where `φ` enters
//!
//! `φ` is already inside `C = h_0 h_1^usk h_2^φ h_3^ρ`; `BlindIssue` signs `C` as it is and does
//! NOT add `φ` again (unlike `Σ-PS`, whose `C` is independent of `φ`). The opening clause of
//! `R_issue` therefore has the public target `C h_0^{-1} h_2^{-φ} = h_1^usk h_3^ρ`, with base
//! `h_1` for the shared `usk` and base `h_3` for a fresh variable `ρ`; this clause is what ties
//! the `φ` of the statement to the `φ` inside `C`.
//!
//! # Generators
//!
//! As in the paper, `h_0, …, h_3` are part of `pp_Σ` and are derived transparently, by hashing a
//! public label to `G_1`, "so that no party (in particular not the key holder) knows a
//! discrete-logarithm relation among them": [`BBSPublicParams`], derived with
//! [`HashToGroup::generators`] under the suffix [`GENERATORS_SUFFIX`]. `vk` is `X̃` alone (96 B
//! over BLS12-381). This is why the base has the type parameter `H`. Anyone can recompute the
//! generators from the deployment label.
//! Consequences: `hvk` does not carry the generators, so a proof is tied to them through its
//! statement (Fiat-Shamir absorbs the clause bases `h_1, h_3` and the targets built from
//! `h_0, h_2`) and through a context that covers `pp_Σ` and not just `hvk`: `ctx_j` and `ctx_0`
//! of the construction box start with `pp`. The unit tests and the conformance flow check that
//! an attestation does not verify under other generators.
//!
//! # Degenerate inputs
//!
//! Implementation notes on values that are decoded rather than honestly generated. Decoding
//! accepts the identity point, so:
//!
//! * **Generators.** With `h_1 = 1` the second possession clause does not depend on `usk` (ONE
//!   credential then satisfies `R_att` next to a tag under ANY key), with `h_2 = 1` it does not
//!   depend on `φ`, with `h_0 = 1` signatures are homogeneous (`A^k` is a signature on `k·m`),
//!   and with `h_3 = 1` the encoding `C` has no blinding term. Honest `Setup` never outputs the
//!   identity ([`HashToGroup`] has range `G \ {1}`), but a decoded `pp` is arbitrary. Hence
//!   [`BBSPublicParams::is_well_formed`] (no generator is the identity) is re-imposed by the
//!   possession verifier as a public check in the sense of Def. "Sigma-friendly credential
//!   base", and by the opening clause. It is a NECESSARY condition only: that the generators
//!   are *independent* (e.g. `h_3 ≠ h_1^2`) cannot be read off the four points, and the
//!   possession proof needs it (whoever knows their discrete logarithms has the witnesses with
//!   `r_3 = 0` of "The possession proof"). Whoever accepts a `pp` it did not derive itself
//!   recomputes `Setup` for the deployment label and compares.
//! * **`B(m) = 1`.** On the `p^2` messages with `B(m) = 1` the signing formula gives `A = 1`,
//!   which `Verify` rejects, so `Sign` and `BlindIssue` (`C = 1`) return `⊥` as in the box;
//!   finding such a message amounts to a discrete-logarithm relation among `h_0, …, h_3`
//!   (proof sketch of the Lemma: correctness holds for every efficiently chosen message). On
//!   such a message the equation of `Verify` reads `e(A, g̃)^{x+e} = 1`, so `Verify` accepts
//!   exactly the pairs `(A, −x)` with `A ≠ 1`: never an output of `Sign` (`e ≠ −x`), and whoever
//!   writes one down knows the signing key. `ReRand` outputs `⊥` on these messages as well, and
//!   `C = 1` is inadmissible on the wire. `Sign` and `BlindIssue` stay the same formula on the
//!   same base, so encoded issuance still has exactly the fresh-signature distribution.
//! * **Inversions.** `1/(x+e)` and `r_2^{-1}` go through `Field::inverse()` (field division by
//!   zero panics): `e` is resampled while `x + e = 0`, which is how `e ← Z_p \ {−x}` is
//!   sampled, and `r_2 ≠ 0` by sampling.
//! * **Keys.** The box samples `x ← Z_p`, so every `X̃ ∈ G_2` is in the range of `KeyGen` and
//!   [`CredentialBase::is_well_formed_key`] is constantly `true`. No component of the certified
//!   message hangs on a key component: `usk`, `φ`, `ρ` are bound through `h_1, h_2, h_3 ∈ pp_Σ`.
//!
//! # The possession proof
//!
//! [`SigmaFriendlyCredentialBase::possession_clauses`] allocates, in this order,
//! `(e, ρ, r_1, r_3)`, and [`SigmaFriendlyCredentialBase::possession_witness`] returns their
//! values in the same order; `usk` is the caller's variable, shared with the tag clause. An
//! attestation thus has 5 responses ([`SigmaFriendlyCredentialBase::POSSESSION_VARIABLES`]` = 4`)
//! and `π_0` has 2 ([`SigmaFriendlyCredentialBase::ISSUANCE_VARIABLES`]` = 1`). The 5-scalar
//! witness `(usk, e, ρ, r_1, r_3)` is built by
//! [`possession_witness_vector`](super::possession_witness_vector) in one allocation. Both
//! clauses live in `G_1`; the only pairings are the two of the public check.
//!
//! The verifier MUST run the public checks first. For `Ā = B̄ = 1` and `D = h_0 h_1^K h_2^φ` the
//! clauses hold with `(e, ρ, r_1, r_3) = (0, 0, 0, 1)` for EVERY key `K`, the pairing equation
//! reads `1 = 1`, and only `Ā ≠ 1` rejects this credential-free statement
//! (`credential_free_forgeries`, behind the cargo feature `test-utils`). A holder that
//! re-randomizes its credential under a message with ANOTHER key satisfies both clauses as
//! well; there only the pairing equation rejects.
//!
//! What the public checks do NOT exclude (proof sketch of the Lemma on `Σ-BBS`: "They do not
//! exclude degenerate witnesses"); the unit tests mount every case. Let `cred*` pass the public
//! checks (`Ā ≠ 1`,
//! `D ≠ 1`, `B̄ = Ā^x`) and let `(usk, e, ρ, r_1, r_3)` satisfy both clauses, that is
//! `Ā^{x+e} = D^{r_1}` and `D^{r_3} = B(m)` for `m = (usk, φ, ρ)`. If `r_1 ≠ 0 ≠ r_3`, then
//! `(Ā^{r_3/r_1}, e)` is a credential that verifies on `m` (the unit tests rebuild it from an
//! extracted witness). The degenerate WITNESSES are left, and they are excluded
//! computationally, not by a public check:
//!
//! * `r_1 = 0` forces `Ā^{x+e} = 1`, i.e. `e = −x`: the witness contains the signing key, the
//!   discrete logarithm of `X̃`.
//! * `r_3 = 0` forces `B(m) = 1`: the witness contains a message with identity base, i.e. a
//!   discrete-logarithm relation among `h_0, …, h_3` (for independent generators, finding one
//!   is as hard as a discrete logarithm in `G_1`; this is the binding argument for `C`, which
//!   the paper's table of hypotheses calls "DL-binding"). Whoever can find such messages for
//!   keys of its choice (knowing the discrete logarithms of the generators, say) attests with
//!   ONE credential, for any label and next to tags under arbitrary keys, with every public
//!   check passing and no signing key involved.
//!
//! A statement with `D = 1` that passes the other two checks has a witness only if BOTH hold
//! (`B(m) = D^{r_3} = 1`, and `Ā^{x+e} = D^{r_1} = 1`, i.e. `e = −x`), and then the same
//! `(usk, e, ρ)` with `(r_1, r_3) = (0, 0)` is a witness for the statement with ANY other `D`,
//! which passes every public check. So the check `D ≠ 1`, kept because the box requires it,
//! rejects nothing that is not already infeasible to prove; `Ā ≠ 1` and the pairing equation
//! are the load-bearing checks (the two examples above).
//!
//! The two-randomizer show is what keeps the helper, who recorded the `e` of every credential
//! it issued, from recognising the attester: "no public pair has the form `(R, R^e)`" (Lemma on
//! `Σ-BBS`, show unlinkability). Implementation note, checked by the unit tests (attack A7 of the
//! reference implementations): with a single randomizer (`r_1 = 1`) the pair
//! `(Ā, D B̄^{-1}) = (Ā, Ā^e)` would be public, and `e(Ā, X̃ g̃^e) = e(D, g̃)` would identify `e`.
//! Do not "simplify" the show to one randomizer; the tests run the helper's tests against both
//! shapes.
//!
//! # Example
//!
//! Encoded issuance (Def. "Credential base", correctness) and a possession proof (Def.
//! "Sigma-friendly credential base"):
//!
//! ```
//! use ark_bls12_381::{Bls12_381, Fr};
//! use predicate_credential_system::{
//!     cred::{
//!         self, possess, verify_possess, CredentialBase, SigmaFriendlyCredentialBase,
//!     },
//!     hash::bls12_381::G1Hasher,
//! };
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type E = Bls12_381;
//! type BBS = cred::BBS<E, G1Hasher>;
//! let mut rng = StdRng::seed_from_u64(1);
//! let pp = BBS::setup(b"example deployment")?;
//! let (vk, sk) = BBS::keygen(&pp, &mut rng);
//! let (usk, phi) = (Fr::from(11u64), Fr::from(22u64));
//!
//! // user: (m_aux, ρ) = (r, r), m_hid = (usk, ρ), C = Com((usk, ρ), φ; ρ) = B(usk, φ, ρ)
//! let (aux, rho) = BBS::sample_issuance(&pp, &mut rng);
//! let m_hid = BBS::hidden_message(&usk, &aux);
//! let c = BBS::issuance_encoding(&pp, &vk, &m_hid, &phi, &rho)?;
//! // signer: BlindIssue(sk, C, φ)      user: Unblind returns the pre-credential as it is
//! let pre = BBS::blind_issue(&pp, &sk, &c, &phi, &mut rng)?;
//! let m = BBS::encode_message(&pp, &m_hid, &phi)?;
//! let cred = BBS::unblind(&pp, &vk, &m, &pre, &rho)?;
//! assert!(BBS::verify(&pp, &vk, &m, &cred));
//!
//! // show: cred* = (Ā, B̄, D) passes the public checks; the proof has 5 responses
//! let (shown, omega) = BBS::rerand(&pp, &vk, &m, &cred, &mut rng)?;
//! assert!(BBS::verify_possess_public(&pp, &vk, &shown, &phi));
//! let proof = possess::<E, BBS, _>(&pp, &vk, &shown, &phi, &m_hid, &omega, b"ctx", &mut rng)?;
//! assert!(verify_possess::<E, BBS>(&pp, &vk, &shown, &phi, b"ctx", &proof));
//! assert!(!verify_possess::<E, BBS>(&pp, &vk, &shown, &(phi + phi), b"ctx", &proof));
//! assert_eq!(proof.responses.len(), 5);
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

use core::{fmt, marker::PhantomData};

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    CredentialBase, SigmaFriendlyCredentialBase, ensure_allocated, pairing_product_is_identity,
};
use crate::{
    error::Error,
    hash::HashToGroup,
    sample::nonzero_scalar,
    sigma::{LinearEquation, PairingRelation, ScalarVar, Witness},
};

pub mod ietf;

/// Oracle suffix under which the generators `h_0, …, h_3` are derived.
pub const GENERATORS_SUFFIX: &[u8] = b"/BBS-GENERATORS";

/// The `Σ-BBS` credential base over the pairing `E`, with generators derived by the
/// hash-to-group oracle `H` (a marker type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BBS<E: Pairing, H: HashToGroup<E::G1>>(PhantomData<(E, H)>);

/// The public parameters `pp_Σ = (h_0, h_1, h_2, h_3)`: independent generators of `G_1`
/// (mutually unknown discrete logarithms in the random-oracle model), none the identity.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPublicParams<E: Pairing> {
    /// `h_0`, the constant term of `B(m)`.
    pub h0: E::G1,
    /// `h_1`, the base of `usk`.
    pub h1: E::G1,
    /// `h_2`, the base of `φ`.
    pub h2: E::G1,
    /// `h_3`, the base of `ρ`.
    pub h3: E::G1,
}

impl<E: Pairing> BBSPublicParams<E> {
    /// `B(m) = h_0 h_1^{m_1} h_2^{m_2} h_3^{m_3}` (§3.2.2): the element that `Sign` raises to
    /// `1/(x+e)`, and the issuance encoding `C` of the message `m = (usk, φ, ρ)`.
    #[must_use]
    pub fn b(&self, m: &BBSMessage<E>) -> E::G1 {
        self.h0 + self.h1 * m.m1 + self.h2 * m.m2 + self.h3 * m.m3
    }

    /// Whether no generator is the identity. This is the key-independent public check of the
    /// possession verifier and of the opening clause (module docs, "Degenerate inputs"); it
    /// costs no group operation.
    ///
    /// Implementation note, not an algorithm of the paper. The condition is necessary, NOT
    /// sufficient, for "independent generators": independence cannot be decided from the four
    /// points. A `pp` received from outside is validated by recomputing
    /// [`CredentialBase::setup`] for the deployment label and comparing.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !(self.h0.is_zero() || self.h1.is_zero() || self.h2.is_zero() || self.h3.is_zero())
    }
}

/// The signing key `sk = x ∈ Z_p`. Secret: wiped on drop, not `Clone`, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSSigningKey<E: Pairing> {
    x: E::ScalarField,
}

impl<E: Pairing> BBSSigningKey<E> {
    /// The verification key `X̃ = g̃^x` of this signing key (`KeyGen` step 1).
    #[must_use]
    pub fn verification_key(&self) -> BBSVerificationKey<E> {
        BBSVerificationKey {
            x_tilde: E::G2::generator() * self.x,
        }
    }

    /// The signing formula that `Sign` applies to `B(m)` and `BlindIssue` to `C` (proof sketch
    /// of the Lemma on `Σ-BBS`: "encoded issuance applies the signing formula to the same base
    /// `C = B(m)` with a fresh signing randomizer `e`"): `e ← Z_p \ {−x}`, then
    /// `(base^{1/(x+e)}, e)`.
    ///
    /// `e` is rejection-sampled: `inverse()` is `None` exactly for the excluded value `e = −x`,
    /// so the accepted `e` is uniform on `Z_p \ {−x}` and the loop repeats with probability
    /// `1/p` per iteration. No field division, hence no panic.
    fn sign_base<R: RngCore + CryptoRng + ?Sized>(
        &self,
        base: &E::G1,
        rng: &mut R,
    ) -> (E::G1, E::ScalarField) {
        loop {
            let e = E::ScalarField::rand(rng);
            if let Some(mut inverse) = (self.x + e).inverse() {
                let a = *base * inverse;
                inverse.zeroize();
                return (a, e);
            }
        }
    }
}

impl<E: Pairing> fmt::Debug for BBSSigningKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BBSSigningKey(<redacted>)")
    }
}

/// The verification key `X̃ = g̃^x` (the generators of the paper's `vk` live in
/// [`BBSPublicParams`]).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSVerificationKey<E: Pairing> {
    /// `X̃ = g̃^x`.
    pub x_tilde: E::G2,
}

/// The hidden certified message `m_hid = (usk, ρ)`. Secret: wiped on drop, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BBSHiddenMessage<E: Pairing> {
    usk: E::ScalarField,
    rho: E::ScalarField,
}

impl<E: Pairing> BBSHiddenMessage<E> {
    /// The hidden message `(usk, ρ)`.
    #[must_use]
    pub fn new(usk: E::ScalarField, rho: E::ScalarField) -> Self {
        Self { usk, rho }
    }
}

impl<E: Pairing> fmt::Debug for BBSHiddenMessage<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BBSHiddenMessage(<redacted>)")
    }
}

/// A signing message `m = (m_1, m_2, m_3) ∈ M_Σ = Z_p^3`; the construction signs
/// `Enc_Σ((usk, ρ), φ) = (usk, φ, ρ)`. Secret: wiped on drop, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BBSMessage<E: Pairing> {
    m1: E::ScalarField,
    m2: E::ScalarField,
    m3: E::ScalarField,
}

impl<E: Pairing> BBSMessage<E> {
    /// The message `(m_1, m_2, m_3)`.
    #[must_use]
    pub fn new(m1: E::ScalarField, m2: E::ScalarField, m3: E::ScalarField) -> Self {
        Self { m1, m2, m3 }
    }
}

impl<E: Pairing> fmt::Debug for BBSMessage<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BBSMessage(<redacted>)")
    }
}

/// A credential `cred = (A, e)` with `A = B(m)^{1/(x+e)}`, `A ≠ 1`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSCredential<E: Pairing> {
    /// `A`.
    pub a: E::G1,
    /// `e`.
    pub e: E::ScalarField,
}

/// A pre-credential `ĉred = (C^{1/(x+e)}, e)`; `Unblind` returns it unchanged as a credential.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPreCredential<E: Pairing> {
    /// `A = C^{1/(x+e)}`.
    pub a: E::G1,
    /// `e`.
    pub e: E::ScalarField,
}

/// A shown credential `cred* = (Ā, B̄, D)`: a blinded encoding that does not verify as a
/// signature (weak show).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSShownCredential<E: Pairing> {
    /// `Ā = A^{r_1 r_2}`.
    pub a_bar: E::G1,
    /// `B̄ = D^{r_1} Ā^{-e}`.
    pub b_bar: E::G1,
    /// `D = B(m)^{r_2}`.
    pub d: E::G1,
}

/// The show state `ω = (e, r_1, r_3)` of `ReRand`. Secret: wiped on drop, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BBSShowState<E: Pairing> {
    e: E::ScalarField,
    r1: E::ScalarField,
    r3: E::ScalarField,
}

impl<E: Pairing> fmt::Debug for BBSShowState<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BBSShowState(<redacted>)")
    }
}

/// `(r, r^{-1})` for `r ← Z_p^*`. `inverse()` is `Some` for every non-zero `r`, so the loop
/// body runs once; written as a loop so that no input and no RNG can cause a panic.
fn nonzero_scalar_with_inverse<F, R>(rng: &mut R) -> (F, F)
where
    F: Field,
    R: RngCore + CryptoRng + ?Sized,
{
    loop {
        let r: F = nonzero_scalar(rng);
        if let Some(inverse) = r.inverse() {
            return (r, inverse);
        }
    }
}

impl<E: Pairing, H: HashToGroup<E::G1>> CredentialBase for BBS<E, H> {
    type PublicParams = BBSPublicParams<E>;
    type SigningKey = BBSSigningKey<E>;
    type VerificationKey = BBSVerificationKey<E>;
    /// `m_hid = (usk, ρ)`.
    type HiddenMessage = BBSHiddenMessage<E>;
    /// `m_pub = φ`.
    type PublicMessage = E::ScalarField;
    type Message = BBSMessage<E>;
    /// `R_Σ = Z_p ∋ ρ`, the same `ρ` as in `m_hid`.
    type IssuanceState = E::ScalarField;
    /// `C_Σ = G_1 ∋ C = B(usk, φ, ρ)`.
    type IssuanceEncoding = E::G1;
    type Credential = BBSCredential<E>;
    type PreCredential = BBSPreCredential<E>;
    type ShownCredential = BBSShownCredential<E>;
    /// `ω = (e, r_1, r_3)`.
    type ShowState = BBSShowState<E>;

    /// `pp_Σ = (h_0, …, h_3)`: the first four outputs of the oracle `H` of the deployment
    /// `domain` under the suffix [`GENERATORS_SUFFIX`] ("let `h_0, h_1, h_2, h_3` be independent
    /// generators", §3.2.2; module docs, "Generators").
    ///
    /// # Errors
    /// [`Error::HashToCurve`] if the oracle cannot be instantiated. Implementation note, for an
    /// oracle `H` that breaks the contract of [`HashToGroup`]: [`Error::LengthMismatch`] if it
    /// does not return four generators, [`Error::DegenerateInput`] if one of them is the
    /// identity.
    fn setup(domain: &[u8]) -> Result<Self::PublicParams, Error> {
        let generators = H::new(domain)?.generators(GENERATORS_SUFFIX, 4);
        let actual = generators.len();
        let [h0, h1, h2, h3] =
            <[E::G1; 4]>::try_from(generators).map_err(|_| Error::LengthMismatch {
                expected: 4,
                actual,
            })?;
        let pp = BBSPublicParams { h0, h1, h2, h3 };
        if pp.is_well_formed() {
            Ok(pp)
        } else {
            Err(Error::DegenerateInput("identity generator of Σ-BBS"))
        }
    }

    /// `KeyGen(pp)` (box `Σ-BBS`): `vk = X̃`; the generators are taken from `pp` (module docs,
    /// "Generators").
    fn keygen<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::VerificationKey, Self::SigningKey) {
        // 1. x ← Z_p, X̃ = g̃^x
        let sk = BBSSigningKey {
            x: E::ScalarField::rand(rng),
        };
        // 2. vk = X̃, sk = x (the generators are taken from pp)
        (sk.verification_key(), sk)
    }

    /// Every `X̃ ∈ G_2` is `g̃^x` for some `x ∈ Z_p`, the key space of the box.
    ///
    /// Implementation note: that includes `X̃ = 1`, the key of `x = 0`. Like every key whose
    /// signing key is known it certifies nothing, which no test on `vk` can tell in general.
    fn is_well_formed_key(_pp: &Self::PublicParams, _vk: &Self::VerificationKey) -> bool {
        true
    }

    /// `Sign(sk, m)` (box `Σ-BBS`).
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] for a message with `B(m) = 1`, the `⊥` of step 1 (module docs,
    /// "Degenerate inputs").
    fn sign<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        m: &Self::Message,
        rng: &mut R,
    ) -> Result<Self::Credential, Error> {
        let b = pp.b(m);
        if b.is_zero() {
            return Err(Error::InvalidMessage);
        }
        // 1. e ← Z_p \ {−x}
        // 2. cred = (A, e), A = B(m)^{1/(x+e)}
        let (a, e) = sk.sign_base(&b, rng);
        Ok(BBSCredential { a, e })
    }

    /// `Verify(vk, m, (A, e)) = [A ≠ 1 ∧ e(A, X̃ g̃^e) = e(B(m), g̃)]` (box `Σ-BBS`), the pairing
    /// equation as ONE product `e(A, X̃ g̃^e) · e(B(m)^{-1}, g̃) = 1` (two Miller loops, one final
    /// exponentiation).
    fn verify(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
    ) -> bool {
        if cred.a.is_zero() {
            return false;
        }
        let g2 = E::G2::generator();
        pairing_product_is_identity::<E>(&[(cred.a, vk.x_tilde + g2 * cred.e), (-pp.b(m), g2)])
    }

    /// `Enc_Σ((usk, ρ), φ) = (usk, φ, ρ)`. Never fails.
    fn encode_message(
        _pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
    ) -> Result<Self::Message, Error> {
        Ok(BBSMessage::new(m_hid.usk, *m_pub, m_hid.rho))
    }

    /// `Com_vk((usk, ρ), φ; ρ) = h_0 h_1^usk h_2^φ h_3^ρ = B(usk, φ, ρ)`. Independent of `vk`
    /// (the generators are in `pp`).
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if the issuance state `r` is not the `ρ` inside `m_hid`: "the
    /// same `ρ` is both a certified hidden component and the local issuance state" (§3.2.2), so
    /// `Com` is only defined on such inputs.
    fn issuance_encoding(
        pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
        r: &Self::IssuanceState,
    ) -> Result<Self::IssuanceEncoding, Error> {
        if *r != m_hid.rho {
            return Err(Error::InvalidMessage);
        }
        Ok(pp.b(&BBSMessage::new(m_hid.usk, *m_pub, m_hid.rho)))
    }

    /// `ReRand(vk, m = (usk, φ, ρ), (A, e))` (box `Σ-BBS`): the two-randomizer show. Keyless;
    /// as in the box, `cred` is not verified first, so a show of a credential that does not
    /// verify on `m` is produced and then rejected by the public pairing check of `Possess`.
    ///
    /// Implementation note on the distribution, a short argument that is not in the paper: for
    /// `A ≠ 1` and `B(m) ≠ 1` the pair `(Ā, D) = (A^{r_1 r_2}, B(m)^{r_2})` is uniform on
    /// `(G_1 \ {1})^2`, because `(r_1, r_2) ↦ (r_1 r_2, r_2)` is a bijection of `(Z_p^*)^2` and
    /// both bases generate `G_1`; and `B̄ = Ā^x` for every credential that verifies on `m`. So
    /// `cred*` by itself is distributed independently of `(m, cred)`.
    ///
    /// # Errors
    /// Implementation note: [`Error::InvalidCredential`] for `A = 1` and for `B(m) = 1`. The box
    /// has no `⊥` case; on these inputs it outputs a `cred*` with `Ā = 1`, resp. `D = 1`, which
    /// every possession verifier rejects. A credential with `A = 1` never verifies. On a
    /// message with `B(m) = 1` exactly the pairs `(A, −x)` with `A ≠ 1` verify; `Sign` never
    /// outputs one, and writing one down takes the signing key (module docs, "Degenerate
    /// inputs").
    fn rerand<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
        rng: &mut R,
    ) -> Result<(Self::ShownCredential, Self::ShowState), Error> {
        let b = pp.b(m);
        if cred.a.is_zero() || b.is_zero() {
            return Err(Error::InvalidCredential);
        }
        // 1. r_1, r_2 ← Z_p^*, D = B(m)^{r_2}
        let r1: E::ScalarField = nonzero_scalar(rng);
        let (mut r2, r3) = nonzero_scalar_with_inverse::<E::ScalarField, _>(rng);
        let d = b * r2;
        // 2. Ā = A^{r_1 r_2}, B̄ = D^{r_1} Ā^{-e}, r_3 = r_2^{-1}
        let a_bar = cred.a * (r1 * r2);
        let b_bar = d * r1 - a_bar * cred.e;
        r2.zeroize();
        // 3. return (cred* = (Ā, B̄, D), ω = (e, r_1, r_3))
        Ok((
            BBSShownCredential { a_bar, b_bar, d },
            BBSShowState { e: cred.e, r1, r3 },
        ))
    }

    /// `BlindIssue(sk, C, φ)` (box `Σ-BBS`). The signer sees only `C` and `φ`. `φ` is already
    /// inside `C` and is NOT added again; that the `φ` inside `C` is the disclosed one is what
    /// the opening clause of `R_issue` proves
    /// ([`SigmaFriendlyCredentialBase::issuance_clauses`]).
    ///
    /// # Errors
    /// [`Error::InvalidIssuanceEncoding`] for `C = 1`, the `⊥` of step 1: the encoding of a
    /// message with `B(m) = 1`, on which [`CredentialBase::sign`] outputs `⊥` too.
    fn blind_issue<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        c: &Self::IssuanceEncoding,
        _m_pub: &Self::PublicMessage,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error> {
        if c.is_zero() {
            return Err(Error::InvalidIssuanceEncoding);
        }
        // 1. parse C = h_0 h_1^usk h_2^φ h_3^ρ, e ← Z_p \ {−x}
        // 2. ĉred = (C^{1/(x+e)}, e)
        let (a, e) = sk.sign_base(c, rng);
        Ok(BBSPreCredential { a, e })
    }

    /// `Unblind(vk, (usk, φ, ρ), ĉred, ρ) = ĉred` (box `Σ-BBS`). Deterministic; as in the box,
    /// the result is not verified here (the caller runs `Verify`).
    ///
    /// # Errors
    /// Implementation notes: [`Error::InvalidPreCredential`] for `A = 1`, which an honest
    /// signer never outputs and which never verifies; [`Error::InvalidMessage`] if the issuance
    /// state `r` is not the `ρ` inside `m` (the box passes the same `ρ` twice).
    fn unblind(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        m: &Self::Message,
        pre: &Self::PreCredential,
        r: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error> {
        if *r != m.m3 {
            return Err(Error::InvalidMessage);
        }
        if pre.a.is_zero() {
            return Err(Error::InvalidPreCredential);
        }
        Ok(BBSCredential { a: pre.a, e: pre.e })
    }
}

impl<E: Pairing, H: HashToGroup<E::G1>> SigmaFriendlyCredentialBase<E> for BBS<E, H> {
    /// `m_aux = ρ`, stored next to `(A, e)` by the holder.
    type Aux = E::ScalarField;
    /// `C` travels inside `π`.
    type WireEncoding = E::G1;

    const REQUIRES_DLOG_IDENTITY: bool = false;
    /// `(e, ρ, r_1, r_3)`.
    const POSSESSION_VARIABLES: usize = 4;
    /// The opening clause adds `ρ`.
    const ISSUANCE_VARIABLES: usize = 1;

    /// `m_hid = (usk, m_aux) = (usk, ρ)`.
    fn hidden_message(usk: &E::ScalarField, aux: &Self::Aux) -> Self::HiddenMessage {
        BBSHiddenMessage::new(*usk, *aux)
    }

    fn split_hidden_message(m_hid: &Self::HiddenMessage) -> (E::ScalarField, Self::Aux) {
        (m_hid.usk, m_hid.rho)
    }

    /// `(m_aux, ρ) = (r, r)`, `r ← Z_p` (§5.1, the display before the protocol box): the same
    /// `r` is certified and is the issuance state.
    fn sample_issuance<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::Aux, Self::IssuanceState) {
        let r = E::ScalarField::rand(rng);
        (r, r)
    }

    fn encoding_to_wire(c: &Self::IssuanceEncoding) -> Self::WireEncoding {
        *c
    }

    /// The transmitted `C`. Implementation note: `C = 1` is inadmissible, because
    /// [`CredentialBase::blind_issue`] outputs `⊥` on it. Every other element of `G_1` is
    /// `B(usk, φ, ρ)` for some `(usk, ρ)`; knowledge of an opening is what `π_0` proves.
    fn encoding_from_wire(
        _pp: &Self::PublicParams,
        wire: &Self::WireEncoding,
        _id: &E::G1,
    ) -> Option<Self::IssuanceEncoding> {
        (!wire.is_zero()).then_some(*wire)
    }

    /// `Possess` step 1 (box `Σ-BBS`): "the verifier rejects if `Ā = 1`, `D = 1`, or
    /// `e(Ā, X̃) ≠ e(B̄, g̃)`", the pairing equation as ONE product `e(Ā, X̃) · e(B̄^{-1}, g̃) = 1`.
    ///
    /// Implementation note on what each check is for (the unit tests isolate each one): with
    /// `Ā = B̄ = 1` the clauses below are satisfiable without any credential, and the pairing
    /// equation, i.e. `B̄ = Ā^x`, is the only place where the helper's key enters. With `D = 1`
    /// the first clause reads `B̄ = Ā^{-e}`, which next to `B̄ = Ā^x` and `Ā ≠ 1` says `e = −x`,
    /// and the second clause reads `B(usk, φ, ρ) = 1`, a relation among the generators alone.
    /// `D ≠ 1` is checked because the box requires it, but it is NOT load-bearing: a party that
    /// knows `x` and such relations passes all three checks with a random `D ≠ 1` and a
    /// witness with `(r_1, r_3) = (0, 0)`. No public check excludes the degenerate witnesses
    /// `r_1 = 0` (which forces `e = −x`) and `r_3 = 0` (which forces `B(usk, φ, ρ) = 1`); they
    /// are infeasible to find (module docs, "The possession proof").
    ///
    /// Implementation note: a `pp` with an identity generator is rejected as well
    /// ([`BBSPublicParams::is_well_formed`]); with `h_1 = 1` the clauses would hold next to a
    /// tag under every key.
    fn verify_possess_public(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        _m_pub: &E::ScalarField,
    ) -> bool {
        pp.is_well_formed()
            && !shown.a_bar.is_zero()
            && !shown.d.is_zero()
            && pairing_product_is_identity::<E>(&[
                (shown.a_bar, vk.x_tilde),
                (-shown.b_bar, E::G2::generator()),
            ])
    }

    /// `Possess` step 2 (box `Σ-BBS`): the two `G_1` clauses
    ///
    /// * `B̄ = D^{r_1} Ā^{-e}` (bases `D`, `Ā^{-1}`; variables `r_1`, `e`) and
    /// * `h_0 h_2^φ = D^{r_3} h_1^{-usk} h_3^{-ρ}` (bases `D`, `h_1^{-1}`, `h_3^{-1}`; variables
    ///   `r_3`, `usk`, `ρ`).
    ///
    /// Allocates `(e, ρ, r_1, r_3)`, in this order; `usk` is the caller's shared variable. `φ`
    /// enters through the target `h_0 h_2^φ`. The relation is left untouched on error.
    fn possession_clauses(
        pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        ensure_allocated(rel, usk)?;
        let (e, rho, r1, r3) = (
            rel.alloc_scalar(),
            rel.alloc_scalar(),
            rel.alloc_scalar(),
            rel.alloc_scalar(),
        );
        rel.add_g1(LinearEquation::new(
            vec![(r1, shown.d), (e, -shown.a_bar)],
            shown.b_bar,
        ))?;
        rel.add_g1(LinearEquation::new(
            vec![(r3, shown.d), (usk, -pp.h1), (rho, -pp.h3)],
            pp.h0 + pp.h2 * *m_pub,
        ))?;
        Ok(vec![e, rho, r1, r3])
    }

    /// The values `(e, ρ, r_1, r_3)`, in the order of [`Self::possession_clauses`].
    fn possession_witness(
        m_hid: &Self::HiddenMessage,
        show_state: &Self::ShowState,
    ) -> Witness<E::ScalarField> {
        Witness::from(vec![show_state.e, m_hid.rho, show_state.r1, show_state.r3])
    }

    /// The opening clause `C h_0^{-1} h_2^{-φ} = h_1^usk h_3^ρ` of `R_issue` (§5.1): one `G_1`
    /// equation with bases `h_1` (shared variable `usk`) and `h_3` (fresh variable `ρ`). The
    /// disclosed `φ` enters through the target, which is how the helper learns that the `φ`
    /// inside `C` is the one it issues for. The relation is left untouched on error.
    ///
    /// # Errors
    /// Implementation note: [`Error::DegenerateInput`] for a `pp` with an identity generator
    /// ([`BBSPublicParams::is_well_formed`]); with `h_1 = 1` the clause would not bind `usk`.
    fn issuance_clauses(
        pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        c: &Self::IssuanceEncoding,
        m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        if !pp.is_well_formed() {
            return Err(Error::DegenerateInput("identity generator of Σ-BBS"));
        }
        ensure_allocated(rel, usk)?;
        let rho = rel.alloc_scalar();
        rel.add_g1(LinearEquation::new(
            vec![(usk, pp.h1), (rho, pp.h3)],
            *c - pp.h0 - pp.h2 * *m_pub,
        ))?;
        Ok(vec![rho])
    }

    /// The value `ρ` (the issuance state, which equals the `ρ` inside `m_hid`).
    fn issuance_witness(
        _m_hid: &Self::HiddenMessage,
        r: &Self::IssuanceState,
    ) -> Witness<E::ScalarField> {
        Witness::from(vec![*r])
    }
}

/// TEST HELPER (crate tests and the cargo feature `test-utils`): the credential-free forgeries
/// of `Σ-BBS` for [`public_base_flow`](super::conformance::public_base_flow), attack W4-B1 of
/// the reference implementations.
///
/// For a forged key `K` and `cred* = (Ā, B̄, D) = (1, 1, h_0 h_1^K h_2^φ h_3^ρ)` both possession
/// clauses hold with `(e, ρ, r_1, r_3) = (e, ρ, 0, 1)` for ANY `e` and `ρ`: the first reads
/// `1 = D^0 · 1^{-e}`, the second `h_0 h_2^φ = D · h_1^{-K} h_3^{-ρ}`, and the pairing equation
/// reads `1 = 1`. Only the public check `Ā ≠ 1` rejects them (two such entries). The third
/// entry, `(1, 1, 1)`, is degenerate too but has no witness unless one knows a
/// discrete-logarithm relation among the generators.
#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn credential_free_forgeries<E: Pairing>(
    pp: &BBSPublicParams<E>,
    _vk: &BBSVerificationKey<E>,
    phi: &E::ScalarField,
    forged_key: &E::ScalarField,
) -> Vec<super::conformance::Forgery<BBSShownCredential<E>, E::ScalarField>> {
    let (zero, one) = (E::ScalarField::zero(), E::ScalarField::ONE);
    let (e, rho) = (E::ScalarField::from(7u64), E::ScalarField::from(5u64));
    let forgery = |d: E::G1, extra_witness: Vec<E::ScalarField>| super::conformance::Forgery {
        shown: BBSShownCredential {
            a_bar: E::G1::zero(),
            b_bar: E::G1::zero(),
            d,
        },
        extra_witness,
    };
    vec![
        forgery(
            pp.b(&BBSMessage::new(*forged_key, *phi, zero)),
            vec![zero, zero, zero, one],
        ),
        forgery(
            pp.b(&BBSMessage::new(*forged_key, *phi, rho)),
            vec![e, rho, zero, one],
        ),
        forgery(E::G1::zero(), vec![zero, zero, zero, one]),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective, g1};
    use ark_bn254::Bn254;
    use ark_ec::{
        CurveGroup,
        hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    };
    use ark_ff::{One, field_hashers::DefaultFieldHasher};
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;

    use super::*;
    use crate::{
        cred::{
            conformance::{FlowReport, public_base_flow},
            issuance_witness_vector, possess, possess_context, possession_relation,
            possession_witness_vector, verify_possess,
        },
        hash::{
            H2_SUFFIX, Transcript, bls12_381::G1Hasher, domain_separation_tag, h0_id,
            h0_identity_point, h0_predicate, oracle_input, testing::InsecureExponentHasher,
        },
        kiprf::{DDH, KIPRF, PCSTag, SigmaFriendlyKIPRF},
        serialization::WireFormat,
        sigma::{FSProof, LinearRelation, commit, extract, fiat_shamir, respond},
    };

    type E = Bls12_381;
    type G1 = G1Projective;
    type G2 = G2Projective;
    type BBS = crate::cred::BBS<E, G1Hasher>;
    /// The same base with generators of KNOWN discrete logarithms (the insecure test oracle):
    /// lets a test build messages with `B(m) = 1` and statements with `D = 1`.
    type WeakBBS = crate::cred::BBS<E, InsecureExponentHasher>;
    type Tag = DDH<G1, G1Hasher>;
    type Pp = BBSPublicParams<E>;

    const DOMAIN: &[u8] = b"sigma-bbs-unit-tests";

    fn phi(label: &[u8]) -> Fr {
        h0_predicate(DOMAIN, label)
    }

    fn msg(usk: Fr, phi: Fr, rho: Fr) -> BBSMessage<E> {
        BBSMessage::new(usk, phi, rho)
    }

    /// `e(P_1, Q_1) = e(P_2, Q_2)`.
    fn pairings_agree(p1: G1, q1: G2, p2: G1, q2: G2) -> bool {
        pairing_product_is_identity::<E>(&[(p1, q1), (-p2, q2)])
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ----- a miniature of the construction of §5.1 ------------------------------------------------

    /// The public side of a deployment: `pp_Tag`, `pp_Σ`, `hvk`.
    #[derive(Clone)]
    struct Dep {
        tag: Tag,
        pp: Pp,
        vk: BBSVerificationKey<E>,
    }

    fn deployment(rng: &mut StdRng) -> (Dep, BBSSigningKey<E>) {
        let pp = BBS::setup(DOMAIN).unwrap();
        let (vk, sk) = BBS::keygen(&pp, rng);
        let tag = Tag::setup(DOMAIN, h0_identity_point(DOMAIN)).unwrap();
        (Dep { tag, pp, vk }, sk)
    }

    /// What a holder keeps: `usk`, `φ` and the PCS credential `(cred_Σ, m_aux) = ((A, e), ρ)`.
    #[derive(Clone)]
    struct Holder {
        usk: Fr,
        phi: Fr,
        rho: Fr,
        cred: BBSCredential<E>,
    }

    impl Holder {
        fn m_hid(&self) -> BBSHiddenMessage<E> {
            BBS::hidden_message(&self.usk, &self.rho)
        }

        fn msg(&self) -> BBSMessage<E> {
            msg(self.usk, self.phi, self.rho)
        }

        /// The same stored credential, claimed for another key and another predicate label.
        fn claiming(&self, usk: Fr, phi: Fr) -> Self {
            Self {
                usk,
                phi,
                ..self.clone()
            }
        }
    }

    /// A holder with a directly signed credential on `Enc((usk, ρ), φ)`.
    fn holder(dep: &Dep, sk: &BBSSigningKey<E>, label: &[u8], rng: &mut StdRng) -> Holder {
        let usk = dep.tag.keygen(rng);
        let phi = phi(label);
        let (rho, _) = BBS::sample_issuance(&dep.pp, rng);
        let cred = BBS::sign(&dep.pp, sk, &msg(usk, phi, rho), rng).unwrap();
        Holder {
            usk,
            phi,
            rho,
            cred,
        }
    }

    /// A holder whose credential went through `Com`, `BlindIssue`, `Unblind`.
    fn issued_holder(dep: &Dep, sk: &BBSSigningKey<E>, label: &[u8], rng: &mut StdRng) -> Holder {
        let usk = dep.tag.keygen(rng);
        let phi = phi(label);
        let (aux, rho) = BBS::sample_issuance(&dep.pp, rng);
        let m_hid = BBS::hidden_message(&usk, &aux);
        let c = BBS::issuance_encoding(&dep.pp, &dep.vk, &m_hid, &phi, &rho).unwrap();
        let pre = BBS::blind_issue(&dep.pp, sk, &c, &phi, rng).unwrap();
        let m = BBS::encode_message(&dep.pp, &m_hid, &phi).unwrap();
        let cred = BBS::unblind(&dep.pp, &dep.vk, &m, &pre, &rho).unwrap();
        Holder {
            usk,
            phi,
            rho: aux,
            cred,
        }
    }

    struct Att {
        t: G1,
        shown: BBSShownCredential<E>,
        phi: Fr,
        pi: FSProof<Fr>,
    }

    impl Att {
        fn with_shown(&self, shown: BBSShownCredential<E>) -> Self {
            Self {
                t: self.t,
                shown,
                phi: self.phi,
                pi: self.pi.clone(),
            }
        }
    }

    impl Dep {
        /// `R_att` for the public statement `(pp, vk, cred*, φ, T, s)`: the two possession
        /// clauses and the tag clause over ONE variable `usk`.
        fn att_relation(
            &self,
            shown: &BBSShownCredential<E>,
            phi: &Fr,
            t: &G1,
            s: &Fr,
        ) -> PairingRelation<E> {
            let mut rel = PairingRelation::new();
            let usk = rel.alloc_scalar();
            let extra =
                BBS::possession_clauses(&self.pp, &self.vk, shown, phi, &mut rel, usk).unwrap();
            assert_eq!(extra.len(), 4);
            for eq in self.tag.tag_equations(usk, t, s) {
                rel.add_g1(eq).unwrap();
            }
            rel
        }

        /// `ctx_j = (pp, hvk, id, φ_j, T_j, cred*_j)`, as in `Attest` step 10; `pp` covers the
        /// generators.
        fn att_ctx(&self, id: &G1, phi: &Fr, t: &G1, shown: &BBSShownCredential<E>) -> Vec<u8> {
            let mut tr = Transcript::new(b"/TEST-CTX-ATT");
            tr.append_serializable(b"pp-base", &self.pp).unwrap();
            tr.append_serializable(b"pp-tag", &self.tag).unwrap();
            tr.append_serializable(b"hvk", &self.vk).unwrap();
            tr.append_serializable(b"id", id).unwrap();
            tr.append_serializable(b"phi", phi).unwrap();
            tr.append_serializable(b"T", t).unwrap();
            tr.append_serializable(b"cred*", shown).unwrap();
            tr.digest().to_vec()
        }

        /// `Attest` steps 4-12 for a holder whose tag key is `tag_key` (honestly, `tag_key` is
        /// the holder's `usk`). An honest attester runs the public checks of `VerifyPossess` on
        /// its own `cred*` before proving (`self_check`), as [`possess`] does; a cheating one
        /// skips them.
        fn attest_inner(
            &self,
            holder: &Holder,
            tag_key: &Fr,
            id: &G1,
            self_check: bool,
            rng: &mut StdRng,
        ) -> Result<Att, Error> {
            let s: Fr = h0_id(DOMAIN, id)?;
            let t = self.tag.eval(tag_key, &s).ok_or(Error::UndefinedTag)?;
            let (shown, omega) = BBS::rerand(&self.pp, &self.vk, &holder.msg(), &holder.cred, rng)?;
            if self_check && !BBS::verify_possess_public(&self.pp, &self.vk, &shown, &holder.phi) {
                return Err(Error::InvalidCredential);
            }
            let rel = self.att_relation(&shown, &holder.phi, &t, &s);
            let w = possession_witness_vector::<E, BBS>(&holder.m_hid(), &omega);
            let ctx = self.att_ctx(id, &holder.phi, &t, &shown);
            let pi = fiat_shamir::prove(&rel, &w, &ctx, rng)?;
            Ok(Att {
                t,
                shown,
                phi: holder.phi,
                pi,
            })
        }

        fn attest(&self, holder: &Holder, id: &G1, rng: &mut StdRng) -> Result<Att, Error> {
            self.attest_inner(holder, &holder.usk, id, true, rng)
        }

        /// `VerifyAtt`: `ValidTag`, the public checks of `VerifyPossess`, then Fiat-Shamir.
        fn verify_att(&self, id: &G1, att: &Att) -> bool {
            let s: Fr = h0_id(DOMAIN, id).unwrap();
            self.tag.valid_tag(&att.t, &s)
                && BBS::verify_possess_public(&self.pp, &self.vk, &att.shown, &att.phi)
                && fiat_shamir::verify(
                    &self.att_relation(&att.shown, &att.phi, &att.t, &s),
                    &self.att_ctx(id, &att.phi, &att.t, &att.shown),
                    &att.pi,
                )
        }

        /// Everything of `VerifyAtt` EXCEPT the public checks of `VerifyPossess`: what a verifier
        /// that forgot them would accept.
        fn verify_att_without_public_checks(&self, id: &G1, att: &Att) -> bool {
            let s: Fr = h0_id(DOMAIN, id).unwrap();
            self.tag.valid_tag(&att.t, &s)
                && fiat_shamir::verify(
                    &self.att_relation(&att.shown, &att.phi, &att.t, &s),
                    &self.att_ctx(id, &att.phi, &att.t, &att.shown),
                    &att.pi,
                )
        }

        /// A complete attestation for the statement `(cred*, φ, T = Tag(key, s))` from an
        /// arbitrary witness `(key, e, ρ, r_1, r_3)`, without any self-check.
        fn forge(
            &self,
            shown: BBSShownCredential<E>,
            phi: Fr,
            witness: [Fr; 5],
            id: &G1,
            rng: &mut StdRng,
        ) -> Result<Att, Error> {
            let s: Fr = h0_id(DOMAIN, id)?;
            let t = self.tag.eval(&witness[0], &s).ok_or(Error::UndefinedTag)?;
            let rel = self.att_relation(&shown, &phi, &t, &s);
            let ctx = self.att_ctx(id, &phi, &t, &shown);
            let pi = fiat_shamir::prove(&rel, &witness, &ctx, rng)?;
            Ok(Att { t, shown, phi, pi })
        }
    }

    /// A fresh identifier `id = g_1^usk'` of some other user.
    fn identifier(dep: &Dep, rng: &mut StdRng) -> G1 {
        G1::generator() * dep.tag.keygen(rng)
    }

    /// The discrete logarithms `a_i` of the generators `h_i = g_1^{a_i}` that the INSECURE test
    /// oracle derives for `domain`, recomputed from its documented construction and checked
    /// against the parameters themselves.
    fn weak_setup(domain: &[u8]) -> (Pp, [Fr; 4]) {
        let pp = WeakBBS::setup(domain).unwrap();
        let exponents: [Fr; 4] = core::array::from_fn(|i| {
            let mut t = Transcript::new(GENERATORS_SUFFIX);
            t.append_bytes(b"deployment", domain);
            t.append_u64(b"counter", 0);
            t.append_bytes(b"msg", &(i as u64).to_le_bytes());
            t.challenge_scalar()
        });
        let g = G1::generator();
        assert_eq!(
            [pp.h0, pp.h1, pp.h2, pp.h3],
            [
                g * exponents[0],
                g * exponents[1],
                g * exponents[2],
                g * exponents[3]
            ]
        );
        (pp, exponents)
    }

    /// The `ρ` with `B(usk, φ, ρ) = 1`, given the discrete logarithms of the generators.
    fn rho_with_identity_base([a0, a1, a2, a3]: [Fr; 4], usk: Fr, phi: Fr) -> Fr {
        -(a0 + a1 * usk + a2 * phi) * a3.inverse().unwrap()
    }

    /// Serves the scripted `u64` words first, then a seeded generator. `Fr::rand` reads four
    /// words and takes them as the (Montgomery) limbs of its candidate, so a script of
    /// `value.0 .0` makes the next sampled scalar equal `value`; the tests check that.
    struct ScriptedRng {
        script: VecDeque<u64>,
        rest: StdRng,
    }

    impl ScriptedRng {
        /// The generator whose first sampled scalars are `values`, in this order (a scripted
        /// `0` is a scalar like any other; a sampler for `Z_p^*` draws again after it).
        fn scalars(values: &[Fr], seed: u64) -> Self {
            Self {
                script: values.iter().flat_map(|value| value.0.0).collect(),
                rest: StdRng::seed_from_u64(seed),
            }
        }

        fn first_scalar(value: Fr, seed: u64) -> Self {
            Self::scalars(&[value], seed)
        }

        /// Whether exactly the script was consumed: nothing of it is left, and the seeded
        /// generator behind it is untouched.
        fn consumed_exactly_the_script(&self, seed: u64) -> bool {
            self.script.is_empty() && self.rest == StdRng::seed_from_u64(seed)
        }
    }

    impl RngCore for ScriptedRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            match self.script.pop_front() {
                Some(word) => word,
                None => self.rest.next_u64(),
            }
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // Test-only marker: the samplers ask for a `CryptoRng`.
    impl CryptoRng for ScriptedRng {}

    // ----- Setup ----------------------------------------------------------------------------------

    #[test]
    fn setup_derives_the_generators_from_the_deployment_label() {
        let pp = BBS::setup(DOMAIN).unwrap();
        assert_eq!(BBS::setup(DOMAIN).unwrap(), pp);
        let expected = G1Hasher::new(DOMAIN)
            .unwrap()
            .generators(GENERATORS_SUFFIX, 4);
        assert_eq!(vec![pp.h0, pp.h1, pp.h2, pp.h3], expected);
        assert!(pp.is_well_formed());
        let all = [pp.h0, pp.h1, pp.h2, pp.h3, G1::generator()];
        for i in 0..all.len() {
            assert!(!all[i].is_zero());
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j], "generators {i} and {j}");
            }
        }
        // another deployment, other generators; the H_2 oracle of the tag is separated too
        let other = BBS::setup(b"another deployment").unwrap();
        for h in [other.h0, other.h1, other.h2, other.h3] {
            assert!(!all.contains(&h));
        }
        let tag = Tag::setup(DOMAIN, h0_identity_point(DOMAIN)).unwrap();
        assert!(!all.contains(&tag.htag(&Fr::from(0u64))));
    }

    /// Known answers for `Setup`. Every credential of a deployment is tied to the `pp_Σ` that
    /// `Setup` derives from the label alone, so a silent change of [`GENERATORS_SUFFIX`], of
    /// the message encoding `i ↦ 8 little-endian bytes` or of the oracle would orphan every
    /// issued credential, and a suffix shared with another oracle (`/H2` of the tag oracle,
    /// say) would put the generators into that oracle's domain. The other tests recompute
    /// `pp_Σ` with the same constant and notice neither.
    ///
    /// 1. The derivation, spelled out WITHOUT the constant and without
    ///    [`HashToGroup::generators`]: `h_i` is arkworks' RFC 9380 suite
    ///    `BLS12381G1_XMD:SHA-256_SSWU_RO_` under the tag `PCS-V1/BBS-GENERATORS`, applied to
    ///    the framed input `(deployment, counter = 0, msg = i)`.
    /// 2. Known-answer vectors for the label `kat`. They were computed with this implementation
    ///    and recomputed by an independent pure-Python implementation of the RFC 9380 suite and
    ///    of the documented framing, which reproduces the five vectors of RFC 9380 for this
    ///    suite first; so they cross-check `Setup`, the framing and arkworks' suite. They are
    ///    NOT vectors of an external specification.
    /// 3. The generators are not outputs of the tag oracle `H_2 = htag` on the same messages.
    #[test]
    fn setup_known_answers() {
        type Suite = MapToCurveBasedHasher<G1, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

        assert_eq!(GENERATORS_SUFFIX, b"/BBS-GENERATORS");
        assert_eq!(
            domain_separation_tag(GENERATORS_SUFFIX),
            b"PCS-V1/BBS-GENERATORS"
        );
        let pp = BBS::setup(b"kat").unwrap();
        let generators = [pp.h0, pp.h1, pp.h2, pp.h3];

        let suite = Suite::new(b"PCS-V1/BBS-GENERATORS").unwrap();
        let tag_oracle = G1Hasher::new(b"kat").unwrap();
        for (i, h) in (0u64..).zip(generators) {
            let expected = suite
                .hash(&oracle_input(b"kat", 0, &i.to_le_bytes()))
                .unwrap();
            assert_eq!(h.into_affine(), expected, "h_{i}");
            assert!(!generators.contains(&tag_oracle.hash(H2_SUFFIX, &i.to_le_bytes())));
        }

        let pinned = [
            "a39eda9da6433ffb0692ec5e0bd2784c4ab30fc57d3984fb5e1e5c6989453c93\
             f6bb2125408a120786f12da4d0d1f236",
            "91b4bfd47f6e0981349bb44571a4a6a15dad889be286e9150798e401a327a914\
             6e29d76a903d508ff1db0d9b7658abcf",
            "820593dc6ddff10901172ce0498797bd87b49c9a64446c1208ee307397dd75ab\
             2fdab73151c97b6f23dd5edb0633a2d8",
            "b0a2020c1667e74a10bb5177a2ddde5d0104187905e76d8fea7638cb2a6e0fb1\
             86c85eb10f00583d1840e3e93ab54168",
        ];
        for (i, (h, expected)) in generators.iter().zip(pinned).enumerate() {
            assert_eq!(hex(&h.to_bytes().unwrap()), expected, "h_{i}");
        }
        assert_eq!(hex(&pp.to_bytes().unwrap()), pinned.concat());
    }

    /// Oracles that break the contract of `HashToGroup`: the identity at one index, or another
    /// number of generators than asked for.
    macro_rules! broken_hasher {
        ($name:ident, $identity_at:expr, $count:expr) => {
            #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
            struct $name {
                domain: Vec<u8>,
            }

            impl HashToGroup<G1> for $name {
                fn new(domain: &[u8]) -> Result<Self, Error> {
                    Ok(Self {
                        domain: domain.to_vec(),
                    })
                }

                fn domain(&self) -> &[u8] {
                    &self.domain
                }

                fn hash(&self, _dst_suffix: &[u8], msg: &[u8]) -> G1 {
                    let identity_at: u64 = $identity_at;
                    if msg == identity_at.to_le_bytes().as_slice() {
                        G1::zero()
                    } else {
                        let index = u64::from(msg.first().copied().unwrap_or(0));
                        G1::generator() * Fr::from(index + 2)
                    }
                }

                fn generators(&self, dst_suffix: &[u8], _n: usize) -> Vec<G1> {
                    let count: u64 = $count;
                    (0..count)
                        .map(|i| self.hash(dst_suffix, &i.to_le_bytes()))
                        .collect()
                }
            }
        };
    }

    broken_hasher!(FourFineGenerators, u64::MAX, 4);
    broken_hasher!(IdentityAt0, 0, 4);
    broken_hasher!(IdentityAt1, 1, 4);
    broken_hasher!(IdentityAt2, 2, 4);
    broken_hasher!(IdentityAt3, 3, 4);
    broken_hasher!(ThreeGenerators, u64::MAX, 3);
    broken_hasher!(FiveGenerators, u64::MAX, 5);

    #[test]
    fn setup_refuses_the_output_of_a_broken_oracle() {
        // control: the test oracle is fine when it returns four non-identity points
        assert!(crate::cred::BBS::<E, FourFineGenerators>::setup(DOMAIN).is_ok());
        for (i, result) in [
            crate::cred::BBS::<E, IdentityAt0>::setup(DOMAIN),
            crate::cred::BBS::<E, IdentityAt1>::setup(DOMAIN),
            crate::cred::BBS::<E, IdentityAt2>::setup(DOMAIN),
            crate::cred::BBS::<E, IdentityAt3>::setup(DOMAIN),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                matches!(result, Err(Error::DegenerateInput(_))),
                "h_{i} = 1"
            );
        }
        assert_eq!(
            crate::cred::BBS::<E, ThreeGenerators>::setup(DOMAIN),
            Err(Error::LengthMismatch {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(
            crate::cred::BBS::<E, FiveGenerators>::setup(DOMAIN),
            Err(Error::LengthMismatch {
                expected: 4,
                actual: 5
            })
        );
    }

    // ----- SIG = (KeyGen, Sign, Verify) -----------------------------------------------------------

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(0xbb01);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        assert_eq!(sk.verification_key(), *vk);
        assert_eq!(vk.x_tilde, G2::generator() * sk.x);
        assert!(BBS::is_well_formed_key(pp, vk));
        for _ in 0..4 {
            let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
            let cred = BBS::sign(pp, &sk, &m, &mut rng).unwrap();
            // A = B(m)^{1/(x+e)}, i.e. A^{x+e} = B(m), with A ≠ 1
            assert!(!cred.a.is_zero());
            assert_eq!(cred.a * (sk.x + cred.e), pp.b(&m));
            assert!(BBS::verify(pp, vk, &m, &cred));
        }
        // B(m) is the multi-base encoding of the three components
        let (m1, m2, m3) = (Fr::from(3u64), Fr::from(5u64), Fr::from(7u64));
        assert_eq!(
            pp.b(&msg(m1, m2, m3)),
            pp.h0 + pp.h1 * m1 + pp.h2 * m2 + pp.h3 * m3
        );
        // edge messages of Z_p^3
        for (m1, m2, m3) in [
            (Fr::zero(), Fr::zero(), Fr::zero()),
            (Fr::one(), Fr::zero(), Fr::zero()),
            (Fr::zero(), -Fr::one(), Fr::one()),
        ] {
            let cred = BBS::sign(pp, &sk, &msg(m1, m2, m3), &mut rng).unwrap();
            assert!(BBS::verify(pp, vk, &msg(m1, m2, m3), &cred));
        }
        // signing is randomized (in e)
        let m = msg(Fr::from(7u64), Fr::from(8u64), Fr::from(9u64));
        let (c1, c2) = (
            BBS::sign(pp, &sk, &m, &mut rng).unwrap(),
            BBS::sign(pp, &sk, &m, &mut rng).unwrap(),
        );
        assert!(c1.e != c2.e && c1.a != c2.a);
    }

    #[test]
    fn verification_rejects_wrong_message_key_and_generators() {
        let mut rng = StdRng::seed_from_u64(0xbb02);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let cred = BBS::sign(pp, &sk, &msg(usk, phi, rho), &mut rng).unwrap();
        assert!(BBS::verify(pp, vk, &msg(usk, phi, rho), &cred));

        // wrong message: each component, permuted components, the zero message
        let one = Fr::one();
        for (i, wrong) in [
            msg(usk + one, phi, rho),
            msg(usk, phi + one, rho),
            msg(usk, phi, rho + one),
            msg(phi, usk, rho),
            msg(usk, rho, phi),
            msg(rho, phi, usk),
            msg(Fr::zero(), Fr::zero(), Fr::zero()),
            msg(Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)),
        ]
        .iter()
        .enumerate()
        {
            assert!(!BBS::verify(pp, vk, wrong, &cred), "message {i}");
        }

        // wrong key, wrong generators (each one)
        let (other_vk, _) = BBS::keygen(pp, &mut rng);
        assert!(!BBS::verify(pp, &other_vk, &msg(usk, phi, rho), &cred));
        let other_pp = BBS::setup(b"another deployment").unwrap();
        assert!(!BBS::verify(&other_pp, vk, &msg(usk, phi, rho), &cred));
        for i in 0..4 {
            let mut bad = pp.clone();
            match i {
                0 => bad.h0 = other_pp.h0,
                1 => bad.h1 = other_pp.h1,
                2 => bad.h2 = other_pp.h2,
                _ => bad.h3 = other_pp.h3,
            }
            assert!(!BBS::verify(&bad, vk, &msg(usk, phi, rho), &cred), "h_{i}");
        }
    }

    #[test]
    fn verification_rejects_tampered_signatures() {
        let mut rng = StdRng::seed_from_u64(0xbb03);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let cred = BBS::sign(pp, &sk, &m, &mut rng).unwrap();
        let r = Fr::rand(&mut rng);
        let tampered = [
            (cred.a + G1::generator(), cred.e),
            (cred.a * r, cred.e),
            (-cred.a, cred.e),
            (cred.a, cred.e + Fr::one()),
            (cred.a, -cred.e),
            (cred.a, Fr::zero()),
            (cred.a * r, cred.e * r),
            (pp.b(&m), cred.e),
            (G1::zero(), cred.e),
            (G1::rand(&mut rng), Fr::rand(&mut rng)),
        ];
        for (i, (a, e)) in tampered.into_iter().enumerate() {
            assert!(
                !BBS::verify(pp, vk, &m, &BBSCredential { a, e }),
                "tampering {i}"
            );
        }
        // control: another e with ITS A is a signature on the same message
        let e2 = cred.e + Fr::one();
        let a2 = pp.b(&m) * (sk.x + e2).inverse().unwrap();
        assert!(BBS::verify(pp, vk, &m, &BBSCredential { a: a2, e: e2 }));
    }

    /// `B(m) = 1` (module docs, "Degenerate inputs"). The pairing equation of `Verify` holds for
    /// `A = 1` and EVERY `e`, so the check `A ≠ 1` is what rejects the output `(1, e)` of the
    /// box's `Sign`. Such a message is NOT without verifying credentials: the equation reads
    /// `e(A, g̃)^{x+e} = 1`, so exactly the pairs `(A, −x)` with `A ≠ 1` verify. `Sign` never
    /// outputs one (`e ≠ −x`), and only a party that knows `x` can write one down. `Sign`,
    /// `BlindIssue`, `ReRand` and the wire decoder refuse the message, resp. its encoding
    /// `C = 1`; `ReRand` refuses `(A, −x)` too, whose show has `D = 1`.
    #[test]
    fn messages_with_identity_base_are_refused() {
        let mut rng = StdRng::seed_from_u64(0xbb04);
        let (pp, exponents) = weak_setup(DOMAIN);
        let (vk, sk) = BBS::keygen(&pp, &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), phi(b"f"));
        let rho = rho_with_identity_base(exponents, usk, phi);
        let m = msg(usk, phi, rho);
        assert!(pp.b(&m).is_zero());

        // Verify: the equation is e(1, ·) = e(1, g̃) ...
        let e = Fr::rand(&mut rng);
        assert!(pairings_agree(
            G1::zero(),
            vk.x_tilde + G2::generator() * e,
            pp.b(&m),
            G2::generator()
        ));
        // ... and A ≠ 1 rejects it
        assert!(!BBS::verify(
            &pp,
            &vk,
            &m,
            &BBSCredential { a: G1::zero(), e }
        ));
        let a = G1::rand(&mut rng);
        assert!(!a.is_zero() && e != -sk.x);
        assert!(!BBS::verify(&pp, &vk, &m, &BBSCredential { a, e }));

        // (A, −x) verifies for ANY A ≠ 1, and only with e = −x and A ≠ 1
        let with_minus_x = BBSCredential { a, e: -sk.x };
        assert!(BBS::verify(&pp, &vk, &m, &with_minus_x));
        let another = BBSCredential {
            a: G1::rand(&mut rng),
            e: -sk.x,
        };
        assert!(another.a != a && BBS::verify(&pp, &vk, &m, &another));
        assert!(!sk.x.is_zero(), "so that x ≠ −x below");
        for (wrong_a, wrong_e) in [(a, -sk.x + Fr::one()), (a, sk.x), (G1::zero(), -sk.x)] {
            let wrong = BBSCredential {
                a: wrong_a,
                e: wrong_e,
            };
            assert!(!BBS::verify(&pp, &vk, &m, &wrong));
        }
        // ReRand refuses it like every credential on this message: the show of the box would be
        // (Ā, B̄, D) = (A^{r_1 r_2}, Ā^x, 1), which passes the pairing check and fails D ≠ 1
        assert_eq!(
            BBS::rerand(&pp, &vk, &m, &with_minus_x, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
        let (r1, r2): (Fr, Fr) = (nonzero_scalar(&mut rng), nonzero_scalar(&mut rng));
        let d = pp.b(&m) * r2;
        let a_bar = a * (r1 * r2);
        let show_of_the_box = BBSShownCredential::<E> {
            a_bar,
            b_bar: d * r1 - a_bar * with_minus_x.e,
            d,
        };
        assert!(show_of_the_box.d.is_zero() && !show_of_the_box.a_bar.is_zero());
        assert_eq!(show_of_the_box.b_bar, show_of_the_box.a_bar * sk.x);
        assert!(!BBS::verify_possess_public(
            &pp,
            &vk,
            &show_of_the_box,
            &phi
        ));

        assert_eq!(
            BBS::sign(&pp, &sk, &m, &mut rng).unwrap_err(),
            Error::InvalidMessage
        );
        let m_hid = BBS::hidden_message(&usk, &rho);
        let c = BBS::issuance_encoding(&pp, &vk, &m_hid, &phi, &rho).unwrap();
        assert!(c.is_zero());
        assert_eq!(
            BBS::blind_issue(&pp, &sk, &c, &phi, &mut rng).unwrap_err(),
            Error::InvalidIssuanceEncoding
        );
        assert_eq!(BBS::encoding_from_wire(&pp, &c, &G1::generator()), None);
        let some_cred = BBSCredential::<E> {
            a: G1::generator(),
            e,
        };
        assert_eq!(
            BBS::rerand(&pp, &vk, &m, &some_cred, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );

        // control: the neighbouring message is an ordinary one, where (A, −x) does not verify
        let m_ok = msg(usk, phi, rho + Fr::one());
        let cred = BBS::sign(&pp, &sk, &m_ok, &mut rng).unwrap();
        assert!(BBS::verify(&pp, &vk, &m_ok, &cred));
        assert!(!BBS::verify(&pp, &vk, &m_ok, &with_minus_x));
        assert!(BBS::rerand(&pp, &vk, &m_ok, &cred, &mut rng).is_ok());
        let c_ok = pp.b(&m_ok);
        assert_eq!(
            BBS::encoding_from_wire(&pp, &c_ok, &G1::generator()),
            Some(c_ok)
        );
    }

    /// `e ← Z_p \ {−x}`: when the generator first proposes `e = −x`, where `1/(x+e)` does not
    /// exist, `Sign` and `BlindIssue` draw again. No panic, no `⊥`, a verifying credential.
    #[test]
    fn e_equal_to_minus_x_is_resampled() {
        let mut rng = StdRng::seed_from_u64(0xbb05);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let minus_x = -sk.x;
        assert!((sk.x + minus_x).inverse().is_none());
        // control: with this generator the first scalar drawn IS −x
        assert_eq!(
            Fr::rand(&mut ScriptedRng::first_scalar(minus_x, 1)),
            minus_x
        );

        let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let mut scripted = ScriptedRng::first_scalar(minus_x, 2);
        let cred = BBS::sign(pp, &sk, &m, &mut scripted).unwrap();
        assert!(scripted.script.is_empty(), "the proposal −x was consumed");
        assert_ne!(cred.e, minus_x);
        assert!(BBS::verify(pp, vk, &m, &cred));
        // it is the credential of the second draw
        assert_eq!(
            cred,
            BBS::sign(pp, &sk, &m, &mut StdRng::seed_from_u64(2)).unwrap()
        );

        let c = pp.b(&m);
        let mut scripted = ScriptedRng::first_scalar(minus_x, 3);
        let pre = BBS::blind_issue(pp, &sk, &c, &Fr::one(), &mut scripted).unwrap();
        assert!(scripted.script.is_empty());
        assert_ne!(pre.e, minus_x);
        let cred = BBSCredential { a: pre.a, e: pre.e };
        assert!(BBS::verify(pp, vk, &m, &cred));

        // x = 0 (a key of the box) excludes e = 0
        let zero_key = BBSSigningKey::<E> { x: Fr::zero() };
        let mut scripted = ScriptedRng::first_scalar(Fr::zero(), 4);
        let cred = BBS::sign(pp, &zero_key, &m, &mut scripted).unwrap();
        assert!(!cred.e.is_zero());
        assert!(BBS::verify(pp, &zero_key.verification_key(), &m, &cred));
    }

    /// The sampling domains of the box that are NOT `Z_p^*`: `KeyGen` step 1 draws `x ← Z_p` and
    /// `Sign`, `BlindIssue` step 1 draw `e ← Z_p \ {−x}`; zero is in both domains (for `e`:
    /// unless `x = 0`, see the test above). Each is ONE draw, the output is exactly what the
    /// coins say, and nothing else is consumed.
    #[test]
    fn keygen_and_sign_draw_from_the_domains_of_the_box() {
        let mut rng = StdRng::seed_from_u64(0xbb23);
        let pp = BBS::setup(DOMAIN).unwrap();
        let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let g2 = G2::generator();

        // a seeded generator: x, resp. e, is its next scalar
        for _ in 0..3 {
            let mut coins = rng.clone();
            let x = Fr::rand(&mut coins);
            let (vk, sk) = BBS::keygen(&pp, &mut rng);
            assert_eq!((sk.x, vk.x_tilde), (x, g2 * x));
            assert_eq!(rng, coins, "KeyGen draws x and nothing else");

            let mut coins = rng.clone();
            let e = Fr::rand(&mut coins);
            assert_ne!(e, -sk.x);
            let cred = BBS::sign(&pp, &sk, &m, &mut rng).unwrap();
            assert_eq!(cred.e, e);
            assert_eq!(cred.a * (sk.x + e), pp.b(&m));
            assert_eq!(rng, coins, "Sign draws e and nothing else");

            let mut coins = rng.clone();
            let e = Fr::rand(&mut coins);
            assert_ne!(e, -sk.x);
            let pre = BBS::blind_issue(&pp, &sk, &pp.b(&m), &m.m2, &mut rng).unwrap();
            assert_eq!(pre.e, e);
            assert_eq!(pre.a * (sk.x + e), pp.b(&m));
            assert_eq!(rng, coins, "BlindIssue draws e and nothing else");
        }

        // scripted coins: zero is a value like any other, for x ...
        for (seed, x) in (0u64..).zip([Fr::zero(), Fr::one(), -Fr::one()]) {
            let mut scripted = ScriptedRng::scalars(&[x], seed);
            let (vk, sk) = BBS::keygen(&pp, &mut scripted);
            assert_eq!((sk.x, vk.x_tilde), (x, g2 * x));
            assert!(scripted.consumed_exactly_the_script(seed));
        }
        // ... and for e (the key is not the one that excludes it)
        let (vk, sk) = BBS::keygen(&pp, &mut rng);
        assert!(!sk.x.is_zero());
        for (seed, e) in (0u64..).zip([Fr::zero(), Fr::one(), -sk.x + Fr::one()]) {
            let mut scripted = ScriptedRng::scalars(&[e], seed);
            let cred = BBS::sign(&pp, &sk, &m, &mut scripted).unwrap();
            assert!(scripted.consumed_exactly_the_script(seed));
            assert_eq!(cred.e, e);
            assert!(BBS::verify(&pp, &vk, &m, &cred));

            let mut scripted = ScriptedRng::scalars(&[e], seed);
            let pre = BBS::blind_issue(&pp, &sk, &pp.b(&m), &m.m2, &mut scripted).unwrap();
            assert!(scripted.consumed_exactly_the_script(seed));
            assert_eq!((pre.a, pre.e), (cred.a, cred.e));
        }
    }

    // ----- encoded issuance -----------------------------------------------------------------------

    /// Def. "Credential base", correctness: `Unblind(BlindIssue(Com(m_hid, φ; ρ), φ), ρ)` verifies
    /// as a signature on `Enc_Σ((usk, ρ), φ)`, and it IS a fresh signature: `A^{x+e} = B(m)`.
    #[test]
    fn blind_issuance_then_unblind_is_a_signature_on_the_encoded_message() {
        let mut rng = StdRng::seed_from_u64(0xbb06);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        for _ in 0..4 {
            let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let (aux, rho) = BBS::sample_issuance(pp, &mut rng);
            assert_eq!(aux, rho, "(m_aux, ρ) = (r, r)");
            let m_hid = BBS::hidden_message(&usk, &aux);
            assert_eq!(BBS::split_hidden_message(&m_hid), (usk, rho));
            let m = BBS::encode_message(pp, &m_hid, &phi).unwrap();
            assert_eq!((m.m1, m.m2, m.m3), (usk, phi, rho));

            let c = BBS::issuance_encoding(pp, vk, &m_hid, &phi, &rho).unwrap();
            assert_eq!(c, pp.h0 + pp.h1 * usk + pp.h2 * phi + pp.h3 * rho);
            assert_eq!(c, pp.b(&m));
            let wire = BBS::encoding_to_wire(&c);
            let c_helper = BBS::encoding_from_wire(pp, &wire, &G1::zero()).unwrap();
            assert_eq!(c_helper, c);

            let pre = BBS::blind_issue(pp, &sk, &c_helper, &phi, &mut rng).unwrap();
            assert_eq!(pre.a * (sk.x + pre.e), c);
            let cred = BBS::unblind(pp, vk, &m, &pre, &rho).unwrap();
            assert_eq!((cred.a, cred.e), (pre.a, pre.e), "Unblind returns ĉred");
            assert!(BBS::verify(pp, vk, &m, &cred));
            assert_eq!(cred.a * (sk.x + cred.e), pp.b(&m));

            // the credential is on (usk, φ, ρ) and on nothing nearby
            assert!(!BBS::verify(pp, vk, &msg(usk, phi + phi, rho), &cred));
            assert!(!BBS::verify(pp, vk, &msg(usk, Fr::zero(), rho), &cred));
            assert!(!BBS::verify(pp, vk, &msg(usk + Fr::one(), phi, rho), &cred));
            assert!(!BBS::verify(pp, vk, &msg(usk, phi, rho + Fr::one()), &cred));
        }
    }

    /// `φ` is inside `C`; `BlindIssue` signs `C` as it is. A `C` built with `φ' ≠ φ` therefore
    /// yields a credential on `φ'`, whatever label the signer was told, and that credential
    /// fails verification for `φ`. (What makes the signer's `φ` the one inside `C` is the opening
    /// clause, see `issuance_opening_clause_binds_usk_and_phi`.)
    #[test]
    fn blind_issue_does_not_add_phi_again() {
        let mut rng = StdRng::seed_from_u64(0xbb07);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let (usk, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let (phi, other_phi) = (phi(b"f"), phi(b"f'"));
        let m_hid = BBS::hidden_message(&usk, &rho);

        let c_other = BBS::issuance_encoding(pp, vk, &m_hid, &other_phi, &rho).unwrap();
        let pre = BBS::blind_issue(pp, &sk, &c_other, &phi, &mut rng).unwrap();
        let cred = BBS::unblind(pp, vk, &msg(usk, phi, rho), &pre, &rho).unwrap();
        assert!(!BBS::verify(pp, vk, &msg(usk, phi, rho), &cred));
        assert!(BBS::verify(pp, vk, &msg(usk, other_phi, rho), &cred));
        // in particular not on the message with φ counted twice, nor with φ' + φ
        assert!(!BBS::verify(pp, vk, &msg(usk, phi + phi, rho), &cred));
        assert!(!BBS::verify(pp, vk, &msg(usk, other_phi + phi, rho), &cred));

        // the signed base is C itself, for every disclosed label
        let c = BBS::issuance_encoding(pp, vk, &m_hid, &phi, &rho).unwrap();
        for label in [phi, other_phi, Fr::zero()] {
            let pre = BBS::blind_issue(pp, &sk, &c, &label, &mut rng).unwrap();
            assert_eq!(pre.a * (sk.x + pre.e), c);
        }
        // issued by another signer: does not verify under vk
        let (_, other_sk) = BBS::keygen(pp, &mut rng);
        let pre = BBS::blind_issue(pp, &other_sk, &c, &phi, &mut rng).unwrap();
        let cred = BBS::unblind(pp, vk, &msg(usk, phi, rho), &pre, &rho).unwrap();
        assert!(!BBS::verify(pp, vk, &msg(usk, phi, rho), &cred));
    }

    /// "The same `ρ` is both a certified hidden component and the local issuance state": `Com`
    /// and `Unblind` refuse an issuance state that is not the `ρ` of the message; `Unblind`
    /// refuses `A = 1`.
    #[test]
    fn issuance_state_must_be_the_certified_rho() {
        let mut rng = StdRng::seed_from_u64(0xbb08);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m_hid = BBS::hidden_message(&usk, &rho);
        assert!(BBS::issuance_encoding(pp, vk, &m_hid, &phi, &rho).is_ok());
        for wrong in [rho + Fr::one(), -rho, Fr::zero(), Fr::rand(&mut rng)] {
            assert_eq!(
                BBS::issuance_encoding(pp, vk, &m_hid, &phi, &wrong),
                Err(Error::InvalidMessage)
            );
        }
        assert_eq!(BBS::issuance_witness(&m_hid, &rho).to_vec(), vec![rho]);

        let c = BBS::issuance_encoding(pp, vk, &m_hid, &phi, &rho).unwrap();
        let pre = BBS::blind_issue(pp, &sk, &c, &phi, &mut rng).unwrap();
        let m = msg(usk, phi, rho);
        assert!(BBS::unblind(pp, vk, &m, &pre, &rho).is_ok());
        assert_eq!(
            BBS::unblind(pp, vk, &m, &pre, &(rho + Fr::one())),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            BBS::unblind(pp, vk, &msg(usk, phi, rho + Fr::one()), &pre, &rho),
            Err(Error::InvalidMessage)
        );
        let degenerate = BBSPreCredential::<E> {
            a: G1::zero(),
            e: pre.e,
        };
        assert_eq!(
            BBS::unblind(pp, vk, &m, &degenerate, &rho),
            Err(Error::InvalidPreCredential)
        );
    }

    /// §5.1: `(m_aux, ρ) = (r, r)` with `r ← Z_p`, ONE fresh draw per issuance. `ρ` is the only
    /// blinding term of `C = h_0 h_1^usk h_2^φ h_3^ρ`: with a constant or reused `r` the
    /// encoding is a function of `(usk, φ)`, and nothing else in the flow would notice (every
    /// other test works for whatever value is returned). `r` ranges over ALL of `Z_p`, zero
    /// included, as in the paper, whose table of hypotheses calls `C` "perfectly hiding" (which
    /// takes a `ρ` that is uniform on `Z_p`).
    #[test]
    fn sample_issuance_draws_one_fresh_scalar_from_zp() {
        let mut rng = StdRng::seed_from_u64(0xbb20);
        let (dep, _sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);

        // a seeded generator: (m_aux, ρ) is its next scalar, twice, and nothing else is drawn
        let (usk, label) = (Fr::rand(&mut rng), phi(b"f"));
        let (mut states, mut encodings) = (Vec::new(), Vec::new());
        for _ in 0..4 {
            let mut coins = rng.clone();
            let r = Fr::rand(&mut coins);
            assert_eq!(BBS::sample_issuance(pp, &mut rng), (r, r));
            assert_eq!(rng, coins, "one draw and nothing else");
            assert!(!states.contains(&r), "a repeated issuance state");
            states.push(r);
            // the encodings of ONE (usk, φ) differ from issuance to issuance
            let m_hid = BBS::hidden_message(&usk, &r);
            let c = BBS::issuance_encoding(pp, vk, &m_hid, &label, &r).unwrap();
            assert!(!encodings.contains(&c), "a repeated issuance encoding");
            encodings.push(c);
        }

        // scripted coins: r is exactly the scalar drawn, from Z_p and not from Z_p^*
        for (seed, r) in (0u64..).zip([Fr::zero(), Fr::one(), -Fr::one(), Fr::from(0xbb5u64)]) {
            // control: with this generator the first scalar drawn IS r
            assert_eq!(Fr::rand(&mut ScriptedRng::scalars(&[r], seed)), r);
            let mut scripted = ScriptedRng::scalars(&[r], seed);
            assert_eq!(BBS::sample_issuance(pp, &mut scripted), (r, r));
            assert!(scripted.consumed_exactly_the_script(seed));
        }
    }

    // ----- ReRand ---------------------------------------------------------------------------------

    /// The two-randomizer show of the box: the algebra of `cred*` and `ω`, the public checks, and
    /// the weak form of show unlinkability (`cred*` is not a signature).
    #[test]
    fn shown_credential_has_the_shape_of_the_box() {
        let mut rng = StdRng::seed_from_u64(0xbb09);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, omega) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();

        // ω = (e, r_1, r_3) with r_1, r_3 ≠ 0; D = B(m)^{r_2}, r_3 = r_2^{-1}
        assert_eq!(omega.e, h.cred.e);
        assert!(!omega.r1.is_zero() && !omega.r3.is_zero());
        let r2 = omega.r3.inverse().unwrap();
        assert_eq!(shown.d, pp.b(&h.msg()) * r2);
        assert_eq!(shown.d * omega.r3, pp.b(&h.msg()));
        // Ā = A^{r_1 r_2}, B̄ = D^{r_1} Ā^{-e}
        assert_eq!(shown.a_bar, h.cred.a * (omega.r1 * r2));
        assert_eq!(shown.b_bar, shown.d * omega.r1 - shown.a_bar * omega.e);
        // what the public pairing check tests: B̄ = Ā^x
        assert_eq!(shown.b_bar, shown.a_bar * sk.x);
        assert!(BBS::verify_possess_public(pp, vk, &shown, &h.phi));
        // the witness lists (e, ρ, r_1, r_3), in this order
        assert_eq!(
            BBS::possession_witness(&h.m_hid(), &omega).to_vec(),
            vec![omega.e, h.rho, omega.r1, omega.r3]
        );

        // weak show: cred* is not a signature on m
        for a in [shown.a_bar, shown.b_bar, shown.d] {
            let as_cred = BBSCredential { a, e: h.cred.e };
            assert!(!BBS::verify(pp, vk, &h.msg(), &as_cred));
        }
        // a credential with A = 1 is refused on its face
        let degenerate = BBSCredential::<E> {
            a: G1::zero(),
            e: h.cred.e,
        };
        assert_eq!(
            BBS::rerand(pp, vk, &h.msg(), &degenerate, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
    }

    #[test]
    fn two_shows_of_one_credential_share_no_group_element() {
        let mut rng = StdRng::seed_from_u64(0xbb0a);
        let (dep, sk) = deployment(&mut rng);
        let h = issued_holder(&dep, &sk, b"f", &mut rng);
        let mut seen = vec![h.cred.a, dep.pp.b(&h.msg()), G1::zero()];
        let mut states = Vec::new();
        for _ in 0..4 {
            let (shown, omega) =
                BBS::rerand(&dep.pp, &dep.vk, &h.msg(), &h.cred, &mut rng).unwrap();
            assert!(BBS::verify_possess_public(&dep.pp, &dep.vk, &shown, &h.phi));
            for element in [shown.a_bar, shown.b_bar, shown.d] {
                assert!(!seen.contains(&element), "a group element repeats");
                seen.push(element);
            }
            // fresh randomizers every time
            assert!(!states.contains(&(omega.r1, omega.r3)));
            states.push((omega.r1, omega.r3));
        }
    }

    /// `ReRand` step 1, "sample `r_1, r_2 ← Z_p^*`": TWO draws, each from `Z_p^*`, and
    /// `(cred*, ω)` is exactly what the box computes from them. The coins are pinned (`r_1` is
    /// the first non-zero scalar of the generator, `r_2` the second, nothing else is consumed)
    /// because nothing downstream notices DEPENDENT randomizers: with `r_1 = r_2` or
    /// `r_1 = r_2 + 1`, say, `cred*` is a function of ONE scalar, it still passes every public
    /// check and its proof verifies, but neither "the two independent randomizers" of the
    /// Lemma on `Σ-BBS` nor the argument in the docs of `rerand` for the distribution of `cred*`
    /// applies to it. A proposed `0` is drawn again, for `r_1` and for `r_2` (`r_1 = 0` gives
    /// `Ā = 1`, `r_2 = 0` has no inverse `r_3`).
    #[test]
    fn rerand_draws_two_independent_randomizers_from_zp_star() {
        let mut rng = StdRng::seed_from_u64(0xbb21);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = issued_holder(&dep, &sk, b"f", &mut rng);
        let (m, b) = (h.msg(), pp.b(&h.msg()));
        // (cred*, ω) is the output of the box for the randomizers (r_1, r_2)
        let assert_show_of =
            |shown: &BBSShownCredential<E>, omega: &BBSShowState<E>, r1: Fr, r2: Fr| {
                let (d, a_bar) = (b * r2, h.cred.a * (r1 * r2));
                let b_bar = d * r1 - a_bar * h.cred.e;
                assert_eq!((shown.a_bar, shown.b_bar, shown.d), (a_bar, b_bar, d));
                let r3: Fr = r2.inverse().unwrap();
                assert_eq!((omega.e, omega.r1, omega.r3), (h.cred.e, r1, r3));
                assert!(BBS::verify_possess_public(pp, vk, shown, &h.phi));
            };

        // a seeded generator: r_1, r_2 are its first two non-zero scalars, nothing else is drawn
        let mut randomizers = Vec::new();
        for _ in 0..4 {
            let mut coins = rng.clone();
            let (r1, r2): (Fr, Fr) = (nonzero_scalar(&mut coins), nonzero_scalar(&mut coins));
            let (shown, omega) = BBS::rerand(pp, vk, &m, &h.cred, &mut rng).unwrap();
            assert_eq!(rng, coins, "ReRand draws r_1, r_2 and nothing else");
            assert_show_of(&shown, &omega, r1, r2);
            for r in [r1, r2] {
                assert!(!randomizers.contains(&r), "a repeated randomizer");
                randomizers.push(r);
            }
        }

        // scripted coins; control: the scripted generator yields its script, zeros included
        let (zero, r1, r2) = (Fr::zero(), Fr::from(0xbb5u64), -Fr::from(3u64));
        let mut control = ScriptedRng::scalars(&[zero, r1, r2], 0);
        let drawn: [Fr; 3] = core::array::from_fn(|_| Fr::rand(&mut control));
        assert_eq!(drawn, [zero, r1, r2]);
        assert!(control.consumed_exactly_the_script(0));
        for (seed, script) in (1u64..).zip([
            vec![r1, r2],
            vec![r2, r1],
            vec![r1, r1],
            // Z_p^*: a proposed 0 is rejected, for r_1 ...
            vec![zero, r1, r2],
            // ... for r_2 ...
            vec![r1, zero, r2],
            // ... and repeatedly
            vec![zero, zero, r1, zero, zero, zero, r2],
        ]) {
            let mut scripted = ScriptedRng::scalars(&script, seed);
            let (shown, omega) = BBS::rerand(pp, vk, &m, &h.cred, &mut scripted).unwrap();
            assert!(scripted.consumed_exactly_the_script(seed), "seed {seed}");
            let nonzero: Vec<Fr> = script.into_iter().filter(|r| !r.is_zero()).collect();
            assert_eq!(nonzero.len(), 2);
            assert_show_of(&shown, &omega, nonzero[0], nonzero[1]);
        }
    }

    // ----- Possess: R_Possess ∧ R_Tag with a shared usk -------------------------------------------

    #[test]
    fn possession_with_tag_clause_is_complete() {
        let mut rng = StdRng::seed_from_u64(0xbb0b);
        let (dep, sk) = deployment(&mut rng);
        let id = identifier(&dep, &mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();

        for h in [
            holder(&dep, &sk, b"f", &mut rng),
            issued_holder(&dep, &sk, b"f", &mut rng),
        ] {
            let att = dep.attest(&h, &id, &mut rng).unwrap();
            assert!(dep.verify_att(&id, &att));
            // five witness coordinates (usk, e, ρ, r_1, r_3), five responses:
            // |att| = 4 G_1 + 7 Z_p = 416 B
            assert_eq!(att.pi.responses.len(), 5);
            assert_eq!(att.t, dep.tag.eval(&h.usk, &s).unwrap());

            // two possession clauses and the tag clause, all in G_1, over 5 variables
            let rel = dep.att_relation(&att.shown, &att.phi, &att.t, &s);
            assert_eq!(rel.num_scalars(), 5);
            assert_eq!(rel.g1_equations().len(), 3);
            assert!(rel.g2_equations().is_empty() && rel.gt_equations().is_empty());

            // the same holder again: same tag, unrelated cred*
            let again = dep.attest(&h, &id, &mut rng).unwrap();
            assert!(dep.verify_att(&id, &again));
            assert_eq!(again.t, att.t);
            assert_ne!(again.shown, att.shown);
        }
    }

    /// The statement the clause function builds, term by term, and the order of the variables.
    #[test]
    fn possession_clauses_are_the_two_equations_of_the_box() {
        let mut rng = StdRng::seed_from_u64(0xbb0c);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, omega) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();

        let mut rel = PairingRelation::<E>::new();
        let usk = rel.alloc_scalar();
        let vars = BBS::possession_clauses(pp, vk, &shown, &h.phi, &mut rel, usk).unwrap();
        assert_eq!(vars.len(), BBS::POSSESSION_VARIABLES);
        let [e, rho, r1, r3] = [vars[0], vars[1], vars[2], vars[3]];
        assert_eq!([usk, e, rho, r1, r3].map(ScalarVar::index), [0, 1, 2, 3, 4]);
        assert_eq!(
            rel.g1_equations(),
            [
                // B̄ = D^{r_1} Ā^{-e}
                LinearEquation::new(vec![(r1, shown.d), (e, -shown.a_bar)], shown.b_bar),
                // h_0 h_2^φ = D^{r_3} h_1^{-usk} h_3^{-ρ}
                LinearEquation::new(
                    vec![(r3, shown.d), (usk, -pp.h1), (rho, -pp.h3)],
                    pp.h0 + pp.h2 * h.phi
                ),
            ]
        );

        let w = possession_witness_vector::<E, BBS>(&h.m_hid(), &omega);
        assert_eq!(w.to_vec(), vec![h.usk, omega.e, h.rho, omega.r1, omega.r3]);
        assert!(rel.is_satisfied_by(&w));
        // every coordinate matters, and so does the order
        for i in 0..5 {
            let mut bad = w.to_vec();
            bad[i] += Fr::one();
            assert!(!rel.is_satisfied_by(&bad), "coordinate {i}");
        }
        assert!(!rel.is_satisfied_by(&[h.usk, h.rho, omega.e, omega.r1, omega.r3]));
        assert!(!rel.is_satisfied_by(&[h.usk, omega.e, h.rho, omega.r3, omega.r1]));
    }

    /// Attack A8: the tag must be under the credential's `usk`.
    ///
    /// (i) Next to an honest `cred*`, a tag under another key has no witness, because `usk` is
    /// ONE variable. (ii) A holder that re-randomizes under the message with the OTHER key
    /// satisfies every clause and gets a Fiat-Shamir proof that verifies; then the public pairing
    /// check `e(Ā, X̃) = e(B̄, g̃)`, and nothing else, rejects the attestation.
    #[test]
    fn tag_under_a_different_key_is_refused_or_rejected() {
        let mut rng = StdRng::seed_from_u64(0xbb0d);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let id = identifier(&dep, &mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let other_key = dep.tag.keygen(&mut rng);
        let t_other = dep.tag.eval(&other_key, &s).unwrap();

        // (i) honest prover code, dishonest tag key
        assert_eq!(
            dep.attest_inner(&h, &other_key, &id, true, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );
        let (shown, omega) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        let w = possession_witness_vector::<E, BBS>(&h.m_hid(), &omega);
        let mut w_other = w.to_vec();
        w_other[0] = other_key;
        let rel = dep.att_relation(&shown, &h.phi, &t_other, &s);
        assert!(!rel.is_satisfied_by(&w)); // satisfies possession, not the tag clause
        assert!(!rel.is_satisfied_by(&w_other)); // satisfies the tag clause, not possession
        for witness in [&w.to_vec(), &w_other] {
            assert_eq!(
                fiat_shamir::prove(&rel, witness, b"ctx", &mut rng),
                Err(Error::WitnessDoesNotSatisfyRelation)
            );
        }
        // control: with the right tag the same relation shape is satisfied
        let t = dep.tag.eval(&h.usk, &s).unwrap();
        assert!(dep.att_relation(&shown, &h.phi, &t, &s).is_satisfied_by(&w));
        // a verifying attestation does not survive swapping in the other key's tag
        let mut att = dep.attest(&h, &id, &mut rng).unwrap();
        assert!(dep.verify_att(&id, &att));
        att.t = t_other;
        assert!(!dep.verify_att(&id, &att));

        // (ii) the holder claims the other key for its credential: ReRand under (other, φ, ρ)
        let liar = h.claiming(other_key, h.phi);
        assert!(!BBS::verify(pp, vk, &liar.msg(), &liar.cred));
        // an honest attester notices on its own cred* ...
        assert_eq!(
            dep.attest_inner(&liar, &other_key, &id, true, &mut rng)
                .err(),
            Some(Error::InvalidCredential)
        );
        // ... a cheating one goes through with it: the clauses hold, the proof verifies,
        let att = dep
            .attest_inner(&liar, &other_key, &id, false, &mut rng)
            .unwrap();
        assert_eq!(att.t, t_other);
        assert!(dep.verify_att_without_public_checks(&id, &att));
        // the statement is not degenerate,
        assert!(pp.is_well_formed() && !att.shown.a_bar.is_zero() && !att.shown.d.is_zero());
        // and the pairing check alone rejects it: B̄ ≠ Ā^x.
        assert_ne!(att.shown.b_bar, att.shown.a_bar * sk.x);
        assert!(!BBS::verify_possess_public(pp, vk, &att.shown, &att.phi));
        assert!(!dep.verify_att(&id, &att));
    }

    #[test]
    fn proof_for_phi_does_not_verify_for_another_phi() {
        let mut rng = StdRng::seed_from_u64(0xbb0e);
        let (dep, sk) = deployment(&mut rng);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let id = identifier(&dep, &mut rng);
        let mut att = dep.attest(&h, &id, &mut rng).unwrap();
        assert!(dep.verify_att(&id, &att));

        let other_phi = phi(b"f'");
        assert_ne!(other_phi, h.phi);
        // (1) relation level, SAME context bytes: φ sits in the target h_0 h_2^φ of clause 2
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let ctx = dep.att_ctx(&id, &h.phi, &att.t, &att.shown);
        let rel = dep.att_relation(&att.shown, &h.phi, &att.t, &s);
        assert!(fiat_shamir::verify(&rel, &ctx, &att.pi));
        let rel_other = dep.att_relation(&att.shown, &other_phi, &att.t, &s);
        assert!(!fiat_shamir::verify(&rel_other, &ctx, &att.pi));
        assert_ne!(
            rel.g1_equations()[1].target,
            rel_other.g1_equations()[1].target
        );
        // (2) attestation level
        att.phi = other_phi;
        assert!(!dep.verify_att(&id, &att));
        // (3) the holder claims another φ for its credential: an honest attester refuses, a
        // cheating one proves its clauses and fails the public pairing check
        let liar = h.claiming(h.usk, other_phi);
        assert_eq!(
            dep.attest(&liar, &id, &mut rng).err(),
            Some(Error::InvalidCredential)
        );
        let att = dep
            .attest_inner(&liar, &liar.usk, &id, false, &mut rng)
            .unwrap();
        assert!(dep.verify_att_without_public_checks(&id, &att));
        assert!(!dep.verify_att(&id, &att));
    }

    /// `hvk` does not carry the generators (module docs, "Generators"): a proof made under the
    /// generators of another deployment label must not verify, for the same `hvk`.
    #[test]
    fn proof_under_other_generators_does_not_verify() {
        let mut rng = StdRng::seed_from_u64(0xbb0f);
        let (dep, sk) = deployment(&mut rng);
        let other = Dep {
            pp: BBS::setup(b"another deployment").unwrap(),
            ..dep.clone()
        };
        assert_ne!(other.pp, dep.pp);
        let id = identifier(&dep, &mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();

        // a holder of the OTHER parameters (same helper key), attesting there
        let h = holder(&other, &sk, b"f", &mut rng);
        let att = other.attest(&h, &id, &mut rng).unwrap();
        assert!(other.verify_att(&id, &att));
        // the public checks do not involve the generators ...
        assert!(BBS::verify_possess_public(
            &dep.pp, &dep.vk, &att.shown, &att.phi
        ));
        // ... (1) the statement does: same context bytes, other clause bases and target
        let ctx = other.att_ctx(&id, &att.phi, &att.t, &att.shown);
        let rel_other = other.att_relation(&att.shown, &att.phi, &att.t, &s);
        assert!(fiat_shamir::verify(&rel_other, &ctx, &att.pi));
        let rel = dep.att_relation(&att.shown, &att.phi, &att.t, &s);
        assert!(!fiat_shamir::verify(&rel, &ctx, &att.pi));
        // ... (2) and so does the context
        assert_ne!(ctx, dep.att_ctx(&id, &att.phi, &att.t, &att.shown));
        assert!(!dep.verify_att(&id, &att));

        // the credential itself is worthless under the deployment's generators
        assert!(!BBS::verify(&dep.pp, &dep.vk, &h.msg(), &h.cred));
        assert_eq!(
            dep.attest(&h, &id, &mut rng).err(),
            Some(Error::InvalidCredential)
        );
        // and in the other direction
        let h = holder(&dep, &sk, b"f", &mut rng);
        let att = dep.attest(&h, &id, &mut rng).unwrap();
        assert!(dep.verify_att(&id, &att) && !other.verify_att(&id, &att));
    }

    #[test]
    fn attestation_is_bound_to_identifier_key_and_shown_credential() {
        let mut rng = StdRng::seed_from_u64(0xbb10);
        let (dep, sk) = deployment(&mut rng);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let id = identifier(&dep, &mut rng);
        let att = dep.attest(&h, &id, &mut rng).unwrap();
        assert!(dep.verify_att(&id, &att));

        // another identifier (non-transferability), another helper key
        assert!(!dep.verify_att(&(id + G1::generator()), &att));
        let (other_vk, _) = BBS::keygen(&dep.pp, &mut rng);
        let other = Dep {
            vk: other_vk,
            ..dep.clone()
        };
        assert!(!other.verify_att(&id, &att));

        // re-blinding cred* inside a finished attestation: (Ā^r, B̄^r, D) still passes the public
        // checks, but the statement is hashed
        let r = Fr::rand(&mut rng);
        let mauled = att.with_shown(BBSShownCredential {
            a_bar: att.shown.a_bar * r,
            b_bar: att.shown.b_bar * r,
            d: att.shown.d,
        });
        assert!(BBS::verify_possess_public(
            &dep.pp,
            &dep.vk,
            &mauled.shown,
            &mauled.phi
        ));
        assert!(!dep.verify_att(&id, &mauled));

        // identity tag, mauled proof, malformed proof
        let mut bad = att.with_shown(att.shown.clone());
        bad.t = G1::zero();
        assert!(!dep.verify_att(&id, &bad));
        for i in 0..5 {
            let mut bad = att.with_shown(att.shown.clone());
            bad.pi.responses[i] += Fr::one();
            assert!(!dep.verify_att(&id, &bad), "response {i}");
        }
        let mut bad = att.with_shown(att.shown.clone());
        bad.pi.responses.pop();
        assert!(!dep.verify_att(&id, &bad));
        bad.pi.responses.clear();
        assert!(!dep.verify_att(&id, &bad));
    }

    /// A credential on `(usk, φ, ρ)` under ANOTHER signer's key does not attest under `vk`: its
    /// clauses hold, the public pairing check fails.
    #[test]
    fn credential_of_another_signer_cannot_be_shown() {
        let mut rng = StdRng::seed_from_u64(0xbb11);
        let (dep, _sk) = deployment(&mut rng);
        let (_, rogue_sk) = BBS::keygen(&dep.pp, &mut rng);
        let h = holder(&dep, &rogue_sk, b"f", &mut rng);
        let id = identifier(&dep, &mut rng);
        assert_eq!(
            dep.attest(&h, &id, &mut rng).err(),
            Some(Error::InvalidCredential)
        );
        let att = dep.attest_inner(&h, &h.usk, &id, false, &mut rng).unwrap();
        assert!(dep.verify_att_without_public_checks(&id, &att));
        assert!(!dep.verify_att(&id, &att));
    }

    // ----- the public checks of VerifyPossess -----------------------------------------------------

    /// Each public check on its own, on an otherwise honest `cred*`.
    #[test]
    fn public_checks_reject_each_degenerate_or_tampered_component() {
        let mut rng = StdRng::seed_from_u64(0xbb12);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, _) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        assert!(BBS::verify_possess_public(pp, vk, &shown, &h.phi));
        // the label is not part of the public checks (it sits in the clause target)
        assert!(BBS::verify_possess_public(pp, vk, &shown, &(h.phi + h.phi)));

        let g = G1::generator();
        let r = Fr::rand(&mut rng);
        let cases = [
            // Ā = 1 (with the matching B̄ = 1, so that the pairing equation holds)
            (G1::zero(), G1::zero(), shown.d),
            (G1::zero(), shown.b_bar, shown.d),
            // D = 1
            (shown.a_bar, shown.b_bar, G1::zero()),
            // B̄ tampered: the pairing equation
            (shown.a_bar, shown.b_bar + g, shown.d),
            (shown.a_bar, shown.b_bar * r, shown.d),
            (shown.a_bar, -shown.b_bar, shown.d),
            (shown.a_bar, G1::zero(), shown.d),
            (shown.a_bar + g, shown.b_bar, shown.d),
            (shown.b_bar, shown.a_bar, shown.d),
        ];
        for (i, (a_bar, b_bar, d)) in cases.into_iter().enumerate() {
            let bad = BBSShownCredential::<E> { a_bar, b_bar, d };
            assert!(
                !BBS::verify_possess_public(pp, vk, &bad, &h.phi),
                "case {i}"
            );
        }
        // D is not covered by the pairing equation: replacing it passes the public checks and
        // fails the clauses (no witness for the new statement)
        let replaced = BBSShownCredential::<E> {
            d: shown.d + g,
            ..shown.clone()
        };
        assert!(BBS::verify_possess_public(pp, vk, &replaced, &h.phi));
        // another helper key
        let (other_vk, _) = BBS::keygen(pp, &mut rng);
        assert!(!BBS::verify_possess_public(pp, &other_vk, &shown, &h.phi));
    }

    /// Attack W4-B1 (credential-free attestation): for `Ā = B̄ = 1` and `D = h_0 h_1^K h_2^φ` the
    /// clauses hold for a forged key `K`, the pairing equation reads `1 = 1`, the Fiat-Shamir
    /// proof verifies and the tag is valid. Only the public check `Ā ≠ 1` stops a party WITHOUT
    /// any credential.
    #[test]
    fn credential_free_statement_is_rejected_although_its_clauses_are_satisfiable() {
        let mut rng = StdRng::seed_from_u64(0xbb13);
        let (dep, _sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let phi = phi(b"f");
        let id = identifier(&dep, &mut rng);
        let forged_key = dep.tag.keygen(&mut rng); // no credential exists for this key

        let forgeries = credential_free_forgeries(pp, vk, &phi, &forged_key);
        assert_eq!(forgeries.len(), 3);
        let mut tags = Vec::new();
        for forgery in &forgeries[..2] {
            let shown = forgery.shown.clone();
            assert!(shown.a_bar.is_zero() && shown.b_bar.is_zero() && !shown.d.is_zero());
            // the pairing equation holds ...
            assert!(pairings_agree(
                shown.a_bar,
                vk.x_tilde,
                shown.b_bar,
                G2::generator()
            ));
            // ... the clauses hold, the bare proof verifies, the tag is valid ...
            let w = [
                forged_key,
                forgery.extra_witness[0],
                forgery.extra_witness[1],
                forgery.extra_witness[2],
                forgery.extra_witness[3],
            ];
            let att = dep.forge(shown, phi, w, &id, &mut rng).unwrap();
            assert!(dep.verify_att_without_public_checks(&id, &att));
            // ... and the attestation is rejected, by Ā ≠ 1 alone.
            assert!(!BBS::verify_possess_public(pp, vk, &att.shown, &phi));
            assert!(!dep.verify_att(&id, &att));
            tags.push(att.t);
        }
        assert_eq!(tags[0], tags[1]);
        // (1, 1, 1): degenerate, and not even provable without a relation among the generators
        let all_identity = &forgeries[2];
        assert!(all_identity.shown.d.is_zero());
        assert!(!BBS::verify_possess_public(
            pp,
            vk,
            &all_identity.shown,
            &phi
        ));
        let w = [forged_key, Fr::zero(), Fr::zero(), Fr::zero(), Fr::one()];
        assert_eq!(
            dep.forge(all_identity.shown.clone(), phi, w, &id, &mut rng)
                .err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );

        // the stand-alone prover refuses, the stand-alone verifier rejects a forged proof
        let shown = forgeries[0].shown.clone();
        let m_hid = BBS::hidden_message(&forged_key, &Fr::zero());
        let omega = BBSShowState::<E> {
            e: Fr::zero(),
            r1: Fr::zero(),
            r3: Fr::one(),
        };
        assert_eq!(
            possess::<E, BBS, _>(pp, vk, &shown, &phi, &m_hid, &omega, b"ctx", &mut rng),
            Err(Error::InvalidCredential)
        );
        let (rel, _) = possession_relation::<E, BBS>(pp, vk, &shown, &phi).unwrap();
        let w = possession_witness_vector::<E, BBS>(&m_hid, &omega);
        assert!(rel.is_satisfied_by(&w));
        let ctx = possess_context::<E, BBS>(pp, vk, &shown, &phi, b"ctx").unwrap();
        let forged = fiat_shamir::prove(&rel, &w, &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &forged));
        assert!(!verify_possess::<E, BBS>(
            pp, vk, &shown, &phi, b"ctx", &forged
        ));
    }

    /// `D = 1`, the second nonidentity check. With `D = 1` the first clause reads `B̄ = Ā^{-e}`,
    /// which together with `B̄ = Ā^x` and `Ā ≠ 1` forces `e = −x`, and the second clause reads
    /// `B(usk, φ, ρ) = 1`, a relation among the generators alone. A party that knows `x` AND
    /// such relations (here: the key holder, under the INSECURE test generators) proves the
    /// statement for ANY tag key without any credential; `Ā ≠ 1` and the pairing equation both
    /// hold, and for THIS statement only `D ≠ 1` rejects.
    ///
    /// Control, so that the check is not taken for a load-bearing one: the SAME party, with the
    /// same `(usk, e, ρ)`, passes ALL public checks with a random `D ≠ 1` and
    /// `(r_1, r_3) = (0, 0)`, and its attestation VERIFIES. What stands in its way is not a
    /// public check but that neither `x` nor a message with `B(m) = 1` can be found (module
    /// docs, "The possession proof"). `D ≠ 1` is kept because the box requires it.
    #[test]
    fn identity_d_is_rejected_but_the_check_is_not_load_bearing() {
        let mut rng = StdRng::seed_from_u64(0xbb14);
        let (pp, exponents) = weak_setup(DOMAIN);
        let (dep, sk) = deployment(&mut rng);
        let dep = Dep { pp, ..dep };
        let phi = phi(b"f");
        let id = identifier(&dep, &mut rng);

        let (mut tags, mut control_tags) = (Vec::new(), Vec::new());
        for _ in 0..2 {
            let forged_key = dep.tag.keygen(&mut rng);
            let rho = rho_with_identity_base(exponents, forged_key, phi);
            let a_bar = G1::rand(&mut rng);
            let shown = BBSShownCredential::<E> {
                a_bar,
                b_bar: a_bar * sk.x,
                d: G1::zero(),
            };
            assert!(!shown.a_bar.is_zero());
            assert!(pairings_agree(
                shown.a_bar,
                dep.vk.x_tilde,
                shown.b_bar,
                G2::generator()
            ));
            // (usk, e, ρ, r_1, r_3) = (K, −x, ρ, arbitrary, arbitrary)
            let w = [
                forged_key,
                -sk.x,
                rho,
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
            ];
            let att = dep.forge(shown, phi, w, &id, &mut rng).unwrap();
            assert!(dep.verify_att_without_public_checks(&id, &att));
            assert!(!BBS::verify_possess_public(
                &dep.pp, &dep.vk, &att.shown, &phi
            ));
            assert!(!dep.verify_att(&id, &att));
            tags.push(att.t);

            // control: the same (K, −x, ρ), a random D ≠ 1 and (r_1, r_3) = (0, 0)
            let shown = BBSShownCredential::<E> {
                a_bar,
                b_bar: a_bar * sk.x,
                d: G1::rand(&mut rng),
            };
            assert!(!shown.d.is_zero());
            assert!(BBS::verify_possess_public(&dep.pp, &dep.vk, &shown, &phi));
            let w = [forged_key, -sk.x, rho, Fr::zero(), Fr::zero()];
            let att = dep.forge(shown, phi, w, &id, &mut rng).unwrap();
            assert!(
                dep.verify_att(&id, &att),
                "accepted: nothing public is wrong"
            );
            control_tags.push(att.t);
        }
        assert_ne!(tags[0], tags[1], "one forger, two attesters");
        assert_eq!(tags, control_tags);
    }

    /// The degenerate WITNESSES `r_1 = 0` and `r_3 = 0` (module docs, "The possession proof").
    /// No public check excludes them; what excludes them is that they cannot be found. Both
    /// attestations below VERIFY, which is expected of a party that holds the signing key,
    /// resp. the discrete logarithms of the INSECURE test generators, and is no attack on an
    /// honest deployment.
    ///
    /// * `r_1 = 0` forces `e = −x`. The key holder (who could sign anyway) attests that way
    ///   without a credential, under the honest generators; with any other `e` the same
    ///   statement has no witness with `r_1 = 0`.
    /// * `r_3 = 0` forces `B(usk, φ, ρ) = 1`. Whoever can solve that for `ρ` (under the INSECURE
    ///   test generators: everybody) attests with ONE credential, WITHOUT the signing key, for
    ///   any label and next to tags under arbitrary keys. Under the honest generators a guessed
    ///   `ρ` fails. This is why the generators have to be independent, which
    ///   [`BBSPublicParams::is_well_formed`] cannot check.
    #[test]
    fn degenerate_witnesses_take_the_signing_key_or_a_generator_relation() {
        let mut rng = StdRng::seed_from_u64(0xbb22);
        let (dep, sk) = deployment(&mut rng);
        let id = identifier(&dep, &mut rng);
        let label = phi(b"f");

        // r_1 = 0: Ā random, B̄ = Ā^x, D = B(K, φ, ρ)^{r_2}; witness (K, −x, ρ, 0, r_2^{-1})
        let (key, rho) = (dep.tag.keygen(&mut rng), Fr::rand(&mut rng));
        let (r2, r3) = nonzero_scalar_with_inverse::<Fr, _>(&mut rng);
        let a_bar = G1::rand(&mut rng);
        let shown = BBSShownCredential::<E> {
            a_bar,
            b_bar: a_bar * sk.x,
            d: dep.pp.b(&msg(key, label, rho)) * r2,
        };
        assert!(BBS::verify_possess_public(&dep.pp, &dep.vk, &shown, &label));
        let w = [key, -sk.x, rho, Fr::zero(), r3];
        let att = dep.forge(shown.clone(), label, w, &id, &mut rng).unwrap();
        assert!(dep.verify_att(&id, &att));
        for e in [-sk.x + Fr::one(), sk.x, Fr::zero(), Fr::rand(&mut rng)] {
            assert_ne!(e, -sk.x);
            let w = [key, e, rho, Fr::zero(), r3];
            assert_eq!(
                dep.forge(shown.clone(), label, w, &id, &mut rng).err(),
                Some(Error::WitnessDoesNotSatisfyRelation)
            );
        }

        // r_3 = 0: the holder of ONE honestly issued credential makes one honest show. It has no
        // signing key; for every label and key it computes a ρ with B(K, φ, ρ) = 1 from the
        // known exponents of the generators
        let (pp, exponents) = weak_setup(DOMAIN);
        let weak = Dep { pp, ..dep.clone() };
        let h = holder(&weak, &sk, b"f", &mut rng);
        let (shown, omega) = BBS::rerand(&weak.pp, &weak.vk, &h.msg(), &h.cred, &mut rng).unwrap();
        let mut tags = Vec::new();
        for label in [h.phi, phi(b"f'"), Fr::zero()] {
            let key = weak.tag.keygen(&mut rng);
            let rho = rho_with_identity_base(exponents, key, label);
            assert!(BBS::verify_possess_public(
                &weak.pp, &weak.vk, &shown, &label
            ));
            let w = [key, omega.e, rho, omega.r1, Fr::zero()];
            let att = weak.forge(shown.clone(), label, w, &id, &mut rng).unwrap();
            assert!(
                weak.verify_att(&id, &att),
                "accepted: nothing public is wrong"
            );
            assert!(!tags.contains(&att.t));
            tags.push(att.t);
        }
        // control: under the honest generators the holder's own ρ, and a guessed one, fail
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, omega) = BBS::rerand(&dep.pp, &dep.vk, &h.msg(), &h.cred, &mut rng).unwrap();
        for (key, rho) in [
            (h.usk, h.rho),
            (dep.tag.keygen(&mut rng), Fr::rand(&mut rng)),
        ] {
            let w = [key, omega.e, rho, omega.r1, Fr::zero()];
            assert_eq!(
                dep.forge(shown.clone(), h.phi, w, &id, &mut rng).err(),
                Some(Error::WitnessDoesNotSatisfyRelation)
            );
        }
    }

    /// Generators with an identity component (module docs, "Degenerate inputs"): what each one
    /// breaks, and that the possession verifier and the opening clause refuse such a `pp`.
    #[test]
    fn degenerate_generators_are_rejected() {
        let mut rng = StdRng::seed_from_u64(0xbb15);
        let (dep, sk) = deployment(&mut rng);
        let id = identifier(&dep, &mut rng);
        let with = |i: usize| {
            let mut pp = dep.pp.clone();
            match i {
                0 => pp.h0 = G1::zero(),
                1 => pp.h1 = G1::zero(),
                2 => pp.h2 = G1::zero(),
                _ => pp.h3 = G1::zero(),
            }
            // the decoder does not mind
            assert_eq!(Pp::from_bytes(&pp.to_bytes().unwrap()).unwrap(), pp);
            assert!(!pp.is_well_formed(), "h_{i} = 1");
            Dep { pp, ..dep.clone() }
        };

        // h_1 = 1: usk is not bound. ONE credential attests under arbitrarily many tag keys,
        // with an honest-looking cred*; only the check on pp rejects.
        let bad = with(1);
        let h = holder(&bad, &sk, b"f", &mut rng);
        assert!(BBS::verify(&bad.pp, &bad.vk, &h.msg(), &h.cred));
        let mut tags = Vec::new();
        for _ in 0..2 {
            let other_key = bad.tag.keygen(&mut rng);
            let (shown, omega) =
                BBS::rerand(&bad.pp, &bad.vk, &h.msg(), &h.cred, &mut rng).unwrap();
            let w = [other_key, omega.e, h.rho, omega.r1, omega.r3];
            let att = bad.forge(shown, h.phi, w, &id, &mut rng).unwrap();
            assert!(bad.verify_att_without_public_checks(&id, &att));
            assert!(!att.shown.a_bar.is_zero() && !att.shown.d.is_zero());
            assert_eq!(att.shown.b_bar, att.shown.a_bar * sk.x);
            assert!(!BBS::verify_possess_public(
                &bad.pp, &bad.vk, &att.shown, &h.phi
            ));
            assert!(!bad.verify_att(&id, &att));
            tags.push(att.t);
        }
        assert_ne!(tags[0], tags[1]);

        // h_2 = 1: φ is not bound. A credential for φ is shown under another label.
        let bad = with(2);
        let h = holder(&bad, &sk, b"f", &mut rng);
        let other_phi = phi(b"f'");
        assert!(BBS::verify(
            &bad.pp,
            &bad.vk,
            &msg(h.usk, other_phi, h.rho),
            &h.cred
        ));
        let (shown, omega) = BBS::rerand(&bad.pp, &bad.vk, &h.msg(), &h.cred, &mut rng).unwrap();
        let w = [h.usk, omega.e, h.rho, omega.r1, omega.r3];
        let att = bad.forge(shown, other_phi, w, &id, &mut rng).unwrap();
        assert!(bad.verify_att_without_public_checks(&id, &att));
        assert!(!bad.verify_att(&id, &att));

        // h_0 = 1: signatures are homogeneous, A^k is a signature on k·m (never signed).
        let bad = with(0);
        let h = holder(&bad, &sk, b"f", &mut rng);
        let k = Fr::from(3u64);
        let scaled = BBSCredential {
            a: h.cred.a * k,
            e: h.cred.e,
        };
        assert!(BBS::verify(
            &bad.pp,
            &bad.vk,
            &msg(h.usk * k, h.phi * k, h.rho * k),
            &scaled
        ));
        // control: not so under the honest generators
        let h = holder(&dep, &sk, b"f", &mut rng);
        let scaled = BBSCredential {
            a: h.cred.a * k,
            e: h.cred.e,
        };
        assert!(!BBS::verify(
            &dep.pp,
            &dep.vk,
            &msg(h.usk * k, h.phi * k, h.rho * k),
            &scaled
        ));

        // h_3 = 1: the issuance encoding has no blinding term.
        let bad = with(3);
        let (usk, label) = (Fr::rand(&mut rng), phi(b"f"));
        let encode = |pp: &Pp, rho: Fr| {
            let m_hid = BBS::hidden_message(&usk, &rho);
            BBS::issuance_encoding(pp, &dep.vk, &m_hid, &label, &rho).unwrap()
        };
        assert_eq!(
            encode(&bad.pp, Fr::from(1u64)),
            encode(&bad.pp, Fr::from(2u64))
        );
        assert_ne!(
            encode(&dep.pp, Fr::from(1u64)),
            encode(&dep.pp, Fr::from(2u64))
        );

        // every such pp is refused by the possession verifier and by the opening clause
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, _) = BBS::rerand(&dep.pp, &dep.vk, &h.msg(), &h.cred, &mut rng).unwrap();
        assert!(BBS::verify_possess_public(&dep.pp, &dep.vk, &shown, &h.phi));
        for i in 0..4 {
            let bad = with(i);
            assert!(
                !BBS::verify_possess_public(&bad.pp, &bad.vk, &shown, &h.phi),
                "h_{i} = 1"
            );
            let mut rel = PairingRelation::<E>::new();
            let var = rel.alloc_scalar();
            assert!(
                matches!(
                    BBS::issuance_clauses(&bad.pp, &bad.vk, &shown.d, &h.phi, &mut rel, var),
                    Err(Error::DegenerateInput(_))
                ),
                "h_{i} = 1"
            );
            assert_eq!(rel.num_scalars(), 1);
            assert!(rel.g1_equations().is_empty());
        }
    }

    // ----- attack A7: the helper tries to recognise the attester ----------------------------------

    /// Every test the helper can run with its list of issued `e_i` (and its key `x`) to decide
    /// whether `cred*` comes from credential `i`; returns the `(i, test)` pairs that fire.
    ///
    /// * `pairing`: `e(Ā, X̃ g̃^{e_i}) = e(D, g̃)`, the single-randomizer pairing test;
    /// * `anchor`: `D B̄^{-1} = Ā^{e_i}`, the public pair `(R, R^e)` of a single-randomizer show;
    /// * `pair`: `S = R^k` for all ordered pairs `(R, S)` of `{Ā, B̄, D}` and
    ///   `k ∈ {±e_i, ±(x + e_i)}`.
    fn helper_tests(
        sk: &BBSSigningKey<E>,
        vk: &BBSVerificationKey<E>,
        issued_e: &[Fr],
        shown: &BBSShownCredential<E>,
    ) -> Vec<(usize, &'static str)> {
        let g2 = G2::generator();
        let elements = [shown.a_bar, shown.b_bar, shown.d];
        let mut fired = Vec::new();
        for (i, e) in issued_e.iter().enumerate() {
            if pairings_agree(shown.a_bar, vk.x_tilde + g2 * *e, shown.d, g2) {
                fired.push((i, "pairing"));
            }
            if shown.d - shown.b_bar == shown.a_bar * *e {
                fired.push((i, "anchor"));
            }
            for (j, r) in elements.iter().enumerate() {
                for (l, s) in elements.iter().enumerate() {
                    let scalars = [*e, -*e, sk.x + *e, -(sk.x + *e)];
                    if j != l && scalars.iter().any(|k| *s == *r * *k) {
                        fired.push((i, "pair"));
                    }
                }
            }
        }
        fired
    }

    /// Attack A7 (helper de-anonymisation). The helper issued 20 credentials and recorded every
    /// `e_i`. None of its tests recognises the attester in a two-randomizer show, while ALL of
    /// them identify it in the single-randomizer show (`r_1 = 1`) that the box replaced.
    /// Evidence on samples for the tests listed; the distributional statement is the argument
    /// in the docs of `rerand`.
    #[test]
    fn helper_cannot_identify_the_attester_from_its_issued_e_values() {
        let mut rng = StdRng::seed_from_u64(0xbb16);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let holders: Vec<Holder> = (0..20)
            .map(|_| issued_holder(&dep, &sk, b"f", &mut rng))
            .collect();
        let issued_e: Vec<Fr> = holders.iter().map(|h| h.cred.e).collect();

        for attester in [0usize, 7, 19] {
            let h = &holders[attester];
            for _ in 0..3 {
                let (shown, _) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
                assert!(BBS::verify_possess_public(pp, vk, &shown, &h.phi));
                assert_eq!(helper_tests(&sk, vk, &issued_e, &shown), vec![]);
            }

            // control: the single-randomizer show Ā = A^{r_2}, D = B(m)^{r_2}, B̄ = D Ā^{-e}
            // passes the same public checks and is recognised by every test, for the right i only
            let r2: Fr = nonzero_scalar(&mut rng);
            let (a_bar, d) = (h.cred.a * r2, pp.b(&h.msg()) * r2);
            let single = BBSShownCredential::<E> {
                a_bar,
                b_bar: d - a_bar * h.cred.e,
                d,
            };
            assert!(BBS::verify_possess_public(pp, vk, &single, &h.phi));
            let fired = helper_tests(&sk, vk, &issued_e, &single);
            assert!(!fired.is_empty());
            assert!(fired.iter().all(|(i, _)| *i == attester));
            for test in ["pairing", "anchor", "pair"] {
                assert!(fired.contains(&(attester, test)), "{test}");
            }
        }
    }

    // ----- special soundness ----------------------------------------------------------------------

    /// Special soundness with a shared coordinate: rewinding the prover of `R_att` yields ONE
    /// `usk`, which opens the tag, and `(e, ρ, r_1, r_3)` from which the extractor rebuilds a
    /// verifying credential `A = Ā^{r_3 / r_1}` on `(usk, φ, ρ)`.
    #[test]
    fn extractor_recovers_the_shared_usk_and_a_credential() {
        let mut rng = StdRng::seed_from_u64(0xbb17);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let id = identifier(&dep, &mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let t = dep.tag.eval(&h.usk, &s).unwrap();
        let (shown, omega) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        let rel = dep.att_relation(&shown, &h.phi, &t, &s);
        let w = possession_witness_vector::<E, BBS>(&h.m_hid(), &omega);

        // "rewinding" = the same random tape twice
        let (a1, st1) = commit(&rel, &mut StdRng::seed_from_u64(77)).unwrap();
        let (a2, st2) = commit(&rel, &mut StdRng::seed_from_u64(77)).unwrap();
        assert_eq!(a1, a2);
        let (c1, c2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let z1 = respond(st1, &w, &c1).unwrap();
        let z2 = respond(st2, &w, &c2).unwrap();
        let extracted = extract(&rel, &a1, (&c1, &z1), (&c2, &z2)).unwrap();
        assert_eq!(extracted, w.to_vec());

        let [usk, e, rho, r1, r3] = [
            extracted[0],
            extracted[1],
            extracted[2],
            extracted[3],
            extracted[4],
        ];
        assert_eq!(dep.tag.eval(&usk, &s).unwrap(), t);
        let rebuilt = BBSCredential {
            a: shown.a_bar * (r3 * r1.inverse().unwrap()),
            e,
        };
        assert!(BBS::verify(pp, vk, &msg(usk, h.phi, rho), &rebuilt));
        assert_eq!(rebuilt, h.cred);
    }

    // ----- the stand-alone Possess / VerifyPossess of cred -----------------------------

    #[test]
    fn standalone_possession_proof() {
        let mut rng = StdRng::seed_from_u64(0xbb18);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = issued_holder(&dep, &sk, b"f", &mut rng);
        let (shown, omega) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();

        let (rel, var) = possession_relation::<E, BBS>(pp, vk, &shown, &h.phi).unwrap();
        assert_eq!((var.index(), rel.num_scalars()), (0, 5));
        assert_eq!(rel.g1_equations().len(), 2);
        assert!(rel.g2_equations().is_empty() && rel.gt_equations().is_empty());

        let m_hid = h.m_hid();
        let pi =
            possess::<E, BBS, _>(pp, vk, &shown, &h.phi, &m_hid, &omega, b"ctx", &mut rng).unwrap();
        assert_eq!(pi.responses.len(), 5);
        assert!(verify_possess::<E, BBS>(
            pp, vk, &shown, &h.phi, b"ctx", &pi
        ));
        assert!(!verify_possess::<E, BBS>(
            pp, vk, &shown, &h.phi, b"ctx2", &pi
        ));
        let other_phi = h.phi + Fr::one();
        assert!(!verify_possess::<E, BBS>(
            pp, vk, &shown, &other_phi, b"ctx", &pi
        ));
        let (other_vk, _) = BBS::keygen(pp, &mut rng);
        assert!(!verify_possess::<E, BBS>(
            pp, &other_vk, &shown, &h.phi, b"ctx", &pi
        ));
        let other_pp = BBS::setup(b"another deployment").unwrap();
        assert!(!verify_possess::<E, BBS>(
            &other_pp, vk, &shown, &h.phi, b"ctx", &pi
        ));
        let (shown2, _) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        assert!(!verify_possess::<E, BBS>(
            pp, vk, &shown2, &h.phi, b"ctx", &pi
        ));

        // wrong hidden message (either component), wrong show state: no proof
        for wrong in [
            BBS::hidden_message(&(h.usk + Fr::one()), &h.rho),
            BBS::hidden_message(&h.usk, &(h.rho + Fr::one())),
        ] {
            assert_eq!(
                possess::<E, BBS, _>(pp, vk, &shown, &h.phi, &wrong, &omega, b"ctx", &mut rng),
                Err(Error::WitnessDoesNotSatisfyRelation)
            );
        }
        let (_, omega2) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        assert_eq!(
            possess::<E, BBS, _>(pp, vk, &shown, &h.phi, &m_hid, &omega2, b"ctx", &mut rng),
            Err(Error::WitnessDoesNotSatisfyRelation)
        );
    }

    // ----- R_issue: C = Com((usk, ρ), φ; ρ) ∧ id ∧ T_0, shared usk --------------------------------

    fn issue_relation(dep: &Dep, c: &G1, phi: &Fr, id: &G1, t0: &G1) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        let usk = rel.alloc_scalar();
        let extra = BBS::issuance_clauses(&dep.pp, &dep.vk, c, phi, &mut rel, usk).unwrap();
        assert_eq!(extra.len(), 1);
        let c0 = *dep.tag.identity_point().unwrap();
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        for eq in dep
            .tag
            .tag_equations(usk, id, &c0)
            .into_iter()
            .chain(dep.tag.tag_equations(usk, t0, &s))
        {
            rel.add_g1(eq).unwrap();
        }
        rel
    }

    #[test]
    fn issuance_opening_clause_binds_usk_and_phi() {
        let mut rng = StdRng::seed_from_u64(0xbb19);
        let (dep, _sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let phi = phi(b"f");
        let usk = dep.tag.keygen(&mut rng);
        let c0 = *dep.tag.identity_point().unwrap();
        let id = dep.tag.eval(&usk, &c0).unwrap();
        let t0 = dep.tag.eval(&usk, &h0_id(DOMAIN, &id).unwrap()).unwrap();

        let (aux, rho) = BBS::sample_issuance(pp, &mut rng);
        let m_hid = BBS::hidden_message(&usk, &aux);
        let c = BBS::issuance_encoding(pp, vk, &m_hid, &phi, &rho).unwrap();
        let rel = issue_relation(&dep, &c, &phi, &id, &t0);
        assert_eq!(rel.num_scalars(), 2);
        assert_eq!(rel.g1_equations().len(), 3);
        // C h_0^{-1} h_2^{-φ} = h_1^usk h_3^ρ, with usk the shared variable 0 and ρ variable 1
        let opening = &rel.g1_equations()[0];
        assert_eq!(opening.target, c - pp.h0 - pp.h2 * phi);
        let terms: Vec<(usize, G1)> = opening.terms.iter().map(|(v, b)| (v.index(), *b)).collect();
        assert_eq!(terms, vec![(0, pp.h1), (1, pp.h3)]);

        let w = issuance_witness_vector::<E, BBS>(&m_hid, &rho);
        assert_eq!(&*w, [usk, rho]);
        let pi0 = fiat_shamir::prove(&rel, &w, b"ctx0", &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, b"ctx0", &pi0));
        assert_eq!(pi0.responses.len(), 2);

        // wrong opening / wrong key
        for bad in [
            [usk, rho + Fr::one()],
            [usk + Fr::one(), rho],
            [rho, usk],
            [Fr::zero(), Fr::zero()],
        ] {
            assert!(!rel.is_satisfied_by(&bad));
            assert_eq!(
                fiat_shamir::prove(&rel, &bad, b"ctx0", &mut rng),
                Err(Error::WitnessDoesNotSatisfyRelation)
            );
        }
        // φ is bound: the SAME C next to another disclosed label has no witness, so a helper
        // cannot be made to believe that C carries a label other than the one inside it
        let other_phi = self::phi(b"f'");
        let rel_phi = issue_relation(&dep, &c, &other_phi, &id, &t0);
        assert!(!rel_phi.is_satisfied_by(&w));
        assert!(!fiat_shamir::verify(&rel_phi, b"ctx0", &pi0));
        // usk is bound: a C for ANOTHER key cannot be opened next to this id
        let other = dep.tag.keygen(&mut rng);
        let m_hid_other = BBS::hidden_message(&other, &aux);
        let c_other = BBS::issuance_encoding(pp, vk, &m_hid_other, &phi, &rho).unwrap();
        let rel_other = issue_relation(&dep, &c_other, &phi, &id, &t0);
        assert!(!rel_other.is_satisfied_by(&[usk, rho]));
        assert!(!rel_other.is_satisfied_by(&[other, rho]));
        // the proof is bound to C, id and T_0
        assert!(!fiat_shamir::verify(&rel_other, b"ctx0", &pi0));
        let rel_id = issue_relation(&dep, &c, &phi, &(id + id), &t0);
        assert!(!fiat_shamir::verify(&rel_id, b"ctx0", &pi0));
        let rel_t0 = issue_relation(&dep, &c, &phi, &id, &(t0 + t0));
        assert!(!fiat_shamir::verify(&rel_t0, b"ctx0", &pi0));
    }

    /// A foreign handle is refused BEFORE anything is allocated. Without that, the handle with
    /// index 2 below would silently alias the fresh variable `ρ` of the possession clauses.
    #[test]
    fn clauses_reject_foreign_variables_and_leave_the_relation_untouched() {
        let mut rng = StdRng::seed_from_u64(0xbb1a);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, _) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        let foreign = PairingRelation::<E>::new().alloc_scalars(3)[2];

        let mut rel = PairingRelation::<E>::new();
        rel.alloc_scalar();
        assert_eq!(
            BBS::possession_clauses(pp, vk, &shown, &h.phi, &mut rel, foreign),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 1
            })
        );
        assert_eq!(rel.num_scalars(), 1);
        assert!(rel.g1_equations().is_empty());

        let mut rel = PairingRelation::<E>::new();
        assert_eq!(
            BBS::issuance_clauses(pp, vk, &shown.d, &h.phi, &mut rel, foreign),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 0
            })
        );
        assert_eq!(rel.num_scalars(), 0);
        assert!(rel.g1_equations().is_empty());
        // index 0 of an EMPTY relation is foreign too
        let first = PairingRelation::<E>::new().alloc_scalar();
        assert!(matches!(
            BBS::issuance_clauses(pp, vk, &shown.d, &h.phi, &mut rel, first),
            Err(Error::UnallocatedVariable {
                index: 0,
                allocated: 0
            })
        ));
        assert_eq!(rel.num_scalars(), 0);
    }

    // ----- encodings and secrets ------------------------------------------------------------------

    #[test]
    fn serialization_sizes_and_round_trips() {
        let mut rng = StdRng::seed_from_u64(0xbb1b);
        let (dep, sk) = deployment(&mut rng);
        let (pp, vk) = (&dep.pp, &dep.vk);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (shown, _) = BBS::rerand(pp, vk, &h.msg(), &h.cred, &mut rng).unwrap();
        let c = BBS::issuance_encoding(pp, vk, &h.m_hid(), &h.phi, &h.rho).unwrap();
        let pre = BBS::blind_issue(pp, &sk, &c, &h.phi, &mut rng).unwrap();

        // BLS12-381: G_1 48 B, G_2 96 B, Z_p 32 B
        let bytes = h.cred.to_bytes().unwrap();
        assert_eq!(bytes.len(), 48 + 32);
        assert_eq!(BBSCredential::<E>::from_bytes(&bytes).unwrap(), h.cred);
        let bytes = shown.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 48);
        assert_eq!(BBSShownCredential::<E>::from_bytes(&bytes).unwrap(), shown);
        let bytes = pre.to_bytes().unwrap();
        assert_eq!(bytes.len(), 48 + 32);
        assert_eq!(BBSPreCredential::<E>::from_bytes(&bytes).unwrap(), pre);
        let bytes = vk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 96);
        assert_eq!(BBSVerificationKey::<E>::from_bytes(&bytes).unwrap(), *vk);
        let bytes = pp.to_bytes().unwrap();
        assert_eq!(bytes.len(), 4 * 48);
        assert_eq!(Pp::from_bytes(&bytes).unwrap(), *pp);
        assert_eq!(BBS::encoding_to_wire(&c).to_bytes().unwrap().len(), 48);
        // m_aux = ρ, stored next to (A, e): |cred_PCS| = 48 + 32 + 32
        assert_eq!(h.rho.to_bytes().unwrap().len(), 32);

        let bytes = sk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        let back = BBSSigningKey::<E>::from_bytes(&bytes).unwrap();
        assert_eq!(back.verification_key(), *vk);

        // trailing bytes and truncation
        let mut long = h.cred.to_bytes().unwrap();
        long.push(0);
        assert_eq!(
            BBSCredential::<E>::from_bytes(&long),
            Err(Error::TrailingBytes)
        );
        assert!(BBSCredential::<E>::from_bytes(&long[..79]).is_err());

        // the identity decodes fine: rejecting it is the verifiers' job
        let degenerate = BBSShownCredential::<E> {
            a_bar: G1::zero(),
            b_bar: G1::zero(),
            d: G1::zero(),
        };
        let back = BBSShownCredential::<E>::from_bytes(&degenerate.to_bytes().unwrap()).unwrap();
        assert_eq!(back, degenerate);
        assert!(!BBS::verify_possess_public(pp, vk, &back, &h.phi));
    }

    #[test]
    fn secrets_are_redacted_and_wiped() {
        let mut rng = StdRng::seed_from_u64(0xbb1c);
        let (dep, mut sk) = deployment(&mut rng);
        assert_eq!(format!("{sk:?}"), "BBSSigningKey(<redacted>)");
        assert!(!sk.x.is_zero());
        sk.zeroize();
        assert!(sk.x.is_zero());

        let mut m = msg(Fr::from(5u64), Fr::from(6u64), Fr::from(7u64));
        assert_eq!(format!("{m:?}"), "BBSMessage(<redacted>)");
        m.zeroize();
        assert!(m.m1.is_zero() && m.m2.is_zero() && m.m3.is_zero());

        let mut m_hid = BBS::hidden_message(&Fr::from(5u64), &Fr::from(6u64));
        assert_eq!(format!("{m_hid:?}"), "BBSHiddenMessage(<redacted>)");
        m_hid.zeroize();
        assert!(m_hid.usk.is_zero() && m_hid.rho.is_zero());

        let (_, sk) = BBS::keygen(&dep.pp, &mut rng);
        let h = holder(&dep, &sk, b"f", &mut rng);
        let (_, mut omega) = BBS::rerand(&dep.pp, &dep.vk, &h.msg(), &h.cred, &mut rng).unwrap();
        assert_eq!(format!("{omega:?}"), "BBSShowState(<redacted>)");
        assert!(!omega.e.is_zero() && !omega.r1.is_zero() && !omega.r3.is_zero());
        omega.zeroize();
        assert!(omega.e.is_zero() && omega.r1.is_zero() && omega.r3.is_zero());

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<BBSSigningKey<E>>();
        assert_zeroize_on_drop::<BBSMessage<E>>();
        assert_zeroize_on_drop::<BBSHiddenMessage<E>>();
        assert_zeroize_on_drop::<BBSShowState<E>>();
    }

    /// Every randomized algorithm accepts an unsized RNG (`R: ?Sized`), e.g. a trait object.
    #[test]
    fn randomized_algorithms_accept_a_dyn_rng() {
        trait DynRng: RngCore + CryptoRng {}
        impl<T: RngCore + CryptoRng> DynRng for T {}

        let mut std_rng = StdRng::seed_from_u64(0xbb1d);
        let rng: &mut dyn DynRng = &mut std_rng;
        let pp = BBS::setup(DOMAIN).unwrap();
        let (vk, sk) = BBS::keygen(&pp, rng);
        let (usk, phi) = (Fr::from(11u64), phi(b"f"));
        let (aux, rho) = BBS::sample_issuance(&pp, rng);
        let m_hid = BBS::hidden_message(&usk, &aux);
        let c = BBS::issuance_encoding(&pp, &vk, &m_hid, &phi, &rho).unwrap();
        let pre = BBS::blind_issue(&pp, &sk, &c, &phi, rng).unwrap();
        let m = msg(usk, phi, rho);
        let cred = BBS::unblind(&pp, &vk, &m, &pre, &rho).unwrap();
        assert!(BBS::verify(&pp, &vk, &m, &cred));
        let direct = BBS::sign(&pp, &sk, &m, rng).unwrap();
        assert!(BBS::verify(&pp, &vk, &m, &direct));
        let (shown, omega) = BBS::rerand(&pp, &vk, &m, &cred, rng).unwrap();
        let pi = possess::<E, BBS, _>(&pp, &vk, &shown, &phi, &m_hid, &omega, b"ctx", rng).unwrap();
        assert!(verify_possess::<E, BBS>(
            &pp, &vk, &shown, &phi, b"ctx", &pi
        ));
    }

    // ----- the generic flow of the construction ---------------------------------------------------

    /// `|att| = 4 G_1 + 7 Z_p` (`T, Ā, B̄, D`; `φ, c, z_usk, z_e, z_ρ, z_{r_1}, z_{r_3}`) and
    /// `|π_0| = 3 Z_p` (`c, z_usk, z_ρ`).
    const REPORT: FlowReport = FlowReport {
        attestation_responses: 5,
        issuance_responses: 2,
    };

    /// The base-and-tag-generic walk through the protocol box (`Attest`, `VerifyAtt`, `Prove`,
    /// `VerifyProof`, `Issue`, `Unblind`, `VerifyCred`, chaining), written against the traits only.
    #[test]
    fn conformance_flow_with_tag_ddh() {
        let report = public_base_flow::<E, BBS, Tag>(DOMAIN, 0xbb1e, credential_free_forgeries);
        assert_eq!(report, REPORT);
        assert_eq!(1 + BBS::POSSESSION_VARIABLES, 5);
        assert_eq!(1 + BBS::ISSUANCE_VARIABLES, 2);
        const { assert!(!BBS::REQUIRES_DLOG_IDENTITY) };
    }

    /// Genericity: the whole flow over a second pairing. arkworks ships no hash-to-curve for
    /// BN254, so generators and `htag` come from the INSECURE test oracle.
    #[test]
    fn conformance_flow_over_bn254() {
        type P = Bn254;
        type PG1 = <Bn254 as Pairing>::G1;
        let report = public_base_flow::<
            P,
            crate::cred::BBS<P, InsecureExponentHasher>,
            DDH<PG1, InsecureExponentHasher>,
        >(DOMAIN, 0xbb1f, credential_free_forgeries);
        assert_eq!(report, REPORT);
    }
}
