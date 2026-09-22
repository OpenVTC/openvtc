//! `Σ-EQ`, the SPS-EQ credential base (paper §3.2.3, "The SPS-EQ instantiation", box "`Σ-EQ`
//! credential base"): the structure-preserving signature on equivalence classes of Fuchsbauer,
//! Hanser and Slamanig, as spelled out in the paper's box.
//!
//! Setting: for `M, N ∈ (G_1 \ {1})^3`, `M ∼ N` iff `N = (M_1^r, M_2^r, M_3^r)` for some
//! `r ∈ Z_p^*`. The certified message `(usk, φ)` is the class of `M = (g_1, g_1^usk, g_1^φ)`;
//! `M_Σ` consists of these classes, whose invariants are `(usk, φ)`. The message map returns
//! `[M]_∼` (here: the canonical representative `M`), and `Com_vk(usk, φ; ∅) = g_1^usk = id`.
//! `g_1` and `g̃` are the standard generators of `G_1` and `G_2`, so `pp_Σ` is empty.
//!
//! | paper (box `Σ-EQ`) | here |
//! |---|---|
//! | `KeyGen(pp)`: `x_1, x_2, x_3 ← Z_p^*`, `X̃_i = g̃^{x_i}` | [`CredentialBase::keygen`] |
//! | `Sign(sk, M)`: `⊥` if some `M_i ∉ G_1 \ {1}`; `y ← Z_p^*`; `Z = (∏ M_i^{x_i})^y`, `Y = g_1^{1/y}`, `Ỹ = g̃^{1/y}` | [`CredentialBase::sign`] |
//! | `Verify`: reject any `M_i = 1`, `Y = 1`, `Ỹ = 1`; `[∏ e(M_i, X̃_i) = e(Z, Ỹ) ∧ e(Y, g̃) = e(g_1, Ỹ)]` | [`CredentialBase::verify`], two pairing products |
//! | `ReRand(vk, M, cred)`: `⊥` if `Verify = 0`; `r, ψ ← Z_p^*`; `M' = M^r`, `cred' = (Z^{rψ}, Y^{1/ψ}, Ỹ^{1/ψ})`; `cred* = (M', cred')`, `ω = ∅` | [`CredentialBase::rerand`] |
//! | `BlindIssue(sk, C, φ)`: `M = (g_1, C, g_1^φ)` with `C = id`; return `Sign(sk, M)` | [`CredentialBase::blind_issue`] |
//! | `Unblind(vk, M, ĉred, ∅) = ĉred` | [`CredentialBase::unblind`] (refuses `Y = 1`, `Ỹ = 1`; does NOT verify `ĉred`, see "Implementation notes") |
//! | `Possess` step 1: reject if `M'_1 = 1`, `Verify(vk, M', cred') = 0` or `M'_3 ≠ (M'_1)^φ` | [`SigmaFriendlyCredentialBase::verify_possess_public`] (also rejects `X̃_i = 1`) |
//! | `Possess` step 2: `M'_2 = (M'_1)^usk` | [`SigmaFriendlyCredentialBase::possession_clauses`], one `G_1` clause |
//! | §5.1: `(m_aux, ρ) = (∅, ∅)`; `C := id`, not transmitted, no opening clause | [`SigmaFriendlyCredentialBase::sample_issuance`], [`SigmaFriendlyCredentialBase::encoding_from_wire`], [`SigmaFriendlyCredentialBase::issuance_clauses`] |
//!
//! The credential stored by the holder is the signature `(Z, Y, Ỹ)`; the message `M` is
//! recomputed from `(usk, φ)` whenever it is needed.
//!
//! Security (Lemma on `Σ-EQ`, §3.2.3): assuming the displayed SPS-EQ scheme is
//! class-unforgeable and DDH holds in `G_1`, `Σ-EQ` is a *strong* sigma-friendly credential
//! base for `Tag_DDH`; freshness of forgeries is modulo `∼`. In the words of its proof sketch,
//! "the signed, nonidentity base `M'_1` anchors a Schnorr proof of the invariant `usk`; the
//! public equation for `φ` binds the second invariant".
//!
//! # In formulas
//!
//! ```math
//! \begin{aligned}
//! M &= \bigl(g_1,\ g_1^{usk},\ g_1^{\varphi}\bigr), \qquad M \sim N \iff N = M^{r} \ \text{ for some } r \in \mathbb{Z}_p^{*} \\
//! \mathsf{Sign}(sk, M) &= (Z, Y, \tilde{Y}) = \Bigl( \bigl(\textstyle\prod_{i=1}^{3} M_i^{x_i}\bigr)^{y},\ g_1^{1/y},\ \tilde{g}^{1/y} \Bigr), \qquad y \leftarrow \mathbb{Z}_p^{*} \\
//! \mathsf{Verify}\bigl(vk, M, (Z, Y, \tilde{Y})\bigr) &= \Bigl[\, \textstyle\prod_{i=1}^{3} e(M_i, \tilde{X}_i) = e(Z, \tilde{Y}) \;\wedge\; e(Y, \tilde{g}) = e(g_1, \tilde{Y}) \,\Bigr]
//! \end{aligned}
//! ```
//!
//! (`Verify` also rejects $`M_i = 1`$, $`Y = 1`$ and $`\tilde{Y} = 1`$.) The show $`cred^{*} = (M', cred')`$ with
//! $`M' = M^{r}`$: the public checks include $`M'_3 = (M'_1)^{\varphi}`$, and the proved clause is
//!
//! ```math
//! M'_2 = (M'_1)^{usk}
//! ```
//!
//! # What binds what
//!
//! * **`usk`** is bound by the possession clause `M'_2 = (M'_1)^usk`, whose base is the SIGNED
//!   component `M'_1` of the shown vector, never a prover-chosen anchor (aireview note R1/R2
//!   after the box). The clause is only meaningful for a vector that carries a valid signature,
//!   so [`SigmaFriendlyCredentialBase::verify_possess_public`] runs the full SPS-EQ `Verify` on
//!   `(M', cred')`: two pairing products with 4 + 2 Miller loops.
//! * **`φ`** does not occur in the clause at all. It is bound by the public equation
//!   `M'_3 = (M'_1)^φ` alone: the relation `R_Possess` of a shown credential is literally the
//!   same for every `φ` (the unit tests show it), so a verifier that skipped the public checks
//!   would accept a credential for `φ` under any `φ'`.
//! * **Issuance needs `id = g_1^usk`**, i.e. `Tag_DDH` with the programmed point
//!   `htag(c_0) = g_1` (construction box, `Setup` step 4):
//!   [`SigmaFriendlyCredentialBase::REQUIRES_DLOG_IDENTITY`] is `true` and the PCS setup refuses
//!   `Tag_DY` ([`check_compatibility`](crate::pcs::check_compatibility)). The helper sets
//!   `C := id` (`VerifyProof` step 1, `Issue` step 3); the identifier clause of `R_issue` already
//!   proves knowledge of `usk` in `C = id`, so "the duplicate opening clause is omitted" (§5.1)
//!   and `issuance_clauses` adds no clause and no variable.
//!
//! # Implementation notes
//!
//! Additions to the box. None of them changes what an honest party computes.
//!
//! * **`Enc_Σ` and `Com` can fail.** `M_2 = g_1^usk` and `M_3 = g_1^φ` must not be the identity,
//!   so `usk = 0` or `φ = 0` is [`Error::InvalidMessage`] in
//!   [`CredentialBase::encode_message`] and [`CredentialBase::issuance_encoding`]. (`Tag_DDH`
//!   keys are non-zero; the PCS layer has to reject predicates with `EncPred(f) = 0`.)
//! * **`C = 1` is inadmissible.** `BlindIssue` returns [`Error::InvalidIssuanceEncoding`] for it
//!   (the box's `Sign` would output `⊥` on `M_2 = 1`), and
//!   [`SigmaFriendlyCredentialBase::encoding_from_wire`] returns `None` for `id = 1`, so that an
//!   issuance proof which verifies is one the helper can answer.
//! * **`Unblind` does not verify.** As in the box it returns `ĉred` unchanged (there is no
//!   blinding to remove). It refuses only what is malformed on its face, `Y = 1` or `Ỹ = 1`
//!   ([`Error::InvalidPreCredential`], no group operation), the convention of `Σ-PS` in this
//!   crate. Whether `ĉred` is a signature on the holder's message (the right `id`, the right
//!   `φ`, the right signer) is NOT checked there: that is `Verify(vk, Enc_Σ(usk, φ), cred)`,
//!   i.e. `VerifyCred` of the construction, one full `Verify` that the caller runs once and
//!   that presupposes a well formed `vk`. A credential that does not verify cannot be shown:
//!   `ReRand` step 1 refuses it.
//! * **Inversions** `1/y`, `1/ψ` go through `Field::inverse()` on values sampled from `Z_p^*`
//!   (field division by zero panics). The `None` branch is unreachable and maps to
//!   [`Error::DegenerateInput`].
//! * **Keys.** The box samples `x_i ← Z_p^*`, but [`EQSigningKey`] and [`EQVerificationKey`]
//!   decode with zero / identity components. With `X̃_2 = 1` the signature does not cover
//!   `M_2 = g_1^usk` (one credential can be shown under any key), with `X̃_3 = 1` it does not
//!   cover `φ`, and with `X̃_1 = 1` it certifies the ratio `usk / φ` only (a credential for
//!   `(usk, φ)` can be shown as one for `(usk · φ'/φ, φ')`). The unit tests mount all three. So:
//!   `KeyGen` uses `Z_p^*` as in the box; [`EQVerificationKey::is_well_formed`]
//!   (`X̃_1, X̃_2, X̃_3 ≠ 1`) is exactly the range of `KeyGen` and is what
//!   [`CredentialBase::is_well_formed_key`] returns;
//!   [`SigmaFriendlyCredentialBase::verify_possess_public`] rejects such a `vk` as a public
//!   check in the sense of Def. "Sigma-friendly credential base"; `sign` / `blind_issue` return
//!   [`Error::InvalidKey`] for a signing key with a zero component. `Verify` itself follows the
//!   box and does not look at the key. No check on `vk` can tell how the exponents were DRAWN:
//!   a key with `x_3 = x_1` or `x_2 = x_1` is well formed, is taken by every algorithm, and does
//!   not bind `φ` (a holder turns a show for `φ` into one for any `φ'`; the unit tests mount
//!   both). Such a key can only be prevented in `KeyGen`, whose three independent draws are
//!   therefore pinned by a test.
//! * **Redundant checks of the box are kept.** `M'_1 ≠ 1` in `Possess` step 1 is implied by
//!   `Verify` (which rejects every `M'_i = 1`), and given the second pairing equation `Y = 1`
//!   holds iff `Ỹ = 1`. Both are spelled out as in the box; they cost no group operation.
//! * **Sizes.** `|cred| = |(Z, Y, Ỹ)| = 48 + 48 + 96 = 192` B and `|cred*| = 144 + 192 = 336` B
//!   over BLS12-381 follow from the box. The paper's comparison table (§5.3) lists `|cred| = 336` B
//!   for `Σ-EQ`, which is `|cred*|` (or a stored `(M, σ)`), not the box's `cred`; the `|att|`
//!   and `|π|` columns (480 B, 2512 B at `k = 5`) do follow from the box. The box is normative
//!   here; the size test pins 192 B / 336 B / 480 B / 2512 B.
//!
//! # Example
//!
//! Direct issuance from the public identifier (Def. "Credential base", correctness), then a
//! show:
//!
//! ```
//! use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1};
//! use ark_ec::PrimeGroup;
//! use predicate_credential_system::cred::{CredentialBase, EQ, SigmaFriendlyCredentialBase};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type Base = EQ<Bls12_381>;
//! let mut rng = StdRng::seed_from_u64(1);
//! let pp = Base::setup(b"example deployment")?;
//! let (vk, sk) = Base::keygen(&pp, &mut rng);
//! let (usk, phi) = (Fr::from(11u64), Fr::from(22u64));
//!
//! // user: the issuance encoding is the public identifier id = g_1^usk; nothing travels in π
//! let id = Base::issuance_encoding(&pp, &vk, &usk, &phi, &())?;
//! assert_eq!(id, G1::generator() * usk);
//! // helper: C := id, BlindIssue(sk, C, φ) = Sign(sk, (g_1, id, g_1^φ)); it never sees usk
//! let c = Base::encoding_from_wire(&pp, &(), &id).expect("id is not the identity");
//! let pre = Base::blind_issue(&pp, &sk, &c, &phi, &mut rng)?;
//! // user: Unblind (nothing to remove, nothing verified), then VerifyCred = Verify on Enc(usk, φ)
//! let m = Base::encode_message(&pp, &usk, &phi)?;
//! let cred = Base::unblind(&pp, &vk, &m, &pre, &())?;
//! assert!(Base::verify(&pp, &vk, &m, &cred));
//!
//! // a show: another representative of the class with an adapted signature
//! let (shown, ()) = Base::rerand(&pp, &vk, &m, &cred, &mut rng)?;
//! assert_ne!(shown.message, m);
//! assert!(Base::verify_possess_public(&pp, &vk, &shown, &phi));
//! assert!(!Base::verify_possess_public(&pp, &vk, &shown, &(phi + phi)));
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

use core::{fmt, marker::PhantomData};

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    CredentialBase, SigmaFriendlyCredentialBase, ensure_allocated, pairing_product_is_identity,
};
use crate::{
    error::Error,
    sample::nonzero_scalar,
    sigma::{LinearEquation, PairingRelation, ScalarVar, Witness},
};

/// The `Σ-EQ` credential base over the pairing `E` (a marker type; all algorithms are
/// associated functions of [`CredentialBase`] and [`SigmaFriendlyCredentialBase`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EQ<E: Pairing>(PhantomData<E>);

/// The signing key `sk = (x_1, x_2, x_3) ∈ (Z_p^*)^3`. Secret: wiped on drop, not `Clone`,
/// redacted in `Debug`.
///
/// Decoding does not enforce `x_i ≠ 0`; [`CredentialBase::sign`] and
/// [`CredentialBase::blind_issue`] refuse such a key with [`Error::InvalidKey`].
#[derive(Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct EQSigningKey<E: Pairing> {
    x1: E::ScalarField,
    x2: E::ScalarField,
    x3: E::ScalarField,
}

impl<E: Pairing> EQSigningKey<E> {
    /// The verification key `vk = (X̃_1, X̃_2, X̃_3)`, `X̃_i = g̃^{x_i}`, of this signing key
    /// (`KeyGen` steps 1-2).
    #[must_use]
    pub fn verification_key(&self) -> EQVerificationKey<E> {
        let g2 = E::G2::generator();
        EQVerificationKey {
            x1_tilde: g2 * self.x1,
            x2_tilde: g2 * self.x2,
            x3_tilde: g2 * self.x3,
        }
    }

    /// Whether `sk ∈ (Z_p^*)^3`, the key space of the box.
    fn is_in_key_space(&self) -> bool {
        !self.x1.is_zero() && !self.x2.is_zero() && !self.x3.is_zero()
    }
}

impl<E: Pairing> fmt::Debug for EQSigningKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EQSigningKey(<redacted>)")
    }
}

/// The verification key `vk = (X̃_1, X̃_2, X̃_3)`, `X̃_i = g̃^{x_i}`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EQVerificationKey<E: Pairing> {
    /// `X̃_1`.
    pub x1_tilde: E::G2,
    /// `X̃_2`.
    pub x2_tilde: E::G2,
    /// `X̃_3`.
    pub x3_tilde: E::G2,
}

impl<E: Pairing> EQVerificationKey<E> {
    /// Whether the key lies in the range of `KeyGen`, i.e. `X̃_1, X̃_2, X̃_3 ≠ 1`. Exact in both
    /// directions: `g̃` generates a group of prime order `p`, so `X̃_i ≠ 1` iff `X̃_i = g̃^{x_i}`
    /// for some `x_i ∈ Z_p^*`. Costs no group operation; never panics.
    ///
    /// Implementation note, not an algorithm of the paper (module docs, "Implementation
    /// notes"): under a key with `X̃_i = 1` the signature does not cover `M_i`. This is also the
    /// key-side public check of the possession verifier.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.x1_tilde.is_zero() && !self.x2_tilde.is_zero() && !self.x3_tilde.is_zero()
    }
}

/// A message vector `M = (M_1, M_2, M_3) ∈ (G_1 \ {1})^3`, a representative of its class
/// `[M]_∼`; the construction signs the class of `(g_1, g_1^usk, g_1^φ)`.
///
/// Unlike the scalar messages of the other bases this vector is no secret (`M_2 = id` is the
/// public identifier). Implementation note: the canonical representative nevertheless
/// identifies its holder, so an attester never publishes it; what leaves the holder is a
/// representative `M'` chosen by `ReRand`.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, CanonicalSerialize, CanonicalDeserialize)]
pub struct EQMessage<E: Pairing> {
    /// `M_1` (`g_1` for the canonical representative).
    pub m1: E::G1,
    /// `M_2` (`g_1^usk = id`).
    pub m2: E::G1,
    /// `M_3` (`g_1^φ`).
    pub m3: E::G1,
}

impl<E: Pairing> EQMessage<E> {
    /// Whether `M ∈ (G_1 \ {1})^3`, the message space of the SPS-EQ scheme (box `Σ-EQ`: `Sign`
    /// step 1, `Verify` step 1). Decoding accepts the identity, so this is an explicit check.
    #[must_use]
    pub fn is_in_message_space(&self) -> bool {
        !self.m1.is_zero() && !self.m2.is_zero() && !self.m3.is_zero()
    }
}

/// A credential `cred = (Z, Y, Ỹ) ∈ G_1 × (G_1 \ {1}) × (G_2 \ {1})`: an SPS-EQ signature.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EQCredential<E: Pairing> {
    /// `Z = (∏ M_i^{x_i})^y`.
    pub z: E::G1,
    /// `Y = g_1^{1/y}`.
    pub y: E::G1,
    /// `Ỹ = g̃^{1/y}`.
    pub y_tilde: E::G2,
}

/// A pre-credential `ĉred = Sign(sk, (g_1, id, g_1^φ))`; `Unblind` returns it unchanged as a
/// credential.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EQPreCredential<E: Pairing> {
    /// `Z`.
    pub z: E::G1,
    /// `Y`.
    pub y: E::G1,
    /// `Ỹ`.
    pub y_tilde: E::G2,
}

impl<E: Pairing> From<EQCredential<E>> for EQPreCredential<E> {
    /// `BlindIssue` "invokes the same signing algorithm" (proof sketch of the Lemma on `Σ-EQ`).
    fn from(cred: EQCredential<E>) -> Self {
        Self {
            z: cred.z,
            y: cred.y,
            y_tilde: cred.y_tilde,
        }
    }
}

/// A shown credential `cred* = (M', cred')`: a fresh representative of the class together with
/// the signature adapted to it.
///
/// `Σ-EQ` is a *strong* base: `(M', cred')` is itself a message-signature pair of the SPS-EQ
/// scheme, for another representative of the same class.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EQShownCredential<E: Pairing> {
    /// `M' = (M_1^r, M_2^r, M_3^r)`.
    pub message: EQMessage<E>,
    /// `cred' = (Z^{rψ}, Y^{1/ψ}, Ỹ^{1/ψ})`.
    pub credential: EQCredential<E>,
}

/// `Enc_Σ` and `Com` are defined on `(usk, φ) ∈ Z_p^* × Z_p^*` only: `g_1^usk` and `g_1^φ` are
/// components of a vector of `(G_1 \ {1})^3`.
fn check_certified_pair<F: Field>(usk: &F, phi: &F) -> Result<(), Error> {
    if usk.is_zero() || phi.is_zero() {
        return Err(Error::InvalidMessage);
    }
    Ok(())
}

impl<E: Pairing> CredentialBase for EQ<E> {
    /// `pp_Σ` is empty: `g_1`, `g̃` are the standard generators of `E`.
    type PublicParams = ();
    type SigningKey = EQSigningKey<E>;
    type VerificationKey = EQVerificationKey<E>;
    /// `m_hid = usk`.
    type HiddenMessage = E::ScalarField;
    /// `m_pub = φ`.
    type PublicMessage = E::ScalarField;
    type Message = EQMessage<E>;
    /// `R_Σ = {∅}`.
    type IssuanceState = ();
    /// `C_Σ = G_1 ∋ C = g_1^usk = id`.
    type IssuanceEncoding = E::G1;
    type Credential = EQCredential<E>;
    type PreCredential = EQPreCredential<E>;
    type ShownCredential = EQShownCredential<E>;
    /// `ω = ∅`.
    type ShowState = ();

    fn setup(_domain: &[u8]) -> Result<Self::PublicParams, Error> {
        Ok(())
    }

    /// `KeyGen(pp)` (box `Σ-EQ`).
    fn keygen<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::VerificationKey, Self::SigningKey) {
        // 1. x_1, x_2, x_3 ← Z_p^*, X̃_i = g̃^{x_i}
        let sk = EQSigningKey {
            x1: nonzero_scalar(rng),
            x2: nonzero_scalar(rng),
            x3: nonzero_scalar(rng),
        };
        // 2. sk = (x_1, x_2, x_3), vk = (X̃_1, X̃_2, X̃_3)
        (sk.verification_key(), sk)
    }

    /// [`EQVerificationKey::is_well_formed`]: `X̃_1, X̃_2, X̃_3 ≠ 1`, the range of `KeyGen`, which
    /// samples `x_i ← Z_p^*`.
    fn is_well_formed_key(_pp: &Self::PublicParams, vk: &Self::VerificationKey) -> bool {
        vk.is_well_formed()
    }

    /// `Sign(sk, M)` (box `Σ-EQ`), for ANY representative `M ∈ (G_1 \ {1})^3`.
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] if some `M_i = 1` (the box's `⊥`). Implementation note:
    /// [`Error::InvalidKey`] for a (decoded) signing key with a zero component, which is
    /// outside the key space `(Z_p^*)^3` and would leave `M_i` unsigned.
    fn sign<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        m: &Self::Message,
        rng: &mut R,
    ) -> Result<Self::Credential, Error> {
        if !sk.is_in_key_space() {
            return Err(Error::InvalidKey);
        }
        // 1. parse M = (M_1, M_2, M_3); ⊥ if any M_i ∉ G_1 \ {1}
        if !m.is_in_message_space() {
            return Err(Error::InvalidMessage);
        }
        // 2. y ← Z_p^*; Z = (∏ M_i^{x_i})^y, Y = g_1^{1/y}, Ỹ = g̃^{1/y}
        let mut y: E::ScalarField = nonzero_scalar(rng);
        let mut y_inv = y
            .inverse()
            .ok_or(Error::DegenerateInput("signing randomizer y = 0"))?;
        let cred = EQCredential {
            z: (m.m1 * sk.x1 + m.m2 * sk.x2 + m.m3 * sk.x3) * y,
            y: E::G1::generator() * y_inv,
            y_tilde: E::G2::generator() * y_inv,
        };
        // (y, Z) reveals the unrandomized, homomorphic value ∏ M_i^{x_i}
        y.zeroize();
        y_inv.zeroize();
        // 3. cred = (Z, Y, Ỹ)
        Ok(cred)
    }

    /// `Verify(vk, M, (Z, Y, Ỹ))` (box `Σ-EQ`): step 1 rejects any `M_i = 1`, `Y = 1`, `Ỹ = 1`
    /// (malformed encodings are rejected by decoding); step 2 checks BOTH pairing equations,
    /// each as ONE pairing product: `∏ e(M_i, X̃_i) · e(Z^{-1}, Ỹ) = 1` (four Miller loops) and
    /// `e(Y, g̃) · e(g_1^{-1}, Ỹ) = 1` (two), with one final exponentiation each.
    ///
    /// Verification is per representative: a signature on `M` does not verify on `M^r`, `r ≠ 1`
    /// (it has to be adapted, as `ReRand` does). As in the box, `vk` is not inspected
    /// ([`EQVerificationKey::is_well_formed`]).
    fn verify(
        _pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
    ) -> bool {
        // 1. reject any M_i = 1, Y = 1, Ỹ = 1
        if !m.is_in_message_space() || cred.y.is_zero() || cred.y_tilde.is_zero() {
            return false;
        }
        // 2. [∏ e(M_i, X̃_i) = e(Z, Ỹ) ∧ e(Y, g̃) = e(g_1, Ỹ)]
        pairing_product_is_identity::<E>(&[
            (m.m1, vk.x1_tilde),
            (m.m2, vk.x2_tilde),
            (m.m3, vk.x3_tilde),
            (-cred.z, cred.y_tilde),
        ]) && pairing_product_is_identity::<E>(&[
            (cred.y, E::G2::generator()),
            (-E::G1::generator(), cred.y_tilde),
        ])
    }

    /// `Enc_Σ(usk, φ) = [(g_1, g_1^usk, g_1^φ)]_∼`, as its canonical representative (the one with
    /// `M_1 = g_1`).
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] for `usk = 0` or `φ = 0`: the vector would not lie in
    /// `(G_1 \ {1})^3`.
    fn encode_message(
        _pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
    ) -> Result<Self::Message, Error> {
        check_certified_pair(m_hid, m_pub)?;
        let g1 = E::G1::generator();
        Ok(EQMessage {
            m1: g1,
            m2: g1 * *m_hid,
            m3: g1 * *m_pub,
        })
    }

    /// `Com_vk(usk, φ; ∅) = g_1^usk = id`: the public identifier itself, independent of `vk` and
    /// of `φ`. It hides nothing: "`Σ-EQ` has no commitment because it issues directly from the
    /// public `id`" (§5.4, caption of the table of hypotheses).
    ///
    /// # Errors
    /// [`Error::InvalidMessage`] for `usk = 0` or `φ = 0`, exactly where `Enc_Σ` fails.
    fn issuance_encoding(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
        _r: &Self::IssuanceState,
    ) -> Result<Self::IssuanceEncoding, Error> {
        check_certified_pair(m_hid, m_pub)?;
        Ok(E::G1::generator() * *m_hid)
    }

    /// `ReRand(vk, M, cred)` (box `Σ-EQ`): the paper's "explicit output-pair wrapper around the
    /// source scheme's `ChgRep` algorithm".
    ///
    /// # Errors
    /// [`Error::InvalidCredential`] if `Verify(vk, M, cred) = 0` (the box's `⊥`).
    fn rerand<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
        rng: &mut R,
    ) -> Result<(Self::ShownCredential, Self::ShowState), Error> {
        // 1. ⊥ if Verify(vk, M, cred) = 0
        if !Self::verify(pp, vk, m, cred) {
            return Err(Error::InvalidCredential);
        }
        // 2. r, ψ ← Z_p^*; M' = (M_1^r, M_2^r, M_3^r), cred' = (Z^{rψ}, Y^{1/ψ}, Ỹ^{1/ψ})
        let mut r: E::ScalarField = nonzero_scalar(rng);
        let mut psi: E::ScalarField = nonzero_scalar(rng);
        let mut psi_inv = psi
            .inverse()
            .ok_or(Error::DegenerateInput("signature randomizer ψ = 0"))?;
        let shown = EQShownCredential {
            message: EQMessage {
                m1: m.m1 * r,
                m2: m.m2 * r,
                m3: m.m3 * r,
            },
            credential: EQCredential {
                z: cred.z * (r * psi),
                y: cred.y * psi_inv,
                y_tilde: cred.y_tilde * psi_inv,
            },
        };
        // r links M' to M (and M_2 = id), ψ links cred' to cred
        r.zeroize();
        psi.zeroize();
        psi_inv.zeroize();
        // 3. (cred* = (M', cred'), ω = ∅)
        Ok((shown, ()))
    }

    /// `BlindIssue(sk, C, φ)` (box `Σ-EQ`): native signing of `(g_1, C, g_1^φ)`, which "the
    /// helper constructs without learning `usk`" (proof sketch of the Lemma on `Σ-EQ`). The
    /// caller is responsible for `C = id` (`Issue` step 3).
    ///
    /// # Errors
    /// [`Error::InvalidIssuanceEncoding`] for `C = 1` and [`Error::InvalidMessage`] for `φ = 0`
    /// (in both cases the box's `Sign` outputs `⊥`); [`Error::InvalidKey`] as for
    /// [`CredentialBase::sign`].
    fn blind_issue<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        c: &Self::IssuanceEncoding,
        m_pub: &Self::PublicMessage,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error> {
        if c.is_zero() {
            return Err(Error::InvalidIssuanceEncoding);
        }
        // 1. M = (g_1, C, g_1^φ), where C = id = g_1^usk
        let g1 = E::G1::generator();
        let m = EQMessage {
            m1: g1,
            m2: *c,
            m3: g1 * *m_pub,
        };
        // 2. ĉred ← Sign(sk, M)
        Self::sign(pp, sk, &m, rng).map(EQPreCredential::from)
    }

    /// `Unblind(vk, M, ĉred, ∅) = ĉred` (box `Σ-EQ`). Deterministic; as in the box, the result
    /// is not verified here (the caller runs `Verify`, which is `VerifyCred` of the construction;
    /// `ReRand` refuses a credential that does not verify in any case).
    ///
    /// # Errors
    /// Implementation note: [`Error::InvalidPreCredential`] for `Y = 1` or `Ỹ = 1`, which an
    /// honest signer (`y ≠ 0`) never outputs and which `Verify` rejects on every message. This
    /// catches a malformed answer on its face only and costs no group operation.
    fn unblind(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        _m: &Self::Message,
        pre: &Self::PreCredential,
        _r: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error> {
        if pre.y.is_zero() || pre.y_tilde.is_zero() {
            return Err(Error::InvalidPreCredential);
        }
        // 1. return ĉred
        Ok(EQCredential {
            z: pre.z,
            y: pre.y,
            y_tilde: pre.y_tilde,
        })
    }
}

impl<E: Pairing> SigmaFriendlyCredentialBase<E> for EQ<E> {
    /// `m_aux = ∅`.
    type Aux = ();
    /// Nothing travels inside `π`: the verifier sets `C := id`.
    type WireEncoding = ();

    /// Issuance signs `(g_1, id, g_1^φ)`, which certifies `usk` only if `id = g_1^usk`.
    const REQUIRES_DLOG_IDENTITY: bool = true;
    /// The witness of `R_Possess` is `usk` alone.
    const POSSESSION_VARIABLES: usize = 0;
    /// No opening clause, no variable.
    const ISSUANCE_VARIABLES: usize = 0;

    fn hidden_message(usk: &E::ScalarField, _aux: &Self::Aux) -> Self::HiddenMessage {
        *usk
    }

    fn split_hidden_message(m_hid: &Self::HiddenMessage) -> (E::ScalarField, Self::Aux) {
        (*m_hid, ())
    }

    /// `(m_aux, ρ) = (∅, ∅)` (§5.1, the display before the protocol box). Uses no randomness.
    fn sample_issuance<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        _rng: &mut R,
    ) -> (Self::Aux, Self::IssuanceState) {
        ((), ())
    }

    /// Nothing: `π = ((att_j)_j, T_0, π_0)` for `Σ-EQ` (`Prove` step 12).
    fn encoding_to_wire(_c: &Self::IssuanceEncoding) -> Self::WireEncoding {}

    /// `C := id` (`VerifyProof` step 1, `Issue` step 3): "the verifier reconstructs it rather
    /// than parsing it from `π`" (§5.1).
    ///
    /// Implementation note: `None` for `id = 1`, which is not `g_1^usk` for any key and on which
    /// `BlindIssue` outputs `⊥`.
    fn encoding_from_wire(
        _pp: &Self::PublicParams,
        _wire: &Self::WireEncoding,
        id: &E::G1,
    ) -> Option<Self::IssuanceEncoding> {
        (!id.is_zero()).then_some(*id)
    }

    /// `Possess` step 1 (box `Σ-EQ`): "the verifier rejects if `M'_1 = 1`,
    /// `Verify(vk, M', cred') = 0`, or `M'_3 ≠ (M'_1)^φ`".
    ///
    /// * With `M' = (1, 1, 1)` and `Z' = 1` both pairing equations hold for any `Y', Ỹ'` with
    ///   `e(Y', g̃) = e(g_1, Ỹ')`, the equation for `φ` reads `1 = 1^φ`, and the clause below reads
    ///   `1 = 1^usk`: a credential-free attestation under every key and for every `φ`.
    /// * `Verify` is what makes `M'_1` a SIGNED base and `M'_2` a signed target; without it the
    ///   prover picks `M'_2 = (M'_1)^K` for a key `K` of its choice.
    /// * `Verify` means BOTH pairing equations (the aireview note R1/R2 after the box: "both
    ///   pairing equations displayed above"). Implementation note: under the first one alone,
    ///   `M' = (g_1, g_1^K, g_1^φ)` with `cred' = (M'_1, Y', X̃_1 X̃_2^K X̃_3^φ)` is a forgery from
    ///   `vk` alone, for every `φ`, every `Y' ≠ 1` and every `K` but the one with
    ///   `X̃_1 X̃_2^K X̃_3^φ = 1`; under the second one alone every vector is "signed" by
    ///   `(Z', g_1, g̃)`, for any `Z'`. A verifier that inlines or batches `Verify` must keep
    ///   both; the unit tests and the conformance flow mount both forgeries up to a complete
    ///   attestation.
    /// * The equation for `φ` is the only place where `φ` is bound: the clause does not depend
    ///   on it.
    ///
    /// Implementation note: a `vk` with some `X̃_i = 1` is rejected as well
    /// ([`EQVerificationKey::is_well_formed`]); under it `Verify` does not cover `M'_i`.
    fn verify_possess_public(
        pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        m_pub: &E::ScalarField,
    ) -> bool {
        let m = &shown.message;
        // key-side check (implementation note): X̃_1, X̃_2, X̃_3 ≠ 1
        vk.is_well_formed()
            // 1. reject if M'_1 = 1, ...
            && !m.m1.is_zero()
            // ... Verify(vk, M', cred') = 0 (which also rejects M'_2 = 1 and M'_3 = 1), ...
            && Self::verify(pp, vk, m, &shown.credential)
            // ... or M'_3 ≠ (M'_1)^φ
            && m.m3 == m.m1 * *m_pub
    }

    /// `Possess` step 2 (box `Σ-EQ`): the representation `M'_2 = (M'_1)^usk`, one `G_1` equation
    /// with base `M'_1` (taken from the shown, signed vector, never from the prover) and target
    /// `M'_2`. The witness is `usk` alone (`ω = ∅`), so no variable is allocated; `vk` and `φ`
    /// enter through the public checks only.
    fn possession_clauses(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        _m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        rel.add_g1(LinearEquation::dlog(
            usk,
            shown.message.m1,
            shown.message.m2,
        ))?;
        Ok(Vec::new())
    }

    fn possession_witness(
        _m_hid: &Self::HiddenMessage,
        _show_state: &Self::ShowState,
    ) -> Witness<E::ScalarField> {
        Witness::new()
    }

    /// No opening clause: the effective `C` is `id`, and "the duplicate opening clause is
    /// omitted" (§5.1) because the identifier clause `id = Tag(usk, c_0) = g_1^usk` of `R_issue`
    /// already proves knowledge of `usk` in `C`. Appends nothing and allocates nothing.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel` (the contract of the
    /// trait, although no equation refers to it here).
    fn issuance_clauses(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        _c: &Self::IssuanceEncoding,
        _m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        ensure_allocated(rel, usk)?;
        Ok(Vec::new())
    }

    fn issuance_witness(
        _m_hid: &Self::HiddenMessage,
        _r: &Self::IssuanceState,
    ) -> Witness<E::ScalarField> {
        Witness::new()
    }
}

/// TEST HELPER (crate tests and the cargo feature `test-utils`): the credential-free forgeries
/// of `Σ-EQ` for [`public_base_flow`](super::conformance::public_base_flow). For every entry the
/// possession clause `M'_2 = (M'_1)^K` holds under the forged key `K`, so only the public checks
/// of `VerifyPossess` reject it:
///
/// 1. attack W4-E1 of the reference implementations: `M' = (1, 1, 1)`, `Z' = 1` and
///    `(Y', Ỹ') = (g_1, g̃)`. Both pairing equations hold, `1 = 1^φ` holds, and the clause reads
///    `1 = 1^K`; only `M'_i ≠ 1` rejects it.
/// 2. the all-identity encoding (also `Y' = Ỹ' = 1`), which is what all-zero point encodings of
///    other libraries decode to.
/// 3. attack A4 without any credential: the never-signed vector `(g_1, g_1^K, g_1^φ)` with an
///    arbitrary `cred' = (g_1, g_1, g̃)`. `M'_1 ≠ 1`, the equation for `φ` and the second pairing
///    equation hold; only the first pairing equation of `Verify` rejects it.
/// 4. the forgery from `vk` ALONE against a verifier that enforces the first pairing equation
///    only: the same never-signed vector with `cred' = (Z', Y', Ỹ') = (M'_1, g_1, X̃_1 X̃_2^K X̃_3^φ)`.
///    Then `∏ e(M'_i, X̃_i) = e(g_1, X̃_1 X̃_2^K X̃_3^φ) = e(Z', Ỹ')`, every `M'_i ≠ 1`, `Y' ≠ 1`, and
///    the equation for `φ` holds, for EVERY `(K, φ)` and without any signature. Only the second
///    pairing equation `e(Y', g̃) = e(g_1, Ỹ')` rejects it: it asks for `Y' = g_1^t`,
///    `t = x_1 + K x_2 + φ x_3`, while the forger has `g̃^t ∈ G_2` only. (Two values of `t`, each
///    taken for exactly one `K ∈ Z_p` since `x_2 ≠ 0`, are special: for `t = 0` the check
///    `Ỹ' ≠ 1` rejects instead, and for `t = 1` this entry and entry 3 ARE signatures, the ones
///    with `y = 1`.)
#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn credential_free_forgeries<E: Pairing>(
    _pp: &(),
    vk: &EQVerificationKey<E>,
    phi: &E::ScalarField,
    forged_key: &E::ScalarField,
) -> Vec<super::conformance::Forgery<EQShownCredential<E>, E::ScalarField>> {
    let (g1, g2) = (E::G1::generator(), E::G2::generator());
    let (one, one_tilde) = (E::G1::zero(), E::G2::zero());
    let identity_vector = EQMessage {
        m1: one,
        m2: one,
        m3: one,
    };
    let never_signed = EQMessage {
        m1: g1,
        m2: g1 * *forged_key,
        m3: g1 * *phi,
    };
    let first_equation_only = vk.x1_tilde + vk.x2_tilde * *forged_key + vk.x3_tilde * *phi;
    [
        (identity_vector.clone(), (one, g1, g2)),
        (identity_vector, (one, one, one_tilde)),
        (never_signed.clone(), (g1, g1, g2)),
        (never_signed, (g1, g1, first_equation_only)),
    ]
    .into_iter()
    .map(|(message, (z, y, y_tilde))| super::conformance::Forgery {
        shown: EQShownCredential {
            message,
            credential: EQCredential { z, y, y_tilde },
        },
        extra_witness: Vec::new(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_bn254::Bn254;
    use ark_ff::{One, UniformRand};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        cred::{
            conformance::{FlowReport, public_base_flow},
            issuance_witness_vector, possess, possess_context, possession_relation,
            possession_witness_vector, verify_possess,
        },
        hash::{
            HashToGroup, Transcript, bls12_381::G1Hasher, h0_id, h0_identity_point, h0_predicate,
            testing::InsecureExponentHasher,
        },
        kiprf::{DDH, DY, KIPRF, PCSTag, SigmaFriendlyKIPRF},
        pcs::check_compatibility,
        serialization::WireFormat,
        sigma::{FSProof, LinearRelation, commit, extract, fiat_shamir, respond},
    };

    type E = Bls12_381;
    type G1 = G1Projective;
    type G2 = G2Projective;
    type Base = EQ<E>;
    type Tag = DDH<G1, G1Hasher>;

    const DOMAIN: &[u8] = b"sigma-eq-unit-tests";

    fn tag() -> Tag {
        Tag::setup(DOMAIN, h0_identity_point(DOMAIN)).unwrap()
    }

    fn phi(label: &[u8]) -> Fr {
        h0_predicate(DOMAIN, label)
    }

    /// `Enc_Σ(usk, φ) = (g_1, g_1^usk, g_1^φ)`.
    fn msg(usk: Fr, phi: Fr) -> EQMessage<E> {
        Base::encode_message(&(), &usk, &phi).unwrap()
    }

    /// The representative `M^r` of the class of `M`.
    fn scaled(m: &EQMessage<E>, r: Fr) -> EQMessage<E> {
        EQMessage {
            m1: m.m1 * r,
            m2: m.m2 * r,
            m3: m.m3 * r,
        }
    }

    fn exponents(sk: &EQSigningKey<E>) -> [Fr; 3] {
        [sk.x1, sk.x2, sk.x3]
    }

    /// The signing formula of the box WITHOUT any of its checks, written independently of the
    /// library code: the oracle for the exact algebra of `Sign` and `ReRand`, and the way a test
    /// obtains "signatures" the library refuses to produce (identity components, zero key
    /// components).
    fn raw_sign(x: [Fr; 3], m: &EQMessage<E>, y: Fr) -> EQCredential<E> {
        let y_inv = y.inverse().unwrap();
        EQCredential {
            z: (m.m1 * x[0] + m.m2 * x[1] + m.m3 * x[2]) * y,
            y: G1::generator() * y_inv,
            y_tilde: G2::generator() * y_inv,
        }
    }

    /// `∏ e(M_i, X̃_i) = e(Z, Ỹ)`, by single pairings (independent of the library's product).
    fn equation_1(vk: &EQVerificationKey<E>, m: &EQMessage<E>, cred: &EQCredential<E>) -> bool {
        E::pairing(m.m1, vk.x1_tilde)
            + E::pairing(m.m2, vk.x2_tilde)
            + E::pairing(m.m3, vk.x3_tilde)
            == E::pairing(cred.z, cred.y_tilde)
    }

    /// `e(Y, g̃) = e(g_1, Ỹ)`, by single pairings.
    fn equation_2(cred: &EQCredential<E>) -> bool {
        E::pairing(cred.y, G2::generator()) == E::pairing(G1::generator(), cred.y_tilde)
    }

    /// A signing key with chosen components, the way an attacker (or a corrupted key file)
    /// gets one: through the decoder, which accepts zero scalars.
    fn signing_key(x: [Fr; 3]) -> EQSigningKey<E> {
        let bytes = x
            .iter()
            .flat_map(|s| s.to_bytes().unwrap())
            .collect::<Vec<u8>>();
        EQSigningKey::from_bytes(&bytes).unwrap()
    }

    /// A holder `(usk, φ, cred)` with a directly signed credential.
    fn holder(
        tag: &Tag,
        sk: &EQSigningKey<E>,
        label: &[u8],
        rng: &mut StdRng,
    ) -> (Fr, Fr, EQCredential<E>) {
        let usk = tag.keygen(rng);
        let phi = phi(label);
        let cred = Base::sign(&(), sk, &msg(usk, phi), rng).unwrap();
        (usk, phi, cred)
    }

    // ----- a miniature of the attestation of §5.1: R_att = R_Possess ∧ R_Tag, shared usk ---------

    struct Att {
        t: G1,
        shown: EQShownCredential<E>,
        phi: Fr,
        pi: FSProof<Fr>,
    }

    /// `R_att` for the public statement `(vk, cred*, φ, T, s)`: the possession clause and the tag
    /// clause over ONE variable `usk`. The verifier builds it from the SHOWN vector.
    fn att_relation(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        shown: &EQShownCredential<E>,
        phi: &Fr,
        t: &G1,
        s: &Fr,
    ) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        let usk = rel.alloc_scalar();
        let extra = Base::possession_clauses(&(), vk, shown, phi, &mut rel, usk).unwrap();
        assert!(extra.is_empty());
        for eq in tag.tag_equations(usk, t, s) {
            rel.add_g1(eq).unwrap();
        }
        rel
    }

    /// `ctx_j = (pp, hvk, id, φ_j, T_j, cred*_j)`, as in `Attest` step 10.
    fn att_ctx(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        id: &G1,
        phi: &Fr,
        t: &G1,
        shown: &EQShownCredential<E>,
    ) -> Vec<u8> {
        let mut tr = Transcript::new(b"/TEST-CTX-ATT");
        tr.append_serializable(b"pp-tag", tag).unwrap();
        tr.append_serializable(b"hvk", vk).unwrap();
        tr.append_serializable(b"id", id).unwrap();
        tr.append_serializable(b"phi", phi).unwrap();
        tr.append_serializable(b"T", t).unwrap();
        tr.append_serializable(b"cred*", shown).unwrap();
        tr.digest().to_vec()
    }

    /// `Attest` steps 4-12 for a holder whose tag key is `tag_key` (honestly, `tag_key = usk`).
    fn attest(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        (usk, phi, cred): (&Fr, &Fr, &EQCredential<E>),
        tag_key: &Fr,
        id: &G1,
        rng: &mut StdRng,
    ) -> Result<Att, Error> {
        let s: Fr = h0_id(DOMAIN, id)?;
        let t = tag.eval(tag_key, &s).ok_or(Error::UndefinedTag)?;
        let (shown, omega) = Base::rerand(&(), vk, &msg(*usk, *phi), cred, rng)?;
        let rel = att_relation(tag, vk, &shown, phi, &t, &s);
        let w = possession_witness_vector::<E, Base>(usk, &omega);
        let pi = fiat_shamir::prove(&rel, &w, &att_ctx(tag, vk, id, phi, &t, &shown), rng)?;
        Ok(Att {
            t,
            shown,
            phi: *phi,
            pi,
        })
    }

    /// `VerifyAtt`: `ValidTag`, the public checks of `VerifyPossess`, then Fiat-Shamir.
    fn verify_att(tag: &Tag, vk: &EQVerificationKey<E>, id: &G1, att: &Att) -> bool {
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        tag.valid_tag(&att.t, &s)
            && Base::verify_possess_public(&(), vk, &att.shown, &att.phi)
            && fiat_shamir::verify(
                &att_relation(tag, vk, &att.shown, &att.phi, &att.t, &s),
                &att_ctx(tag, vk, id, &att.phi, &att.t, &att.shown),
                &att.pi,
            )
    }

    /// Everything of `VerifyAtt` EXCEPT the public checks of `VerifyPossess`: what a verifier
    /// that forgot them would accept.
    fn verify_att_without_public_checks(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        id: &G1,
        att: &Att,
    ) -> bool {
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        tag.valid_tag(&att.t, &s)
            && fiat_shamir::verify(
                &att_relation(tag, vk, &att.shown, &att.phi, &att.t, &s),
                &att_ctx(tag, vk, id, &att.phi, &att.t, &att.shown),
                &att.pi,
            )
    }

    /// A complete attestation by a forger that knows a witness `key` of the CLAUSES for the
    /// shown credential `shown` (it does not care about the public checks).
    fn forge_att(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        shown: EQShownCredential<E>,
        phi: Fr,
        key: &Fr,
        id: &G1,
        rng: &mut StdRng,
    ) -> Att {
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        let t = tag.eval(key, &s).unwrap();
        let rel = att_relation(tag, vk, &shown, &phi, &t, &s);
        assert!(rel.is_satisfied_by(&[*key]), "the forger's clauses hold");
        let ctx = att_ctx(tag, vk, id, &phi, &t, &shown);
        let pi = fiat_shamir::prove(&rel, &[*key], &ctx, rng).unwrap();
        let att = Att { t, shown, phi, pi };
        assert!(verify_att_without_public_checks(tag, vk, id, &att));
        att
    }

    // ----- SIG = (KeyGen, Sign, Verify) ----------------------------------------------------------

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(0xe901);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        assert_eq!(sk.verification_key(), vk);
        assert_eq!(vk.x1_tilde, G2::generator() * sk.x1);
        assert_eq!(vk.x2_tilde, G2::generator() * sk.x2);
        assert_eq!(vk.x3_tilde, G2::generator() * sk.x3);
        for _ in 0..4 {
            let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng));
            // the coins of Sign are y ← Z_p^*: the output is EXACTLY the box's formula
            let y: Fr = nonzero_scalar(&mut rng.clone());
            let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
            assert_eq!(cred, raw_sign(exponents(&sk), &m, y));
            assert!(!cred.y.is_zero() && !cred.y_tilde.is_zero());
            assert!(equation_1(&vk, &m, &cred) && equation_2(&cred));
            assert!(Base::verify(&(), &vk, &m, &cred));
        }
        // Sign takes ANY representative of ANY class, not only canonical ones
        let m = EQMessage::<E> {
            m1: G1::rand(&mut rng),
            m2: G1::rand(&mut rng),
            m3: G1::rand(&mut rng),
        };
        assert!(m.is_in_message_space());
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        assert!(Base::verify(&(), &vk, &m, &cred));
        // edge invariants of Z_p^* × Z_p^*
        for (usk, phi) in [
            (Fr::one(), Fr::one()),
            (-Fr::one(), Fr::one()),
            (Fr::one(), -Fr::one()),
        ] {
            let cred = Base::sign(&(), &sk, &msg(usk, phi), &mut rng).unwrap();
            assert!(Base::verify(&(), &vk, &msg(usk, phi), &cred));
        }
        // signing is randomized, in every component
        let m = msg(Fr::from(7u64), Fr::from(8u64));
        let (a, b) = (
            Base::sign(&(), &sk, &m, &mut rng).unwrap(),
            Base::sign(&(), &sk, &m, &mut rng).unwrap(),
        );
        assert!(a.z != b.z && a.y != b.y && a.y_tilde != b.y_tilde);
    }

    #[test]
    fn verification_rejects_wrong_message_and_wrong_key() {
        let mut rng = StdRng::seed_from_u64(0xe902);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        assert!(Base::verify(&(), &vk, &m, &cred));

        // another class: either invariant, swapped invariants, neighbours, a random class
        assert!(!Base::verify(&(), &vk, &msg(usk + Fr::one(), phi), &cred));
        assert!(!Base::verify(&(), &vk, &msg(usk, phi + Fr::one()), &cred));
        assert!(!Base::verify(&(), &vk, &msg(phi, usk), &cred));
        assert!(!Base::verify(
            &(),
            &vk,
            &msg(Fr::rand(&mut rng), Fr::rand(&mut rng)),
            &cred
        ));
        // each component of the vector is covered
        for i in 0..3 {
            let mut bad = m.clone();
            match i {
                0 => bad.m1 += G1::generator(),
                1 => bad.m2 += G1::generator(),
                _ => bad.m3 += G1::generator(),
            }
            assert!(!Base::verify(&(), &vk, &bad, &cred), "component {i}");
        }

        // Verification is per REPRESENTATIVE: on M^r the signature has to be adapted (Z^r) ...
        let r = Fr::rand(&mut rng);
        assert!(!Base::verify(&(), &vk, &scaled(&m, r), &cred));
        let adapted = EQCredential::<E> {
            z: cred.z * r,
            ..cred.clone()
        };
        assert!(Base::verify(&(), &vk, &scaled(&m, r), &adapted));
        // ... and the adapted signature no longer verifies on M
        assert!(!Base::verify(&(), &vk, &m, &adapted));

        // wrong key: an independent key, and the right key with one component replaced
        let (other_vk, _) = Base::keygen(&(), &mut rng);
        assert!(!Base::verify(&(), &other_vk, &m, &cred));
        for i in 0..3 {
            let mut bad = vk.clone();
            match i {
                0 => bad.x1_tilde = other_vk.x1_tilde,
                1 => bad.x2_tilde = other_vk.x2_tilde,
                _ => bad.x3_tilde = other_vk.x3_tilde,
            }
            assert!(!Base::verify(&(), &bad, &m, &cred), "key component {i}");
        }
    }

    /// Each of the two pairing equations is load-bearing: there are tamperings that ONLY the
    /// first one and tamperings that ONLY the second one catches.
    #[test]
    fn verification_rejects_tampered_signatures() {
        let mut rng = StdRng::seed_from_u64(0xe903);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng));
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        let (g, g_tilde) = (G1::generator(), G2::generator());
        let t = Fr::rand(&mut rng);
        let t_inv = t.inverse().unwrap();
        let (z, y, y_tilde) = (cred.z, cred.y, cred.y_tilde);

        // (tampered signature, first equation holds, second equation holds)
        let tampered = [
            ((z + g, y, y_tilde), false, true),
            ((z * t, y, y_tilde), false, true),
            ((-z, y, y_tilde), false, true),
            ((G1::zero(), y, y_tilde), false, true),
            ((y, z, y_tilde), false, false),
            ((z, y + g, y_tilde), true, false),
            ((z, y * t, y_tilde), true, false),
            ((z, -y, y_tilde), true, false),
            ((z, g, y_tilde), true, false),
            ((z, y, y_tilde + g_tilde), false, false),
            ((z, y, y_tilde * t), false, false),
            // a consistent pair (Y, Ỹ) = (g_1^{t/y}, g̃^{t/y}) without the matching Z
            ((z, y * t, y_tilde * t), false, true),
            (
                (G1::rand(&mut rng), G1::rand(&mut rng), G2::rand(&mut rng)),
                false,
                false,
            ),
        ];
        for (i, ((z, y, y_tilde), first, second)) in tampered.into_iter().enumerate() {
            let bad = EQCredential::<E> { z, y, y_tilde };
            assert_eq!(equation_1(&vk, &m, &bad), first, "tampering {i}");
            assert_eq!(equation_2(&bad), second, "tampering {i}");
            assert!(!Base::verify(&(), &vk, &m, &bad), "tampering {i}");
        }
        // control: (Z^t, Y^{1/t}, Ỹ^{1/t}) is the signature with randomizer y·t
        let adapted = EQCredential::<E> {
            z: z * t,
            y: y * t_inv,
            y_tilde: y_tilde * t_inv,
        };
        assert!(Base::verify(&(), &vk, &m, &adapted));
    }

    /// `Sign` step 1 and `Verify` step 1: every identity component of `M` is rejected, although
    /// BOTH pairing equations hold for the raw signature on such a vector.
    #[test]
    fn identity_message_components_are_rejected_although_the_equations_hold() {
        let mut rng = StdRng::seed_from_u64(0xe904);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let honest = msg(Fr::rand(&mut rng), Fr::rand(&mut rng));
        for i in 0..4 {
            let mut m = honest.clone();
            match i {
                0 => m.m1 = G1::zero(),
                1 => m.m2 = G1::zero(),
                2 => m.m3 = G1::zero(),
                _ => (m.m1, m.m2, m.m3) = (G1::zero(), G1::zero(), G1::zero()),
            }
            assert!(!m.is_in_message_space(), "case {i}");
            assert_eq!(
                Base::sign(&(), &sk, &m, &mut rng).unwrap_err(),
                Error::InvalidMessage,
                "case {i}"
            );
            // what Sign would have output
            let cred = raw_sign(exponents(&sk), &m, Fr::rand(&mut rng));
            assert!(equation_1(&vk, &m, &cred) && equation_2(&cred), "case {i}");
            assert!(!cred.y.is_zero() && !cred.y_tilde.is_zero());
            assert!(!Base::verify(&(), &vk, &m, &cred), "case {i}");
            // ... and nothing that USES a credential takes it either (Unblind is no such check:
            // it never looks at M and hands the signature on)
            assert_eq!(
                Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap_err(),
                Error::InvalidCredential,
                "case {i}"
            );
            assert_eq!(
                Base::unblind(&(), &vk, &m, &cred.clone().into(), &()),
                Ok(cred.clone()),
                "case {i}"
            );
            let shown = EQShownCredential::<E> {
                message: m,
                credential: cred,
            };
            assert!(
                !Base::verify_possess_public(&(), &vk, &shown, &Fr::one()),
                "case {i}"
            );
        }
    }

    /// `Verify` step 1: `Y = 1`, `Ỹ = 1`. For a vector in the kernel of the key
    /// (`∏ M_i^{x_i} = 1`; only the signer can compute one) the signature `(Z, 1, 1)` satisfies
    /// BOTH pairing equations for every `Z`.
    #[test]
    fn identity_signature_components_are_rejected_although_the_equations_hold() {
        let mut rng = StdRng::seed_from_u64(0xe905);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let c = -(a * sk.x1 + b * sk.x2) * sk.x3.inverse().unwrap();
        let g = G1::generator();
        let kernel = EQMessage::<E> {
            m1: g * a,
            m2: g * b,
            m3: g * c,
        };
        assert!(kernel.is_in_message_space());
        for z in [G1::zero(), G1::rand(&mut rng)] {
            let bad = EQCredential::<E> {
                z,
                y: G1::zero(),
                y_tilde: G2::zero(),
            };
            assert!(equation_1(&vk, &kernel, &bad) && equation_2(&bad));
            assert!(!Base::verify(&(), &vk, &kernel, &bad));
            assert_eq!(
                Base::rerand(&(), &vk, &kernel, &bad, &mut rng).unwrap_err(),
                Error::InvalidCredential
            );
        }
        // one of the two alone (then the second equation fails as well)
        let cred = Base::sign(&(), &sk, &kernel, &mut rng).unwrap();
        assert!(Base::verify(&(), &vk, &kernel, &cred));
        let no_y = EQCredential::<E> {
            y: G1::zero(),
            ..cred.clone()
        };
        let no_y_tilde = EQCredential::<E> {
            y_tilde: G2::zero(),
            ..cred.clone()
        };
        assert!(!Base::verify(&(), &vk, &kernel, &no_y));
        assert!(!Base::verify(&(), &vk, &kernel, &no_y_tilde));
    }

    // ----- Enc, Com and direct issuance ----------------------------------------------------------

    #[test]
    fn message_map_and_issuance_encoding() {
        let mut rng = StdRng::seed_from_u64(0xe906);
        let (vk, _sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let g = G1::generator();
        // Enc(usk, φ) = (g_1, g_1^usk, g_1^φ), Com(usk, φ; ∅) = g_1^usk = id = M_2
        let m = Base::encode_message(&(), &usk, &phi).unwrap();
        assert_eq!((m.m1, m.m2, m.m3), (g, g * usk, g * phi));
        let c = Base::issuance_encoding(&(), &vk, &usk, &phi, &()).unwrap();
        assert_eq!(c, g * usk);
        assert_eq!(c, m.m2);
        // ... which is the identifier of Tag_DDH with the programmed point
        let tag = tag();
        assert_eq!(tag.eval(&usk, &h0_identity_point(DOMAIN)).unwrap(), c);

        // usk = 0 or φ = 0 has no encoding: the vector would leave (G_1 \ {1})^3
        let zero = Fr::zero();
        for (usk, phi) in [(zero, phi), (usk, zero), (zero, zero)] {
            assert_eq!(
                Base::encode_message(&(), &usk, &phi).unwrap_err(),
                Error::InvalidMessage
            );
            assert_eq!(
                Base::issuance_encoding(&(), &vk, &usk, &phi, &()).unwrap_err(),
                Error::InvalidMessage
            );
        }

        // m_hid = usk, m_aux = ∅, ρ = ∅; sampling them uses no randomness
        let before = rng.clone();
        let ((), ()) = Base::sample_issuance(&(), &mut rng);
        assert_eq!(Fr::rand(&mut rng), Fr::rand(&mut before.clone()));
        let m_hid = Base::hidden_message(&usk, &());
        assert_eq!(m_hid, usk);
        assert_eq!(Base::split_hidden_message(&m_hid), (usk, ()));
        assert!(Base::possession_witness(&m_hid, &()).is_empty());
        assert!(Base::issuance_witness(&m_hid, &()).is_empty());
        assert_eq!(&*possession_witness_vector::<E, Base>(&m_hid, &()), [usk]);
        assert_eq!(&*issuance_witness_vector::<E, Base>(&m_hid, &()), [usk]);
    }

    /// Def. "Credential base", correctness, for direct issuance: the helper sees `(id, φ)` only,
    /// and `Unblind(BlindIssue(sk, id, φ))` verifies as a signature on `Enc_Σ(usk, φ)`.
    #[test]
    fn blind_issuance_signs_the_vector_built_from_the_public_identifier() {
        let mut rng = StdRng::seed_from_u64(0xe907);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        for _ in 0..3 {
            let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let id = Base::issuance_encoding(&(), &vk, &usk, &phi, &()).unwrap();
            // nothing travels; the helper reconstructs C := id
            let () = Base::encoding_to_wire(&id);
            let c_helper = Base::encoding_from_wire(&(), &(), &id).unwrap();
            assert_eq!(c_helper, id);

            let y: Fr = nonzero_scalar(&mut rng.clone());
            let pre = Base::blind_issue(&(), &sk, &c_helper, &phi, &mut rng).unwrap();
            let m = msg(usk, phi);
            // BlindIssue IS Sign on (g_1, id, g_1^φ) = Enc(usk, φ)
            assert_eq!(pre, raw_sign(exponents(&sk), &m, y).into());
            let cred = Base::unblind(&(), &vk, &m, &pre, &()).unwrap();
            assert_eq!((cred.z, cred.y, cred.y_tilde), (pre.z, pre.y, pre.y_tilde));
            assert!(Base::verify(&(), &vk, &m, &cred));
            // it certifies (usk, φ) and nothing nearby
            assert!(!Base::verify(&(), &vk, &msg(usk, phi + phi), &cred));
            assert!(!Base::verify(&(), &vk, &msg(usk + Fr::one(), phi), &cred));
        }
    }

    #[test]
    fn blind_issuance_rejects_inadmissible_input() {
        let mut rng = StdRng::seed_from_u64(0xe908);
        let (_vk, sk) = Base::keygen(&(), &mut rng);
        let (id, phi) = (G1::generator() * Fr::rand(&mut rng), Fr::rand(&mut rng));
        // C = 1: no identifier, the signed vector would have M_2 = 1
        assert_eq!(Base::encoding_from_wire(&(), &(), &G1::zero()), None);
        assert_eq!(
            Base::blind_issue(&(), &sk, &G1::zero(), &phi, &mut rng).unwrap_err(),
            Error::InvalidIssuanceEncoding
        );
        // φ = 0: M_3 = 1
        assert_eq!(
            Base::blind_issue(&(), &sk, &id, &Fr::zero(), &mut rng).unwrap_err(),
            Error::InvalidMessage
        );
        assert!(Base::blind_issue(&(), &sk, &id, &phi, &mut rng).is_ok());
    }

    /// `Unblind` returns `ĉred` as it is, as in the box. Implementation note: it refuses `Y = 1`
    /// and `Ỹ = 1` (each of them alone) and NOTHING else. A pre-credential that is not a
    /// signature on the holder's message passes `Unblind`; it is `Verify` (`VerifyCred` of the
    /// construction) that tells, and `ReRand` that refuses to show it.
    #[test]
    fn unblind_returns_the_pre_credential_and_checks_its_face_only() {
        let mut rng = StdRng::seed_from_u64(0xe909);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let (id, m) = (G1::generator() * usk, msg(usk, phi));
        let pre = Base::blind_issue(&(), &sk, &id, &phi, &mut rng).unwrap();
        let cred = Base::unblind(&(), &vk, &m, &pre, &()).unwrap();
        assert_eq!((cred.z, cred.y, cred.y_tilde), (pre.z, pre.y, pre.y_tilde));
        assert!(Base::verify(&(), &vk, &m, &cred));

        // NOT a signature on the holder's message: issued for another identifier, under another
        // φ, by another signer, tampered, or with Z = 1 (a legal value of Z ∈ G_1)
        let other_id = Base::blind_issue(&(), &sk, &(id + id), &phi, &mut rng).unwrap();
        let other_phi = Base::blind_issue(&(), &sk, &id, &(phi + phi), &mut rng).unwrap();
        let (_, other_sk) = Base::keygen(&(), &mut rng);
        let other_signer = Base::blind_issue(&(), &other_sk, &id, &phi, &mut rng).unwrap();
        let tampered = EQPreCredential::<E> {
            z: pre.z + G1::generator(),
            ..pre.clone()
        };
        let no_z = EQPreCredential::<E> {
            z: G1::zero(),
            ..pre.clone()
        };
        for (i, wrong) in [other_id, other_phi, other_signer, tampered, no_z]
            .into_iter()
            .enumerate()
        {
            let cred = Base::unblind(&(), &vk, &m, &wrong, &()).unwrap();
            assert_eq!(wrong, cred.clone().into(), "case {i}: handed on unchanged");
            assert!(!Base::verify(&(), &vk, &m, &cred), "case {i}");
            assert_eq!(
                Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap_err(),
                Error::InvalidCredential,
                "case {i}"
            );
        }
        // the holder's message is not the one that was signed: Unblind does not look at M
        let not_signed = msg(usk + Fr::one(), phi);
        let cred = Base::unblind(&(), &vk, &not_signed, &pre, &()).unwrap();
        assert!(!Base::verify(&(), &vk, &not_signed, &cred));

        // malformed on its face: Y = 1, Ỹ = 1, both
        for (y, y_tilde) in [
            (G1::zero(), pre.y_tilde),
            (pre.y, G2::zero()),
            (G1::zero(), G2::zero()),
        ] {
            let degenerate = EQPreCredential::<E> {
                z: pre.z,
                y,
                y_tilde,
            };
            assert_eq!(
                Base::unblind(&(), &vk, &m, &degenerate, &()),
                Err(Error::InvalidPreCredential)
            );
        }
    }

    // ----- ReRand (ChgRep) -----------------------------------------------------------------------

    /// `ReRand` is the box's formula for the coins `r, ψ ← Z_p^*`; its output is the signature
    /// on the new representative "with effective signing randomizer `yψ`" (proof sketch of the
    /// Lemma on `Σ-EQ`), verifies, passes the public checks, and differs from the input in EVERY
    /// group element.
    #[test]
    fn rerand_changes_the_representative_and_adapts_the_signature() {
        let mut rng = StdRng::seed_from_u64(0xe90a);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let y: Fr = nonzero_scalar(&mut rng.clone());
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();

        let mut coins = rng.clone();
        let (r, psi): (Fr, Fr) = (nonzero_scalar(&mut coins), nonzero_scalar(&mut coins));
        let (shown, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        let psi_inv = psi.inverse().unwrap();
        assert_eq!(shown.message, scaled(&m, r));
        assert_eq!(
            shown.credential,
            EQCredential {
                z: cred.z * (r * psi),
                y: cred.y * psi_inv,
                y_tilde: cred.y_tilde * psi_inv,
            }
        );
        assert_eq!(
            shown.credential,
            raw_sign(exponents(&sk), &shown.message, y * psi)
        );

        // (M', cred') is a message-signature pair for another representative of the SAME class
        assert!(Base::verify(&(), &vk, &shown.message, &shown.credential));
        assert!(Base::verify_possess_public(&(), &vk, &shown, &phi));
        assert!(!shown.message.m1.is_zero());
        assert_eq!(shown.message.m2, shown.message.m1 * usk);
        assert_eq!(shown.message.m3, shown.message.m1 * phi);
        // every element changed
        assert!(shown.message.m1 != m.m1 && shown.message.m2 != m.m2 && shown.message.m3 != m.m3);
        assert_ne!(shown.credential.z, cred.z);
        assert_ne!(shown.credential.y, cred.y);
        assert_ne!(shown.credential.y_tilde, cred.y_tilde);
        // the pairs do not mix
        assert!(!Base::verify(&(), &vk, &m, &shown.credential));
        assert!(!Base::verify(&(), &vk, &shown.message, &cred));

        // a shown pair can be re-randomized again (strong base)
        let (again, ()) =
            Base::rerand(&(), &vk, &shown.message, &shown.credential, &mut rng).unwrap();
        assert!(Base::verify_possess_public(&(), &vk, &again, &phi));
        assert_eq!(again.message.m2, again.message.m1 * usk);
    }

    /// `ReRand` step 1: `⊥` unless `Verify(vk, M, cred) = 1`.
    #[test]
    fn rerand_refuses_a_credential_that_does_not_verify() {
        let mut rng = StdRng::seed_from_u64(0xe90b);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        assert!(Base::rerand(&(), &vk, &m, &cred, &mut rng).is_ok());

        let invalid = Error::InvalidCredential;
        let (other_vk, _) = Base::keygen(&(), &mut rng);
        let tampered = EQCredential::<E> {
            z: cred.z + G1::generator(),
            ..cred.clone()
        };
        let inconsistent = EQCredential::<E> {
            y: cred.y + G1::generator(),
            ..cred.clone()
        };
        for (i, (vk, m, cred)) in [
            (&vk, &msg(usk + Fr::one(), phi), &cred),
            (&vk, &msg(usk, phi + Fr::one()), &cred),
            (&vk, &scaled(&m, Fr::from(2u64)), &cred),
            (&other_vk, &m, &cred),
            (&vk, &m, &tampered),
            (&vk, &m, &inconsistent),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                Base::rerand(&(), vk, m, cred, &mut rng).unwrap_err(),
                invalid,
                "case {i}"
            );
        }
    }

    /// Class-hiding SANITY check: two shows of one credential share no group element, with each
    /// other or with the stored credential and its canonical vector. (That the shows are
    /// unlinkable is the Lemma's argument, perfect adaptation plus class hiding under DDH; a
    /// test cannot show it.)
    #[test]
    fn two_shows_of_one_credential_share_no_group_element() {
        let mut rng = StdRng::seed_from_u64(0xe90c);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        let (a, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        let (b, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();

        let g1_elements = |s: &EQShownCredential<E>| {
            [
                s.message.m1,
                s.message.m2,
                s.message.m3,
                s.credential.z,
                s.credential.y,
            ]
        };
        let stored = [m.m1, m.m2, m.m3, cred.z, cred.y];
        for x in g1_elements(&a) {
            assert!(!g1_elements(&b).contains(&x));
            assert!(!stored.contains(&x));
        }
        for x in g1_elements(&b) {
            assert!(!stored.contains(&x));
        }
        assert_ne!(a.credential.y_tilde, b.credential.y_tilde);
        assert_ne!(a.credential.y_tilde, cred.y_tilde);
        assert_ne!(b.credential.y_tilde, cred.y_tilde);
        // both are shows of the same class all the same
        for s in [&a, &b] {
            assert!(Base::verify_possess_public(&(), &vk, s, &phi));
            assert_eq!(s.message.m2, s.message.m1 * usk);
        }
    }

    // ----- Possess: R_Possess ∧ R_Tag with a shared usk ------------------------------------------

    #[test]
    fn possession_with_tag_clause_is_complete() {
        let mut rng = StdRng::seed_from_u64(0xe90d);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);

        let att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));
        // one witness coordinate, one response
        assert_eq!(att.pi.responses.len(), 1);
        assert_eq!(att.t, tag.eval(&usk, &h0_id(DOMAIN, &id).unwrap()).unwrap());

        // a credential obtained through direct issuance from id = g_1^usk attests just the same
        let own_id = tag.eval(&usk, &h0_identity_point(DOMAIN)).unwrap();
        let pre = Base::blind_issue(&(), &sk, &own_id, &phi, &mut rng).unwrap();
        let issued = Base::unblind(&(), &vk, &msg(usk, phi), &pre, &()).unwrap();
        let att = attest(&tag, &vk, (&usk, &phi, &issued), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));

        // two attestations by the same holder for the same id: same tag, unrelated cred*
        let again = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert_eq!(again.t, att.t);
        assert_ne!(again.shown, att.shown);
    }

    /// The tag must be under the credential's `usk`: the two clauses share ONE variable, so no
    /// witness exists for a tag under another key, and the honest prover refuses.
    #[test]
    fn tag_under_a_different_key_cannot_be_proven() {
        let mut rng = StdRng::seed_from_u64(0xe90e);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let other_key = tag.keygen(&mut rng);

        // honest prover code, dishonest tag key
        assert_eq!(
            attest(&tag, &vk, (&usk, &phi, &cred), &other_key, &id, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );
        // a holder that claims the other key as its usk does not get past ReRand
        assert_eq!(
            attest(
                &tag,
                &vk,
                (&other_key, &phi, &cred),
                &other_key,
                &id,
                &mut rng
            )
            .err(),
            Some(Error::InvalidCredential)
        );

        // a verifying attestation does not survive swapping in the other key's tag
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let mut att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));
        att.t = tag.eval(&other_key, &s).unwrap();
        assert!(!verify_att(&tag, &vk, &id, &att));
    }

    /// Attack A3 of the reference implementations: ONE credential, re-randomized `k` times and
    /// shown next to tags under `k` fresh keys (which would defeat the threshold). It fails
    /// because `M'_2 = (M'_1)^usk` is proven against the SIGNED base `M'_1`: a proof against an
    /// anchor of the prover's choice exists, but it is not a proof of the verifier's statement.
    #[test]
    fn attack_a3_one_credential_under_several_fresh_tag_keys() {
        let mut rng = StdRng::seed_from_u64(0xe90f);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();

        let mut accepted = 0;
        let mut tags = Vec::new();
        for _ in 0..5 {
            let fresh = tag.keygen(&mut rng);
            assert_ne!(fresh, usk);
            let t = tag.eval(&fresh, &s).unwrap();
            let (shown, ()) = Base::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
            let rel = att_relation(&tag, &vk, &shown, &phi, &t, &s);
            let ctx = att_ctx(&tag, &vk, &id, &phi, &t, &shown);

            // no witness: usk fails the tag clause, the fresh key fails the possession clause
            assert!(!rel.is_satisfied_by(&[usk]));
            assert!(!rel.is_satisfied_by(&[fresh]));
            for w in [usk, fresh] {
                assert_eq!(
                    fiat_shamir::prove(&rel, &[w], &ctx, &mut rng),
                    Err(Error::WitnessDoesNotSatisfyRelation)
                );
            }

            // the forger's statement: M'_2 = B^fresh for an anchor B it picks itself
            let anchor = shown.message.m2 * fresh.inverse().unwrap();
            let mut rel_anchor = PairingRelation::<E>::new();
            let var = rel_anchor.alloc_scalar();
            rel_anchor
                .add_g1(LinearEquation::dlog(var, anchor, shown.message.m2))
                .unwrap();
            for eq in tag.tag_equations(var, &t, &s) {
                rel_anchor.add_g1(eq).unwrap();
            }
            let pi = fiat_shamir::prove(&rel_anchor, &[fresh], &ctx, &mut rng).unwrap();
            assert!(fiat_shamir::verify(&rel_anchor, &ctx, &pi));

            // everything public about this attestation is honest ...
            assert!(tag.valid_tag(&t, &s));
            assert!(Base::verify_possess_public(&(), &vk, &shown, &phi));
            // ... and it is rejected, because the verifier states the clause itself
            let att = Att { t, shown, phi, pi };
            if verify_att(&tag, &vk, &id, &att) {
                accepted += 1;
            }
            tags.push(t);
        }
        assert_eq!(accepted, 0, "attestations under keys without a credential");
        for i in 0..tags.len() {
            for j in i + 1..tags.len() {
                assert_ne!(tags[i], tags[j]);
            }
        }
        // control: under its own key the credential attests
        let att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));
    }

    /// Attack A4 of the reference implementations: the key vector
    /// `M_B = (M'_1, (M'_1)^{usk_B}, M'_3)` for a never-signed key `usk_B`, next to A's adapted
    /// signature. The forger's clauses hold and its Fiat-Shamir proof verifies; the first pairing
    /// equation of `Verify` (run inside the public checks) rejects every trial.
    #[test]
    fn attack_a4_forged_key_vector_on_an_adapted_signature() {
        const TRIALS: usize = 100;
        let mut rng = StdRng::seed_from_u64(0xe910);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk_a, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);

        let mut forged = 0;
        for trial in 0..TRIALS {
            let usk_b = tag.keygen(&mut rng);
            assert_ne!(usk_b, usk_a);
            let (shown, ()) = Base::rerand(&(), &vk, &msg(usk_a, phi), &cred, &mut rng).unwrap();
            let forgery = EQShownCredential::<E> {
                message: EQMessage {
                    m1: shown.message.m1,
                    m2: shown.message.m1 * usk_b,
                    m3: shown.message.m3,
                },
                credential: shown.credential.clone(),
            };
            // what the forger gets right ...
            assert!(forgery.message.is_in_message_space());
            assert_eq!(forgery.message.m3, forgery.message.m1 * phi);
            assert!(equation_2(&forgery.credential));
            // ... and what it cannot
            assert!(!equation_1(&vk, &forgery.message, &forgery.credential));
            if Base::verify(&(), &vk, &forgery.message, &forgery.credential)
                || Base::verify_possess_public(&(), &vk, &forgery, &phi)
            {
                forged += 1;
            }
            // as a stored credential ("VerifyCred") on the canonical vector of usk_B
            if Base::verify(&(), &vk, &msg(usk_b, phi), &cred) {
                forged += 1;
            }
            // a few trials go all the way to an attestation
            if trial < 3 {
                let att = forge_att(&tag, &vk, forgery, phi, &usk_b, &id, &mut rng);
                if verify_att(&tag, &vk, &id, &att) {
                    forged += 1;
                }
            }
        }
        assert_eq!(forged, 0, "credentials on never-signed keys");
    }

    /// Attack W4-E1 of the reference implementations: `M' = (1, 1, 1)`, `Z' = 1`. Both pairing
    /// equations hold, the equation for `φ` holds, the clause reads `1 = 1^usk`, so a party
    /// WITHOUT any credential produces a complete attestation whose Fiat-Shamir proof verifies.
    /// Only the identity checks stop it.
    #[test]
    fn attack_w4_e1_credential_free_identity_vector() {
        let mut rng = StdRng::seed_from_u64(0xe911);
        let tag = tag();
        let (vk, _sk) = Base::keygen(&(), &mut rng);
        let phi = phi(b"f");
        let id = G1::generator() * tag.keygen(&mut rng);
        let forged_key = tag.keygen(&mut rng); // no credential exists for this key

        for (y, y_tilde) in [
            (G1::generator(), G2::generator()),
            (G1::generator() * phi, G2::generator() * phi),
            (G1::zero(), G2::zero()),
        ] {
            let shown = EQShownCredential::<E> {
                message: EQMessage {
                    m1: G1::zero(),
                    m2: G1::zero(),
                    m3: G1::zero(),
                },
                credential: EQCredential {
                    z: G1::zero(),
                    y,
                    y_tilde,
                },
            };
            // the pairing equations and the equation for φ hold ...
            assert!(equation_1(&vk, &shown.message, &shown.credential));
            assert!(equation_2(&shown.credential));
            assert_eq!(shown.message.m3, shown.message.m1 * phi);
            // ... the clauses hold, the bare proof verifies, the tag is valid ...
            let att = forge_att(&tag, &vk, shown.clone(), phi, &forged_key, &id, &mut rng);
            // ... and the attestation is rejected, by the identity checks alone
            assert!(!Base::verify(&(), &vk, &shown.message, &shown.credential));
            assert!(!Base::verify_possess_public(&(), &vk, &shown, &phi));
            assert!(!verify_att(&tag, &vk, &id, &att));
            // the decoder does not help: the forgery travels on the wire
            let back = EQShownCredential::<E>::from_bytes(&shown.to_bytes().unwrap()).unwrap();
            assert_eq!(back, shown);
        }
    }

    /// `φ` is bound by the PUBLIC equation `M'_3 = (M'_1)^φ` and by nothing else: the relation
    /// of a shown credential does not depend on `φ`.
    #[test]
    fn shown_credential_for_phi_fails_the_public_check_for_another_phi() {
        let mut rng = StdRng::seed_from_u64(0xe912);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let other_phi = self::phi(b"f'");
        assert_ne!(other_phi, phi);
        let id = G1::generator() * tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let mut att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));

        // (1) the public check
        assert!(Base::verify_possess_public(&(), &vk, &att.shown, &phi));
        assert!(!Base::verify_possess_public(
            &(),
            &vk,
            &att.shown,
            &other_phi
        ));
        for wrong in [phi + Fr::one(), -phi, Fr::zero(), Fr::one()] {
            assert!(!Base::verify_possess_public(&(), &vk, &att.shown, &wrong));
        }
        // (2) ... is the ONLY thing that binds φ: same relation, and under the same context
        // bytes the same proof verifies for the other φ
        let rel = att_relation(&tag, &vk, &att.shown, &phi, &att.t, &s);
        let rel_other = att_relation(&tag, &vk, &att.shown, &other_phi, &att.t, &s);
        assert_eq!(rel, rel_other);
        let ctx = att_ctx(&tag, &vk, &id, &phi, &att.t, &att.shown);
        assert!(fiat_shamir::verify(&rel_other, &ctx, &att.pi));
        // (3) attestation level: relabelling a finished attestation, and claiming the other φ
        // from the start (then the context is the forger's too, and only the public check
        // rejects)
        let claimed = forge_att(&tag, &vk, att.shown.clone(), other_phi, &usk, &id, &mut rng);
        assert!(!verify_att(&tag, &vk, &id, &claimed));
        att.phi = other_phi;
        assert!(!verify_att(&tag, &vk, &id, &att));
        // (4) rewriting M'_3 to match the other φ breaks the signature instead
        let mut rewritten = att.shown.clone();
        rewritten.message.m3 = rewritten.message.m1 * other_phi;
        assert_eq!(rewritten.message.m3, rewritten.message.m1 * other_phi);
        assert!(!Base::verify(
            &(),
            &vk,
            &rewritten.message,
            &rewritten.credential
        ));
        assert!(!Base::verify_possess_public(
            &(),
            &vk,
            &rewritten,
            &other_phi
        ));
        let forged = forge_att(&tag, &vk, rewritten, other_phi, &usk, &id, &mut rng);
        assert!(!verify_att(&tag, &vk, &id, &forged));
        // (5) the honest prover cannot claim another φ for its credential either
        assert_eq!(
            attest(&tag, &vk, (&usk, &other_phi, &cred), &usk, &id, &mut rng).err(),
            Some(Error::InvalidCredential)
        );
    }

    #[test]
    fn attestation_is_bound_to_identifier_key_and_shown_credential() {
        let mut rng = StdRng::seed_from_u64(0xe913);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));

        // another identifier (non-transferability), another helper key
        assert!(!verify_att(&tag, &vk, &(id + G1::generator()), &att));
        let (other_vk, _) = Base::keygen(&(), &mut rng);
        assert!(!verify_att(&tag, &other_vk, &id, &att));

        // re-randomizing cred* inside a finished attestation: the new pair passes the public
        // checks and satisfies the clauses, but the statement is hashed
        let (mauled_shown, ()) = Base::rerand(
            &(),
            &vk,
            &att.shown.message,
            &att.shown.credential,
            &mut rng,
        )
        .unwrap();
        assert!(Base::verify_possess_public(&(), &vk, &mauled_shown, &phi));
        let mauled = Att {
            shown: mauled_shown,
            t: att.t,
            phi: att.phi,
            pi: att.pi.clone(),
        };
        assert!(!verify_att(&tag, &vk, &id, &mauled));

        // identity tag, mauled proof, malformed proof
        let bad = Att {
            t: G1::zero(),
            shown: att.shown.clone(),
            phi: att.phi,
            pi: att.pi.clone(),
        };
        assert!(!verify_att(&tag, &vk, &id, &bad));
        let mut bad_pi = att.pi.clone();
        bad_pi.responses[0] += Fr::one();
        let bad = Att {
            pi: bad_pi,
            shown: att.shown.clone(),
            ..att
        };
        assert!(!verify_att(&tag, &vk, &id, &bad));
        let bad = Att {
            pi: FSProof {
                challenge: bad.pi.challenge,
                responses: vec![],
            },
            ..bad
        };
        assert!(!verify_att(&tag, &vk, &id, &bad));
    }

    /// A credential on `(usk, φ)` under ANOTHER signer's key does not attest under `vk`.
    #[test]
    fn credential_of_another_signer_cannot_be_shown() {
        let mut rng = StdRng::seed_from_u64(0xe914);
        let tag = tag();
        let (vk, _sk) = Base::keygen(&(), &mut rng);
        let (rogue_vk, rogue_sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &rogue_sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        // the honest holder code notices at once
        assert_eq!(
            attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).err(),
            Some(Error::InvalidCredential)
        );
        // a show prepared under the rogue key has true clauses and is rejected by Verify
        let (shown, ()) = Base::rerand(&(), &rogue_vk, &msg(usk, phi), &cred, &mut rng).unwrap();
        assert!(Base::verify_possess_public(&(), &rogue_vk, &shown, &phi));
        assert!(!Base::verify_possess_public(&(), &vk, &shown, &phi));
        let att = forge_att(&tag, &vk, shown, phi, &usk, &id, &mut rng);
        assert!(!verify_att(&tag, &vk, &id, &att));
    }

    /// Special soundness with a shared coordinate: rewinding the prover of `R_att` yields ONE
    /// `usk`, which opens the tag AND is the invariant of the signed class.
    #[test]
    fn extractor_recovers_the_shared_usk() {
        let mut rng = StdRng::seed_from_u64(0xe915);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let t = tag.eval(&usk, &s).unwrap();
        let (shown, ()) = Base::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
        let rel = att_relation(&tag, &vk, &shown, &phi, &t, &s);

        // "rewinding" = the same random tape twice
        let (a1, st1) = commit(&rel, &mut StdRng::seed_from_u64(77)).unwrap();
        let (a2, st2) = commit(&rel, &mut StdRng::seed_from_u64(77)).unwrap();
        assert_eq!(a1, a2);
        let (c1, c2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let z1 = respond(st1, &[usk], &c1).unwrap();
        let z2 = respond(st2, &[usk], &c2).unwrap();
        let extracted = extract(&rel, &a1, (&c1, &z1), (&c2, &z2)).unwrap();
        assert_eq!(extracted, vec![usk]);
        assert_eq!(tag.eval(&extracted[0], &s).unwrap(), t);
        // together with the public checks: M' is a signed representative of the class of
        // Enc(usk, φ) for the EXTRACTED usk
        assert!(Base::verify_possess_public(&(), &vk, &shown, &phi));
        assert_eq!(shown.message.m2, shown.message.m1 * extracted[0]);
        assert_eq!(shown.message.m3, shown.message.m1 * phi);
    }

    // ----- the stand-alone Possess / VerifyPossess of cred ----------------------------

    #[test]
    fn standalone_possession_proof() {
        let mut rng = StdRng::seed_from_u64(0xe916);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        let (shown, omega) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();

        let (rel, var) = possession_relation::<E, Base>(&(), &vk, &shown, &phi).unwrap();
        assert_eq!((var.index(), rel.num_scalars()), (0, 1));
        // ONE G_1 equation: base M'_1 (signed), target M'_2
        assert_eq!(
            rel.g1_equations(),
            [LinearEquation::dlog(
                var,
                shown.message.m1,
                shown.message.m2
            )]
        );
        assert!(rel.g2_equations().is_empty() && rel.gt_equations().is_empty());
        assert!(rel.is_satisfied_by(&[usk]));
        assert!(!rel.is_satisfied_by(&[usk + Fr::one()]));
        assert!(!rel.is_satisfied_by(&[phi]));

        let pi =
            possess::<E, Base, _>(&(), &vk, &shown, &phi, &usk, &omega, b"ctx", &mut rng).unwrap();
        assert_eq!(pi.responses.len(), 1);
        assert!(verify_possess::<E, Base>(
            &(),
            &vk,
            &shown,
            &phi,
            b"ctx",
            &pi
        ));
        assert!(!verify_possess::<E, Base>(
            &(),
            &vk,
            &shown,
            &phi,
            b"ctx2",
            &pi
        ));
        assert!(!verify_possess::<E, Base>(
            &(),
            &vk,
            &shown,
            &(phi + Fr::one()),
            b"ctx",
            &pi
        ));
        let (other_vk, _) = Base::keygen(&(), &mut rng);
        assert!(!verify_possess::<E, Base>(
            &(),
            &other_vk,
            &shown,
            &phi,
            b"ctx",
            &pi
        ));
        let (shown2, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        assert!(!verify_possess::<E, Base>(
            &(),
            &vk,
            &shown2,
            &phi,
            b"ctx",
            &pi
        ));

        // wrong hidden message: no proof
        assert_eq!(
            possess::<E, Base, _>(
                &(),
                &vk,
                &shown,
                &phi,
                &(usk + Fr::one()),
                &omega,
                b"ctx",
                &mut rng
            ),
            Err(Error::WitnessDoesNotSatisfyRelation)
        );
        // degenerate cred*: refused by the prover, rejected by the verifier although ANY scalar
        // is a witness of its clause and the bare proof verifies under the verifier's context
        let degenerate = credential_free_forgeries::<E>(&(), &vk, &phi, &usk)
            .swap_remove(0)
            .shown;
        assert_eq!(
            possess::<E, Base, _>(&(), &vk, &degenerate, &phi, &usk, &omega, b"ctx", &mut rng),
            Err(Error::InvalidCredential)
        );
        let (rel, _) = possession_relation::<E, Base>(&(), &vk, &degenerate, &phi).unwrap();
        let forged_witness = [Fr::rand(&mut rng)];
        assert!(rel.is_satisfied_by(&forged_witness));
        let ctx = possess_context::<E, Base>(&(), &vk, &degenerate, &phi, b"ctx").unwrap();
        let forged = fiat_shamir::prove(&rel, &forged_witness, &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &forged));
        assert!(!verify_possess::<E, Base>(
            &(),
            &vk,
            &degenerate,
            &phi,
            b"ctx",
            &forged
        ));
    }

    // ----- R_issue: id ∧ T_0 with a shared usk, NO opening clause --------------------------------

    fn issue_relation(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        c: &G1,
        phi: &Fr,
        id: &G1,
        t0: &G1,
    ) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        let usk = rel.alloc_scalar();
        let extra = Base::issuance_clauses(&(), vk, c, phi, &mut rel, usk).unwrap();
        assert!(extra.is_empty());
        // no clause was appended
        assert_eq!(rel.num_scalars(), 1);
        assert!(rel.g1_equations().is_empty());
        assert!(rel.g2_equations().is_empty() && rel.gt_equations().is_empty());
        let c0 = *tag.identity_point().unwrap();
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        for eq in tag
            .tag_equations(usk, id, &c0)
            .into_iter()
            .chain(tag.tag_equations(usk, t0, &s))
        {
            rel.add_g1(eq).unwrap();
        }
        rel
    }

    /// `C := id`, and the identifier clause `id = g_1^usk` of `R_issue` IS the statement that the
    /// requester knows the `usk` inside the vector `(g_1, id, g_1^φ)` the helper signs.
    #[test]
    fn issuance_has_no_opening_clause_and_is_bound_by_the_identifier_clause() {
        let mut rng = StdRng::seed_from_u64(0xe917);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let phi = phi(b"f");
        let usk = tag.keygen(&mut rng);
        let c0 = *tag.identity_point().unwrap();
        let id = tag.eval(&usk, &c0).unwrap();
        let t0 = tag.eval(&usk, &h0_id(DOMAIN, &id).unwrap()).unwrap();

        let (aux, rho) = Base::sample_issuance(&(), &mut rng);
        let m_hid = Base::hidden_message(&usk, &aux);
        let c = Base::issuance_encoding(&(), &vk, &m_hid, &phi, &rho).unwrap();
        assert_eq!(c, id);
        let rel = issue_relation(&tag, &vk, &c, &phi, &id, &t0);
        assert_eq!(rel.num_scalars(), 1);
        assert_eq!(rel.g1_equations().len(), 2);
        // the identifier clause: base g_1, target id = C
        assert_eq!(
            rel.g1_equations()[0],
            LinearEquation::dlog(rel.g1_equations()[0].terms[0].0, G1::generator(), c)
        );

        let w = issuance_witness_vector::<E, Base>(&m_hid, &rho);
        assert_eq!(&*w, [usk]);
        let pi0 = fiat_shamir::prove(&rel, &w, b"ctx0", &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, b"ctx0", &pi0));
        // π_0 = (c, z_usk): 2 Z_p next to T_0
        assert_eq!(pi0.responses.len(), 1);

        // the helper: C := id from NOTHING on the wire, verify, sign
        let c_helper = Base::encoding_from_wire(&(), &Base::encoding_to_wire(&c), &id).unwrap();
        let rel_helper = issue_relation(&tag, &vk, &c_helper, &phi, &id, &t0);
        assert!(fiat_shamir::verify(&rel_helper, b"ctx0", &pi0));
        let pre = Base::blind_issue(&(), &sk, &c_helper, &phi, &mut rng).unwrap();
        let m = Base::encode_message(&(), &m_hid, &phi).unwrap();
        let cred = Base::unblind(&(), &vk, &m, &pre, &rho).unwrap();
        assert!(Base::verify(&(), &vk, &m, &cred));

        // someone else's identifier: no witness, the proof does not transfer, and a credential
        // issued for it is useless to this user
        let other = tag.keygen(&mut rng);
        let other_id = tag.eval(&other, &c0).unwrap();
        let rel_other = issue_relation(&tag, &vk, &other_id, &phi, &other_id, &t0);
        assert!(!rel_other.is_satisfied_by(&[usk]));
        assert!(!rel_other.is_satisfied_by(&[other]));
        assert!(!fiat_shamir::verify(&rel_other, b"ctx0", &pi0));
        let pre_other = Base::blind_issue(&(), &sk, &other_id, &phi, &mut rng).unwrap();
        let useless = Base::unblind(&(), &vk, &m, &pre_other, &rho).unwrap();
        assert!(!Base::verify(&(), &vk, &m, &useless));
        assert_eq!(
            Base::rerand(&(), &vk, &m, &useless, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
        // the proof is bound to T_0
        let rel_t0 = issue_relation(&tag, &vk, &c, &phi, &id, &(t0 + t0));
        assert!(!fiat_shamir::verify(&rel_t0, b"ctx0", &pi0));
    }

    #[test]
    fn clauses_reject_foreign_variables() {
        let mut rng = StdRng::seed_from_u64(0xe918);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let m = msg(Fr::one(), Fr::one());
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        let (shown, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        let foreign = PairingRelation::<E>::new().alloc_scalars(3)[2];
        let mut rel = PairingRelation::<E>::new();
        rel.alloc_scalar();
        assert_eq!(
            Base::possession_clauses(&(), &vk, &shown, &Fr::one(), &mut rel, foreign),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 1
            })
        );
        assert!(rel.g1_equations().is_empty());
        assert_eq!(
            Base::issuance_clauses(&(), &vk, &m.m2, &Fr::one(), &mut rel, foreign),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 1
            })
        );
        let mut rel = PairingRelation::<E>::new();
        assert_eq!(
            Base::issuance_clauses(&(), &vk, &m.m2, &Fr::one(), &mut rel, foreign),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 0
            })
        );
        assert_eq!(rel, PairingRelation::new());
    }

    // ----- encodings and secrets -----------------------------------------------------------------

    #[test]
    fn serialization_sizes_and_round_trips() {
        let mut rng = StdRng::seed_from_u64(0xe919);
        assert_eq!(Base::setup(DOMAIN), Ok(()));
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let m = msg(usk, phi);
        let (shown, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        let id = G1::generator() * usk;
        let pre = Base::blind_issue(&(), &sk, &id, &phi, &mut rng).unwrap();

        // BLS12-381: G_1 48 B, G_2 96 B, Z_p 32 B. The box is normative: cred = (Z, Y, Ỹ) is
        // 192 B and cred* = (M', cred') is 336 B. (The paper's comparison table lists
        // |cred| = 336 B for Σ-EQ, which is |cred*| or a stored (M, σ); see the module docs.)
        let bytes = cred.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48 + 96);
        assert_eq!(EQCredential::<E>::from_bytes(&bytes).unwrap(), cred);
        let bytes = shown.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 48 + 2 * 48 + 96);
        assert_eq!(bytes.len(), 336);
        assert_eq!(EQShownCredential::<E>::from_bytes(&bytes).unwrap(), shown);
        let bytes = pre.to_bytes().unwrap();
        assert_eq!(bytes.len(), 192);
        assert_eq!(EQPreCredential::<E>::from_bytes(&bytes).unwrap(), pre);
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 48);
        assert_eq!(EQMessage::<E>::from_bytes(&bytes).unwrap(), m);
        let bytes = vk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 96);
        assert_eq!(EQVerificationKey::<E>::from_bytes(&bytes).unwrap(), vk);
        // C is not transmitted
        fn wire_len<B: SigmaFriendlyCredentialBase<E>>(c: &B::IssuanceEncoding) -> usize {
            B::encoding_to_wire(c).to_bytes().unwrap().len()
        }
        assert_eq!(wire_len::<Base>(&id), 0);

        let bytes = sk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 32);
        let back = EQSigningKey::<E>::from_bytes(&bytes).unwrap();
        assert_eq!(back.verification_key(), vk);

        // |att| = |T| + |cred*| + |φ| + |(c, z)| = 480 B and, at k = 5 with π_0 = (c, z) and no
        // C, |π| = 5 |att| + |T_0| + |π_0| = 2512 B: the table's columns that DO follow from the box
        let other_id = G1::generator() * tag.keygen(&mut rng);
        let att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &other_id, &mut rng).unwrap();
        let att_len = att.t.to_bytes().unwrap().len()
            + att.shown.to_bytes().unwrap().len()
            + att.phi.to_bytes().unwrap().len()
            + att.pi.compact_size();
        assert_eq!(att_len, 480);
        let pi0_len = (1 + 1 + <Base as SigmaFriendlyCredentialBase<E>>::ISSUANCE_VARIABLES) * 32;
        assert_eq!(5 * att_len + 48 + pi0_len, 2512);

        // trailing bytes and truncation
        let mut long = cred.to_bytes().unwrap();
        long.push(0);
        assert_eq!(
            EQCredential::<E>::from_bytes(&long),
            Err(Error::TrailingBytes)
        );
        assert!(EQCredential::<E>::from_bytes(&long[..191]).is_err());

        // the identity decodes fine: rejecting it is the verifiers' job
        let degenerate = credential_free_forgeries::<E>(&(), &vk, &phi, &usk)
            .swap_remove(1)
            .shown;
        let back = EQShownCredential::<E>::from_bytes(&degenerate.to_bytes().unwrap()).unwrap();
        assert_eq!(back, degenerate);
        assert!(!Base::verify_possess_public(&(), &vk, &back, &phi));
    }

    #[test]
    fn secrets_are_redacted_and_wiped() {
        let mut rng = StdRng::seed_from_u64(0xe91a);
        let (_, mut sk) = Base::keygen(&(), &mut rng);
        assert_eq!(format!("{sk:?}"), "EQSigningKey(<redacted>)");
        assert!(!sk.x1.is_zero() && !sk.x2.is_zero() && !sk.x3.is_zero());
        sk.zeroize();
        assert!(sk.x1.is_zero() && sk.x2.is_zero() && sk.x3.is_zero());

        let mut m = msg(Fr::from(5u64), Fr::from(6u64));
        m.zeroize();
        assert!(m.m1.is_zero() && m.m2.is_zero() && m.m3.is_zero());

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<EQSigningKey<E>>();
    }

    // ----- degenerate keys (module docs, "Implementation notes") ---------------------------------

    #[test]
    fn keygen_outputs_well_formed_keys_only() {
        let mut rng = StdRng::seed_from_u64(0xe91b);
        for _ in 0..8 {
            let (vk, sk) = Base::keygen(&(), &mut rng);
            assert!(sk.is_in_key_space());
            assert!(vk.is_well_formed());
            assert!(Base::is_well_formed_key(&(), &vk));
        }
    }

    /// `KeyGen` step 1: `x_1, x_2, x_3 ← Z_p^*` are THREE draws. The key is exactly what the
    /// coins say (as for `y` in `Sign` and `r, ψ` in `ReRand`), `KeyGen` consumes nothing else,
    /// and no exponent repeats within a key or across keys. Neither `sk ∈ (Z_p^*)^3` nor a well
    /// formed `vk` implies any of this: see the next test.
    #[test]
    fn keygen_draws_three_independent_exponents() {
        let mut rng = StdRng::seed_from_u64(0xe926);
        let mut seen: Vec<Fr> = Vec::new();
        for _ in 0..4 {
            let mut coins = rng.clone();
            let expected: [Fr; 3] = [
                nonzero_scalar(&mut coins),
                nonzero_scalar(&mut coins),
                nonzero_scalar(&mut coins),
            ];
            let (vk, sk) = Base::keygen(&(), &mut rng);
            assert_eq!(exponents(&sk), expected);
            assert_eq!(rng, coins, "KeyGen draws x_1, x_2, x_3 and nothing else");
            assert_eq!(vk, signing_key(expected).verification_key());
            for x in exponents(&sk) {
                assert!(!seen.contains(&x), "a repeated exponent");
                seen.push(x);
            }
        }
        assert_eq!(seen.len(), 12);
    }

    /// Why the coins of `KeyGen` are pinned: a key with DEPENDENT exponents lies in the key
    /// space, its `vk` is well formed, every algorithm takes it, and it does not bind `φ`. Write
    /// `M' = (A, A^usk, A^φ)` for an honest show.
    ///
    /// * `x_3 = x_1`: the signature covers `(M_1 M_3, M_2)` only. Moving
    ///   `D = A^{(φ − φ')/(1 + φ')}` from `M'_3` to `M'_1` leaves `Z'` valid and gives a show for
    ///   `φ'` under the key `usk (1 + φ')/(1 + φ)`.
    /// * `x_2 = x_1`: it covers `(M_1 M_2, M_3)` only. Moving `D = A^{φ/φ' − 1}` from `M'_2` to
    ///   `M'_1` gives a show for `φ'` under the key `(usk + 1) φ'/φ − 1`.
    ///
    /// NOTHING on the verifier path rejects these (the forged attestations verify): such a key
    /// can only be prevented where it is generated.
    #[test]
    fn dependent_key_exponents_would_unbind_phi() {
        let mut rng = StdRng::seed_from_u64(0xe927);
        let tag = tag();
        let id = G1::generator() * tag.keygen(&mut rng);
        let (phi, other_phi) = (phi(b"f"), phi(b"f'"));
        assert_ne!(other_phi, phi);
        let one = Fr::one();

        for x3_equals_x1 in [true, false] {
            let (a, b): (Fr, Fr) = (nonzero_scalar(&mut rng), nonzero_scalar(&mut rng));
            let sk = signing_key(if x3_equals_x1 { [a, b, a] } else { [a, a, b] });
            let vk = sk.verification_key();
            assert!(sk.is_in_key_space());
            assert!(vk.is_well_formed() && Base::is_well_formed_key(&(), &vk));

            // an honest credential for (usk, φ) under this key, and one honest show
            let usk = tag.keygen(&mut rng);
            let cred = Base::sign(&(), &sk, &msg(usk, phi), &mut rng).unwrap();
            let (shown, ()) = Base::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
            assert!(Base::verify_possess_public(&(), &vk, &shown, &phi));
            assert!(!Base::verify_possess_public(&(), &vk, &shown, &other_phi));

            // the holder (no signing key involved) shifts D between two components
            let mut forgery = shown.clone();
            let a1 = shown.message.m1;
            let other_key = if x3_equals_x1 {
                let d = a1 * ((phi - other_phi) * (one + other_phi).inverse().unwrap());
                forgery.message.m1 += d;
                forgery.message.m3 -= d;
                usk * (one + other_phi) * (one + phi).inverse().unwrap()
            } else {
                let d = a1 * (phi * other_phi.inverse().unwrap() - one);
                forgery.message.m1 += d;
                forgery.message.m2 -= d;
                (usk + one) * other_phi * phi.inverse().unwrap() - one
            };
            assert_ne!(other_key, usk);
            assert_eq!(forgery.credential, shown.credential);

            // every public check accepts the show for φ' ...
            assert!(Base::verify(
                &(),
                &vk,
                &forgery.message,
                &forgery.credential
            ));
            assert!(Base::verify_possess_public(&(), &vk, &forgery, &other_phi));
            // ... and so do the stand-alone verifier and a complete attestation under the
            // never-certified key
            let pi = possess::<E, Base, _>(
                &(),
                &vk,
                &forgery,
                &other_phi,
                &other_key,
                &(),
                b"ctx",
                &mut rng,
            )
            .unwrap();
            assert!(verify_possess::<E, Base>(
                &(),
                &vk,
                &forgery,
                &other_phi,
                b"ctx",
                &pi
            ));
            let att = forge_att(&tag, &vk, forgery, other_phi, &other_key, &id, &mut rng);
            assert!(verify_att(&tag, &vk, &id, &att));
        }

        // control: under a key from KeyGen the same two shifts break the signature
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let usk = tag.keygen(&mut rng);
        let cred = Base::sign(&(), &sk, &msg(usk, phi), &mut rng).unwrap();
        let (shown, ()) = Base::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
        let d = shown.message.m1 * ((phi - other_phi) * (one + other_phi).inverse().unwrap());
        let mut first = shown.clone();
        first.message.m1 += d;
        first.message.m3 -= d;
        assert_eq!(first.message.m3, first.message.m1 * other_phi);
        assert!(!Base::verify_possess_public(&(), &vk, &first, &other_phi));
        let d = shown.message.m1 * (phi * other_phi.inverse().unwrap() - one);
        let mut second = shown;
        second.message.m1 += d;
        second.message.m2 -= d;
        assert_eq!(second.message.m3, second.message.m1 * other_phi);
        assert!(!Base::verify_possess_public(&(), &vk, &second, &other_phi));
    }

    #[test]
    fn malformed_keys_are_recognised() {
        let mut rng = StdRng::seed_from_u64(0xe91c);
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng));
        let id = m.m2;
        let one = <E as Pairing>::G2::zero();
        for i in 0..3 {
            // identity components, as accepted by the decoder
            let mut bad = vk.clone();
            let mut x = exponents(&sk);
            x[i] = Fr::zero();
            match i {
                0 => bad.x1_tilde = one,
                1 => bad.x2_tilde = one,
                _ => bad.x3_tilde = one,
            }
            let back = EQVerificationKey::<E>::from_bytes(&bad.to_bytes().unwrap()).unwrap();
            assert_eq!(back, bad, "case {i}: the decoder does not mind");
            assert!(!bad.is_well_formed(), "case {i}");
            assert!(!Base::is_well_formed_key(&(), &bad), "case {i}");

            // the matching signing key decodes too, and is refused by both signing algorithms
            let bad_sk = signing_key(x);
            assert_eq!(bad_sk.verification_key(), bad, "case {i}");
            assert!(!bad_sk.is_in_key_space(), "case {i}");
            assert_eq!(
                Base::sign(&(), &bad_sk, &m, &mut rng).unwrap_err(),
                Error::InvalidKey,
                "case {i}"
            );
            assert_eq!(
                Base::blind_issue(&(), &bad_sk, &id, &Fr::one(), &mut rng).unwrap_err(),
                Error::InvalidKey,
                "case {i}"
            );
        }
        // nothing else is constrained: every vector of (G_2 \ {1})^3 is a key
        let (other, _) = Base::keygen(&(), &mut rng);
        let mixed = EQVerificationKey::<E> {
            x2_tilde: other.x2_tilde,
            ..vk.clone()
        };
        assert!(mixed.is_well_formed());
    }

    /// The setting of the three tests below: a signer whose key has `x_i = 0` (it does not use
    /// this library's `Sign`, which refuses), a credential on `(usk, φ)` under it, and one
    /// honest show `(M', cred')`.
    #[allow(clippy::type_complexity)]
    fn degenerate_key_setting(
        i: usize,
        rng: &mut StdRng,
    ) -> (Tag, EQVerificationKey<E>, (Fr, Fr), EQShownCredential<E>) {
        let tag = tag();
        let mut x = [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
        x[i] = Fr::zero();
        let vk = signing_key(x).verification_key();
        assert!(!vk.is_well_formed());
        let (usk, phi) = (tag.keygen(rng), phi(b"f"));
        let m = msg(usk, phi);
        let cred = raw_sign(x, &m, Fr::rand(rng));
        assert!(Base::verify(&(), &vk, &m, &cred));
        let (shown, ()) = Base::rerand(&(), &vk, &m, &cred, rng).unwrap();
        // the honest show is fine in every respect but the key
        assert!(Base::verify(&(), &vk, &shown.message, &shown.credential));
        assert_eq!(shown.message.m3, shown.message.m1 * phi);
        assert!(!Base::verify_possess_public(&(), &vk, &shown, &phi));
        (tag, vk, (usk, phi), shown)
    }

    /// Asserts that `forgery` passes EVERY check of the possession verifier on `cred*`, that
    /// its clauses hold under `key` with a verifying proof and a valid tag, and that it is
    /// rejected all the same, i.e. by the key-side check alone.
    fn assert_only_the_key_check_rejects(
        tag: &Tag,
        vk: &EQVerificationKey<E>,
        forgery: EQShownCredential<E>,
        phi: Fr,
        key: &Fr,
        rng: &mut StdRng,
    ) -> G1 {
        assert!(!forgery.message.m1.is_zero());
        assert!(Base::verify(&(), vk, &forgery.message, &forgery.credential));
        assert_eq!(forgery.message.m3, forgery.message.m1 * phi);
        let id = G1::generator() * Fr::from(1234u64);
        let att = forge_att(tag, vk, forgery, phi, key, &id, rng);
        assert!(!Base::verify_possess_public(&(), vk, &att.shown, &phi));
        assert!(!verify_att(tag, vk, &id, &att));
        // the stand-alone verifier as well
        let (rel, _) = possession_relation::<E, Base>(&(), vk, &att.shown, &phi).unwrap();
        let ctx = possess_context::<E, Base>(&(), vk, &att.shown, &phi, b"ctx").unwrap();
        let pi = fiat_shamir::prove(&rel, &[*key], &ctx, rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &pi));
        assert!(!verify_possess::<E, Base>(
            &(),
            vk,
            &att.shown,
            &phi,
            b"ctx",
            &pi
        ));
        att.t
    }

    /// `X̃_2 = 1`: the signature does not cover `M_2`, so ONE credential attests under
    /// arbitrarily many tag keys with `M'_2 := (M'_1)^K`.
    #[test]
    fn x2_identity_unbinds_usk_and_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0xe91d);
        let (tag, vk, (usk, phi), shown) = degenerate_key_setting(1, &mut rng);
        // the box's Verify cannot tell: the adapted signature "verifies" next to every M'_2
        let mut tags = Vec::new();
        for _ in 0..3 {
            let other = tag.keygen(&mut rng);
            assert_ne!(other, usk);
            let mut forgery = shown.clone();
            forgery.message.m2 = forgery.message.m1 * other;
            tags.push(assert_only_the_key_check_rejects(
                &tag, &vk, forgery, phi, &other, &mut rng,
            ));
        }
        assert!(tags[0] != tags[1] && tags[1] != tags[2] && tags[0] != tags[2]);
        // the stand-alone prover refuses the key
        assert_eq!(
            possess::<E, Base, _>(&(), &vk, &shown, &phi, &usk, &(), b"ctx", &mut rng),
            Err(Error::InvalidKey)
        );
    }

    /// `X̃_3 = 1`: the signature does not cover `M_3`, so a credential for `φ` can be shown for
    /// every `φ'` with `M'_3 := (M'_1)^{φ'}`.
    #[test]
    fn x3_identity_unbinds_phi_and_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0xe91e);
        let (tag, vk, (usk, phi), shown) = degenerate_key_setting(2, &mut rng);
        let other_phi = self::phi(b"f'");
        assert_ne!(other_phi, phi);
        let mut forgery = shown;
        forgery.message.m3 = forgery.message.m1 * other_phi;
        let t = assert_only_the_key_check_rejects(&tag, &vk, forgery, other_phi, &usk, &mut rng);
        assert!(tag.valid_tag(&t, &Fr::zero()));
    }

    /// `X̃_1 = 1`: the signature covers `(M_2, M_3)` only, i.e. the ratio `usk / φ`. With
    /// `M'_1 := (M'_1)^{φ/φ'}` a credential for `(usk, φ)` is shown as one for
    /// `(usk · φ'/φ, φ')`.
    #[test]
    fn x1_identity_certifies_only_a_ratio_and_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0xe91f);
        let (tag, vk, (usk, phi), shown) = degenerate_key_setting(0, &mut rng);
        let other_phi = self::phi(b"f'");
        let ratio = other_phi * phi.inverse().unwrap();
        let mut forgery = shown;
        forgery.message.m1 *= ratio.inverse().unwrap();
        let other_key = usk * ratio;
        assert_ne!(other_key, usk);
        let t =
            assert_only_the_key_check_rejects(&tag, &vk, forgery, other_phi, &other_key, &mut rng);
        assert!(tag.valid_tag(&t, &Fr::zero()));
    }

    /// An RNG under which every other scalar draw is `0 ∈ Z_p`: four zero limbs, then four
    /// limbs of a counter, and so on (`Fr` is sampled from four `u64`s).
    #[derive(Default)]
    struct ZeroEveryOtherScalar {
        calls: u64,
    }

    impl ark_std::rand::RngCore for ZeroEveryOtherScalar {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let zero_block = (self.calls / 4).is_multiple_of(2);
            self.calls += 1;
            if zero_block { 0 } else { self.calls }
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

    // Test-only marker: the algorithms ask for a `CryptoRng`.
    impl ark_std::rand::CryptoRng for ZeroEveryOtherScalar {}

    /// The box samples `x_i`, `y`, `r`, `ψ` from `Z_p^*`. Under an RNG whose first answer to
    /// every scalar draw is zero, plain `Z_p` sampling would give `x_i = 0` (a key that does not
    /// cover `M_i`), `y = 0` or `ψ = 0` (no inverse), `r = 0` (`M' = (1, 1, 1)`).
    #[test]
    fn coins_are_sampled_from_zp_star() {
        // control: with this RNG, plain sampling returns zero, then a non-zero scalar
        let mut rng = ZeroEveryOtherScalar::default();
        assert!(Fr::rand(&mut rng).is_zero());
        assert!(!Fr::rand(&mut rng).is_zero());

        let mut rng = ZeroEveryOtherScalar::default();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        assert!(sk.is_in_key_space());
        assert!(vk.is_well_formed());
        let (usk, phi) = (Fr::from(3u64), Fr::from(4u64));
        let m = msg(usk, phi);
        let cred = Base::sign(&(), &sk, &m, &mut rng).unwrap();
        assert!(Base::verify(&(), &vk, &m, &cred));
        let pre = Base::blind_issue(&(), &sk, &m.m2, &phi, &mut rng).unwrap();
        let issued = Base::unblind(&(), &vk, &m, &pre, &()).unwrap();
        assert!(Base::verify(&(), &vk, &m, &issued));
        for _ in 0..2 {
            let (shown, ()) = Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
            assert!(shown.message.is_in_message_space());
            assert!(Base::verify_possess_public(&(), &vk, &shown, &phi));
        }
    }

    /// Every randomized algorithm accepts an unsized RNG (`R: ?Sized`), e.g. a trait object.
    #[test]
    fn randomized_algorithms_accept_a_dyn_rng() {
        use ark_std::rand::{CryptoRng, RngCore};
        trait DynRng: RngCore + CryptoRng {}
        impl<T: RngCore + CryptoRng> DynRng for T {}

        let mut std_rng = StdRng::seed_from_u64(0xe920);
        let rng: &mut dyn DynRng = &mut std_rng;
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), rng);
        let usk = tag.keygen(rng);
        let (phi, ((), ())) = (phi(b"f"), Base::sample_issuance(&(), rng));
        let c = Base::issuance_encoding(&(), &vk, &usk, &phi, &()).unwrap();
        let pre = Base::blind_issue(&(), &sk, &c, &phi, rng).unwrap();
        let cred = Base::unblind(&(), &vk, &msg(usk, phi), &pre, &()).unwrap();
        assert!(Base::verify(&(), &vk, &msg(usk, phi), &cred));
        let direct = Base::sign(&(), &sk, &msg(usk, phi), rng).unwrap();
        assert!(Base::verify(&(), &vk, &msg(usk, phi), &direct));
        let (shown, omega) = Base::rerand(&(), &vk, &msg(usk, phi), &cred, rng).unwrap();
        let pi = possess::<E, Base, _>(&(), &vk, &shown, &phi, &usk, &omega, b"ctx", rng).unwrap();
        assert!(verify_possess::<E, Base>(
            &(),
            &vk,
            &shown,
            &phi,
            b"ctx",
            &pi
        ));
    }

    // ----- the generic flow of the construction --------------------------------------------------

    /// The base-and-tag-generic walk through the protocol box (`Attest`, `VerifyAtt`, `Prove`,
    /// `VerifyProof`, `Issue`, `Unblind`, `VerifyCred`, chaining), written against the traits
    /// only, with the exported [`credential_free_forgeries`].
    #[test]
    fn conformance_flow_with_tag_ddh() {
        let report = public_base_flow::<E, Base, Tag>(DOMAIN, 0xe921, credential_free_forgeries);
        // |att| = 6 G_1 + G_2 + 3 Z_p and π_0 = (c, z_usk): ONE response each, no C
        assert_eq!(
            report,
            FlowReport {
                attestation_responses: 1,
                issuance_responses: 1,
            }
        );
    }

    /// All four exported forgeries satisfy the clauses (the flow only requires one), and each is
    /// rejected by ANOTHER part of the public checks: the identity checks on `M'`, those on
    /// `(Y', Ỹ')`, the first pairing equation, the second pairing equation. The key is well
    /// formed and the equation for `φ` holds throughout, so dropping any one of these parts
    /// from the verifier path lets one entry through.
    #[test]
    fn exported_forgeries_cover_the_identity_checks_and_both_equations() {
        let mut rng = StdRng::seed_from_u64(0xe922);
        let tag = tag();
        let (vk, _sk) = Base::keygen(&(), &mut rng);
        assert!(vk.is_well_formed());
        let (phi, key) = (phi(b"f"), tag.keygen(&mut rng));
        let id = G1::generator() * tag.keygen(&mut rng);
        let forgeries = credential_free_forgeries::<E>(&(), &vk, &phi, &key);
        // (M' ∈ (G_1 \ {1})^3, Y' ≠ 1 ∧ Ỹ' ≠ 1, first equation, second equation)
        let expected = [
            // W4-E1: the identity vector, both equations hold
            (false, true, true, true),
            // the all-identity encoding
            (false, false, true, true),
            // a never-signed vector next to (g_1, g_1, g̃): ONLY the first equation rejects
            (true, true, false, true),
            // the forgery from vk alone: ONLY the second equation rejects
            (true, true, true, false),
        ];
        assert_eq!(forgeries.len(), expected.len());
        for (i, (forgery, (in_space, nonidentity, first, second))) in
            forgeries.into_iter().zip(expected).enumerate()
        {
            assert!(forgery.extra_witness.is_empty());
            let shown = forgery.shown;
            let (m, cred) = (&shown.message, &shown.credential);
            assert_eq!(m.m3, m.m1 * phi, "forgery {i}");
            assert_eq!(m.is_in_message_space(), in_space, "forgery {i}");
            assert_eq!(
                !cred.y.is_zero() && !cred.y_tilde.is_zero(),
                nonidentity,
                "forgery {i}"
            );
            assert_eq!(equation_1(&vk, m, cred), first, "forgery {i}");
            assert_eq!(equation_2(cred), second, "forgery {i}");
            assert!(!Base::verify(&(), &vk, m, cred), "forgery {i}");
            assert!(
                !Base::verify_possess_public(&(), &vk, &shown, &phi),
                "forgery {i}"
            );

            // the stand-alone verifier: the clause holds under the forged key, the bare proof
            // verifies under the verifier's own context, and VerifyPossess rejects
            let (rel, _) = possession_relation::<E, Base>(&(), &vk, &shown, &phi).unwrap();
            assert!(rel.is_satisfied_by(&[key]), "forgery {i}");
            let ctx = possess_context::<E, Base>(&(), &vk, &shown, &phi, b"ctx").unwrap();
            let pi = fiat_shamir::prove(&rel, &[key], &ctx, &mut rng).unwrap();
            assert!(fiat_shamir::verify(&rel, &ctx, &pi), "forgery {i}");
            assert!(
                !verify_possess::<E, Base>(&(), &vk, &shown, &phi, b"ctx", &pi),
                "forgery {i}"
            );
            // ... and a complete attestation
            let att = forge_att(&tag, &vk, shown, phi, &key, &id, &mut rng);
            assert!(!verify_att(&tag, &vk, &id, &att), "forgery {i}");
        }
    }

    /// The forgery from `vk` ALONE that a verifier enforcing the FIRST pairing equation only
    /// would accept, for every never-signed key `K`, every `φ`, every representative and every
    /// `Y' ≠ 1`: `Z' = M'_1`, `Ỹ' = X̃_1 X̃_2^K X̃_3^φ`. Everything on the verifier path but the
    /// second equation `e(Y', g̃) = e(g_1, Ỹ')` accepts it; its clauses hold under `K` and its
    /// Fiat-Shamir proof verifies.
    #[test]
    fn forgery_from_the_verification_key_fails_the_second_equation_only() {
        let mut rng = StdRng::seed_from_u64(0xe925);
        let tag = tag();
        let (vk, sk) = Base::keygen(&(), &mut rng);
        assert!(vk.is_well_formed());
        let id = G1::generator() * tag.keygen(&mut rng);
        let g = G1::generator();

        let mut forged = 0;
        for _ in 0..5 {
            let key = tag.keygen(&mut rng);
            let (phi, r): (Fr, Fr) = (nonzero_scalar(&mut rng), nonzero_scalar(&mut rng));
            let message = scaled(&msg(key, phi), r);
            let y_tilde = vk.x1_tilde + vk.x2_tilde * key + vk.x3_tilde * phi;
            for y in [g, message.m1, G1::rand(&mut rng)] {
                let shown = EQShownCredential::<E> {
                    message: message.clone(),
                    credential: EQCredential {
                        z: message.m1,
                        y,
                        y_tilde,
                    },
                };
                // what the forger gets right: everything but the second equation
                assert!(shown.message.is_in_message_space());
                assert!(!shown.credential.y.is_zero() && !shown.credential.y_tilde.is_zero());
                assert_eq!(shown.message.m3, shown.message.m1 * phi);
                assert_eq!(shown.message.m2, shown.message.m1 * key);
                assert!(equation_1(&vk, &shown.message, &shown.credential));
                assert!(!equation_2(&shown.credential));
                if Base::verify(&(), &vk, &shown.message, &shown.credential)
                    || Base::verify_possess_public(&(), &vk, &shown, &phi)
                    || Base::rerand(&(), &vk, &shown.message, &shown.credential, &mut rng).is_ok()
                {
                    forged += 1;
                }
                let att = forge_att(&tag, &vk, shown, phi, &key, &id, &mut rng);
                if verify_att(&tag, &vk, &id, &att) {
                    forged += 1;
                }
            }

            // control: WITH the signing key, Y' = g_1^t for t = x_1 + K x_2 + φ x_3 completes the
            // triple to the signature with randomizer y = 1/t, so the algebra above is right and
            // Y' is all the forger lacks
            let t = sk.x1 + key * sk.x2 + phi * sk.x3;
            let signed = EQCredential::<E> {
                z: message.m1,
                y: g * t,
                y_tilde,
            };
            assert_eq!(y_tilde, G2::generator() * t);
            assert_eq!(
                signed,
                raw_sign(exponents(&sk), &message, t.inverse().unwrap())
            );
            assert!(Base::verify(&(), &vk, &message, &signed));
        }
        assert_eq!(forged, 0, "forgeries from the verification key alone");
    }

    /// The documented refusal: `Σ-EQ` needs `id = g_1^usk` and is compatible with `Tag_DDH`
    /// under `htag(c_0) = g_1` only, "not with `Tag_DY`" (proof sketch of the Lemma on `Σ-EQ`).
    #[test]
    fn tag_dy_and_unprogrammed_tag_ddh_are_refused() {
        const { assert!(<Base as SigmaFriendlyCredentialBase<E>>::REQUIRES_DLOG_IDENTITY) };
        const { assert!(!<DY<G1> as PCSTag<G1>>::IDENTITY_IS_DLOG) };
        let mut rng = StdRng::seed_from_u64(0xe923);
        let c0: Fr = h0_identity_point(DOMAIN);
        assert_eq!(
            check_compatibility::<E, Base, DY<G1>>(&DY::new(), &c0),
            Err(Error::IncompatibleBaseAndTag)
        );
        assert_eq!(check_compatibility::<E, Base, Tag>(&tag(), &c0), Ok(()));
        let plain = Tag::new(G1Hasher::new(DOMAIN).unwrap());
        assert_eq!(
            check_compatibility::<E, Base, Tag>(&plain, &c0),
            Err(Error::IncompatibleBaseAndTag)
        );

        // What the refusal prevents: under Tag_DY the identifier is g_1^{1/(usk + c_0)}, so the
        // helper's signature on (g_1, id, g_1^φ) is not a credential on Enc(usk, φ).
        let (vk, sk) = Base::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), phi(b"f"));
        let id_dy = G1::generator() * (usk + c0).inverse().unwrap();
        let pre = Base::blind_issue(&(), &sk, &id_dy, &phi, &mut rng).unwrap();
        let m = msg(usk, phi);
        let cred = Base::unblind(&(), &vk, &m, &pre, &()).unwrap();
        assert!(!Base::verify(&(), &vk, &m, &cred));
        assert_eq!(
            Base::rerand(&(), &vk, &m, &cred, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
    }

    // ----- genericity ----------------------------------------------------------------------------

    /// The whole flow over a second pairing. arkworks ships no hash-to-curve for BN254, so
    /// `htag` is the test-only INSECURE oracle; the programmed point `htag(c_0) = g_1` is what
    /// `Σ-EQ` needs from it.
    #[test]
    fn generic_over_the_pairing() {
        type G1Bn = <Bn254 as Pairing>::G1;
        let report = public_base_flow::<Bn254, EQ<Bn254>, DDH<G1Bn, InsecureExponentHasher>>(
            b"sigma-eq-unit-tests/bn254",
            0xe924,
            credential_free_forgeries,
        );
        assert_eq!(
            report,
            FlowReport {
                attestation_responses: 1,
                issuance_responses: 1,
            }
        );
    }
}
