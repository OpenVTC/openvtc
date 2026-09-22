//! `Σ-PS`, the Pointcheval-Sanders credential base and main instantiation of the paper
//! (§3.2.1, "The Pointcheval-Sanders instantiation", box "`Σ-PS` credential base").
//!
//! Setting: `M_Σ = Z_p^2`, `m_hid = usk`, `m_pub = φ`, `Y_1 = g_1^{y_1}` and
//! `(X̃, Ỹ_1, Ỹ_2) = (g̃^x, g̃^{y_1}, g̃^{y_2})`. The maps are `Enc_Σ(usk, φ) = (usk, φ)` and
//! `Com_vk(usk, φ; ρ) = g_1^ρ Y_1^usk`.
//!
//! | paper (box `Σ-PS`) | here |
//! |---|---|
//! | `KeyGen(pp)`: `x ← Z_p`, `y_1, y_2 ← Z_p^*`, `sk = (x, y_1, y_2)`, `vk = (X̃, Ỹ_1, Ỹ_2, Y_1)` | [`CredentialBase::keygen`] |
//! | `Sign(sk, (m_1, m_2))`: `h ← G_1 \ {1}`, `cred = (h, h^{x + y_1 m_1 + y_2 m_2})` | [`CredentialBase::sign`] |
//! | `Verify`: `[σ_1 ≠ 1 ∧ e(σ_1, X̃ Ỹ_1^{m_1} Ỹ_2^{m_2}) = e(σ_2, g̃)]` | [`CredentialBase::verify`], ONE pairing product |
//! | `ReRand`: `r ← Z_p^*`, `cred* = (σ_1^r, σ_2^r)`, `ω = ∅` | [`CredentialBase::rerand`] |
//! | `BlindIssue(sk, C, φ)`: `u ← Z_p^*`, `ĉred = (g_1^u, (g_1^x C g_1^{y_2 φ})^u)` | [`CredentialBase::blind_issue`] |
//! | `Unblind(vk, (usk, φ), (σ̂_1, σ̂_2), ρ) = (σ̂_1, σ̂_2 / σ̂_1^ρ)` | [`CredentialBase::unblind`] |
//! | `Possess` step 1: the verifier rejects if `σ'_1 = 1`, `Ỹ_1 = 1` or `Ỹ_2 = 1` | [`SigmaFriendlyCredentialBase::verify_possess_public`] |
//! | `Possess` step 2: `e(σ'_1, Ỹ_1)^usk = e(σ'_2, g̃) e(σ'_1, X̃ Ỹ_2^φ)^{-1}` | [`SigmaFriendlyCredentialBase::possession_clauses`], one lazy `G_T` clause |
//! | §5.1: `(m_aux, ρ) = (∅, r)`, `r ← Z_p`; opening clause `C = g_1^ρ Y_1^usk` of `R_issue` | [`SigmaFriendlyCredentialBase::sample_issuance`], [`SigmaFriendlyCredentialBase::issuance_clauses`] |
//!
//! `φ` enters the credential exactly once, in `BlindIssue` (`g_1^{y_2 φ}`); `C` does not depend
//! on it. `g_1` and `g̃` are the standard generators of `G_1` and `G_2`, so `pp_Σ` is empty.
//!
//! Security (Lemma on `Σ-PS`, §3.2.1): under the PS assumption (or `q`-MSDH-1) and the one-more
//! security of the displayed blind-issuance protocol, `Σ-PS` is a *strong* sigma-friendly
//! credential base; re-randomization is perfect, and `σ'_1 ≠ 1` "prevents a vacuous clause".
//!
//! # In formulas
//!
//! ```math
//! \begin{aligned}
//! \mathsf{Sign}\bigl(sk, (m_1, m_2)\bigr) &= \bigl(h,\ h^{\,x + y_1 m_1 + y_2 m_2}\bigr), \qquad h \leftarrow \mathbb{G}_1 \setminus \{1\} \\
//! \mathsf{Verify}\bigl(vk, (m_1, m_2), (\sigma_1, \sigma_2)\bigr) &= \bigl[\, \sigma_1 \neq 1 \;\wedge\; e\bigl(\sigma_1,\ \tilde{X}\, \tilde{Y}_1^{m_1}\, \tilde{Y}_2^{m_2}\bigr) = e(\sigma_2, \tilde{g}) \,\bigr] \\
//! \mathsf{Com}_{vk}(usk, \varphi; \rho) &= g_1^{\rho}\, Y_1^{usk}
//! \end{aligned}
//! ```
//!
//! The possession clause for a shown credential $`(\sigma'_1, \sigma'_2) = (\sigma_1^{r}, \sigma_2^{r})`$, after the
//! public check $`\sigma'_1 \neq 1`$:
//!
//! ```math
//! e(\sigma'_1, \tilde{Y}_1)^{usk} = e(\sigma'_2, \tilde{g}) \cdot e\bigl(\sigma'_1,\ \tilde{X}\, \tilde{Y}_2^{\varphi}\bigr)^{-1}
//! ```
//!
//! # Degenerate keys
//!
//! Why the box samples `y_1, y_2` from `Z_p^*` and why `Possess` rejects `Ỹ_1 = 1` and `Ỹ_2 = 1`
//! (proof sketch of the Lemma on `Σ-PS`):
//!
//! * With `y_1 = 0` the base `e(σ'_1, Ỹ_1)` of the possession clause is `1`: the clause no longer
//!   depends on `usk`, so ONE credential satisfies `R_att` next to a tag under ANY key, and
//!   `σ'_1 ≠ 1` does not help. With `y_2 = 0` a credential for `φ` verifies, and can be shown,
//!   under every `φ'`. The unit tests mount both.
//! * Validated decoding accepts `Ỹ_i = 1` and `y_i = 0`, so a key that was received is
//!   arbitrary: [`PSVerificationKey::is_well_formed`] is the membership test for the range of
//!   `KeyGen`, and the possession verifier runs it as a public check in the sense of Def.
//!   "Sigma-friendly credential base".
//!
//! The possession clause lives in `G_T`. It is stated in lazy pairing-product form
//! ([`GtEquation`]), so committing and verifying cost one multi-pairing and no exponentiation
//! in `G_T`; the proof carries one response, shared with the tag clause through the variable
//! `usk`.
//!
//! # Example
//!
//! Encoded issuance (Def. "Credential base", correctness):
//!
//! ```
//! use ark_bls12_381::{Bls12_381, Fr};
//! use predicate_credential_system::cred::{self, CredentialBase};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type PS = cred::PS<Bls12_381>;
//! let mut rng = StdRng::seed_from_u64(1);
//! let pp = PS::setup(b"example deployment")?;
//! let (vk, sk) = PS::keygen(&pp, &mut rng);
//! let (usk, phi, rho) = (Fr::from(11u64), Fr::from(22u64), Fr::from(33u64));
//!
//! // user: C = Com(usk, φ; ρ)      signer: BlindIssue(sk, C, φ)      user: Unblind(.., ρ)
//! let c = PS::issuance_encoding(&pp, &vk, &usk, &phi, &rho)?;
//! let pre = PS::blind_issue(&pp, &sk, &c, &phi, &mut rng)?;
//! let m = PS::encode_message(&pp, &usk, &phi)?;
//! let cred = PS::unblind(&pp, &vk, &m, &pre, &rho)?;
//! assert!(PS::verify(&pp, &vk, &m, &cred));
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

use core::{fmt, marker::PhantomData};

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    CredentialBase, SigmaFriendlyCredentialBase, ensure_allocated, pairing_product_is_identity,
};
use crate::{
    error::Error,
    sample::nonzero_scalar,
    sigma::{GtEquation, LinearEquation, PairingRelation, ScalarVar, Witness},
};

/// The `Σ-PS` credential base over the pairing `E` (a marker type; all algorithms are
/// associated functions of [`CredentialBase`] and [`SigmaFriendlyCredentialBase`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PS<E: Pairing>(PhantomData<E>);

/// The signing key `sk = (x, y_1, y_2) ∈ Z_p × (Z_p^*)^2`. Secret: wiped on drop, not `Clone`,
/// redacted in `Debug`.
///
/// Decoding does not enforce `y_1, y_2 ≠ 0`; check the matching verification key with
/// [`PSVerificationKey::is_well_formed`] after reading a key back.
#[derive(Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct PSSigningKey<E: Pairing> {
    x: E::ScalarField,
    y1: E::ScalarField,
    y2: E::ScalarField,
}

impl<E: Pairing> PSSigningKey<E> {
    /// The verification key `vk = (X̃, Ỹ_1, Ỹ_2, Y_1) = (g̃^x, g̃^{y_1}, g̃^{y_2}, g_1^{y_1})` of this
    /// signing key (`KeyGen` step 2).
    #[must_use]
    pub fn verification_key(&self) -> PSVerificationKey<E> {
        let g2 = E::G2::generator();
        PSVerificationKey {
            x_tilde: g2 * self.x,
            y1_tilde: g2 * self.y1,
            y2_tilde: g2 * self.y2,
            y1: E::G1::generator() * self.y1,
        }
    }
}

impl<E: Pairing> fmt::Debug for PSSigningKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSSigningKey(<redacted>)")
    }
}

/// The verification key `vk = (X̃, Ỹ_1, Ỹ_2, Y_1)`. Only `Y_1 = g_1^{y_1}` lives in `G_1`; it is
/// the base of `usk` in the issuance encoding.
///
/// Implementation note: `g_1^x` is not part of `vk` and must stay secret; together with `Y_1` it
/// already yields signatures `(g_1^t, (g_1^x Y_1^{m_1})^t)` on every message `(m_1, 0)` (the unit
/// tests build one).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PSVerificationKey<E: Pairing> {
    /// `X̃ = g̃^x`.
    pub x_tilde: E::G2,
    /// `Ỹ_1 = g̃^{y_1}`.
    pub y1_tilde: E::G2,
    /// `Ỹ_2 = g̃^{y_2}`.
    pub y2_tilde: E::G2,
    /// `Y_1 = g_1^{y_1}`.
    pub y1: E::G1,
}

impl<E: Pairing> PSVerificationKey<E> {
    /// Whether the key binds both message components: `Ỹ_1 ≠ 1` and `Ỹ_2 ≠ 1`. These are the
    /// key-side public checks of the possession verifier (module docs, "Degenerate keys"); they
    /// cost no group operation.
    #[must_use]
    pub fn binds_the_message(&self) -> bool {
        !self.y1_tilde.is_zero() && !self.y2_tilde.is_zero()
    }

    /// Whether the key lies in the range of `KeyGen`, i.e. whether
    /// `vk = (g̃^x, g̃^{y_1}, g̃^{y_2}, g_1^{y_1})` for some `x ∈ Z_p` and `y_1, y_2 ∈ Z_p^*`:
    /// `Ỹ_1 ≠ 1`, `Ỹ_2 ≠ 1` and `e(Y_1, g̃) = e(g_1, Ỹ_1)` (the two copies of `y_1` agree, which
    /// also gives `Y_1 ≠ 1`). Exact in both directions, because `g_1` and `g̃` generate groups of
    /// prime order `p` and the pairing is non-degenerate. One pairing product; never panics.
    ///
    /// Implementation note, not an algorithm of the paper (module docs, "Degenerate keys").
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.binds_the_message()
            && pairing_product_is_identity::<E>(&[
                (self.y1, E::G2::generator()),
                (-E::G1::generator(), self.y1_tilde),
            ])
    }
}

/// A signing message `m = (m_1, m_2) ∈ M_Σ = Z_p^2`; the construction signs
/// `Enc_Σ(usk, φ) = (usk, φ)`. Secret (it contains `usk`): wiped on drop, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PSMessage<E: Pairing> {
    m1: E::ScalarField,
    m2: E::ScalarField,
}

impl<E: Pairing> PSMessage<E> {
    /// The message `(m_1, m_2)`.
    #[must_use]
    pub fn new(m1: E::ScalarField, m2: E::ScalarField) -> Self {
        Self { m1, m2 }
    }
}

impl<E: Pairing> fmt::Debug for PSMessage<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSMessage(<redacted>)")
    }
}

/// A credential `cred = (σ_1, σ_2)`: a PS signature, `σ_2 = σ_1^{x + y_1 m_1 + y_2 m_2}` with
/// `σ_1 ≠ 1`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PSCredential<E: Pairing> {
    /// `σ_1`.
    pub sigma_1: E::G1,
    /// `σ_2`.
    pub sigma_2: E::G1,
}

/// A blinded pre-credential `ĉred = (σ̂_1, σ̂_2)`, the output of `BlindIssue`: a PS signature up
/// to the factor `σ̂_1^ρ` that `Unblind` removes.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PSPreCredential<E: Pairing> {
    /// `σ̂_1 = g_1^u`.
    pub sigma_1: E::G1,
    /// `σ̂_2 = (g_1^x C g_1^{y_2 φ})^u`.
    pub sigma_2: E::G1,
}

/// A shown credential `cred* = σ' = (σ'_1, σ'_2) = (σ_1^r, σ_2^r)`, the output of `ReRand`.
///
/// `Σ-PS` is a *strong* base: `σ'` is itself a PS signature on the same message (hence the
/// conversion into [`PSCredential`]). A type of its own keeps a value that was published apart
/// from the holder's stored credential.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PSShownCredential<E: Pairing> {
    /// `σ'_1 = σ_1^r`.
    pub sigma_1: E::G1,
    /// `σ'_2 = σ_2^r`.
    pub sigma_2: E::G1,
}

impl<E: Pairing> From<PSShownCredential<E>> for PSCredential<E> {
    fn from(shown: PSShownCredential<E>) -> Self {
        Self {
            sigma_1: shown.sigma_1,
            sigma_2: shown.sigma_2,
        }
    }
}

impl<E: Pairing> CredentialBase for PS<E> {
    /// `pp_Σ` is empty: `g_1`, `g̃` are the standard generators of `E`.
    type PublicParams = ();
    type SigningKey = PSSigningKey<E>;
    type VerificationKey = PSVerificationKey<E>;
    /// `m_hid = usk`.
    type HiddenMessage = E::ScalarField;
    /// `m_pub = φ`.
    type PublicMessage = E::ScalarField;
    type Message = PSMessage<E>;
    /// `R_Σ = Z_p ∋ ρ`.
    type IssuanceState = E::ScalarField;
    /// `C_Σ = G_1 ∋ C = g_1^ρ Y_1^usk`.
    type IssuanceEncoding = E::G1;
    type Credential = PSCredential<E>;
    type PreCredential = PSPreCredential<E>;
    type ShownCredential = PSShownCredential<E>;
    /// `ω = ∅`.
    type ShowState = ();

    fn setup(_domain: &[u8]) -> Result<Self::PublicParams, Error> {
        Ok(())
    }

    /// `KeyGen(pp)` (box `Σ-PS`): `x ← Z_p` and `y_1, y_2 ← Z_p^*`, so that every generated key
    /// is well formed (module docs, "Degenerate keys").
    fn keygen<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::VerificationKey, Self::SigningKey) {
        // 1. x ← Z_p, y_1, y_2 ← Z_p^*, sk = (x, y_1, y_2)
        let sk = PSSigningKey {
            x: E::ScalarField::rand(rng),
            y1: nonzero_scalar(rng),
            y2: nonzero_scalar(rng),
        };
        // 2. vk = (X̃, Ỹ_1, Ỹ_2, Y_1)
        (sk.verification_key(), sk)
    }

    /// [`PSVerificationKey::is_well_formed`].
    fn is_well_formed_key(_pp: &Self::PublicParams, vk: &Self::VerificationKey) -> bool {
        vk.is_well_formed()
    }

    /// `Sign(sk, m = (m_1, m_2))` (box `Σ-PS`). Never fails: every pair of scalars is a message.
    ///
    /// Implementation note: `h ← G_1 \ {1}` is sampled as `h = g_1^t`, `t ← Z_p^*`, which is
    /// the uniform distribution on `G_1 \ {1}` because `g_1` generates the prime-order group.
    fn sign<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        m: &Self::Message,
        rng: &mut R,
    ) -> Result<Self::Credential, Error> {
        // 1. h ← G_1 \ {1}
        let h = E::G1::generator() * nonzero_scalar::<E::ScalarField, _>(rng);
        // 2. cred = (h, h^{x + y_1 m_1 + y_2 m_2})
        Ok(PSCredential {
            sigma_1: h,
            sigma_2: h * (sk.x + sk.y1 * m.m1 + sk.y2 * m.m2),
        })
    }

    /// `Verify(vk, m, (σ_1, σ_2)) = [σ_1 ≠ 1 ∧ e(σ_1, X̃ Ỹ_1^{m_1} Ỹ_2^{m_2}) = e(σ_2, g̃)]` (box
    /// `Σ-PS`), the pairing equation as ONE product
    /// `e(σ_1, X̃ Ỹ_1^{m_1} Ỹ_2^{m_2}) · e(σ_2^{-1}, g̃) = 1` (two Miller loops, one final
    /// exponentiation).
    fn verify(
        _pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m: &Self::Message,
        cred: &Self::Credential,
    ) -> bool {
        if cred.sigma_1.is_zero() {
            return false;
        }
        let key_side = vk.x_tilde + vk.y1_tilde * m.m1 + vk.y2_tilde * m.m2;
        pairing_product_is_identity::<E>(&[
            (cred.sigma_1, key_side),
            (-cred.sigma_2, E::G2::generator()),
        ])
    }

    /// `Enc_Σ(usk, φ) = (usk, φ)`. Never fails.
    fn encode_message(
        _pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
    ) -> Result<Self::Message, Error> {
        Ok(PSMessage::new(*m_hid, *m_pub))
    }

    /// `Com_vk(usk, φ; ρ) = g_1^ρ Y_1^usk`: a Pedersen commitment to `usk`, independent of `φ`.
    /// Never fails.
    fn issuance_encoding(
        _pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        m_hid: &Self::HiddenMessage,
        _m_pub: &Self::PublicMessage,
        r: &Self::IssuanceState,
    ) -> Result<Self::IssuanceEncoding, Error> {
        Ok(E::G1::generator() * *r + vk.y1 * *m_hid)
    }

    /// `ReRand(vk, m, (σ_1, σ_2))` (box `Σ-PS`). Keyless and message-independent.
    ///
    /// # Errors
    /// Implementation note: [`Error::InvalidCredential`] for `σ_1 = 1`. Such a credential never
    /// verifies and its shown form would be rejected by every possession verifier; the box has
    /// no `⊥` case because it only considers verifying credentials.
    fn rerand<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        _m: &Self::Message,
        cred: &Self::Credential,
        rng: &mut R,
    ) -> Result<(Self::ShownCredential, Self::ShowState), Error> {
        if cred.sigma_1.is_zero() {
            return Err(Error::InvalidCredential);
        }
        // 1. r ← Z_p^*, cred* = (σ_1^r, σ_2^r)
        let r: E::ScalarField = nonzero_scalar(rng);
        let shown = PSShownCredential {
            sigma_1: cred.sigma_1 * r,
            sigma_2: cred.sigma_2 * r,
        };
        // 2. return (cred*, ω = ∅)
        Ok((shown, ()))
    }

    /// `BlindIssue(sk, C, φ)` (box `Σ-PS`). The signer sees only `C` and `φ`; this is where `φ`
    /// enters the credential. Never fails: every element of `G_1` is an issuance encoding.
    fn blind_issue<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        sk: &Self::SigningKey,
        c: &Self::IssuanceEncoding,
        m_pub: &Self::PublicMessage,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error> {
        // 1. parse C = g_1^ρ Y_1^usk, u ← Z_p^*
        let u: E::ScalarField = nonzero_scalar(rng);
        // 2. ĉred = (g_1^u, (g_1^x C g_1^{y_2 φ})^u)
        let g1 = E::G1::generator();
        Ok(PSPreCredential {
            sigma_1: g1 * u,
            sigma_2: (g1 * (sk.x + sk.y2 * *m_pub) + *c) * u,
        })
    }

    /// `Unblind(vk, (usk, φ), (σ̂_1, σ̂_2), ρ) = (σ̂_1, σ̂_2 / σ̂_1^ρ)` (box `Σ-PS`). Deterministic;
    /// as in the box, the result is not verified here (the caller runs `Verify`).
    ///
    /// # Errors
    /// Implementation note: [`Error::InvalidPreCredential`] for `σ̂_1 = 1`, which an honest
    /// signer (`u ≠ 0`) never outputs and which cannot unblind to a verifying credential.
    fn unblind(
        _pp: &Self::PublicParams,
        _vk: &Self::VerificationKey,
        _m: &Self::Message,
        pre: &Self::PreCredential,
        r: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error> {
        if pre.sigma_1.is_zero() {
            return Err(Error::InvalidPreCredential);
        }
        Ok(PSCredential {
            sigma_1: pre.sigma_1,
            sigma_2: pre.sigma_2 - pre.sigma_1 * *r,
        })
    }
}

impl<E: Pairing> SigmaFriendlyCredentialBase<E> for PS<E> {
    /// `m_aux = ∅`.
    type Aux = ();
    /// `C` travels inside `π`.
    type WireEncoding = E::G1;

    const REQUIRES_DLOG_IDENTITY: bool = false;
    /// The witness of `R_Possess` is `usk` alone.
    const POSSESSION_VARIABLES: usize = 0;
    /// The opening clause adds `ρ`.
    const ISSUANCE_VARIABLES: usize = 1;

    fn hidden_message(usk: &E::ScalarField, _aux: &Self::Aux) -> Self::HiddenMessage {
        *usk
    }

    fn split_hidden_message(m_hid: &Self::HiddenMessage) -> (E::ScalarField, Self::Aux) {
        (*m_hid, ())
    }

    /// `(m_aux, ρ) = (∅, r)`, `r ← Z_p` (§5.1, the display before the protocol box).
    fn sample_issuance<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::Aux, Self::IssuanceState) {
        ((), E::ScalarField::rand(rng))
    }

    fn encoding_to_wire(c: &Self::IssuanceEncoding) -> Self::WireEncoding {
        *c
    }

    /// Every element of `G_1`, the identity included, is `g_1^ρ Y_1^usk` for some `(usk, ρ)`,
    /// so nothing is rejected here; knowledge of an opening is what `π_0` proves.
    fn encoding_from_wire(
        _pp: &Self::PublicParams,
        wire: &Self::WireEncoding,
        _id: &E::G1,
    ) -> Option<Self::IssuanceEncoding> {
        Some(*wire)
    }

    /// `Possess` step 1 (box `Σ-PS`): "the verifier rejects if `σ'_1 = 1`". With `σ'_1 = 1` (and
    /// `σ'_2 = 1`) the clause below reads `1^usk = 1` and holds for every `usk`.
    ///
    /// Implementation note: the same happens for ANY `σ'` when `Ỹ_1 = 1`, and the clause does not
    /// depend on `φ` when `Ỹ_2 = 1`, so both are rejected as well (module docs, "Degenerate
    /// keys"; [`PSVerificationKey::binds_the_message`]).
    fn verify_possess_public(
        _pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        _m_pub: &E::ScalarField,
    ) -> bool {
        vk.binds_the_message() && !shown.sigma_1.is_zero()
    }

    /// `Possess` step 2 (box `Σ-PS`): the representation
    /// `e(σ'_1, Ỹ_1)^usk = e(σ'_2, g̃) e(σ'_1, X̃ Ỹ_2^φ)^{-1}` as one lazy `G_T` clause with base
    /// `[(σ'_1, Ỹ_1)]` and target `[(σ'_2, g̃), (σ'_1^{-1}, X̃ Ỹ_2^φ)]`. The witness is `usk` alone
    /// (`ω = ∅`), so no variable is allocated.
    fn possession_clauses(
        _pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        shown: &Self::ShownCredential,
        m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        rel.add_gt(GtEquation::new(
            vec![(usk, vec![(shown.sigma_1, vk.y1_tilde)])],
            vec![
                (shown.sigma_2, E::G2::generator()),
                (-shown.sigma_1, vk.x_tilde + vk.y2_tilde * *m_pub),
            ],
        ))?;
        Ok(Vec::new())
    }

    fn possession_witness(
        _m_hid: &Self::HiddenMessage,
        _show_state: &Self::ShowState,
    ) -> Witness<E::ScalarField> {
        Witness::new()
    }

    /// The opening clause `C = g_1^ρ Y_1^usk` of `R_issue` (§5.1): one `G_1` equation with bases
    /// `g_1` (fresh variable `ρ`) and `Y_1` (shared variable `usk`). Independent of `φ`.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`. Implementation note:
    /// [`Error::InvalidKey`] for `Y_1 = 1`, under which `C` would not commit to `usk` at all.
    /// The relation is left untouched on error.
    fn issuance_clauses(
        _pp: &Self::PublicParams,
        vk: &Self::VerificationKey,
        c: &Self::IssuanceEncoding,
        _m_pub: &E::ScalarField,
        rel: &mut PairingRelation<E>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        if vk.y1.is_zero() {
            return Err(Error::InvalidKey);
        }
        // BEFORE `ρ` is allocated: a foreign handle with the index `ρ` is about to get would
        // alias it, and the clause would read `C = (g_1 Y_1)^ρ` without any error.
        ensure_allocated(rel, usk)?;
        let rho = rel.alloc_scalar();
        rel.add_g1(LinearEquation::new(
            vec![(rho, E::G1::generator()), (usk, vk.y1)],
            *c,
        ))?;
        Ok(vec![rho])
    }

    fn issuance_witness(
        _m_hid: &Self::HiddenMessage,
        r: &Self::IssuanceState,
    ) -> Witness<E::ScalarField> {
        Witness::from(vec![*r])
    }
}

/// TEST HELPER (crate tests and the cargo feature `test-utils`): the credential-free forgeries
/// of `Σ-PS` for [`public_base_flow`](super::conformance::public_base_flow), attack A1 of the
/// reference implementations. For `σ' = (1, 1)` the possession clause reads `1^K = 1` and holds
/// for every forged key `K`; `(1, σ'_2)` with `σ'_2 ≠ 1` is degenerate too, but has no witness.
/// Only the public check `σ'_1 ≠ 1` rejects the former.
#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn credential_free_forgeries<E: Pairing>(
    _pp: &(),
    _vk: &PSVerificationKey<E>,
    _phi: &E::ScalarField,
    _forged_key: &E::ScalarField,
) -> Vec<super::conformance::Forgery<PSShownCredential<E>, E::ScalarField>> {
    [E::G1::zero(), E::G1::generator()]
        .into_iter()
        .map(|sigma_2| super::conformance::Forgery {
            shown: PSShownCredential {
                sigma_1: E::G1::zero(),
                sigma_2,
            },
            extra_witness: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Projective};
    use ark_bn254::Bn254;
    use ark_ff::{Field, One};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        cred::{
            conformance::{FlowReport, public_base_flow},
            issuance_witness_vector, possess, possess_context, possession_relation,
            possession_witness_vector, verify_possess,
        },
        hash::{Transcript, bls12_381::G1Hasher, h0_id, h0_identity_point, h0_predicate},
        kiprf::{DDH, KIPRF, PCSTag, SigmaFriendlyKIPRF},
        serialization::WireFormat,
        sigma::{FSProof, LinearRelation, commit, extract, fiat_shamir, respond},
    };

    type E = Bls12_381;
    type G1 = G1Projective;
    type PS = crate::cred::PS<E>;
    type Tag = DDH<G1, G1Hasher>;

    const DOMAIN: &[u8] = b"sigma-ps-unit-tests";

    fn tag() -> Tag {
        Tag::setup(DOMAIN, h0_identity_point(DOMAIN)).unwrap()
    }

    fn phi(label: &[u8]) -> Fr {
        h0_predicate(DOMAIN, label)
    }

    fn msg(usk: Fr, phi: Fr) -> PSMessage<E> {
        PS::encode_message(&(), &usk, &phi).unwrap()
    }

    /// A holder `(usk, φ, cred)` with a directly signed credential.
    fn holder(
        tag: &Tag,
        sk: &PSSigningKey<E>,
        label: &[u8],
        rng: &mut StdRng,
    ) -> (Fr, Fr, PSCredential<E>) {
        let usk = tag.keygen(rng);
        let phi = phi(label);
        let cred = PS::sign(&(), sk, &msg(usk, phi), rng).unwrap();
        (usk, phi, cred)
    }

    // ----- a miniature of the attestation of §5.1: R_att = R_Possess ∧ R_Tag, shared usk ---------

    struct Att {
        t: G1,
        shown: PSShownCredential<E>,
        phi: Fr,
        pi: FSProof<Fr>,
    }

    /// `R_att` for the public statement `(vk, cred*, φ, T, s)`: the possession clause and the tag
    /// clause over ONE variable `usk`.
    fn att_relation(
        tag: &Tag,
        vk: &PSVerificationKey<E>,
        shown: &PSShownCredential<E>,
        phi: &Fr,
        t: &G1,
        s: &Fr,
    ) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        let usk = rel.alloc_scalar();
        let extra = PS::possession_clauses(&(), vk, shown, phi, &mut rel, usk).unwrap();
        assert!(extra.is_empty());
        for eq in tag.tag_equations(usk, t, s) {
            rel.add_g1(eq).unwrap();
        }
        rel
    }

    /// `ctx_j = (pp, hvk, id, φ_j, T_j, cred*_j)`, as in `Attest` step 10.
    fn att_ctx(
        tag: &Tag,
        vk: &PSVerificationKey<E>,
        id: &G1,
        phi: &Fr,
        t: &G1,
        shown: &PSShownCredential<E>,
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
        vk: &PSVerificationKey<E>,
        (usk, phi, cred): (&Fr, &Fr, &PSCredential<E>),
        tag_key: &Fr,
        id: &G1,
        rng: &mut StdRng,
    ) -> Result<Att, Error> {
        let s: Fr = h0_id(DOMAIN, id)?;
        let t = tag.eval(tag_key, &s).ok_or(Error::UndefinedTag)?;
        let (shown, omega) = PS::rerand(&(), vk, &msg(*usk, *phi), cred, rng)?;
        let rel = att_relation(tag, vk, &shown, phi, &t, &s);
        let w = possession_witness_vector::<E, PS>(usk, &omega);
        let pi = fiat_shamir::prove(&rel, &w, &att_ctx(tag, vk, id, phi, &t, &shown), rng)?;
        Ok(Att {
            t,
            shown,
            phi: *phi,
            pi,
        })
    }

    /// `VerifyAtt`: `ValidTag`, the public checks of `VerifyPossess`, then Fiat-Shamir.
    fn verify_att(tag: &Tag, vk: &PSVerificationKey<E>, id: &G1, att: &Att) -> bool {
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        tag.valid_tag(&att.t, &s)
            && PS::verify_possess_public(&(), vk, &att.shown, &att.phi)
            && fiat_shamir::verify(
                &att_relation(tag, vk, &att.shown, &att.phi, &att.t, &s),
                &att_ctx(tag, vk, id, &att.phi, &att.t, &att.shown),
                &att.pi,
            )
    }

    // ----- SIG = (KeyGen, Sign, Verify) ----------------------------------------------------------

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(0x9501);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        assert_eq!(sk.verification_key(), vk);
        for _ in 0..4 {
            let (m1, m2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let cred = PS::sign(&(), &sk, &msg(m1, m2), &mut rng).unwrap();
            assert!(!cred.sigma_1.is_zero());
            assert_eq!(
                cred.sigma_2,
                cred.sigma_1 * (sk.x + sk.y1 * m1 + sk.y2 * m2)
            );
            assert!(PS::verify(&(), &vk, &msg(m1, m2), &cred));
        }
        // edge messages of Z_p^2
        for (m1, m2) in [
            (Fr::zero(), Fr::zero()),
            (Fr::one(), Fr::zero()),
            (Fr::zero(), -Fr::one()),
        ] {
            let cred = PS::sign(&(), &sk, &msg(m1, m2), &mut rng).unwrap();
            assert!(PS::verify(&(), &vk, &msg(m1, m2), &cred));
        }
        // signing is randomized
        let m = msg(Fr::from(7u64), Fr::from(8u64));
        assert_ne!(
            PS::sign(&(), &sk, &m, &mut rng).unwrap(),
            PS::sign(&(), &sk, &m, &mut rng).unwrap()
        );
    }

    #[test]
    fn verification_rejects_wrong_message_and_wrong_key() {
        let mut rng = StdRng::seed_from_u64(0x9502);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let cred = PS::sign(&(), &sk, &msg(usk, phi), &mut rng).unwrap();
        assert!(PS::verify(&(), &vk, &msg(usk, phi), &cred));

        // wrong message: either component, swapped components, neighbours
        assert!(!PS::verify(&(), &vk, &msg(usk + Fr::one(), phi), &cred));
        assert!(!PS::verify(&(), &vk, &msg(usk, phi + Fr::one()), &cred));
        assert!(!PS::verify(&(), &vk, &msg(phi, usk), &cred));
        assert!(!PS::verify(&(), &vk, &msg(Fr::zero(), Fr::zero()), &cred));
        assert!(!PS::verify(
            &(),
            &vk,
            &msg(Fr::rand(&mut rng), Fr::rand(&mut rng)),
            &cred
        ));

        // wrong key: an independent key, and the right key with one component replaced
        let (other_vk, _) = PS::keygen(&(), &mut rng);
        assert!(!PS::verify(&(), &other_vk, &msg(usk, phi), &cred));
        for i in 0..3 {
            let mut bad = vk.clone();
            match i {
                0 => bad.x_tilde = other_vk.x_tilde,
                1 => bad.y1_tilde = other_vk.y1_tilde,
                _ => bad.y2_tilde = other_vk.y2_tilde,
            }
            assert!(
                !PS::verify(&(), &bad, &msg(usk, phi), &cred),
                "component {i}"
            );
        }
    }

    #[test]
    fn verification_rejects_tampered_signatures() {
        let mut rng = StdRng::seed_from_u64(0x9503);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = PS::sign(&(), &sk, &m, &mut rng).unwrap();
        let g = G1::generator();
        let r = Fr::rand(&mut rng);
        let tampered = [
            (cred.sigma_1 + g, cred.sigma_2),
            (cred.sigma_1, cred.sigma_2 + g),
            (cred.sigma_1 * r, cred.sigma_2),
            (cred.sigma_1, cred.sigma_2 * r),
            (cred.sigma_2, cred.sigma_1),
            (-cred.sigma_1, cred.sigma_2),
            (cred.sigma_1, G1::zero()),
            (G1::rand(&mut rng), G1::rand(&mut rng)),
        ];
        for (i, (sigma_1, sigma_2)) in tampered.into_iter().enumerate() {
            let bad = PSCredential { sigma_1, sigma_2 };
            assert!(!PS::verify(&(), &vk, &m, &bad), "tampering {i}");
        }
        // control: scaling BOTH components is re-randomization and still verifies
        let scaled = PSCredential {
            sigma_1: cred.sigma_1 * r,
            sigma_2: cred.sigma_2 * r,
        };
        assert!(PS::verify(&(), &vk, &m, &scaled));
    }

    /// `σ_1 = 1` is rejected by `Verify` AND by the possession verifier, although the pairing
    /// equation holds for `(1, 1)` under every key and message.
    #[test]
    fn identity_sigma_1_is_rejected_everywhere() {
        let mut rng = StdRng::seed_from_u64(0x9504);
        let (vk, _sk) = PS::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);

        let key_side = vk.x_tilde + vk.y1_tilde * usk + vk.y2_tilde * phi;
        assert!(pairing_product_is_identity::<E>(&[
            (G1::zero(), key_side),
            (-G1::zero(), <E as Pairing>::G2::generator()),
        ]));
        let degenerate = PSCredential::<E> {
            sigma_1: G1::zero(),
            sigma_2: G1::zero(),
        };
        assert!(!PS::verify(&(), &vk, &m, &degenerate));
        let half = PSCredential::<E> {
            sigma_1: G1::zero(),
            sigma_2: G1::rand(&mut rng),
        };
        assert!(!PS::verify(&(), &vk, &m, &half));

        for sigma_2 in [G1::zero(), G1::rand(&mut rng)] {
            let shown = PSShownCredential::<E> {
                sigma_1: G1::zero(),
                sigma_2,
            };
            assert!(!PS::verify_possess_public(&(), &vk, &shown, &phi));
        }
        // σ'_2 = 1 alone is not a public rejection reason (box: only σ'_1); the clause is then
        // simply false for the honest usk.
        let shown = PSShownCredential::<E> {
            sigma_1: G1::generator(),
            sigma_2: G1::zero(),
        };
        assert!(PS::verify_possess_public(&(), &vk, &shown, &phi));

        // holder-side face checks
        assert_eq!(
            PS::rerand(&(), &vk, &m, &degenerate, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
        let pre = PSPreCredential::<E> {
            sigma_1: G1::zero(),
            sigma_2: G1::generator(),
        };
        assert_eq!(
            PS::unblind(&(), &vk, &m, &pre, &Fr::one()).unwrap_err(),
            Error::InvalidPreCredential
        );
    }

    // ----- encoded issuance ----------------------------------------------------------------------

    /// Def. "Credential base", correctness: `Unblind(BlindIssue(Com(m_hid, φ; ρ), φ), ρ)` verifies
    /// as a signature on `Enc_Σ(m_hid, φ)`; and it is exactly a fresh signature with `h = g_1^u`.
    #[test]
    fn blind_issuance_then_unblind_is_a_signature_on_the_encoded_message() {
        let mut rng = StdRng::seed_from_u64(0x9505);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        for _ in 0..4 {
            let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let (aux, rho) = PS::sample_issuance(&(), &mut rng);
            let m_hid = PS::hidden_message(&usk, &aux);
            assert_eq!(PS::split_hidden_message(&m_hid), (usk, ()));
            let c = PS::issuance_encoding(&(), &vk, &m_hid, &phi, &rho).unwrap();
            assert_eq!(c, G1::generator() * rho + vk.y1 * usk);
            let wire = PS::encoding_to_wire(&c);
            let c_helper = PS::encoding_from_wire(&(), &wire, &G1::zero()).unwrap();
            assert_eq!(c_helper, c);

            let pre = PS::blind_issue(&(), &sk, &c_helper, &phi, &mut rng).unwrap();
            let m = PS::encode_message(&(), &m_hid, &phi).unwrap();
            // the pre-credential itself is not a signature on m (it is blinded by ρ)
            let pre_as_cred = PSCredential::<E> {
                sigma_1: pre.sigma_1,
                sigma_2: pre.sigma_2,
            };
            assert!(!PS::verify(&(), &vk, &m, &pre_as_cred));

            let cred = PS::unblind(&(), &vk, &m, &pre, &rho).unwrap();
            assert!(PS::verify(&(), &vk, &m, &cred));
            // the fresh-signature form: σ_2 = σ_1^{x + y_1 usk + y_2 φ}, σ_1 = g_1^u ≠ 1
            assert_eq!(cred.sigma_1, pre.sigma_1);
            assert!(!cred.sigma_1.is_zero());
            assert_eq!(
                cred.sigma_2,
                cred.sigma_1 * (sk.x + sk.y1 * usk + sk.y2 * phi)
            );

            // φ is injected exactly once: the credential is on (usk, φ) and on nothing nearby
            assert!(!PS::verify(&(), &vk, &msg(usk, phi + phi), &cred));
            assert!(!PS::verify(&(), &vk, &msg(usk, Fr::zero()), &cred));
            assert!(!PS::verify(&(), &vk, &msg(usk + Fr::one(), phi), &cred));
        }
    }

    #[test]
    fn unblinding_with_a_wrong_rho_does_not_verify() {
        let mut rng = StdRng::seed_from_u64(0x9506);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let c = PS::issuance_encoding(&(), &vk, &usk, &phi, &rho).unwrap();
        let pre = PS::blind_issue(&(), &sk, &c, &phi, &mut rng).unwrap();
        let m = msg(usk, phi);
        assert!(PS::verify(
            &(),
            &vk,
            &m,
            &PS::unblind(&(), &vk, &m, &pre, &rho).unwrap()
        ));
        for wrong in [rho + Fr::one(), -rho, Fr::zero(), Fr::rand(&mut rng)] {
            let cred = PS::unblind(&(), &vk, &m, &pre, &wrong).unwrap();
            assert!(!PS::verify(&(), &vk, &m, &cred));
        }
        // issued under another φ than the one the user expects
        let pre = PS::blind_issue(&(), &sk, &c, &(phi + Fr::one()), &mut rng).unwrap();
        let cred = PS::unblind(&(), &vk, &m, &pre, &rho).unwrap();
        assert!(!PS::verify(&(), &vk, &m, &cred));
        // issued by another signer
        let (_, other_sk) = PS::keygen(&(), &mut rng);
        let pre = PS::blind_issue(&(), &other_sk, &c, &phi, &mut rng).unwrap();
        let cred = PS::unblind(&(), &vk, &m, &pre, &rho).unwrap();
        assert!(!PS::verify(&(), &vk, &m, &cred));
    }

    // ----- ReRand --------------------------------------------------------------------------------

    /// Strong re-randomization (Def. "Credential base", show unlinkability): `cred*` verifies on
    /// the same message and differs from `cred`. (That its distribution is independent of
    /// `cred` is the Lemma's argument, not something a test can show.)
    #[test]
    fn rerandomized_credential_verifies_and_differs() {
        let mut rng = StdRng::seed_from_u64(0x9507);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = PS::sign(&(), &sk, &m, &mut rng).unwrap();

        let (shown, ()) = PS::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        assert!(!shown.sigma_1.is_zero());
        assert_ne!(shown.sigma_1, cred.sigma_1);
        assert_ne!(shown.sigma_2, cred.sigma_2);
        let as_cred = PSCredential::from(shown.clone());
        assert!(PS::verify(&(), &vk, &m, &as_cred));
        assert!(PS::verify_possess_public(&(), &vk, &shown, &phi));

        // fresh coins, fresh encoding; and a shown credential can be re-randomized again
        let (shown2, ()) = PS::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        assert_ne!(shown2, shown);
        let (shown3, ()) = PS::rerand(&(), &vk, &m, &as_cred, &mut rng).unwrap();
        assert!(PS::verify(&(), &vk, &m, &shown3.into()));
    }

    // ----- Possess: R_Possess ∧ R_Tag with a shared usk ------------------------------------------

    #[test]
    fn possession_with_tag_clause_is_complete() {
        let mut rng = StdRng::seed_from_u64(0x9508);
        let tag = tag();
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);

        let att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));
        // one witness coordinate, one response: |att| = 3 G_1 + 3 Z_p
        assert_eq!(att.pi.responses.len(), 1);
        assert_eq!(att.t, tag.eval(&usk, &h0_id(DOMAIN, &id).unwrap()).unwrap());

        // a credential obtained through blind issuance attests just the same
        let rho = Fr::rand(&mut rng);
        let c = PS::issuance_encoding(&(), &vk, &usk, &phi, &rho).unwrap();
        let pre = PS::blind_issue(&(), &sk, &c, &phi, &mut rng).unwrap();
        let issued = PS::unblind(&(), &vk, &msg(usk, phi), &pre, &rho).unwrap();
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
        let mut rng = StdRng::seed_from_u64(0x9509);
        let tag = tag();
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let other_key = tag.keygen(&mut rng);

        // honest prover code, dishonest tag key
        assert_eq!(
            attest(&tag, &vk, (&usk, &phi, &cred), &other_key, &id, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );

        // neither candidate witness satisfies the conjunction
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let t = tag.eval(&other_key, &s).unwrap();
        let (shown, ()) = PS::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
        let rel = att_relation(&tag, &vk, &shown, &phi, &t, &s);
        assert!(!rel.is_satisfied_by(&[usk])); // satisfies possession, not the tag clause
        assert!(!rel.is_satisfied_by(&[other_key])); // satisfies the tag clause, not possession
        for w in [usk, other_key] {
            assert_eq!(
                fiat_shamir::prove(&rel, &[w], b"ctx", &mut rng),
                Err(Error::WitnessDoesNotSatisfyRelation)
            );
        }
        // control: with the right tag the same relation shape is satisfied by usk
        let t = tag.eval(&usk, &s).unwrap();
        assert!(att_relation(&tag, &vk, &shown, &phi, &t, &s).is_satisfied_by(&[usk]));

        // a verifying attestation does not survive swapping in the other key's tag
        let mut att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        att.t = tag.eval(&other_key, &s).unwrap();
        assert!(!verify_att(&tag, &vk, &id, &att));
    }

    #[test]
    fn proof_for_phi_does_not_verify_for_another_phi() {
        let mut rng = StdRng::seed_from_u64(0x950a);
        let tag = tag();
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let mut att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));

        let other_phi = self::phi(b"f'");
        assert_ne!(other_phi, phi);
        // (1) relation level, SAME context bytes: φ sits in the target X̃ Ỹ_2^φ of the clause
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let ctx = att_ctx(&tag, &vk, &id, &phi, &att.t, &att.shown);
        let rel = att_relation(&tag, &vk, &att.shown, &phi, &att.t, &s);
        assert!(fiat_shamir::verify(&rel, &ctx, &att.pi));
        let rel_other = att_relation(&tag, &vk, &att.shown, &other_phi, &att.t, &s);
        assert!(!fiat_shamir::verify(&rel_other, &ctx, &att.pi));
        assert!(!rel_other.is_satisfied_by(&[usk]));
        // (2) attestation level
        att.phi = other_phi;
        assert!(!verify_att(&tag, &vk, &id, &att));
        // (3) the honest prover cannot claim another φ for its credential either
        assert_eq!(
            attest(&tag, &vk, (&usk, &other_phi, &cred), &usk, &id, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );
    }

    #[test]
    fn attestation_is_bound_to_identifier_key_and_shown_credential() {
        let mut rng = StdRng::seed_from_u64(0x950b);
        let tag = tag();
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let att = attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&tag, &vk, &id, &att));

        // another identifier (non-transferability), another helper key
        assert!(!verify_att(&tag, &vk, &(id + G1::generator()), &att));
        let (other_vk, _) = PS::keygen(&(), &mut rng);
        assert!(!verify_att(&tag, &other_vk, &id, &att));

        // re-randomizing cred* inside a finished attestation (the statement is hashed)
        let r = Fr::rand(&mut rng);
        let mauled = Att {
            shown: PSShownCredential {
                sigma_1: att.shown.sigma_1 * r,
                sigma_2: att.shown.sigma_2 * r,
            },
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
        let mut rng = StdRng::seed_from_u64(0x950c);
        let tag = tag();
        let (vk, _sk) = PS::keygen(&(), &mut rng);
        let (_, rogue_sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &rogue_sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        assert_eq!(
            attest(&tag, &vk, (&usk, &phi, &cred), &usk, &id, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );
    }

    /// Attack A1 (credential-free attestation with a degenerate shown credential): for
    /// `σ' = (1, 1)` the possession clause reads `1^usk = 1`, so a party WITHOUT any credential
    /// satisfies `R_att`'s equations under a fresh key and produces a Fiat-Shamir proof that
    /// verifies. Only the public check `σ'_1 ≠ 1` of `VerifyPossess` stops it.
    #[test]
    fn degenerate_shown_credential_is_rejected_although_its_clause_is_satisfiable() {
        let mut rng = StdRng::seed_from_u64(0x950d);
        let tag = tag();
        let (vk, _sk) = PS::keygen(&(), &mut rng);
        let phi = phi(b"f");
        let id = G1::generator() * tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();

        let forged_key = tag.keygen(&mut rng); // no credential exists for this key
        let t = tag.eval(&forged_key, &s).unwrap();
        let shown = PSShownCredential::<E> {
            sigma_1: G1::zero(),
            sigma_2: G1::zero(),
        };
        let rel = att_relation(&tag, &vk, &shown, &phi, &t, &s);
        // the algebra is satisfied ...
        assert!(rel.is_satisfied_by(&[forged_key]));
        let ctx = att_ctx(&tag, &vk, &id, &phi, &t, &shown);
        let pi = fiat_shamir::prove(&rel, &[forged_key], &ctx, &mut rng).unwrap();
        // ... the bare Fiat-Shamir proof verifies ...
        assert!(fiat_shamir::verify(&rel, &ctx, &pi));
        // ... the tag is perfectly valid ...
        assert!(tag.valid_tag(&t, &s));
        // ... and the attestation is rejected, by the public check alone.
        assert!(!PS::verify_possess_public(&(), &vk, &shown, &phi));
        let att = Att { t, shown, phi, pi };
        assert!(!verify_att(&tag, &vk, &id, &att));
    }

    /// Special soundness with a shared coordinate: rewinding the prover of `R_att` yields ONE
    /// `usk`, which opens the tag AND makes `cred*` a valid signature on `(usk, φ)`.
    #[test]
    fn extractor_recovers_the_shared_usk() {
        let mut rng = StdRng::seed_from_u64(0x950e);
        let tag = tag();
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        let id = G1::generator() * tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let t = tag.eval(&usk, &s).unwrap();
        let (shown, ()) = PS::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
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
        assert!(PS::verify(&(), &vk, &msg(extracted[0], phi), &shown.into()));
    }

    // ----- the stand-alone Possess / VerifyPossess of cred ----------------------------

    #[test]
    fn standalone_possession_proof() {
        let mut rng = StdRng::seed_from_u64(0x950f);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = PS::sign(&(), &sk, &m, &mut rng).unwrap();
        let (shown, omega) = PS::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();

        let (rel, var) = possession_relation::<E, PS>(&(), &vk, &shown, &phi).unwrap();
        assert_eq!((var.index(), rel.num_scalars()), (0, 1));
        assert_eq!(rel.gt_equations().len(), 1);
        assert!(rel.g1_equations().is_empty() && rel.g2_equations().is_empty());
        assert!(rel.is_satisfied_by(&[usk]));
        assert!(!rel.is_satisfied_by(&[usk + Fr::one()]));

        let pi =
            possess::<E, PS, _>(&(), &vk, &shown, &phi, &usk, &omega, b"ctx", &mut rng).unwrap();
        assert!(verify_possess::<E, PS>(&(), &vk, &shown, &phi, b"ctx", &pi));
        assert!(!verify_possess::<E, PS>(
            &(),
            &vk,
            &shown,
            &phi,
            b"ctx2",
            &pi
        ));
        assert!(!verify_possess::<E, PS>(
            &(),
            &vk,
            &shown,
            &(phi + Fr::one()),
            b"ctx",
            &pi
        ));
        let (other_vk, _) = PS::keygen(&(), &mut rng);
        assert!(!verify_possess::<E, PS>(
            &(),
            &other_vk,
            &shown,
            &phi,
            b"ctx",
            &pi
        ));
        let (shown2, ()) = PS::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        assert!(!verify_possess::<E, PS>(
            &(),
            &vk,
            &shown2,
            &phi,
            b"ctx",
            &pi
        ));

        // wrong hidden message: no proof
        assert_eq!(
            possess::<E, PS, _>(
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
        // degenerate cred*: refused by the prover, rejected by the verifier
        let degenerate = PSShownCredential::<E> {
            sigma_1: G1::zero(),
            sigma_2: G1::zero(),
        };
        assert_eq!(
            possess::<E, PS, _>(&(), &vk, &degenerate, &phi, &usk, &omega, b"ctx", &mut rng),
            Err(Error::InvalidCredential)
        );
        // A cheating prover needs no credential for the degenerate statement: ANY scalar is a
        // witness, and it can run Fiat-Shamir under exactly the context the verifier derives.
        // Only the public checks of VerifyPossess stand between this proof and acceptance.
        let (rel, _) = possession_relation::<E, PS>(&(), &vk, &degenerate, &phi).unwrap();
        let forged_witness = [Fr::rand(&mut rng)];
        assert!(rel.is_satisfied_by(&forged_witness));
        let ctx = possess_context::<E, PS>(&(), &vk, &degenerate, &phi, b"ctx").unwrap();
        let forged = fiat_shamir::prove(&rel, &forged_witness, &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &forged));
        assert!(!verify_possess::<E, PS>(
            &(),
            &vk,
            &degenerate,
            &phi,
            b"ctx",
            &forged
        ));
    }

    // ----- R_issue: C = Com(usk, φ; ρ) ∧ id ∧ T_0, shared usk ------------------------------------

    fn issue_relation(
        tag: &Tag,
        vk: &PSVerificationKey<E>,
        c: &G1,
        phi: &Fr,
        id: &G1,
        t0: &G1,
    ) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        let usk = rel.alloc_scalar();
        let extra = PS::issuance_clauses(&(), vk, c, phi, &mut rel, usk).unwrap();
        assert_eq!(extra.len(), 1);
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

    #[test]
    fn issuance_opening_clause_shares_usk_with_the_tag_clauses() {
        let mut rng = StdRng::seed_from_u64(0x9510);
        let tag = tag();
        let (vk, _sk) = PS::keygen(&(), &mut rng);
        let phi = phi(b"f");
        let usk = tag.keygen(&mut rng);
        let c0 = *tag.identity_point().unwrap();
        let id = tag.eval(&usk, &c0).unwrap();
        let t0 = tag.eval(&usk, &h0_id(DOMAIN, &id).unwrap()).unwrap();

        let (aux, rho) = PS::sample_issuance(&(), &mut rng);
        let m_hid = PS::hidden_message(&usk, &aux);
        let c = PS::issuance_encoding(&(), &vk, &m_hid, &phi, &rho).unwrap();
        let rel = issue_relation(&tag, &vk, &c, &phi, &id, &t0);
        assert_eq!(rel.num_scalars(), 2);
        assert_eq!(rel.g1_equations().len(), 3);

        let w = issuance_witness_vector::<E, PS>(&m_hid, &rho);
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
        // a commitment to ANOTHER key cannot be opened next to this id: usk is one variable
        let other = tag.keygen(&mut rng);
        let c_other = PS::issuance_encoding(&(), &vk, &other, &phi, &rho).unwrap();
        let rel_other = issue_relation(&tag, &vk, &c_other, &phi, &id, &t0);
        assert!(!rel_other.is_satisfied_by(&[usk, rho]));
        assert!(!rel_other.is_satisfied_by(&[other, rho]));
        // the proof is bound to C, id and T_0
        assert!(!fiat_shamir::verify(&rel_other, b"ctx0", &pi0));
        let rel_id = issue_relation(&tag, &vk, &c, &phi, &(id + id), &t0);
        assert!(!fiat_shamir::verify(&rel_id, b"ctx0", &pi0));
        let rel_t0 = issue_relation(&tag, &vk, &c, &phi, &id, &(t0 + t0));
        assert!(!fiat_shamir::verify(&rel_t0, b"ctx0", &pi0));
    }

    #[test]
    fn clauses_reject_foreign_variables() {
        let mut rng = StdRng::seed_from_u64(0x9511);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let cred = PS::sign(&(), &sk, &msg(Fr::one(), Fr::one()), &mut rng).unwrap();
        let shown = PSShownCredential::<E> {
            sigma_1: cred.sigma_1,
            sigma_2: cred.sigma_2,
        };
        let foreign = PairingRelation::<E>::new().alloc_scalars(3)[2];
        let mut rel = PairingRelation::<E>::new();
        rel.alloc_scalar();
        assert_eq!(
            PS::possession_clauses(&(), &vk, &shown, &Fr::one(), &mut rel, foreign),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 1
            })
        );
        assert!(rel.gt_equations().is_empty());
        let mut rel = PairingRelation::<E>::new();
        assert!(matches!(
            PS::issuance_clauses(&(), &vk, &cred.sigma_1, &Fr::one(), &mut rel, foreign),
            Err(Error::UnallocatedVariable { index: 2, .. })
        ));
        assert!(rel.g1_equations().is_empty());

        // The aliasing case: a foreign handle with exactly the index that `ρ` is about to get.
        // Checked only when the equation is added, it would pass (`ρ` is allocated by then) and
        // the clause would silently read C = (g_1 Y_1)^ρ, with `usk` and `ρ` one variable.
        for allocated in 0..3usize {
            let mut rel = PairingRelation::<E>::new();
            rel.alloc_scalars(allocated);
            let alias = PairingRelation::<E>::new().alloc_scalars(allocated + 1)[allocated];
            assert_eq!(alias.index(), rel.num_scalars());
            assert_eq!(
                PS::issuance_clauses(&(), &vk, &cred.sigma_1, &Fr::one(), &mut rel, alias),
                Err(Error::UnallocatedVariable {
                    index: allocated,
                    allocated
                })
            );
            // the relation is untouched: no equation, and no variable was allocated
            assert!(rel.g1_equations().is_empty());
            assert_eq!(rel.num_scalars(), allocated);
        }
        // control: the caller's own variable is accepted, and `ρ` is a second, fresh variable
        let mut rel = PairingRelation::<E>::new();
        let usk = rel.alloc_scalar();
        let allocated =
            PS::issuance_clauses(&(), &vk, &cred.sigma_1, &Fr::one(), &mut rel, usk).unwrap();
        assert_eq!(allocated.len(), 1);
        assert_ne!(allocated[0], usk);
        assert_eq!(rel.num_scalars(), 2);
    }

    // ----- encodings and secrets -----------------------------------------------------------------

    #[test]
    fn serialization_sizes_and_round_trips() {
        let mut rng = StdRng::seed_from_u64(0x9512);
        assert_eq!(PS::setup(DOMAIN), Ok(()));
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = PS::sign(&(), &sk, &m, &mut rng).unwrap();
        let (shown, ()) = PS::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        let c = PS::issuance_encoding(&(), &vk, &usk, &phi, &rho).unwrap();
        let pre = PS::blind_issue(&(), &sk, &c, &phi, &mut rng).unwrap();

        // BLS12-381: G_1 48 B, G_2 96 B, Z_p 32 B
        let bytes = cred.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48);
        assert_eq!(PSCredential::<E>::from_bytes(&bytes).unwrap(), cred);
        let bytes = shown.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48);
        assert_eq!(PSShownCredential::<E>::from_bytes(&bytes).unwrap(), shown);
        let bytes = pre.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48);
        assert_eq!(PSPreCredential::<E>::from_bytes(&bytes).unwrap(), pre);
        let bytes = vk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 96 + 48);
        assert_eq!(PSVerificationKey::<E>::from_bytes(&bytes).unwrap(), vk);
        assert_eq!(PS::encoding_to_wire(&c).to_bytes().unwrap().len(), 48);
        assert_eq!(().to_bytes().unwrap().len(), 0);

        let bytes = sk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 32);
        let back = PSSigningKey::<E>::from_bytes(&bytes).unwrap();
        assert_eq!(back.verification_key(), vk);

        // trailing bytes and truncation
        let mut long = cred.to_bytes().unwrap();
        long.push(0);
        assert_eq!(
            PSCredential::<E>::from_bytes(&long),
            Err(Error::TrailingBytes)
        );
        assert!(PSCredential::<E>::from_bytes(&long[..95]).is_err());

        // the identity decodes fine: rejecting it is the verifiers' job
        let degenerate = PSShownCredential::<E> {
            sigma_1: G1::zero(),
            sigma_2: G1::zero(),
        };
        let back = PSShownCredential::<E>::from_bytes(&degenerate.to_bytes().unwrap()).unwrap();
        assert_eq!(back, degenerate);
        assert!(!PS::verify_possess_public(&(), &vk, &back, &phi));
    }

    #[test]
    fn secrets_are_redacted_and_wiped() {
        let mut rng = StdRng::seed_from_u64(0x9513);
        let (_, mut sk) = PS::keygen(&(), &mut rng);
        assert_eq!(format!("{sk:?}"), "PSSigningKey(<redacted>)");
        assert!(!sk.x.is_zero() && !sk.y1.is_zero() && !sk.y2.is_zero());
        sk.zeroize();
        assert!(sk.x.is_zero() && sk.y1.is_zero() && sk.y2.is_zero());

        let mut m = msg(Fr::from(5u64), Fr::from(6u64));
        assert_eq!(format!("{m:?}"), "PSMessage(<redacted>)");
        m.zeroize();
        assert!(m.m1.is_zero() && m.m2.is_zero());

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<PSSigningKey<E>>();
        assert_zeroize_on_drop::<PSMessage<E>>();
    }

    // ----- degenerate keys (module docs, "Degenerate keys") --------------------------------------

    /// A signing key with chosen components, the way an attacker (or a corrupted key file)
    /// gets one: through the decoder, which accepts zero scalars.
    fn signing_key(x: Fr, y1: Fr, y2: Fr) -> PSSigningKey<E> {
        let bytes = [x, y1, y2]
            .iter()
            .flat_map(|s| s.to_bytes().unwrap())
            .collect::<Vec<u8>>();
        PSSigningKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn keygen_outputs_well_formed_keys_only() {
        let mut rng = StdRng::seed_from_u64(0x9517);
        for _ in 0..8 {
            let (vk, sk) = PS::keygen(&(), &mut rng);
            assert!(!sk.y1.is_zero() && !sk.y2.is_zero());
            assert!(vk.binds_the_message());
            assert!(vk.is_well_formed());
            assert!(PS::is_well_formed_key(&(), &vk));
        }
        // x = 0 is a key of the box and stays one: X̃ = 1 is well formed
        let sk = signing_key(Fr::zero(), Fr::from(2u64), Fr::from(3u64));
        assert!(sk.verification_key().x_tilde.is_zero());
        assert!(sk.verification_key().is_well_formed());
    }

    #[test]
    fn malformed_verification_keys_are_recognised() {
        let mut rng = StdRng::seed_from_u64(0x9518);
        let (vk, _) = PS::keygen(&(), &mut rng);
        let (other, _) = PS::keygen(&(), &mut rng);
        let g2_one = <E as Pairing>::G2::zero();

        // identity components, as accepted by the decoder
        for (i, bad) in [
            PSVerificationKey::<E> {
                y1_tilde: g2_one,
                ..vk.clone()
            },
            PSVerificationKey::<E> {
                y2_tilde: g2_one,
                ..vk.clone()
            },
            PSVerificationKey::<E> {
                y1: G1::zero(),
                ..vk.clone()
            },
            // Ỹ_1 = 1 AND Y_1 = 1: consistent with y_1 = 0, still outside the key space
            PSVerificationKey::<E> {
                y1_tilde: g2_one,
                y1: G1::zero(),
                ..vk.clone()
            },
            // the two copies of y_1 disagree
            PSVerificationKey::<E> {
                y1: other.y1,
                ..vk.clone()
            },
            PSVerificationKey::<E> {
                y1_tilde: other.y1_tilde,
                ..vk.clone()
            },
        ]
        .into_iter()
        .enumerate()
        {
            let back = PSVerificationKey::<E>::from_bytes(&bad.to_bytes().unwrap()).unwrap();
            assert_eq!(back, bad, "case {i}: the decoder does not mind");
            assert!(!bad.is_well_formed(), "case {i}");
            assert!(!PS::is_well_formed_key(&(), &bad), "case {i}");
        }
        // X̃ and Ỹ_2 are unconstrained beyond Ỹ_2 ≠ 1
        let fine = PSVerificationKey::<E> {
            x_tilde: other.x_tilde,
            y2_tilde: other.y2_tilde,
            ..vk.clone()
        };
        assert!(fine.is_well_formed());
    }

    /// `y_1 = 0`: the possession clause has base `e(σ'_1, Ỹ_1) = 1` and is satisfied by EVERY
    /// scalar, so ONE credential attests under arbitrarily many tag keys, with `σ'_1 ≠ 1`. The
    /// key-side public check is the only thing that rejects these attestations.
    #[test]
    fn y1_zero_makes_possession_vacuous_and_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0x9519);
        let tag = tag();
        let sk = signing_key(Fr::from(5u64), Fr::zero(), Fr::from(7u64));
        let vk = sk.verification_key();
        assert!(vk.y1_tilde.is_zero() && vk.y1.is_zero());
        assert!(!vk.binds_the_message() && !vk.is_well_formed());

        let (usk, phi, cred) = holder(&tag, &sk, b"f", &mut rng);
        // the box's Verify cannot tell: the credential "verifies" for every usk
        assert!(PS::verify(&(), &vk, &msg(usk, phi), &cred));
        assert!(PS::verify(&(), &vk, &msg(usk + Fr::one(), phi), &cred));

        let id = G1::generator() * tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let (shown, ()) = PS::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
        assert!(!shown.sigma_1.is_zero());
        let mut tags = Vec::new();
        for _ in 0..3 {
            // a tag key for which NO credential exists
            let other = tag.keygen(&mut rng);
            let t = tag.eval(&other, &s).unwrap();
            let rel = att_relation(&tag, &vk, &shown, &phi, &t, &s);
            assert!(rel.is_satisfied_by(&[other]));
            let ctx = att_ctx(&tag, &vk, &id, &phi, &t, &shown);
            let pi = fiat_shamir::prove(&rel, &[other], &ctx, &mut rng).unwrap();
            assert!(fiat_shamir::verify(&rel, &ctx, &pi));
            assert!(tag.valid_tag(&t, &s));
            // ... rejected by the public checks, and by them alone
            assert!(!PS::verify_possess_public(&(), &vk, &shown, &phi));
            let att = Att {
                t,
                shown: shown.clone(),
                phi,
                pi,
            };
            assert!(!verify_att(&tag, &vk, &id, &att));
            tags.push(t);
        }
        assert!(tags[0] != tags[1] && tags[1] != tags[2] && tags[0] != tags[2]);

        // the stand-alone prover refuses the key, the stand-alone verifier the statement
        assert_eq!(
            possess::<E, PS, _>(&(), &vk, &shown, &phi, &usk, &(), b"ctx", &mut rng),
            Err(Error::InvalidKey)
        );
        let (rel, _) = possession_relation::<E, PS>(&(), &vk, &shown, &phi).unwrap();
        let ctx = possess_context::<E, PS>(&(), &vk, &shown, &phi, b"ctx").unwrap();
        let forged = fiat_shamir::prove(&rel, &[Fr::rand(&mut rng)], &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &forged));
        assert!(!verify_possess::<E, PS>(
            &(),
            &vk,
            &shown,
            &phi,
            b"ctx",
            &forged
        ));

        // the opening clause C = g_1^ρ Y_1^usk would not commit to usk either
        let mut rel = PairingRelation::<E>::new();
        let var = rel.alloc_scalar();
        assert_eq!(
            PS::issuance_clauses(&(), &vk, &G1::generator(), &phi, &mut rel, var),
            Err(Error::InvalidKey)
        );
        assert_eq!(rel.num_scalars(), 1);
        assert!(rel.g1_equations().is_empty());
    }

    /// `y_2 = 0`: a credential for `φ` verifies and can be shown under every `φ'`; rejected by
    /// the same key-side check.
    #[test]
    fn y2_zero_unbinds_phi_and_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0x951a);
        let sk = signing_key(Fr::from(5u64), Fr::from(6u64), Fr::zero());
        let vk = sk.verification_key();
        assert!(!vk.binds_the_message() && !vk.is_well_formed());

        let (usk, phi, other_phi) = (Fr::rand(&mut rng), phi(b"f"), phi(b"f'"));
        let cred = PS::sign(&(), &sk, &msg(usk, phi), &mut rng).unwrap();
        assert!(PS::verify(&(), &vk, &msg(usk, other_phi), &cred));
        let (shown, ()) = PS::rerand(&(), &vk, &msg(usk, phi), &cred, &mut rng).unwrap();
        let (rel, _) = possession_relation::<E, PS>(&(), &vk, &shown, &other_phi).unwrap();
        assert!(rel.is_satisfied_by(&[usk]));
        assert!(!PS::verify_possess_public(&(), &vk, &shown, &other_phi));
        assert!(!PS::verify_possess_public(&(), &vk, &shown, &phi));
        assert_eq!(
            possess::<E, PS, _>(&(), &vk, &shown, &other_phi, &usk, &(), b"ctx", &mut rng),
            Err(Error::InvalidKey)
        );
    }

    /// The implementation note on [`PSVerificationKey`]: from `g_1^x` and the published `Y_1`
    /// one obtains signatures on every `(m_1, 0)`, and (without `g_1^{y_2}`) on nothing else.
    #[test]
    fn g1_x_forges_exactly_the_messages_with_m2_zero() {
        let mut rng = StdRng::seed_from_u64(0x951b);
        let (vk, sk) = PS::keygen(&(), &mut rng);
        let g1_x = G1::generator() * sk.x;
        let (m1, t) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let forged = PSCredential::<E> {
            sigma_1: G1::generator() * t,
            sigma_2: (g1_x + vk.y1 * m1) * t,
        };
        assert!(PS::verify(&(), &vk, &msg(m1, Fr::zero()), &forged));
        assert!(!PS::verify(&(), &vk, &msg(m1, Fr::one()), &forged));
        assert!(!PS::verify(&(), &vk, &msg(m1, phi(b"f")), &forged));
    }

    /// Every randomized algorithm accepts an unsized RNG (`R: ?Sized`), e.g. a trait object.
    #[test]
    fn randomized_algorithms_accept_a_dyn_rng() {
        use ark_std::rand::{CryptoRng, RngCore};
        trait DynRng: RngCore + CryptoRng {}
        impl<T: RngCore + CryptoRng> DynRng for T {}

        let mut std_rng = StdRng::seed_from_u64(0x951c);
        let rng: &mut dyn DynRng = &mut std_rng;
        let tag = tag();
        let (vk, sk) = PS::keygen(&(), rng);
        let usk = tag.keygen(rng);
        let (phi, (_, rho)) = (phi(b"f"), PS::sample_issuance(&(), rng));
        let c = PS::issuance_encoding(&(), &vk, &usk, &phi, &rho).unwrap();
        let pre = PS::blind_issue(&(), &sk, &c, &phi, rng).unwrap();
        let cred = PS::unblind(&(), &vk, &msg(usk, phi), &pre, &rho).unwrap();
        assert!(PS::verify(&(), &vk, &msg(usk, phi), &cred));
        let direct = PS::sign(&(), &sk, &msg(usk, phi), rng).unwrap();
        assert!(PS::verify(&(), &vk, &msg(usk, phi), &direct));
        let (shown, omega) = PS::rerand(&(), &vk, &msg(usk, phi), &cred, rng).unwrap();
        let pi = possess::<E, PS, _>(&(), &vk, &shown, &phi, &usk, &omega, b"ctx", rng).unwrap();
        assert!(verify_possess::<E, PS>(&(), &vk, &shown, &phi, b"ctx", &pi));
        let t = tag.eval(&usk, &phi).unwrap();
        let tag_pi = crate::kiprf::prove_tag(&tag, &usk, &t, &phi, b"ctx", rng).unwrap();
        assert!(crate::kiprf::verify_tag(&tag, &t, &phi, b"ctx", &tag_pi));
    }

    // ----- the generic flow of the construction --------------------------------------------------

    /// The base-and-tag-generic walk through the protocol box (`Attest`, `VerifyAtt`, `Prove`,
    /// `VerifyProof`, `Issue`, `Unblind`, `VerifyCred`, chaining), written against the traits only.
    #[test]
    fn conformance_flow_with_tag_ddh() {
        let report = public_base_flow::<E, PS, Tag>(DOMAIN, 0x9516, credential_free_forgeries);
        // |att| = 3 G_1 + 3 Z_p (T, σ'_1, σ'_2; φ, c, z) and |π_0| = 3 Z_p (c, z_usk, z_ρ)
        assert_eq!(
            report,
            FlowReport {
                attestation_responses: 1,
                issuance_responses: 2,
            }
        );
    }

    // ----- genericity ----------------------------------------------------------------------------

    /// The whole base over a second pairing. arkworks ships no hash-to-curve for BN254, so the
    /// tag clause is replaced by a plain Schnorr clause `T = P^usk` to a random base.
    fn generic_flow<P: Pairing>(seed: u64) {
        type B<P> = crate::cred::PS<P>;
        let mut rng = StdRng::seed_from_u64(seed);
        let (vk, sk) = B::<P>::keygen(&(), &mut rng);
        let (usk, phi) = (
            P::ScalarField::rand(&mut rng),
            P::ScalarField::rand(&mut rng),
        );
        let (aux, rho) = B::<P>::sample_issuance(&(), &mut rng);
        let m_hid = B::<P>::hidden_message(&usk, &aux);
        let m = B::<P>::encode_message(&(), &m_hid, &phi).unwrap();
        let c = B::<P>::issuance_encoding(&(), &vk, &m_hid, &phi, &rho).unwrap();
        let pre = B::<P>::blind_issue(&(), &sk, &c, &phi, &mut rng).unwrap();
        let cred = B::<P>::unblind(&(), &vk, &m, &pre, &rho).unwrap();
        assert!(B::<P>::verify(&(), &vk, &m, &cred));
        let wrong = B::<P>::encode_message(&(), &(usk + P::ScalarField::ONE), &phi).unwrap();
        assert!(!B::<P>::verify(&(), &vk, &wrong, &cred));

        let (shown, omega) = B::<P>::rerand(&(), &vk, &m, &cred, &mut rng).unwrap();
        assert!(B::<P>::verify_possess_public(&(), &vk, &shown, &phi));
        let base = P::G1::rand(&mut rng);
        let build = |t: P::G1| {
            let mut rel = PairingRelation::<P>::new();
            let var = rel.alloc_scalar();
            B::<P>::possession_clauses(&(), &vk, &shown, &phi, &mut rel, var).unwrap();
            rel.add_g1(LinearEquation::dlog(var, base, t)).unwrap();
            rel
        };
        let rel = build(base * usk);
        let mut w = Witness::new();
        w.push(usk);
        w.extend_from_slice(&B::<P>::possession_witness(&m_hid, &omega));
        let pi = fiat_shamir::prove(&rel, &w, b"ctx", &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, b"ctx", &pi));
        let rel_bad = build(base * (usk + P::ScalarField::ONE));
        assert!(!fiat_shamir::verify(&rel_bad, b"ctx", &pi));
        assert!(fiat_shamir::prove(&rel_bad, &w, b"ctx", &mut rng).is_err());
    }

    #[test]
    fn generic_over_the_pairing() {
        generic_flow::<Bn254>(0x9514);
        generic_flow::<Bls12_381>(0x9515);
    }
}
