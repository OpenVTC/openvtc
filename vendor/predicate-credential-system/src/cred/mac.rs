//! `Σ-MAC`, the designated-verifier algebraic-MAC credential base (paper §3.2.4,
//! "Designated-verifier Sigma-MAC instantiation", box "`Σ-MAC` credential base").
//!
//! Setting: a prime-order group `G` of order `q` with independent generators `g, h`,
//! `M_Σ = Z_q^2`, `(m_hid, m_pub) = (usk, φ)`. The maps are `Enc_Σ(usk, φ) = (usk, φ)` and the
//! Pedersen commitment `Com_pp(usk, φ; ρ) = g^usk h^ρ`. The key `dvk = (x, y_1, y_2)` "is
//! retained by the helper and is used for both signing and verification": there is no
//! verification key, and a user cannot verify its own credential.
//!
//! | paper (box `Σ-MAC`) | here |
//! |---|---|
//! | `KeyGen(pp)`: `x ← Z_q`, `y_1, y_2 ← Z_q^*`, `dvk = (x, y_1, y_2)` | [`DVCredentialBase::keygen`] |
//! | `Sign(dvk, (m_1, m_2))`: `t ← Z_q^*`, `U = g^t`, `cred = (U, U^{x + y_1 m_1 + y_2 m_2})` | [`DVCredentialBase::sign`] |
//! | `Verify(dvk, m, (U, V)) = [U ≠ 1 ∧ V = U^{x + y_1 m_1 + y_2 m_2}]` | [`DVCredentialBase::verify`] |
//! | `ReRand(pp, m, (U, V))`: `r ← Z_q^*`, `cred* = (U^r, V^r)`, `ω = ∅` | [`DVCredentialBase::rerand`] |
//! | `BlindIssue(dvk, C, φ)`: `t ← Z_q^*`, `U = g^t`, `W = h^{t y_1}`, `ĉred = (U, W, U^x U^{y_2 φ} C^{t y_1})` | [`DVCredentialBase::blind_issue`] |
//! | `Unblind(pp, (usk, φ), (U, W, V'), ρ) = (U, V' W^{-ρ})` | [`DVCredentialBase::unblind`] |
//! | `Possess` step 1: the verifier rejects if `U' = 1` | [`SigmaFriendlyDVCredentialBase::verify_possess_public`] |
//! | `Possess` step 2: `V' (U')^{-x - y_2 φ} = (U')^{y_1 usk}`, proved as the equivalent clause `X = (U')^usk` with the public base `U'`, "where `X` is never sent: the prover computes `X` from its witness, and the verifier derives `X = (V'(U')^{-x-y_2φ})^{1/y_1}` from `dvk`" | [`SigmaFriendlyDVCredentialBase::possession_clauses_prover`], [`SigmaFriendlyDVCredentialBase::possession_clauses_verifier`] |
//! | `Possess(pp, (U', V'), φ; usk, ∅) → Π`, stand-alone | [`MAC::possess`], [`MAC::verify_possess`] |
//! | §5.1: `(m_aux, ρ) = (∅, r)`, `r ← Z_q`; opening clause `C = g^usk h^ρ` of `R_issue` | [`SigmaFriendlyDVCredentialBase::sample_issuance`], [`SigmaFriendlyDVCredentialBase::issuance_clauses`] |
//!
//! `φ` enters the credential exactly once, in `BlindIssue` (`U^{y_2 φ}`); `C` does not depend on
//! it. `Unblind` works because `C^{t y_1} = U^{y_1 usk} W^ρ` (proof sketch of the Lemma on
//! `Σ-MAC`).
//!
//! # In formulas
//!
//! ```math
//! \begin{aligned}
//! \mathsf{Sign}\bigl(dvk, (m_1, m_2)\bigr) &= \bigl(U,\ U^{\,x + y_1 m_1 + y_2 m_2}\bigr), \qquad U = g^{t},\quad t \leftarrow \mathbb{Z}_q^{*} \\
//! \mathsf{Verify}\bigl(dvk, (m_1, m_2), (U, V)\bigr) &= \bigl[\, U \neq 1 \;\wedge\; V = U^{\,x + y_1 m_1 + y_2 m_2} \,\bigr] \\
//! \mathsf{Com}_{pp}(usk, \varphi; \rho) &= g^{usk}\, h^{\rho}
//! \end{aligned}
//! ```
//!
//! The possession relation of the box, for a shown credential $`(U', V') = (U^{r}, V^{r})`$ with $`U' \neq 1`$:
//!
//! ```math
//! V'\, (U')^{-x - y_2 \varphi} = (U')^{\,y_1\, usk}
//! ```
//!
//! # The prover never sees `dvk`
//!
//! In the displayed relation `V' (U')^{-x - y_2 φ} = (U')^{y_1 usk}` both the base `(U')^{y_1}`
//! and the target are computable with `dvk` only, while a compact `(c, z)` proof makes both
//! parties hash the same statement and recompute the same commitment (first remark after the
//! box). Prover and verifier therefore use the equivalent clause of `Possess` step 2,
//!
//! ```text
//! X = (U')^usk        (base U', shared variable usk)
//! ```
//!
//! whose target each side obtains in its own way:
//!
//! * the **prover** sets `X_P := (U')^usk` from its witness
//!   ([`SigmaFriendlyDVCredentialBase::possession_clauses_prover`]; no `dvk`, and `φ` is not
//!   even used);
//! * the **verifier** derives `X_V := (V' (U')^{-x - y_2 φ})^{1/y_1}` from `dvk`
//!   ([`SigmaFriendlyDVCredentialBase::possession_clauses_verifier`]).
//!
//! Raising to `y_1 ≠ 0` is a bijection of `G`, so `X_V = (U')^usk` is the displayed relation,
//! and `X_P = X_V` holds iff `V' = (U')^{x + y_1 usk + y_2 φ}`, i.e. (given `U' ≠ 1`) iff `cred*`
//! is a MAC on `(usk, φ)`. `X` is never transmitted. The Fiat-Shamir challenge absorbs every
//! base and target of the statement, so a proof computed for `X_P` is checked against `X_V`:
//! the two sides hash the same statement exactly when that equation holds for the prover's
//! `usk` and the verifier's `φ` and `dvk`.
//!
//! What the paper covers: the proof sketch of the Lemma on `Σ-MAC` argues sigma-friendliness
//! for the displayed relation of the interactive protocol ("the usual two-transcript extractor
//! recovers `usk`"). That the compact Fiat-Shamir form stays sound when the verifier derives
//! the target itself is an argument sketch of this implementation, not a statement of the
//! paper: in the random-oracle model an accepted proof was, except with probability about
//! `1/q`, hashed with the statement the verifier built, so its prover has stated `X_V`, and
//! rewinding at that query yields a `usk` with `X_V = (U')^usk` (the extractor needs `dvk`,
//! or the verifier's decisions, to recognise accepting proofs).
//!
//! Consequences the unit tests pin down:
//!
//! * the prover's own relation is satisfied *by construction*; a holder of an invalid MAC (or
//!   one that claims another `usk`) gets a proof without any error, and the verifier rejects it;
//! * `y_1^{-1}` goes through `Field::inverse()`; a key with `y_1 = 0` is [`Error::InvalidKey`]
//!   (and so is one with `y_2 = 0`, see "Generators, degenerate parameters and keys");
//! * for `(U', V') = (1, 1)` the verifier derives `X_V = 1`, the clause reads `1 = 1^usk` and
//!   holds for every `usk`: only the public check `U' ≠ 1` rejects this credential-free show
//!   (attack A2 of the reference implementations; the test helper `credential_free_forgeries`
//!   lists it for the conformance flow).
//!
//! # The verifier's statement is secret
//!
//! **The possession statement that the verifier derives from `dvk` must never leave the
//! verifier** (second remark after the box: "Only the accept/reject bit may be released"). The
//! prover's statement contains nothing derived from `dvk`; the VERIFIER's does: `X_V` is a
//! function of `dvk` and of
//! the `(U', V', φ)` that an attacker submits, and it is a group element, not a bit. Three
//! values suffice for a universal forgery. The inputs `(U', V', φ) = (g, g, 0)`, `(g, 1, 0)` and
//! `(g, 1, 1)`, all of which pass the public check `U' ≠ 1`, yield
//!
//! ```text
//! X_a = g^{(1 - x)/y_1}     X_b = g^{-x/y_1}     X_c = g^{-(x + y_2)/y_1}
//! ```
//!
//! hence `g^{1/y_1} = X_a / X_b`, `g^{x/y_1} = 1 / X_b` and `g^{y_2/y_1} = X_b / X_c`, and
//! `(U, V) = (g^{1/y_1}, g^{x/y_1} g^{m_1} (g^{y_2/y_1})^{m_2})` is a MAC on ANY `(m_1, m_2)`
//! (unit test `three_leaked_verifier_targets_give_a_universal_forgery`). This is not an
//! artefact of the clause `X = (U')^usk`: the displayed relation of the box is key-derived on
//! the verifier's side as well, and its base `(U')^{y_1}` and target `V' (U')^{-x - y_2 φ}` for
//! the inputs `(g, 1, 0)` and `(g, 1, 1)` are `g^{y_1}`, `g^{-x}` and `g^{-x - y_2}`, from which
//! `(g, g^x (g^{y_1})^{m_1} (g^{y_2})^{m_2})` is a MAC on any `(m_1, m_2)` (same unit test).
//!
//! The relation that [`SigmaFriendlyDVCredentialBase::possession_clauses_verifier`] appends must
//! therefore be handled like `dvk` itself: never log it ([`GroupRelation`] derives `Debug`, and
//! [`LinearEquation::target`] is a public field), never serialize it, never return it to a
//! caller and never put it into an error value, for accepted and for rejected shows alike. Its
//! only use is as the input of the Fiat-Shamir verifier. This module does exactly that:
//! [`MAC::verify_possess`] hashes the statement and returns one bit, no error of this module
//! carries a group element, and the stand-alone builder of the verifier's relation
//! (`MAC::possession_relation_verifier`) exists only in test builds (`cfg(test)` and the
//! cargo feature `test-utils`). A layer that composes the verifier's clause with the tag clause
//! (the designated-verifier construction) has to keep the same discipline.
//!
//! # Generators, degenerate parameters and keys
//!
//! Implementation notes.
//!
//! * `g, h` are derived with [`HashToGroup::generators`] under the suffix
//!   [`GENERATORS_SUFFIX`], so their mutual discrete logarithm is unknown in the random-oracle
//!   model (Pedersen binding) and they are independent of the generator that `Tag_DDH` programs
//!   at `c_0`. Anyone can recompute them: `pp == MAC::setup(domain)` is the complete check
//!   of received parameters. [`MACPublicParams::is_well_formed`] is only the part of it that
//!   needs no deployment label (`g ≠ 1`, `h ≠ 1`, `g ≠ h`); decoding accepts the identity, and
//!   the algorithms that use the generators refuse parameters that fail it
//!   ([`Error::DegenerateInput`]): with `g = 1` every issued `U` would be `1` and `C` would
//!   not depend on `usk`, with `h = 1` or `g = h` the commitment `C` would not hide,
//!   respectively not bind, `usk`.
//! * Degenerate keys. With `y_1 = 0` a MAC does not depend on `usk` (and the possession
//!   verifier would have to invert zero); with `y_2 = 0` it does not depend on `φ`: a credential
//!   for `φ` verifies, and can be shown, under every `φ'`. The box excludes both events
//!   (`y_1, y_2 ← Z_q^*`), but [`MACKey`] decodes with either scalar zero:
//!   [`DVCredentialBase::is_well_formed_key`] is `y_1 ≠ 0 ∧ y_2 ≠ 0`, the membership test for
//!   the range of `KeyGen`; `Sign`, `BlindIssue` and the possession verifier return
//!   [`Error::InvalidKey`] for a key that fails it, and `Verify` and
//!   [`MAC::verify_possess`] return `false`. The possession verifier's public check is
//!   keyless, so the keyed algorithms are the only place where `y_2 ≠ 0` can be enforced.
//!   `dvk` never leaves its holder, so in practice this concerns a helper that reads back a
//!   corrupted key of its own; the unit tests mount both events.
//!
//! # Security and limitations
//!
//! Lemma on `Σ-MAC` (§3.2.4): if discrete logarithm is hard in `G`, "the displayed Pedersen
//! committed-issuance protocol is one-more secure for the underlying MAC, and the MAC is
//! unforgeable", then `Σ-MAC` has correct issuance, issuance indistinguishability,
//! designated-verifier unforgeability, strong show unlinkability and designated-verifier
//! sigma-friendliness (Defs. "Designated-verifier credential base", "Sigma-friendly
//! designated-verifier credential base"); `U' ≠ 1` "prevents vacuity". The one-more property is
//! a hypothesis: §3.2 flags that the candidate's "displayed issuance protocol does not satisfy
//! the full one-more issuance requirement". The base does not instantiate the protocol box of
//! §5.1 as written; it needs "a designated-verifier PCS variant in which its verification key
//! remains in `hsk` and the helper runs the keyed attestation and issuance-proof verifiers"
//! (§5.1).
//!
//! A user cannot verify a credential alone, and "a malicious issuer can instead return an
//! unusable pre-credential, causing denial of service" (after Def. "Designated-verifier
//! credential base"). Implementation note: the base has no public issuer parameters and no
//! proof of correct issuance, so a holder cannot tell under WHICH key its MAC was computed
//! either. An issuer that uses one key
//! per holder recognises the holder behind a show by testing which key accepts it; the unit
//! test `an_issuer_with_one_key_per_holder_links_shows` mounts this.
//!
//! # Example
//!
//! Encoded issuance (Def. "Designated-verifier credential base", correctness), then a show with
//! a keyless prover and a keyed verifier:
//!
//! ```
//! use ark_bls12_381::{Fr, G1Projective as G1};
//! use predicate_credential_system::{
//!     cred::{self, DVCredentialBase},
//!     hash::bls12_381::G1Hasher,
//! };
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! type MAC = cred::MAC<G1, G1Hasher>;
//! let mut rng = StdRng::seed_from_u64(1);
//! let pp = MAC::setup(b"example deployment")?;
//! let dvk = MAC::keygen(&pp, &mut rng); // stays with the helper
//! let (usk, phi, rho) = (Fr::from(11u64), Fr::from(22u64), Fr::from(33u64));
//!
//! // user: C = Com(usk, φ; ρ)      helper: BlindIssue(dvk, C, φ)      user: Unblind(.., ρ)
//! let c = MAC::issuance_encoding(&pp, &usk, &phi, &rho)?;
//! let pre = MAC::blind_issue(&pp, &dvk, &c, &phi, &mut rng)?;
//! let m = MAC::encode_message(&pp, &usk, &phi)?;
//! let cred = MAC::unblind(&pp, &m, &pre, &rho)?;
//! // only the key holder can check the result
//! assert!(MAC::verify(&pp, &dvk, &m, &cred));
//!
//! // user: ReRand and Possess, without dvk      helper: the keyed possession verifier
//! let (shown, omega) = MAC::rerand(&pp, &m, &cred, &mut rng)?;
//! let proof = MAC::possess(&pp, &shown, &phi, &usk, &omega, b"context", &mut rng)?;
//! assert!(MAC::verify_possess(&pp, &dvk, &shown, &phi, b"context", &proof));
//! assert!(!MAC::verify_possess(&pp, &dvk, &shown, &Fr::from(23u64), b"context", &proof));
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

use core::{fmt, marker::PhantomData};

use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{DVCredentialBase, SigmaFriendlyDVCredentialBase, ensure_allocated};
use crate::{
    error::Error,
    hash::{HashToGroup, Transcript},
    sample::nonzero_scalar,
    sigma::{FSProof, GroupRelation, LinearEquation, ScalarVar, Witness, fiat_shamir},
};

/// Oracle suffix under which the generators `g, h` are derived.
pub const GENERATORS_SUFFIX: &[u8] = b"/MAC-GENERATORS";

/// Oracle suffix of the Fiat-Shamir context of a stand-alone possession proof.
const POSSESS_SUFFIX: &[u8] = b"/MAC-POSSESS";

/// The `Σ-MAC` designated-verifier credential base over the prime-order group `G`, with
/// generators derived by the hash-to-group oracle `H` (a marker type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MAC<G: PrimeGroup, H: HashToGroup<G>>(PhantomData<(G, H)>);

/// The public parameters `pp = (g, h)`: independent generators of `G`, neither the identity.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MACPublicParams<G: PrimeGroup> {
    /// `g`, the base of `usk` in `C` and of the MAC randomizer `U = g^t`.
    pub g: G,
    /// `h`, the base of `ρ` in `C`.
    pub h: G,
}

impl<G: PrimeGroup> MACPublicParams<G> {
    /// The checks on `pp` that need no deployment label: `g ≠ 1`, `h ≠ 1` and `g ≠ h`. Never
    /// panics.
    ///
    /// Implementation note (module docs, "Generators, degenerate parameters and keys"): this is
    /// necessary, not sufficient. "Independent generators" cannot be tested on the values; the
    /// complete check of received parameters is `pp == MAC::setup(domain)`.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.g.is_zero() && !self.h.is_zero() && self.g != self.h
    }

    /// [`Self::is_well_formed`] as a `Result`, for the algorithms that use the generators.
    fn check(&self) -> Result<(), Error> {
        if self.is_well_formed() {
            Ok(())
        } else {
            Err(Error::DegenerateInput(
                "the generators g, h of Σ-MAC must be distinct and different from the identity",
            ))
        }
    }
}

/// The key `dvk = (x, y_1, y_2)` with `y_1 ≠ 0` and `y_2 ≠ 0`, retained by the designated
/// verifier. Secret: wiped on drop, not `Clone`, redacted in `Debug`.
///
/// Decoding enforces neither `y_1 ≠ 0` nor `y_2 ≠ 0`; check a key that was read back with
/// [`MACKey::is_well_formed`].
#[derive(Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct MACKey<G: PrimeGroup> {
    x: G::ScalarField,
    y1: G::ScalarField,
    y2: G::ScalarField,
}

impl<G: PrimeGroup> MACKey<G> {
    /// Whether the key lies in the range of [`DVCredentialBase::keygen`] (`x ← Z_q`,
    /// `y_1, y_2 ← Z_q^*`), i.e. whether it binds both message components: `y_1 ≠ 0` and
    /// `y_2 ≠ 0`. Under `y_1 = 0` a MAC does not depend on `usk`, and the possession verifier
    /// would have to invert zero; under `y_2 = 0` a MAC does not depend on `φ`. Never panics.
    ///
    /// See the module docs, "Generators, degenerate parameters and keys".
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.y1.is_zero() && !self.y2.is_zero()
    }

    /// The exponent `x + y_1 m_1 + y_2 m_2` of a MAC on `m`.
    fn exponent(&self, m: &MACMessage<G>) -> G::ScalarField {
        self.x + self.y1 * m.m1 + self.y2 * m.m2
    }
}

impl<G: PrimeGroup> fmt::Debug for MACKey<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MACKey(<redacted>)")
    }
}

/// An authenticated message `m = (m_1, m_2) ∈ M_Σ = Z_q^2`; the construction authenticates
/// `Enc_Σ(usk, φ) = (usk, φ)`. Secret: wiped on drop, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MACMessage<G: PrimeGroup> {
    m1: G::ScalarField,
    m2: G::ScalarField,
}

impl<G: PrimeGroup> MACMessage<G> {
    /// The message `(m_1, m_2)`.
    #[must_use]
    pub fn new(m1: G::ScalarField, m2: G::ScalarField) -> Self {
        Self { m1, m2 }
    }
}

impl<G: PrimeGroup> fmt::Debug for MACMessage<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MACMessage(<redacted>)")
    }
}

/// A credential `cred = (U, V)`: a MAC, `V = U^{x + y_1 m_1 + y_2 m_2}` with `U ≠ 1`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MACCredential<G: PrimeGroup> {
    /// `U = g^t`.
    pub u: G,
    /// `V`.
    pub v: G,
}

/// A pre-credential `ĉred = (U, W, V')` with the cancellation term `W = h^{t y_1}` for `ρ`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MACPreCredential<G: PrimeGroup> {
    /// `U = g^t`.
    pub u: G,
    /// `W = h^{t y_1}`.
    pub w: G,
    /// `V' = U^x U^{y_2 φ} C^{t y_1}`.
    pub v_prime: G,
}

/// A shown credential `cred* = (U', V') = (U^r, V^r)`: itself a MAC on the same message (strong
/// show, hence the conversion into [`MACCredential`]), verifiable only with `dvk`. A type of
/// its own keeps a value that was published apart from the holder's stored credential.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MACShownCredential<G: PrimeGroup> {
    /// `U' = U^r`.
    pub u_prime: G,
    /// `V' = V^r`.
    pub v_prime: G,
}

impl<G: PrimeGroup> From<MACShownCredential<G>> for MACCredential<G> {
    fn from(shown: MACShownCredential<G>) -> Self {
        Self {
            u: shown.u_prime,
            v: shown.v_prime,
        }
    }
}

impl<G: PrimeGroup, H: HashToGroup<G>> DVCredentialBase for MAC<G, H> {
    type PublicParams = MACPublicParams<G>;
    type DVKey = MACKey<G>;
    /// `m_hid = usk`.
    type HiddenMessage = G::ScalarField;
    /// `m_pub = φ`.
    type PublicMessage = G::ScalarField;
    type Message = MACMessage<G>;
    /// `R_Σ = Z_q ∋ ρ`.
    type IssuanceState = G::ScalarField;
    /// `C_Σ = G ∋ C = g^usk h^ρ`.
    type IssuanceEncoding = G;
    type Credential = MACCredential<G>;
    type PreCredential = MACPreCredential<G>;
    type ShownCredential = MACShownCredential<G>;
    /// `ω = ∅`.
    type ShowState = ();

    /// `pp = (g, h)`: "independent generators `g, h`" (§3.2.4), derived from the deployment
    /// label as `H_{/MAC-GENERATORS}(0)`, `H_{/MAC-GENERATORS}(1)`. Deterministic.
    ///
    /// # Errors
    /// [`Error::HashToCurve`] if the oracle cannot be instantiated. Implementation note:
    /// [`Error::LengthMismatch`] / [`Error::DegenerateInput`] if the oracle does not return two
    /// distinct non-identity elements, which a [`HashToGroup`] that keeps its contract never
    /// does (`g = h` has probability about `1/q`).
    fn setup(domain: &[u8]) -> Result<Self::PublicParams, Error> {
        let generators = H::new(domain)?.generators(GENERATORS_SUFFIX, 2);
        let [g, h]: [G; 2] =
            generators
                .try_into()
                .map_err(|generators: Vec<G>| Error::LengthMismatch {
                    expected: 2,
                    actual: generators.len(),
                })?;
        let pp = MACPublicParams { g, h };
        pp.check()?;
        Ok(pp)
    }

    /// `KeyGen(pp)` (box `Σ-MAC`): `x ← Z_q` and `y_1, y_2 ← Z_q^*`, so that every generated key
    /// binds `usk` and `φ` (module docs, "Generators, degenerate parameters and keys").
    fn keygen<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> Self::DVKey {
        // 1. x ← Z_q, y_1, y_2 ← Z_q^*
        let x = G::ScalarField::rand(rng);
        let y1 = nonzero_scalar(rng);
        let y2 = nonzero_scalar(rng);
        // 2. return the retained key dvk = (x, y_1, y_2)
        MACKey { x, y1, y2 }
    }

    /// [`MACKey::is_well_formed`]: `y_1 ≠ 0 ∧ y_2 ≠ 0`, the range of `KeyGen` (`x ← Z_q`,
    /// `y_1, y_2 ← Z_q^*`).
    fn is_well_formed_key(_pp: &Self::PublicParams, dvk: &Self::DVKey) -> bool {
        dvk.is_well_formed()
    }

    /// `Sign(dvk, (m_1, m_2))` (box `Σ-MAC`). Every pair of scalars is a message.
    ///
    /// # Errors
    /// Implementation notes: [`Error::InvalidKey`] for a (decoded) key with `y_1 = 0` or
    /// `y_2 = 0`; [`Error::DegenerateInput`] for parameters that fail
    /// [`MACPublicParams::is_well_formed`] (with `g = 1` the result would be `U = 1`, which
    /// never verifies).
    fn sign<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        m: &Self::Message,
        rng: &mut R,
    ) -> Result<Self::Credential, Error> {
        pp.check()?;
        if !dvk.is_well_formed() {
            return Err(Error::InvalidKey);
        }
        // 1. t ← Z_q^*, U = g^t
        let t: G::ScalarField = nonzero_scalar(rng);
        let u = pp.g * t;
        // 2. cred = (U, U^{x + y_1 m_1 + y_2 m_2})
        Ok(MACCredential {
            u,
            v: u * dvk.exponent(m),
        })
    }

    /// `Verify(dvk, m, (U, V)) = [U ≠ 1 ∧ V = U^{x + y_1 m_1 + y_2 m_2}]` (box `Σ-MAC`). Keyed:
    /// only the holder of `dvk` can run it.
    ///
    /// Implementation note: `false` under a (decoded) key with `y_1 = 0` or `y_2 = 0`, under
    /// which the equation does not depend on `m_1`, respectively on `m_2`: a pair `(U, V)` that
    /// satisfies it for one such component satisfies it for every other one.
    fn verify(
        _pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        m: &Self::Message,
        cred: &Self::Credential,
    ) -> bool {
        if !dvk.is_well_formed() {
            return false;
        }
        // 1. [U ≠ 1 ∧ V = U^{x + y_1 m_1 + y_2 m_2}]
        !cred.u.is_zero() && cred.v == cred.u * dvk.exponent(m)
    }

    /// `Enc_Σ(usk, φ) = (usk, φ)`. Never fails.
    fn encode_message(
        _pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        m_pub: &Self::PublicMessage,
    ) -> Result<Self::Message, Error> {
        Ok(MACMessage::new(*m_hid, *m_pub))
    }

    /// `Com_pp(usk, φ; ρ) = g^usk h^ρ`: a Pedersen commitment to `usk`, independent of `φ`.
    ///
    /// # Errors
    /// Implementation note: [`Error::DegenerateInput`] for parameters that fail
    /// [`MACPublicParams::is_well_formed`] (with `h = 1` the "commitment" would publish
    /// `g^usk`).
    fn issuance_encoding(
        pp: &Self::PublicParams,
        m_hid: &Self::HiddenMessage,
        _m_pub: &Self::PublicMessage,
        r: &Self::IssuanceState,
    ) -> Result<Self::IssuanceEncoding, Error> {
        pp.check()?;
        Ok(pp.g * *m_hid + pp.h * *r)
    }

    /// `ReRand(pp, m, (U, V))` (box `Σ-MAC`). Keyless and message-independent: the holder
    /// cannot verify `cred` first.
    ///
    /// # Errors
    /// Implementation note: [`Error::InvalidCredential`] for `U = 1`. Such a credential never
    /// verifies and its shown form would be rejected by every possession verifier; the box has
    /// no `⊥` case because it only considers valid MACs.
    fn rerand<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        _m: &Self::Message,
        cred: &Self::Credential,
        rng: &mut R,
    ) -> Result<(Self::ShownCredential, Self::ShowState), Error> {
        if cred.u.is_zero() {
            return Err(Error::InvalidCredential);
        }
        // 1. r ← Z_q^*, cred* = (U^r, V^r), ω = ∅
        let r: G::ScalarField = nonzero_scalar(rng);
        let shown = MACShownCredential {
            u_prime: cred.u * r,
            v_prime: cred.v * r,
        };
        Ok((shown, ()))
    }

    /// `BlindIssue(dvk, C, φ)` (box `Σ-MAC`). The helper sees only `C` and `φ`; this is where
    /// `φ` enters the credential. Every element of `G` is an issuance encoding.
    ///
    /// # Errors
    /// Implementation notes: [`Error::InvalidKey`] for a (decoded) key with `y_1 = 0` or
    /// `y_2 = 0`; [`Error::DegenerateInput`] for parameters that fail
    /// [`MACPublicParams::is_well_formed`].
    fn blind_issue<R: RngCore + CryptoRng + ?Sized>(
        pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        c: &Self::IssuanceEncoding,
        m_pub: &Self::PublicMessage,
        rng: &mut R,
    ) -> Result<Self::PreCredential, Error> {
        pp.check()?;
        if !dvk.is_well_formed() {
            return Err(Error::InvalidKey);
        }
        // 1. parse C = g^usk h^ρ, t ← Z_q^*, U = g^t, W = h^{t y_1}
        let t: G::ScalarField = nonzero_scalar(rng);
        let t_y1 = t * dvk.y1;
        let u = pp.g * t;
        let w = pp.h * t_y1;
        // 2. ĉred = (U, W, U^x U^{y_2 φ} C^{t y_1})
        Ok(MACPreCredential {
            u,
            w,
            v_prime: u * (dvk.x + dvk.y2 * *m_pub) + *c * t_y1,
        })
    }

    /// `Unblind(pp, (usk, φ), (U, W, V'), ρ) = (U, V' W^{-ρ})` (box `Σ-MAC`). Deterministic. The
    /// result is NOT verified, and cannot be: only the helper holds `dvk`.
    ///
    /// # Errors
    /// Implementation note: [`Error::InvalidPreCredential`] for `U = 1` or `W = 1`, neither of
    /// which an honest helper outputs (`t, y_1 ≠ 0` and `g, h ≠ 1`). This catches a malformed
    /// answer on its face only; an answer that merely does not unblind to a valid MAC goes
    /// unnoticed (module docs, "Security and limitations").
    fn unblind(
        _pp: &Self::PublicParams,
        _m: &Self::Message,
        pre: &Self::PreCredential,
        r: &Self::IssuanceState,
    ) -> Result<Self::Credential, Error> {
        if pre.u.is_zero() || pre.w.is_zero() {
            return Err(Error::InvalidPreCredential);
        }
        // 1. return (U, V' W^{-ρ})
        Ok(MACCredential {
            u: pre.u,
            v: pre.v_prime - pre.w * *r,
        })
    }
}

impl<G: PrimeGroup, H: HashToGroup<G>> SigmaFriendlyDVCredentialBase<G> for MAC<G, H> {
    /// `m_aux = ∅`.
    type Aux = ();
    /// `C` travels inside `π`.
    type WireEncoding = G;

    const REQUIRES_DLOG_IDENTITY: bool = false;
    /// The witness of the possession clause is `usk` alone.
    const POSSESSION_VARIABLES: usize = 0;
    /// The opening clause adds `ρ`.
    const ISSUANCE_VARIABLES: usize = 1;

    fn hidden_message(usk: &G::ScalarField, _aux: &Self::Aux) -> Self::HiddenMessage {
        *usk
    }

    fn split_hidden_message(m_hid: &Self::HiddenMessage) -> (G::ScalarField, Self::Aux) {
        (*m_hid, ())
    }

    /// `(m_aux, ρ) = (∅, r)`, `r ← Z_q` (§5.1: "The designated-verifier `Σ-MAC` variant also
    /// uses `(∅, r)` (over `Z_q`)").
    fn sample_issuance<R: RngCore + CryptoRng + ?Sized>(
        _pp: &Self::PublicParams,
        rng: &mut R,
    ) -> (Self::Aux, Self::IssuanceState) {
        ((), G::ScalarField::rand(rng))
    }

    fn encoding_to_wire(c: &Self::IssuanceEncoding) -> Self::WireEncoding {
        *c
    }

    /// Every element of `G`, the identity included, is `g^usk h^ρ` for some `(usk, ρ)`, so
    /// nothing is rejected here; knowledge of an opening is what `π_0` proves.
    fn encoding_from_wire(
        _pp: &Self::PublicParams,
        wire: &Self::WireEncoding,
        _id: &G,
    ) -> Option<Self::IssuanceEncoding> {
        Some(*wire)
    }

    /// `Possess` step 1 (box `Σ-MAC`): "the verifier rejects if `U' = 1`". Keyless. With
    /// `U' = 1` the verifier's clause reads `X_V = 1^usk`, and for `V' = 1` its target is
    /// `X_V = 1`: the clause then holds for every `usk`.
    fn verify_possess_public(
        _pp: &Self::PublicParams,
        shown: &Self::ShownCredential,
        _m_pub: &G::ScalarField,
    ) -> bool {
        !shown.u_prime.is_zero()
    }

    /// `Possess` step 2 (box `Σ-MAC`), PROVER: "the prover uses only `(U', V', φ, usk)`". The
    /// clause is `X = (U')^usk` with base `U'` and the target `X := (U')^usk` computed from the
    /// witness (module docs, "The prover never sees `dvk`"); `ω = ∅`, so no variable is
    /// allocated.
    ///
    /// The clause is satisfied by `usk` by construction, whatever `cred*` is: a holder cannot
    /// notice here that its MAC is invalid or that it claims a wrong `usk`. The verifier does.
    fn possession_clauses_prover(
        _pp: &Self::PublicParams,
        shown: &Self::ShownCredential,
        _m_pub: &G::ScalarField,
        m_hid: &Self::HiddenMessage,
        _show_state: &Self::ShowState,
        rel: &mut GroupRelation<G>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        let target = shown.u_prime * *m_hid;
        rel.add_equation(LinearEquation::dlog(usk, shown.u_prime, target))?;
        Ok(Vec::new())
    }

    /// `Possess` step 2 (box `Σ-MAC`), VERIFIER: "the verifier uses `dvk` to check the
    /// equation". The same clause `X = (U')^usk` with the target
    /// `X = (V' (U')^{-x - y_2 φ})^{1/y_1}` derived from `dvk`, which is the displayed relation
    /// `V' (U')^{-x - y_2 φ} = (U')^{y_1 usk}` (module docs, "The prover never sees `dvk`").
    /// Allocates nothing. The public check `U' ≠ 1` is NOT part of the clause; run
    /// [`Self::verify_possess_public`] first.
    ///
    /// # The appended clause is SECRET
    /// Implementation note (module docs, "The verifier's statement is secret"): the target `X`
    /// is a function of `dvk` and of the attacker-chosen `(U', V', φ)`, and three such targets
    /// give a universal forgery. After this call `rel` must never leave the verifier; handle it
    /// like `dvk`: never log it (it is `Debug`), serialize it, return it or put it into an
    /// error; feed it to the Fiat-Shamir verifier and drop it.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`; [`Error::InvalidKey`]
    /// for a (decoded) key with `y_1 = 0`, which has no inverse, or with `y_2 = 0`, under which
    /// the clause would hold for every `φ` (implementation note). Nothing is appended then.
    fn possession_clauses_verifier(
        _pp: &Self::PublicParams,
        dvk: &Self::DVKey,
        shown: &Self::ShownCredential,
        m_pub: &G::ScalarField,
        rel: &mut GroupRelation<G>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        if !dvk.is_well_formed() {
            return Err(Error::InvalidKey);
        }
        // `inverse` is `None` exactly for y_1 = 0, which the check above has excluded; it is
        // used, without `unwrap`, because field division by zero would panic.
        let y1_inverse = dvk.y1.inverse().ok_or(Error::InvalidKey)?;
        let target = (shown.v_prime - shown.u_prime * (dvk.x + dvk.y2 * *m_pub)) * y1_inverse;
        rel.add_equation(LinearEquation::dlog(usk, shown.u_prime, target))?;
        Ok(Vec::new())
    }

    fn possession_witness(
        _m_hid: &Self::HiddenMessage,
        _show_state: &Self::ShowState,
    ) -> Witness<G::ScalarField> {
        Witness::new()
    }

    /// The opening clause `C = g^usk h^ρ` of `R_issue` (§5.1): one equation with bases `g`
    /// (shared variable `usk`) and `h` (fresh variable `ρ`). Keyless and independent of `φ`.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if `usk` does not belong to `rel`. Implementation note:
    /// [`Error::DegenerateInput`] for parameters that fail [`MACPublicParams::is_well_formed`]
    /// (with `g = 1` the clause would not bind `usk` at all). The relation is left untouched on
    /// error: nothing is appended and nothing is allocated.
    fn issuance_clauses(
        pp: &Self::PublicParams,
        c: &Self::IssuanceEncoding,
        _m_pub: &G::ScalarField,
        rel: &mut GroupRelation<G>,
        usk: ScalarVar,
    ) -> Result<Vec<ScalarVar>, Error> {
        pp.check()?;
        // BEFORE `ρ` is allocated: a foreign handle with the index `ρ` is about to get would
        // alias it, and the clause would read `C = (g h)^ρ` without any error.
        ensure_allocated(rel, usk)?;
        let rho = rel.alloc_scalar();
        rel.add_equation(LinearEquation::new(vec![(usk, pp.g), (rho, pp.h)], *c))?;
        Ok(vec![rho])
    }

    /// The value `ρ`.
    fn issuance_witness(
        _m_hid: &Self::HiddenMessage,
        r: &Self::IssuanceState,
    ) -> Witness<G::ScalarField> {
        Witness::from(vec![*r])
    }
}

// ---------------------------------------------------------------------------------------------
// The stand-alone sigma protocol for the possession relation
// ---------------------------------------------------------------------------------------------

impl<G: PrimeGroup, H: HashToGroup<G>> MAC<G, H> {
    /// The PROVER's statement of the possession relation for `(cred*, φ)`: a fresh
    /// [`GroupRelation`] whose variable 0 is `usk` (returned), holding the clause of
    /// [`SigmaFriendlyDVCredentialBase::possession_clauses_prover`]. The witness vector is
    /// `[usk]`. The designated-verifier construction extends exactly this relation by the tag
    /// clause on the same variable. The public check `U' ≠ 1` is NOT part of it.
    ///
    /// This statement is built from `(U', usk)` alone and contains nothing derived from `dvk`.
    /// The verifier's statement does, and is secret (module docs, "The verifier's statement is
    /// secret").
    ///
    /// # Errors
    /// None for this base; the signature is that of the clause builder it wraps.
    pub fn possession_relation_prover(
        pp: &MACPublicParams<G>,
        shown: &MACShownCredential<G>,
        m_pub: &G::ScalarField,
        m_hid: &G::ScalarField,
    ) -> Result<(GroupRelation<G>, ScalarVar), Error> {
        let mut rel = GroupRelation::new();
        let usk = rel.alloc_scalar();
        Self::possession_clauses_prover(pp, shown, m_pub, m_hid, &(), &mut rel, usk)?;
        Ok((rel, usk))
    }

    /// The VERIFIER's statement of the possession relation for `(cred*, φ)`: a fresh
    /// [`GroupRelation`] whose variable 0 is `usk`, holding the clause that
    /// [`SigmaFriendlyDVCredentialBase::possession_clauses_verifier`] derives from `dvk`.
    /// SECRET (module docs, "The verifier's statement is secret"), hence private: the only
    /// non-test caller is [`Self::verify_possess`], which hashes it and returns one bit.
    fn keyed_possession_relation(
        pp: &MACPublicParams<G>,
        dvk: &MACKey<G>,
        shown: &MACShownCredential<G>,
        m_pub: &G::ScalarField,
    ) -> Result<(GroupRelation<G>, ScalarVar), Error> {
        let mut rel = GroupRelation::new();
        let usk = rel.alloc_scalar();
        Self::possession_clauses_verifier(pp, dvk, shown, m_pub, &mut rel, usk)?;
        Ok((rel, usk))
    }

    /// TEST HELPER (crate tests and the cargo feature `test-utils`): the VERIFIER's statement of
    /// the possession relation for `(cred*, φ)`, derived from `dvk`
    /// ([`SigmaFriendlyDVCredentialBase::possession_clauses_verifier`]); variable 0 is `usk`
    /// (returned). This is the relation [`Self::verify_possess`] verifies against, exposed so
    /// that a test harness can run the interactive protocol and the extractor on it.
    ///
    /// For `U' ≠ 1` it equals the prover's statement iff `cred*` is a MAC on the prover's
    /// `(usk, φ)` under `dvk`. The public check `U' ≠ 1` is NOT part of it: for
    /// `(U', V') = (1, 1)` the two statements coincide for EVERY `usk`, although `(1, 1)` is not
    /// a MAC.
    ///
    /// # The result is SECRET
    /// Implementation note (module docs, "The verifier's statement is secret"): the target of
    /// the returned relation is a function of `dvk` and of the attacker-chosen `(cred*, φ)`;
    /// three such targets give a universal forgery. That is why this builder is not part of the
    /// default API. Never log, serialize or return what it outputs.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] for a (decoded) key with `y_1 = 0` or `y_2 = 0`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn possession_relation_verifier(
        pp: &MACPublicParams<G>,
        dvk: &MACKey<G>,
        shown: &MACShownCredential<G>,
        m_pub: &G::ScalarField,
    ) -> Result<(GroupRelation<G>, ScalarVar), Error> {
        Self::keyed_possession_relation(pp, dvk, shown, m_pub)
    }

    /// `ctx' = (pp, cred*, φ, ctx)`: the public statement of the possession relation next to
    /// the caller's context. `dvk` cannot be part of it (the prover does not have it), and the
    /// box has no public counterpart of `dvk` that could take its place. Implementation note,
    /// as for `cred::possess`.
    fn possess_context(
        pp: &MACPublicParams<G>,
        shown: &MACShownCredential<G>,
        m_pub: &G::ScalarField,
        ctx: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut transcript = Transcript::new(POSSESS_SUFFIX);
        transcript.append_serializable(b"pp", pp)?;
        transcript.append_serializable(b"cred*", shown)?;
        transcript.append_serializable(b"m_pub", m_pub)?;
        transcript.append_bytes(b"ctx", ctx);
        Ok(transcript.digest().to_vec())
    }

    /// `Possess(pp, (U', V'), φ; usk, ∅) → Π` (box `Σ-MAC`; Def. "Sigma-friendly
    /// designated-verifier credential base": "the prover uses only public parameters,
    /// `(cred*, m_pub)`, and witness `(m_hid, ω)`"): a stand-alone Fiat-Shamir proof of
    /// knowledge of the `usk` certified by the shown MAC, bound to the context `ctx`.
    ///
    /// The credential system never uses this proof on its own; it composes the same clause
    /// with the tag clause under one shared variable `usk`. The stand-alone form exists for
    /// applications and for the test harness.
    ///
    /// Without `dvk` the prover cannot tell whether `cred*` is a MAC on `(usk, φ)`; if it is
    /// not, the proof is produced all the same and [`Self::verify_possess`] rejects it.
    ///
    /// # Errors
    /// [`Error::InvalidCredential`] if `cred*` fails the public check `U' ≠ 1`.
    pub fn possess<R: RngCore + CryptoRng + ?Sized>(
        pp: &MACPublicParams<G>,
        shown: &MACShownCredential<G>,
        m_pub: &G::ScalarField,
        m_hid: &G::ScalarField,
        _show_state: &(),
        ctx: &[u8],
        rng: &mut R,
    ) -> Result<FSProof<G::ScalarField>, Error> {
        if !Self::verify_possess_public(pp, shown, m_pub) {
            return Err(Error::InvalidCredential);
        }
        let (rel, _) = Self::possession_relation_prover(pp, shown, m_pub, m_hid)?;
        let witness = Witness::from(vec![*m_hid]);
        let full_ctx = Self::possess_context(pp, shown, m_pub, ctx)?;
        fiat_shamir::prove(&rel, &witness, &full_ctx, rng)
    }

    /// The keyed possession verifier (Def. "Sigma-friendly designated-verifier credential
    /// base": "the verifier additionally uses `dvk`"; "The possession verifier includes the
    /// required public validity checks and returns `0` if one fails."): first the public check
    /// `U' ≠ 1`, then Fiat-Shamir verification of the statement derived from `dvk` for
    /// `(cred*, φ)` and the context `ctx`. `false` under a key with `y_1 = 0` or `y_2 = 0`
    /// (implementation note). Never panics.
    ///
    /// The derived statement is secret (module docs, "The verifier's statement is secret"); it
    /// is hashed here and dropped, and the one bit returned is all that leaves this function.
    #[must_use]
    pub fn verify_possess(
        pp: &MACPublicParams<G>,
        dvk: &MACKey<G>,
        shown: &MACShownCredential<G>,
        m_pub: &G::ScalarField,
        ctx: &[u8],
        proof: &FSProof<G::ScalarField>,
    ) -> bool {
        if !Self::verify_possess_public(pp, shown, m_pub) {
            return false;
        }
        let (Ok((rel, _)), Ok(full_ctx)) = (
            Self::keyed_possession_relation(pp, dvk, shown, m_pub),
            Self::possess_context(pp, shown, m_pub, ctx),
        ) else {
            return false;
        };
        fiat_shamir::verify(&rel, &full_ctx, proof)
    }
}

/// TEST HELPER (crate tests and the cargo feature `test-utils`): the credential-free forgeries
/// of `Σ-MAC` for [`dv_base_flow`](super::conformance::dv_base_flow), attack A2 of the
/// reference implementations. For `(U', V') = (1, 1)` the verifier derives the target
/// `X = (1 · 1)^{1/y_1} = 1` under EVERY well-formed key, so the forger knows its statement
/// without `dvk`, and `1 = 1^K` holds for every forged key `K`; `(1, V')` with `V' ≠ 1` is
/// degenerate too, but has no witness. Only the public check `U' ≠ 1` rejects the former.
#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn credential_free_forgeries<G: PrimeGroup>(
    pp: &MACPublicParams<G>,
    _phi: &G::ScalarField,
    _forged_key: &G::ScalarField,
) -> Vec<super::conformance::Forgery<MACShownCredential<G>, G::ScalarField>> {
    [G::zero(), pp.g]
        .into_iter()
        .map(|v_prime| super::conformance::Forgery {
            shown: MACShownCredential {
                u_prime: G::zero(),
                v_prime,
            },
            extra_witness: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ff::{Field, One};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        cred::{
            bbs,
            conformance::{FlowReport, dv_base_flow},
        },
        hash::{
            H2_SUFFIX, bls12_381::G1Hasher, h0_id, h0_identity_point, h0_predicate,
            testing::InsecureExponentHasher,
        },
        kiprf::{DDH, KIPRF, PCSTag, SigmaFriendlyKIPRF},
        serialization::WireFormat,
        sigma::{self, LinearRelation, commit, extract, respond, simulate},
    };

    type G1 = G1Projective;
    type MAC = crate::cred::MAC<G1, G1Hasher>;
    type Tag = DDH<G1, G1Hasher>;
    type Pp = MACPublicParams<G1>;

    const DOMAIN: &[u8] = b"sigma-mac-unit-tests";

    /// The public parameters of a deployment: `pp_Σ = (g, h)` and `pp_Tag`.
    struct Dep {
        pp: Pp,
        tag: Tag,
    }

    fn dep() -> Dep {
        Dep {
            pp: MAC::setup(DOMAIN).unwrap(),
            tag: Tag::setup(DOMAIN, h0_identity_point(DOMAIN)).unwrap(),
        }
    }

    fn phi(label: &[u8]) -> Fr {
        h0_predicate(DOMAIN, label)
    }

    fn msg(usk: Fr, phi: Fr) -> MACMessage<G1> {
        MACMessage::new(usk, phi)
    }

    fn cred(u: G1, v: G1) -> MACCredential<G1> {
        MACCredential { u, v }
    }

    fn shown(u_prime: G1, v_prime: G1) -> MACShownCredential<G1> {
        MACShownCredential { u_prime, v_prime }
    }

    /// A key with chosen components, the way a corrupted key file yields one: through the
    /// decoder, which accepts zero scalars.
    fn key(x: Fr, y1: Fr, y2: Fr) -> MACKey<G1> {
        let bytes = [x, y1, y2]
            .iter()
            .flat_map(|s| s.to_bytes().unwrap())
            .collect::<Vec<u8>>();
        MACKey::from_bytes(&bytes).unwrap()
    }

    /// A holder `(usk, φ, cred)` with a directly computed MAC.
    fn holder(
        dep: &Dep,
        dvk: &MACKey<G1>,
        label: &[u8],
        rng: &mut StdRng,
    ) -> (Fr, Fr, MACCredential<G1>) {
        let usk = dep.tag.keygen(rng);
        let phi = phi(label);
        let cred = MAC::sign(&dep.pp, dvk, &msg(usk, phi), rng).unwrap();
        (usk, phi, cred)
    }

    /// A scripted RNG: the field elements drawn from it are `0` at the positions listed in
    /// `zero_at` (position `i` = the `i`-th element drawn, rejected draws included) and small
    /// non-zero values elsewhere. NOT random; it only drives the `Z_q^*` samplers into their
    /// rejection branch, at a chosen draw.
    struct ScriptedZeros {
        zero_at: Vec<usize>,
        calls: usize,
    }

    impl ScriptedZeros {
        /// One field element of BLS12-381's `Z_q` takes four 64-bit outputs (the tests that use
        /// this RNG check that with a control draw).
        const WORDS_PER_SCALAR: usize = 4;

        /// Zero at the given positions.
        fn zero_at(positions: &[usize]) -> Self {
            Self {
                zero_at: positions.to_vec(),
                calls: 0,
            }
        }

        /// The first `n` field elements are zero.
        fn zero_scalars(n: usize) -> Self {
            Self::zero_at(&(0..n).collect::<Vec<usize>>())
        }
    }

    impl RngCore for ScriptedZeros {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let position = self.calls / Self::WORDS_PER_SCALAR;
            self.calls += 1;
            if self.zero_at.contains(&position) {
                0
            } else {
                self.calls as u64
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

    // Test-only marker: the samplers' bound asks for a `CryptoRng`.
    impl CryptoRng for ScriptedZeros {}

    // ----- a miniature of the designated-verifier attestation: R_att = R_Possess ∧ R_Tag --------

    struct Att {
        t: G1,
        shown: MACShownCredential<G1>,
        phi: Fr,
        pi: FSProof<Fr>,
    }

    /// The PROVER's `R_att` for `(cred*, φ, T, s)` and the `usk` it claims: the possession clause
    /// and the tag clause over ONE variable. No `dvk` in sight.
    fn prover_relation(
        dep: &Dep,
        shown: &MACShownCredential<G1>,
        phi: &Fr,
        claimed_usk: &Fr,
        t: &G1,
        s: &Fr,
    ) -> GroupRelation<G1> {
        let (mut rel, usk) =
            MAC::possession_relation_prover(&dep.pp, shown, phi, claimed_usk).unwrap();
        for eq in dep.tag.tag_equations(usk, t, s) {
            rel.add_equation(eq).unwrap();
        }
        rel
    }

    /// The VERIFIER's `R_att` for `(cred*, φ, T, s)`, derived from `dvk`.
    fn verifier_relation(
        dep: &Dep,
        dvk: &MACKey<G1>,
        shown: &MACShownCredential<G1>,
        phi: &Fr,
        t: &G1,
        s: &Fr,
    ) -> Result<GroupRelation<G1>, Error> {
        let (mut rel, usk) = MAC::possession_relation_verifier(&dep.pp, dvk, shown, phi)?;
        for eq in dep.tag.tag_equations(usk, t, s) {
            rel.add_equation(eq)?;
        }
        Ok(rel)
    }

    /// `ctx_j = (pp, id, φ_j, T_j, cred*_j)`: `Attest` step 10 without `hvk`, which the
    /// designated-verifier variant does not have.
    fn att_ctx(dep: &Dep, id: &G1, phi: &Fr, t: &G1, shown: &MACShownCredential<G1>) -> Vec<u8> {
        let mut tr = Transcript::new(b"/TEST-CTX-ATT-DV");
        tr.append_serializable(b"pp", &dep.pp).unwrap();
        tr.append_serializable(b"pp-tag", &dep.tag).unwrap();
        tr.append_serializable(b"id", id).unwrap();
        tr.append_serializable(b"phi", phi).unwrap();
        tr.append_serializable(b"T", t).unwrap();
        tr.append_serializable(b"cred*", shown).unwrap();
        tr.digest().to_vec()
    }

    /// Keyless `Attest` for a holder that claims `usk` and whose tag key is `tag_key` (honestly,
    /// `tag_key = usk`).
    fn attest(
        dep: &Dep,
        (usk, phi, cred): (&Fr, &Fr, &MACCredential<G1>),
        tag_key: &Fr,
        id: &G1,
        rng: &mut StdRng,
    ) -> Result<Att, Error> {
        let s: Fr = h0_id(DOMAIN, id)?;
        let t = dep.tag.eval(tag_key, &s).ok_or(Error::UndefinedTag)?;
        let (shown, ()) = MAC::rerand(&dep.pp, &msg(*usk, *phi), cred, rng)?;
        let rel = prover_relation(dep, &shown, phi, usk, &t, &s);
        let pi = fiat_shamir::prove(&rel, &[*usk], &att_ctx(dep, id, phi, &t, &shown), rng)?;
        Ok(Att {
            t,
            shown,
            phi: *phi,
            pi,
        })
    }

    /// Keyed `VerifyAtt`: `ValidTag`, the public check `U' ≠ 1`, then Fiat-Shamir on the
    /// statement derived from `dvk`.
    fn verify_att(dep: &Dep, dvk: &MACKey<G1>, id: &G1, att: &Att) -> bool {
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        dep.tag.valid_tag(&att.t, &s)
            && MAC::verify_possess_public(&dep.pp, &att.shown, &att.phi)
            && verifier_relation(dep, dvk, &att.shown, &att.phi, &att.t, &s).is_ok_and(|rel| {
                fiat_shamir::verify(
                    &rel,
                    &att_ctx(dep, id, &att.phi, &att.t, &att.shown),
                    &att.pi,
                )
            })
    }

    // ----- Setup ---------------------------------------------------------------------------------

    #[test]
    fn setup_derives_the_generators_from_the_deployment_label() {
        let Dep { pp, tag } = dep();
        assert!(pp.is_well_formed());
        assert!(!pp.g.is_zero() && !pp.h.is_zero());
        assert_ne!(pp.g, pp.h);
        // g, h = H_{/MAC-GENERATORS}(0), H_{/MAC-GENERATORS}(1) of the deployment's oracle
        let hasher = G1Hasher::new(DOMAIN).unwrap();
        assert_eq!(hasher.generators(GENERATORS_SUFFIX, 2), [pp.g, pp.h]);
        // The suffix is pinned as a literal (it is part of the parameters' definition), and it
        // is not the suffix of Σ-BBS, whose generators h_0, .., h_3 come from the same oracle
        // and live in the same group: g, h must be none of them.
        assert_eq!(GENERATORS_SUFFIX, b"/MAC-GENERATORS");
        assert_eq!(hasher.generators(b"/MAC-GENERATORS", 2), [pp.g, pp.h]);
        assert_ne!(GENERATORS_SUFFIX, bbs::GENERATORS_SUFFIX);
        let bbs_generators = hasher.generators(bbs::GENERATORS_SUFFIX, 4);
        assert_eq!(bbs_generators.len(), 4);
        assert!(!bbs_generators.contains(&pp.g) && !bbs_generators.contains(&pp.h));
        // deterministic and deployment-bound
        assert_eq!(MAC::setup(DOMAIN).unwrap(), pp);
        let other = MAC::setup(b"another deployment").unwrap();
        assert!(other.g != pp.g && other.h != pp.h);
        // independent of what Tag_DDH uses: the programmed generator and the oracle H_2
        let c0: Fr = h0_identity_point(DOMAIN);
        assert_eq!(tag.htag(&c0), G1::generator());
        for generator in [pp.g, pp.h] {
            assert_ne!(generator, G1::generator());
            assert_ne!(generator, hasher.hash(H2_SUFFIX, &0u64.to_le_bytes()));
            assert_ne!(generator, hasher.hash(H2_SUFFIX, &1u64.to_le_bytes()));
        }
    }

    /// A hash-to-group oracle that BREAKS its contract, selected by the deployment label (the
    /// only input `HashToGroup::new` has).
    #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
    struct BrokenHasher {
        domain: Vec<u8>,
    }

    impl HashToGroup<G1> for BrokenHasher {
        fn new(domain: &[u8]) -> Result<Self, Error> {
            if domain == b"unavailable" {
                return Err(Error::HashToCurve("unavailable".into()));
            }
            Ok(Self {
                domain: domain.to_vec(),
            })
        }

        fn domain(&self) -> &[u8] {
            &self.domain
        }

        fn hash(&self, _dst_suffix: &[u8], msg: &[u8]) -> G1 {
            match (self.domain.as_slice(), msg.first()) {
                (b"constant", _) => G1::generator(),
                (b"identity-g", Some(0)) | (b"identity-h", Some(1)) => G1::zero(),
                (_, first) => {
                    G1::generator() * Fr::from(2 + u64::from(first.copied().unwrap_or(0)))
                }
            }
        }

        fn generators(&self, dst_suffix: &[u8], n: usize) -> Vec<G1> {
            let n = if self.domain == b"short" { 1 } else { n };
            (0..n as u64)
                .map(|i| self.hash(dst_suffix, &i.to_le_bytes()))
                .collect()
        }
    }

    #[test]
    fn setup_refuses_degenerate_generators() {
        type Broken = crate::cred::MAC<G1, BrokenHasher>;
        // control: the test oracle as such is fine
        let pp = Broken::setup(b"fine").unwrap();
        assert!(pp.is_well_formed());
        assert_eq!(
            (pp.g, pp.h),
            (
                G1::generator() * Fr::from(2u64),
                G1::generator() * Fr::from(3u64)
            )
        );
        for domain in [&b"constant"[..], b"identity-g", b"identity-h"] {
            assert!(
                matches!(Broken::setup(domain), Err(Error::DegenerateInput(_))),
                "{}",
                String::from_utf8_lossy(domain)
            );
        }
        assert_eq!(
            Broken::setup(b"short"),
            Err(Error::LengthMismatch {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            Broken::setup(b"unavailable"),
            Err(Error::HashToCurve("unavailable".into()))
        );
    }

    /// Decoding accepts the identity, so parameters from the wire can be degenerate. The
    /// algorithms that use the generators refuse them; each line below fails if the check is
    /// removed from the algorithm it names.
    #[test]
    fn malformed_public_parameters_are_refused() {
        let mut rng = StdRng::seed_from_u64(0x3ac01);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let c = MAC::issuance_encoding(&pp, &usk, &phi, &rho).unwrap();

        for (i, bad) in [
            Pp {
                g: G1::zero(),
                h: pp.h,
            },
            Pp {
                g: pp.g,
                h: G1::zero(),
            },
            Pp { g: pp.g, h: pp.g },
            Pp {
                g: G1::zero(),
                h: G1::zero(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let back = Pp::from_bytes(&bad.to_bytes().unwrap()).unwrap();
            assert_eq!(back, bad, "case {i}: the decoder does not mind");
            assert!(!bad.is_well_formed(), "case {i}");
            assert!(
                matches!(
                    MAC::sign(&bad, &dvk, &msg(usk, phi), &mut rng),
                    Err(Error::DegenerateInput(_))
                ),
                "case {i}"
            );
            assert!(
                matches!(
                    MAC::blind_issue(&bad, &dvk, &c, &phi, &mut rng),
                    Err(Error::DegenerateInput(_))
                ),
                "case {i}"
            );
            assert!(
                matches!(
                    MAC::issuance_encoding(&bad, &usk, &phi, &rho),
                    Err(Error::DegenerateInput(_))
                ),
                "case {i}"
            );
            let mut rel = GroupRelation::<G1>::new();
            let var = rel.alloc_scalar();
            assert!(
                matches!(
                    MAC::issuance_clauses(&bad, &c, &phi, &mut rel, var),
                    Err(Error::DegenerateInput(_))
                ),
                "case {i}"
            );
            // nothing was appended
            assert_eq!(rel.num_scalars(), 1);
            assert!(rel.equations().is_empty());
        }
        // what the check is for: with g = 1 the opening clause would not bind usk ...
        let (g, h) = (G1::zero(), pp.h);
        let mut rel = GroupRelation::<G1>::new();
        let vars = rel.alloc_scalars(2);
        rel.add_equation(LinearEquation::new(
            vec![(vars[0], g), (vars[1], h)],
            h * rho,
        ))
        .unwrap();
        assert!(rel.is_satisfied_by(&[usk, rho]));
        assert!(rel.is_satisfied_by(&[usk + Fr::one(), rho]));
        // ... and the algorithms that do not touch g, h do not mind the parameters
        let bad = Pp { g, h };
        let cred = MAC::sign(&pp, &dvk, &msg(usk, phi), &mut rng).unwrap();
        assert!(MAC::verify(&bad, &dvk, &msg(usk, phi), &cred));
    }

    // ----- MAC = (KeyGen, Sign, Verify) ----------------------------------------------------------

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(0x3ac02);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        for _ in 0..4 {
            let (m1, m2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let cred = MAC::sign(&pp, &dvk, &msg(m1, m2), &mut rng).unwrap();
            assert!(!cred.u.is_zero());
            assert_eq!(cred.v, cred.u * (dvk.x + dvk.y1 * m1 + dvk.y2 * m2));
            assert!(MAC::verify(&pp, &dvk, &msg(m1, m2), &cred));
        }
        // edge messages of Z_q^2
        for (m1, m2) in [
            (Fr::zero(), Fr::zero()),
            (Fr::one(), Fr::zero()),
            (Fr::zero(), -Fr::one()),
        ] {
            let cred = MAC::sign(&pp, &dvk, &msg(m1, m2), &mut rng).unwrap();
            assert!(MAC::verify(&pp, &dvk, &msg(m1, m2), &cred));
        }
        // signing is randomized, with U = g^t for the ONE scalar t ← Z_q^* it draws
        let m = msg(Fr::from(7u64), Fr::from(8u64));
        let mut replay = StdRng::seed_from_u64(99);
        let cred = MAC::sign(&pp, &dvk, &m, &mut StdRng::seed_from_u64(99)).unwrap();
        let t: Fr = nonzero_scalar(&mut replay);
        assert_eq!(cred.u, pp.g * t);
        assert_ne!(MAC::sign(&pp, &dvk, &m, &mut rng).unwrap(), cred);
    }

    #[test]
    fn verification_rejects_wrong_message_and_wrong_key() {
        let mut rng = StdRng::seed_from_u64(0x3ac03);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let cred = MAC::sign(&pp, &dvk, &msg(usk, phi), &mut rng).unwrap();
        assert!(MAC::verify(&pp, &dvk, &msg(usk, phi), &cred));

        // wrong message: either component, swapped components, neighbours
        assert!(!MAC::verify(&pp, &dvk, &msg(usk + Fr::one(), phi), &cred));
        assert!(!MAC::verify(&pp, &dvk, &msg(usk, phi + Fr::one()), &cred));
        assert!(!MAC::verify(&pp, &dvk, &msg(phi, usk), &cred));
        assert!(!MAC::verify(&pp, &dvk, &msg(Fr::zero(), Fr::zero()), &cred));
        assert!(!MAC::verify(
            &pp,
            &dvk,
            &msg(Fr::rand(&mut rng), Fr::rand(&mut rng)),
            &cred
        ));

        // wrong key: an independent key, and the right key with one component replaced
        let other = MAC::keygen(&pp, &mut rng);
        assert!(!MAC::verify(&pp, &other, &msg(usk, phi), &cred));
        for (i, bad) in [
            key(other.x, dvk.y1, dvk.y2),
            key(dvk.x, other.y1, dvk.y2),
            key(dvk.x, dvk.y1, other.y2),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                !MAC::verify(&pp, bad, &msg(usk, phi), &cred),
                "component {i}"
            );
        }
        // control: the decoder round-trips the right key
        assert!(MAC::verify(
            &pp,
            &key(dvk.x, dvk.y1, dvk.y2),
            &msg(usk, phi),
            &cred
        ));
    }

    #[test]
    fn verification_rejects_tampered_macs() {
        let mut rng = StdRng::seed_from_u64(0x3ac04);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let m = msg(Fr::rand(&mut rng), Fr::rand(&mut rng));
        let MACCredential { u, v } = MAC::sign(&pp, &dvk, &m, &mut rng).unwrap();
        let r = Fr::rand(&mut rng);
        let tampered = [
            (u + pp.g, v),
            (u, v + pp.g),
            (u * r, v),
            (u, v * r),
            (v, u),
            (-u, v),
            (u, G1::zero()),
            (G1::rand(&mut rng), G1::rand(&mut rng)),
        ];
        for (i, (u, v)) in tampered.into_iter().enumerate() {
            assert!(!MAC::verify(&pp, &dvk, &m, &cred(u, v)), "tampering {i}");
        }
        // control: scaling BOTH components is re-randomization and still verifies
        assert!(MAC::verify(&pp, &dvk, &m, &cred(u * r, v * r)));
    }

    /// `U = 1` is rejected by `Verify` AND by the possession verifier, although `V = U^e` holds
    /// for `(1, 1)` under every key and message.
    #[test]
    fn identity_u_is_rejected_everywhere() {
        let mut rng = StdRng::seed_from_u64(0x3ac05);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);

        let degenerate = cred(G1::zero(), G1::zero());
        assert_eq!(degenerate.v, degenerate.u * dvk.exponent(&m));
        assert!(!MAC::verify(&pp, &dvk, &m, &degenerate));
        assert!(!MAC::verify(
            &pp,
            &dvk,
            &m,
            &cred(G1::zero(), G1::rand(&mut rng))
        ));

        for v_prime in [G1::zero(), G1::rand(&mut rng)] {
            assert!(!MAC::verify_possess_public(
                &pp,
                &shown(G1::zero(), v_prime),
                &phi
            ));
        }
        // V' = 1 alone is not a public rejection reason (box: only U'); it is the MAC of the
        // messages with x + y_1 m_1 + y_2 m_2 = 0, and the clause is false for every other usk.
        assert!(MAC::verify_possess_public(
            &pp,
            &shown(pp.g, G1::zero()),
            &phi
        ));
        let m1 = -(dvk.x + dvk.y2 * phi) * dvk.y1.inverse().unwrap();
        assert!(MAC::verify(
            &pp,
            &dvk,
            &msg(m1, phi),
            &cred(pp.g, G1::zero())
        ));

        // holder-side face checks
        assert_eq!(
            MAC::rerand(&pp, &m, &degenerate, &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
        assert_eq!(
            MAC::rerand(&pp, &m, &cred(G1::zero(), pp.g), &mut rng).unwrap_err(),
            Error::InvalidCredential
        );
        for (u, w) in [(G1::zero(), pp.h), (pp.g, G1::zero())] {
            let pre = MACPreCredential {
                u,
                w,
                v_prime: pp.g,
            };
            assert_eq!(
                MAC::unblind(&pp, &m, &pre, &Fr::one()).unwrap_err(),
                Error::InvalidPreCredential
            );
        }
    }

    /// "Sample `t ← Z_q^*`", "`y_1, y_2 ← Z_q^*`", "`r ← Z_q^*`" (box `Σ-MAC`): with an RNG that
    /// yields the field element `0` at the draw in question, every `Z_q^*` sampler must skip it.
    /// Each assertion fails if the sampler
    /// it names draws from all of `Z_q`.
    #[test]
    fn the_box_samples_from_zq_star() {
        let Dep { pp, .. } = dep();
        // control: this RNG makes the plain sampler return zero, exactly at the scripted draws
        assert!(Fr::rand(&mut ScriptedZeros::zero_scalars(1)).is_zero());
        let mut script = ScriptedZeros::zero_at(&[0, 1, 3]);
        let draws: Vec<bool> = (0..6).map(|_| Fr::rand(&mut script).is_zero()).collect();
        assert_eq!(draws, [true, true, false, true, false, false]);
        let mut std_rng = StdRng::seed_from_u64(0x3ac06);
        let dvk = MAC::keygen(&pp, &mut std_rng);
        let (usk, phi, rho) = (Fr::from(3u64), Fr::from(4u64), Fr::from(5u64));
        let m = msg(usk, phi);

        // KeyGen draws x, then y_1, then y_2. x ← Z_q may be zero (draw 0); y_1 ← Z_q^* skips
        // the zero of draw 1 and takes draw 2; y_2 ← Z_q^* skips the zero of draw 3.
        let mut script = ScriptedZeros::zero_at(&[0, 1, 3]);
        let scripted = MAC::keygen(&pp, &mut script);
        assert!(scripted.x.is_zero());
        assert!(!scripted.y1.is_zero());
        assert!(!scripted.y2.is_zero());
        assert!(scripted.is_well_formed());
        // five draws were consumed: x, (0), y_1, (0), y_2
        assert_eq!(script.calls, 5 * ScriptedZeros::WORDS_PER_SCALAR);
        // y_2 alone: x and y_1 come from draws 0 and 1, draw 2 is the zero y_2 must not take
        let scripted = MAC::keygen(&pp, &mut ScriptedZeros::zero_at(&[2]));
        assert!(!scripted.x.is_zero() && !scripted.y1.is_zero());
        assert!(!scripted.y2.is_zero());
        assert!(MAC::is_well_formed_key(&pp, &scripted));

        // Sign: t ≠ 0, i.e. U ≠ 1
        let cred = MAC::sign(&pp, &dvk, &m, &mut ScriptedZeros::zero_scalars(1)).unwrap();
        assert!(!cred.u.is_zero());
        assert!(MAC::verify(&pp, &dvk, &m, &cred));

        // ReRand: r ≠ 0, i.e. U' ≠ 1
        let (shown, ()) = MAC::rerand(&pp, &m, &cred, &mut ScriptedZeros::zero_scalars(1)).unwrap();
        assert!(!shown.u_prime.is_zero());
        assert!(MAC::verify_possess_public(&pp, &shown, &phi));

        // BlindIssue: t ≠ 0, i.e. U ≠ 1 and W ≠ 1
        let c = MAC::issuance_encoding(&pp, &usk, &phi, &rho).unwrap();
        let pre =
            MAC::blind_issue(&pp, &dvk, &c, &phi, &mut ScriptedZeros::zero_scalars(1)).unwrap();
        assert!(!pre.u.is_zero() && !pre.w.is_zero());
        let cred = MAC::unblind(&pp, &m, &pre, &rho).unwrap();
        assert!(MAC::verify(&pp, &dvk, &m, &cred));

        // the issuance state, in contrast, is ρ ← Z_q (§5.1)
        let ((), rho) = MAC::sample_issuance(&pp, &mut ScriptedZeros::zero_scalars(1));
        assert!(rho.is_zero());
    }

    // ----- encoded issuance ----------------------------------------------------------------------

    /// Def. "Designated-verifier credential base", correctness: `Unblind(BlindIssue(Com(usk, φ;
    /// ρ), φ), ρ)` verifies as a MAC on `Enc_Σ(usk, φ)`; and it is exactly a fresh MAC with
    /// `U = g^t` (proof sketch of the Lemma on `Σ-MAC`: "uniform nonzero `t` gives the fresh-MAC
    /// distribution").
    #[test]
    fn blind_issuance_then_unblind_is_a_mac_on_the_encoded_message() {
        let mut rng = StdRng::seed_from_u64(0x3ac07);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        for round in 0..4u64 {
            let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let (aux, rho) = MAC::sample_issuance(&pp, &mut rng);
            let m_hid = MAC::hidden_message(&usk, &aux);
            assert_eq!(MAC::split_hidden_message(&m_hid), (usk, ()));
            // C = g^usk h^ρ, independent of φ
            let c = MAC::issuance_encoding(&pp, &m_hid, &phi, &rho).unwrap();
            assert_eq!(c, pp.g * usk + pp.h * rho);
            assert_eq!(
                MAC::issuance_encoding(&pp, &m_hid, &(phi + Fr::one()), &rho).unwrap(),
                c
            );
            let wire = MAC::encoding_to_wire(&c);
            let c_helper = MAC::encoding_from_wire(&pp, &wire, &G1::zero()).unwrap();
            assert_eq!(c_helper, c);

            // the box, step by step, for the ONE scalar t ← Z_q^* the helper draws
            let seed = 1000 + round;
            let pre =
                MAC::blind_issue(&pp, &dvk, &c_helper, &phi, &mut StdRng::seed_from_u64(seed))
                    .unwrap();
            let t: Fr = nonzero_scalar(&mut StdRng::seed_from_u64(seed));
            assert_eq!(pre.u, pp.g * t);
            assert_eq!(pre.w, pp.h * (t * dvk.y1));
            assert_eq!(
                pre.v_prime,
                pre.u * dvk.x + pre.u * (dvk.y2 * phi) + c * (t * dvk.y1)
            );
            // C^{t y_1} = U^{y_1 usk} W^ρ
            assert_eq!(c * (t * dvk.y1), pre.u * (dvk.y1 * usk) + pre.w * rho);

            let m = MAC::encode_message(&pp, &m_hid, &phi).unwrap();
            // the pre-credential itself is not a MAC on m (it is blinded by ρ)
            assert!(!MAC::verify(&pp, &dvk, &m, &cred(pre.u, pre.v_prime)));

            let issued = MAC::unblind(&pp, &m, &pre, &rho).unwrap();
            assert!(MAC::verify(&pp, &dvk, &m, &issued));
            // the fresh-MAC form: V = U^{x + y_1 usk + y_2 φ}, U = g^t ≠ 1
            assert_eq!(issued.u, pre.u);
            assert!(!issued.u.is_zero());
            assert_eq!(issued.v, issued.u * (dvk.x + dvk.y1 * usk + dvk.y2 * phi));
            // i.e. literally what Sign outputs on (usk, φ) with the same coins
            assert_eq!(
                MAC::sign(&pp, &dvk, &m, &mut StdRng::seed_from_u64(seed)).unwrap(),
                issued
            );

            // φ is injected exactly once: the MAC is on (usk, φ) and on nothing nearby
            assert!(!MAC::verify(&pp, &dvk, &msg(usk, phi + phi), &issued));
            assert!(!MAC::verify(&pp, &dvk, &msg(usk, Fr::zero()), &issued));
            assert!(!MAC::verify(&pp, &dvk, &msg(usk + Fr::one(), phi), &issued));
        }

        // every element of G is an issuance encoding, the identity included: C = 1 = g^0 h^0
        let phi = phi(b"f");
        let c = MAC::encoding_from_wire(&pp, &G1::zero(), &G1::zero()).unwrap();
        assert_eq!(
            c,
            MAC::issuance_encoding(&pp, &Fr::zero(), &phi, &Fr::zero()).unwrap()
        );
        let pre = MAC::blind_issue(&pp, &dvk, &c, &phi, &mut rng).unwrap();
        let m = msg(Fr::zero(), phi);
        let issued = MAC::unblind(&pp, &m, &pre, &Fr::zero()).unwrap();
        assert!(MAC::verify(&pp, &dvk, &m, &issued));
    }

    #[test]
    fn unblinding_with_a_wrong_rho_does_not_verify() {
        let mut rng = StdRng::seed_from_u64(0x3ac08);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let c = MAC::issuance_encoding(&pp, &usk, &phi, &rho).unwrap();
        let pre = MAC::blind_issue(&pp, &dvk, &c, &phi, &mut rng).unwrap();
        let m = msg(usk, phi);
        assert!(MAC::verify(
            &pp,
            &dvk,
            &m,
            &MAC::unblind(&pp, &m, &pre, &rho).unwrap()
        ));
        for wrong in [rho + Fr::one(), -rho, Fr::zero(), Fr::rand(&mut rng)] {
            let cred = MAC::unblind(&pp, &m, &pre, &wrong).unwrap();
            assert!(!MAC::verify(&pp, &dvk, &m, &cred));
        }
        // a tampered cancellation term W
        let bad = MACPreCredential {
            w: pre.w + pp.h,
            ..pre.clone()
        };
        let cred = MAC::unblind(&pp, &m, &bad, &rho).unwrap();
        assert!(!MAC::verify(&pp, &dvk, &m, &cred));
        // issued under another φ than the one the user expects
        let pre = MAC::blind_issue(&pp, &dvk, &c, &(phi + Fr::one()), &mut rng).unwrap();
        let cred = MAC::unblind(&pp, &m, &pre, &rho).unwrap();
        assert!(!MAC::verify(&pp, &dvk, &m, &cred));
        assert!(MAC::verify(&pp, &dvk, &msg(usk, phi + Fr::one()), &cred));
        // issued under another key
        let other = MAC::keygen(&pp, &mut rng);
        let pre = MAC::blind_issue(&pp, &other, &c, &phi, &mut rng).unwrap();
        let cred = MAC::unblind(&pp, &m, &pre, &rho).unwrap();
        assert!(!MAC::verify(&pp, &dvk, &m, &cred));
    }

    // ----- ReRand --------------------------------------------------------------------------------

    /// Strong re-randomization (Def. "Credential base", show unlinkability, with the changes of
    /// Def. "Designated-verifier credential base"): `cred*` verifies on the same message and
    /// differs from `cred` in BOTH elements. (That its distribution is the fresh-MAC
    /// distribution is the Lemma's argument, not something a test can show.)
    #[test]
    fn rerandomized_credential_verifies_and_differs() {
        let mut rng = StdRng::seed_from_u64(0x3ac09);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = MAC::sign(&pp, &dvk, &m, &mut rng).unwrap();

        let (shown, ()) = MAC::rerand(&pp, &m, &cred, &mut StdRng::seed_from_u64(7)).unwrap();
        // (U^r, V^r) for the ONE scalar r ← Z_q^* it draws
        let r: Fr = nonzero_scalar(&mut StdRng::seed_from_u64(7));
        assert_eq!((shown.u_prime, shown.v_prime), (cred.u * r, cred.v * r));
        assert!(!shown.u_prime.is_zero());
        assert_ne!(shown.u_prime, cred.u);
        assert_ne!(shown.v_prime, cred.v);
        let as_cred = MACCredential::from(shown.clone());
        assert!(MAC::verify(&pp, &dvk, &m, &as_cred));
        assert!(!MAC::verify(
            &pp,
            &dvk,
            &msg(usk, phi + Fr::one()),
            &as_cred
        ));
        assert!(MAC::verify_possess_public(&pp, &shown, &phi));

        // fresh coins, fresh encoding; and a shown credential can be re-randomized again
        let (shown2, ()) = MAC::rerand(&pp, &m, &cred, &mut rng).unwrap();
        assert_ne!(shown2, shown);
        assert!(shown2.u_prime != shown.u_prime && shown2.v_prime != shown.v_prime);
        let (shown3, ()) = MAC::rerand(&pp, &m, &as_cred, &mut rng).unwrap();
        assert!(MAC::verify(&pp, &dvk, &m, &shown3.into()));

        // ReRand is keyless and cannot verify: it re-randomizes an invalid MAC just the same
        let invalid = MACCredential {
            u: cred.u,
            v: cred.v + pp.g,
        };
        let (shown4, ()) = MAC::rerand(&pp, &m, &invalid, &mut rng).unwrap();
        assert!(!MAC::verify(&pp, &dvk, &m, &shown4.into()));
    }

    // ----- Possess: keyless prover, keyed verifier, tag clause with a shared usk -----------------

    #[test]
    fn keyless_prover_and_keyed_verifier_are_complete_with_the_tag_clause() {
        let mut rng = StdRng::seed_from_u64(0x3ac0a);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();

        let att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));
        // one witness coordinate, one response: |att| = 3 G + 3 Z_q
        assert_eq!(att.pi.responses.len(), 1);
        assert_eq!(att.t, dep.tag.eval(&usk, &s).unwrap());

        // Both sides state the SAME relation: two equations over one variable, with the
        // possession target X = (U')^usk that the prover computed and the verifier derived.
        let rel_p = prover_relation(&dep, &att.shown, &phi, &usk, &att.t, &s);
        let rel_v = verifier_relation(&dep, &dvk, &att.shown, &phi, &att.t, &s).unwrap();
        assert_eq!(rel_p, rel_v);
        assert_eq!(rel_v.num_scalars(), 1);
        let x = att.shown.u_prime * usk;
        let var = MAC::possession_relation_prover(&dep.pp, &att.shown, &phi, &usk)
            .unwrap()
            .1;
        assert_eq!(var.index(), 0);
        assert_eq!(
            rel_v.equations(),
            [
                LinearEquation::dlog(var, att.shown.u_prime, x),
                LinearEquation::dlog(var, dep.tag.htag(&s), att.t),
            ]
        );
        // ... which is the displayed relation V' (U')^{-x - y_2 φ} = (U')^{y_1 usk}
        assert_eq!(
            att.shown.v_prime - att.shown.u_prime * (dvk.x + dvk.y2 * phi),
            att.shown.u_prime * (dvk.y1 * usk)
        );
        assert!(rel_v.is_satisfied_by(&[usk]));
        assert!(!rel_v.is_satisfied_by(&[usk + Fr::one()]));

        // a credential obtained through blind issuance attests just the same
        let rho = Fr::rand(&mut rng);
        let c = MAC::issuance_encoding(&dep.pp, &usk, &phi, &rho).unwrap();
        let pre = MAC::blind_issue(&dep.pp, &dvk, &c, &phi, &mut rng).unwrap();
        let issued = MAC::unblind(&dep.pp, &msg(usk, phi), &pre, &rho).unwrap();
        let att = attest(&dep, (&usk, &phi, &issued), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));

        // two attestations by the same holder for the same id: same tag, unrelated cred*
        let again = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &again));
        assert_eq!(again.t, att.t);
        assert_ne!(again.shown, att.shown);
    }

    /// The prover-side clause functions take no key: the statement they build depends on
    /// `(U', usk)` alone, not on `V'`, `φ` or `pp`.
    #[test]
    fn prover_statement_depends_on_u_prime_and_usk_only() {
        let mut rng = StdRng::seed_from_u64(0x3ac0b);
        let dep = dep();
        let (u_prime, usk) = (G1::rand(&mut rng), Fr::rand(&mut rng));
        let (rel, var) = MAC::possession_relation_prover(
            &dep.pp,
            &shown(u_prime, G1::rand(&mut rng)),
            &Fr::rand(&mut rng),
            &usk,
        )
        .unwrap();
        assert_eq!(
            rel.equations(),
            [LinearEquation::dlog(var, u_prime, u_prime * usk)]
        );
        assert!(rel.is_satisfied_by(&[usk]));
        assert!(MAC::possession_witness(&usk, &()).is_empty());
        const { assert!(<MAC as SigmaFriendlyDVCredentialBase<G1>>::POSSESSION_VARIABLES == 0) };
        const { assert!(<MAC as SigmaFriendlyDVCredentialBase<G1>>::ISSUANCE_VARIABLES == 1) };
        const { assert!(!<MAC as SigmaFriendlyDVCredentialBase<G1>>::REQUIRES_DLOG_IDENTITY) };
    }

    #[test]
    fn a_verifier_with_another_key_rejects() {
        let mut rng = StdRng::seed_from_u64(0x3ac0c);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));

        let other = MAC::keygen(&dep.pp, &mut rng);
        assert!(!verify_att(&dep, &other, &id, &att));
        // every single key component matters
        for (i, bad) in [
            key(other.x, dvk.y1, dvk.y2),
            key(dvk.x, other.y1, dvk.y2),
            key(dvk.x, dvk.y1, other.y2),
        ]
        .iter()
        .enumerate()
        {
            assert!(!verify_att(&dep, bad, &id, &att), "component {i}");
            let s: Fr = h0_id(DOMAIN, &id).unwrap();
            let rel = verifier_relation(&dep, bad, &att.shown, &phi, &att.t, &s).unwrap();
            assert!(!rel.is_satisfied_by(&[usk]), "component {i}");
        }
        assert!(verify_att(&dep, &key(dvk.x, dvk.y1, dvk.y2), &id, &att));
    }

    /// The tag must be under the credential's `usk`: the two clauses share ONE variable, so no
    /// witness exists for a tag under another key, and the honest prover refuses.
    #[test]
    fn tag_under_a_different_key_cannot_be_proven() {
        let mut rng = StdRng::seed_from_u64(0x3ac0d);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let other_key = dep.tag.keygen(&mut rng);

        // honest prover code, dishonest tag key
        assert_eq!(
            attest(&dep, (&usk, &phi, &cred), &other_key, &id, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );

        // neither candidate witness satisfies the verifier's conjunction
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let t = dep.tag.eval(&other_key, &s).unwrap();
        let (shown, ()) = MAC::rerand(&dep.pp, &msg(usk, phi), &cred, &mut rng).unwrap();
        let rel = verifier_relation(&dep, &dvk, &shown, &phi, &t, &s).unwrap();
        assert!(!rel.is_satisfied_by(&[usk])); // satisfies possession, not the tag clause
        assert!(!rel.is_satisfied_by(&[other_key])); // satisfies the tag clause, not possession
        for w in [usk, other_key] {
            assert_eq!(
                fiat_shamir::prove(&rel, &[w], b"ctx", &mut rng),
                Err(Error::WitnessDoesNotSatisfyRelation)
            );
        }
        // control: with the right tag the same relation shape is satisfied by usk
        let t = dep.tag.eval(&usk, &s).unwrap();
        let rel = verifier_relation(&dep, &dvk, &shown, &phi, &t, &s).unwrap();
        assert!(rel.is_satisfied_by(&[usk]));

        // a verifying attestation does not survive swapping in the other key's tag
        let mut att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        att.t = dep.tag.eval(&other_key, &s).unwrap();
        assert!(!verify_att(&dep, &dvk, &id, &att));
    }

    /// A holder that claims ANOTHER `usk` for its MAC, consistently: tag and possession target
    /// under the other key. Its own relation is satisfied by construction, the keyless prover
    /// runs through, and the keyed verifier rejects: it derives `X = (U')^usk` of the REAL `usk`.
    #[test]
    fn a_holder_claiming_a_different_usk_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0x3ac0e);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let claimed = dep.tag.keygen(&mut rng);
        assert_ne!(claimed, usk);

        let att = attest(&dep, (&claimed, &phi, &cred), &claimed, &id, &mut rng).unwrap();
        // everything the prover can check is in order ...
        assert!(dep.tag.valid_tag(&att.t, &s));
        assert!(MAC::verify_possess_public(&dep.pp, &att.shown, &phi));
        let rel_p = prover_relation(&dep, &att.shown, &phi, &claimed, &att.t, &s);
        assert!(rel_p.is_satisfied_by(&[claimed]));
        let ctx = att_ctx(&dep, &id, &phi, &att.t, &att.shown);
        assert!(fiat_shamir::verify(&rel_p, &ctx, &att.pi));
        // ... and the verifier states another relation, which the claimed key does not satisfy
        let rel_v = verifier_relation(&dep, &dvk, &att.shown, &phi, &att.t, &s).unwrap();
        assert_ne!(rel_v, rel_p);
        assert!(!rel_v.is_satisfied_by(&[claimed]));
        assert!(!rel_v.is_satisfied_by(&[usk]));
        assert!(!fiat_shamir::verify(&rel_v, &ctx, &att.pi));
        assert!(!verify_att(&dep, &dvk, &id, &att));

        // control: the same holder, honest
        let att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));
    }

    /// A prover that does NOT hold a valid MAC cannot make the verifier accept: it can state and
    /// prove its own relation for any `(U', V')`, but the verifier's target differs from the
    /// prover's unless `V' = (U')^{x + y_1 usk + y_2 φ}`.
    #[test]
    fn a_prover_without_a_valid_mac_is_rejected() {
        let mut rng = StdRng::seed_from_u64(0x3ac0f);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let other = MAC::keygen(&dep.pp, &mut rng);
        let u = G1::rand(&mut rng);

        let invalid = [
            // a random V'
            MACCredential {
                u,
                v: G1::rand(&mut rng),
            },
            // a guess at the key: V' = U^{x' + y_1' usk + y_2' φ} for a key of the forger's own
            MAC::sign(&dep.pp, &other, &msg(usk, phi), &mut rng).unwrap(),
            // a valid MAC, but on another usk / on another φ
            MAC::sign(&dep.pp, &dvk, &msg(usk + Fr::one(), phi), &mut rng).unwrap(),
            MAC::sign(&dep.pp, &dvk, &msg(usk, phi + Fr::one()), &mut rng).unwrap(),
            // a valid MAC with one element off
            MACCredential {
                u: cred.u,
                v: cred.v + dep.pp.g,
            },
            MACCredential {
                u: cred.u + dep.pp.g,
                v: cred.v,
            },
        ];
        for (i, forged) in invalid.iter().enumerate() {
            assert!(
                !MAC::verify(&dep.pp, &dvk, &msg(usk, phi), forged),
                "case {i}"
            );
            // the keyless prover runs through without an error ...
            let att = attest(&dep, (&usk, &phi, forged), &usk, &id, &mut rng).unwrap();
            let s: Fr = h0_id(DOMAIN, &id).unwrap();
            let rel_p = prover_relation(&dep, &att.shown, &phi, &usk, &att.t, &s);
            let ctx = att_ctx(&dep, &id, &phi, &att.t, &att.shown);
            assert!(fiat_shamir::verify(&rel_p, &ctx, &att.pi), "case {i}");
            // ... and is rejected
            assert!(!verify_att(&dep, &dvk, &id, &att), "case {i}");
            let pi = MAC::possess(&dep.pp, &att.shown, &phi, &usk, &(), b"ctx", &mut rng).unwrap();
            assert!(
                !MAC::verify_possess(&dep.pp, &dvk, &att.shown, &phi, b"ctx", &pi),
                "case {i}"
            );
        }
        // control
        let att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));
    }

    #[test]
    fn proof_for_phi_does_not_verify_for_another_phi() {
        let mut rng = StdRng::seed_from_u64(0x3ac10);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let mut att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));

        let other_phi = self::phi(b"f'");
        assert_ne!(other_phi, phi);
        // (1) relation level, SAME context bytes: φ sits in the target the verifier derives
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let ctx = att_ctx(&dep, &id, &phi, &att.t, &att.shown);
        let rel = verifier_relation(&dep, &dvk, &att.shown, &phi, &att.t, &s).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &att.pi));
        let rel_other = verifier_relation(&dep, &dvk, &att.shown, &other_phi, &att.t, &s).unwrap();
        assert!(!fiat_shamir::verify(&rel_other, &ctx, &att.pi));
        assert!(!rel_other.is_satisfied_by(&[usk]));
        // (2) attestation level
        att.phi = other_phi;
        assert!(!verify_att(&dep, &dvk, &id, &att));
        // (3) a holder that claims another φ for its MAC: the keyless prover cannot notice (its
        // statement does not even contain φ), the verifier rejects
        let att = attest(&dep, (&usk, &other_phi, &cred), &usk, &id, &mut rng).unwrap();
        assert_eq!(att.phi, other_phi);
        assert!(!verify_att(&dep, &dvk, &id, &att));
    }

    #[test]
    fn attestation_is_bound_to_identifier_and_shown_credential() {
        let mut rng = StdRng::seed_from_u64(0x3ac11);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let att = attest(&dep, (&usk, &phi, &cred), &usk, &id, &mut rng).unwrap();
        assert!(verify_att(&dep, &dvk, &id, &att));

        // another identifier (non-transferability)
        assert!(!verify_att(&dep, &dvk, &(id + G1::generator()), &att));

        // re-randomizing cred* inside a finished attestation: still a valid MAC on (usk, φ), but
        // the statement (base U', target X) is hashed
        let r = Fr::rand(&mut rng);
        let mauled = Att {
            shown: shown(att.shown.u_prime * r, att.shown.v_prime * r),
            t: att.t,
            phi: att.phi,
            pi: att.pi.clone(),
        };
        assert!(MAC::verify(
            &dep.pp,
            &dvk,
            &msg(usk, phi),
            &mauled.shown.clone().into()
        ));
        assert!(!verify_att(&dep, &dvk, &id, &mauled));

        // identity tag, mauled proof, malformed proof
        let bad = Att {
            t: G1::zero(),
            shown: att.shown.clone(),
            phi: att.phi,
            pi: att.pi.clone(),
        };
        assert!(!verify_att(&dep, &dvk, &id, &bad));
        let mut bad_pi = att.pi.clone();
        bad_pi.responses[0] += Fr::one();
        let bad = Att {
            pi: bad_pi,
            shown: att.shown.clone(),
            ..att
        };
        assert!(!verify_att(&dep, &dvk, &id, &bad));
        let bad = Att {
            pi: FSProof {
                challenge: bad.pi.challenge,
                responses: vec![],
            },
            ..bad
        };
        assert!(!verify_att(&dep, &dvk, &id, &bad));
    }

    /// Attack A2 (credential-free attestation with a degenerate shown credential): for
    /// `(U', V') = (1, 1)` the verifier derives `X = 1` under every key, the possession clause
    /// reads `1 = 1^usk`, and a party WITHOUT any credential and WITHOUT `dvk` builds exactly the
    /// verifier's statement, satisfies it under a fresh key and produces a Fiat-Shamir proof that
    /// verifies. Only the public check `U' ≠ 1` stops it.
    #[test]
    fn degenerate_shown_credential_is_rejected_although_its_clause_is_satisfiable() {
        let mut rng = StdRng::seed_from_u64(0x3ac12);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let phi = phi(b"f");
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();

        let forged_key = dep.tag.keygen(&mut rng); // no credential exists for this key
        let t = dep.tag.eval(&forged_key, &s).unwrap();
        let degenerate = shown(G1::zero(), G1::zero());
        // the forger's keyless statement IS the verifier's ...
        let rel = prover_relation(&dep, &degenerate, &phi, &forged_key, &t, &s);
        let rel_v = verifier_relation(&dep, &dvk, &degenerate, &phi, &t, &s).unwrap();
        assert_eq!(rel, rel_v);
        // ... the algebra is satisfied ...
        assert!(rel_v.is_satisfied_by(&[forged_key]));
        let ctx = att_ctx(&dep, &id, &phi, &t, &degenerate);
        let pi = fiat_shamir::prove(&rel, &[forged_key], &ctx, &mut rng).unwrap();
        // ... the bare Fiat-Shamir proof verifies against the VERIFIER's relation ...
        assert!(fiat_shamir::verify(&rel_v, &ctx, &pi));
        // ... the tag is perfectly valid ...
        assert!(dep.tag.valid_tag(&t, &s));
        // ... and the attestation is rejected, by the public check alone.
        assert!(!MAC::verify_possess_public(&dep.pp, &degenerate, &phi));
        let att = Att {
            t,
            shown: degenerate,
            phi,
            pi,
        };
        assert!(!verify_att(&dep, &dvk, &id, &att));

        // the exported forgery list: (1, 1) is the satisfiable one, (1, g) has no witness
        let forgeries = credential_free_forgeries(&dep.pp, &phi, &forged_key);
        assert_eq!(forgeries.len(), 2);
        let satisfiable: Vec<bool> = forgeries
            .iter()
            .map(|f| {
                assert!(f.extra_witness.is_empty());
                assert!(!MAC::verify_possess_public(&dep.pp, &f.shown, &phi));
                verifier_relation(&dep, &dvk, &f.shown, &phi, &t, &s)
                    .unwrap()
                    .is_satisfied_by(&[forged_key])
            })
            .collect();
        assert_eq!(satisfiable, [true, false]);
    }

    /// Special soundness with a shared coordinate: rewinding the prover of `R_att` yields ONE
    /// `usk`, which opens the tag AND makes `cred*` a valid MAC on `(usk, φ)` (proof sketch of
    /// the Lemma on `Σ-MAC`: "the usual two-transcript extractor recovers `usk`"). And HVZK
    /// "against the designated verifier": whoever can state the relation, i.e. the holder of
    /// `dvk`, simulates accepting transcripts without a witness.
    #[test]
    fn extractor_recovers_the_shared_usk_and_the_verifier_can_simulate() {
        let mut rng = StdRng::seed_from_u64(0x3ac13);
        let dep = dep();
        let dvk = MAC::keygen(&dep.pp, &mut rng);
        let (usk, phi, cred) = holder(&dep, &dvk, b"f", &mut rng);
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let t = dep.tag.eval(&usk, &s).unwrap();
        let (shown, ()) = MAC::rerand(&dep.pp, &msg(usk, phi), &cred, &mut rng).unwrap();
        // the prover commits and responds on ITS relation, the verifier checks on its own
        let rel_p = prover_relation(&dep, &shown, &phi, &usk, &t, &s);
        let rel_v = verifier_relation(&dep, &dvk, &shown, &phi, &t, &s).unwrap();

        // "rewinding" = the same random tape twice
        let (a1, st1) = commit(&rel_p, &mut StdRng::seed_from_u64(77)).unwrap();
        let (a2, st2) = commit(&rel_p, &mut StdRng::seed_from_u64(77)).unwrap();
        assert_eq!(a1, a2);
        let (c1, c2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let z1 = respond(st1, &[usk], &c1).unwrap();
        let z2 = respond(st2, &[usk], &c2).unwrap();
        assert!(sigma::verify(&rel_v, &a1, &c1, &z1));
        let extracted = extract(&rel_v, &a1, (&c1, &z1), (&c2, &z2)).unwrap();
        assert_eq!(extracted, vec![usk]);
        assert_eq!(dep.tag.eval(&extracted[0], &s).unwrap(), t);
        assert!(MAC::verify(
            &dep.pp,
            &dvk,
            &msg(extracted[0], phi),
            &shown.into()
        ));

        let c = Fr::rand(&mut rng);
        let (a, z) = simulate(&rel_v, &c, &mut rng).unwrap();
        assert!(sigma::verify(&rel_v, &a, &c, &z));
    }

    // ----- the stand-alone Possess / keyed possession verifier -----------------------------------

    #[test]
    fn standalone_possession_proof() {
        let mut rng = StdRng::seed_from_u64(0x3ac14);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = MAC::sign(&pp, &dvk, &m, &mut rng).unwrap();
        let (shown, omega) = MAC::rerand(&pp, &m, &cred, &mut rng).unwrap();

        let (rel, var) = MAC::possession_relation_verifier(&pp, &dvk, &shown, &phi).unwrap();
        assert_eq!((var.index(), rel.num_scalars()), (0, 1));
        assert_eq!(rel.equations().len(), 1);
        assert!(rel.is_satisfied_by(&[usk]));
        assert!(!rel.is_satisfied_by(&[usk + Fr::one()]));
        assert_eq!(
            MAC::possession_relation_prover(&pp, &shown, &phi, &usk).unwrap(),
            (rel, var)
        );

        let pi = MAC::possess(&pp, &shown, &phi, &usk, &omega, b"ctx", &mut rng).unwrap();
        assert_eq!(pi.responses.len(), 1);
        assert!(MAC::verify_possess(&pp, &dvk, &shown, &phi, b"ctx", &pi));
        // bound to the context, to φ, to the key, to cred*, to pp
        assert!(!MAC::verify_possess(&pp, &dvk, &shown, &phi, b"ctx2", &pi));
        let other_phi = phi + Fr::one();
        assert!(!MAC::verify_possess(
            &pp, &dvk, &shown, &other_phi, b"ctx", &pi
        ));
        let other = MAC::keygen(&pp, &mut rng);
        assert!(!MAC::verify_possess(&pp, &other, &shown, &phi, b"ctx", &pi));
        let (shown2, ()) = MAC::rerand(&pp, &m, &cred, &mut rng).unwrap();
        assert!(!MAC::verify_possess(&pp, &dvk, &shown2, &phi, b"ctx", &pi));
        let other_pp = MAC::setup(b"another deployment").unwrap();
        assert!(!MAC::verify_possess(
            &other_pp, &dvk, &shown, &phi, b"ctx", &pi
        ));
        // malformed proofs
        let mut bad = pi.clone();
        bad.responses[0] += Fr::one();
        assert!(!MAC::verify_possess(&pp, &dvk, &shown, &phi, b"ctx", &bad));
        bad.responses.clear();
        assert!(!MAC::verify_possess(&pp, &dvk, &shown, &phi, b"ctx", &bad));

        // wrong hidden message: the keyless prover cannot notice, the verifier does
        let wrong = MAC::possess(
            &pp,
            &shown,
            &phi,
            &(usk + Fr::one()),
            &omega,
            b"ctx",
            &mut rng,
        )
        .unwrap();
        assert!(!MAC::verify_possess(
            &pp, &dvk, &shown, &phi, b"ctx", &wrong
        ));

        // degenerate cred*: refused by the prover, rejected by the verifier
        let degenerate = self::shown(G1::zero(), G1::zero());
        assert_eq!(
            MAC::possess(&pp, &degenerate, &phi, &usk, &omega, b"ctx", &mut rng),
            Err(Error::InvalidCredential)
        );
        // A cheating prover needs no credential and no key for the degenerate statement: ANY
        // scalar is a witness, and it can run Fiat-Shamir under exactly the context the verifier
        // derives. Only the public check stands between this proof and acceptance.
        let (rel, _) = MAC::possession_relation_verifier(&pp, &dvk, &degenerate, &phi).unwrap();
        let forged_witness = [Fr::rand(&mut rng)];
        assert!(rel.is_satisfied_by(&forged_witness));
        let ctx = MAC::possess_context(&pp, &degenerate, &phi, b"ctx").unwrap();
        let forged = fiat_shamir::prove(&rel, &forged_witness, &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &forged));
        assert!(!MAC::verify_possess(
            &pp,
            &dvk,
            &degenerate,
            &phi,
            b"ctx",
            &forged
        ));
        // control: that context is the one an accepted proof is verified under
        let (rel, _) = MAC::possession_relation_verifier(&pp, &dvk, &shown, &phi).unwrap();
        let ctx = MAC::possess_context(&pp, &shown, &phi, b"ctx").unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &pi));
    }

    /// Module docs, "The verifier's statement is secret": the target `X_V` that the VERIFIER
    /// derives is key material. Whoever sees it for three inputs of its choice, all with
    /// `U' ≠ 1` so that the public check passes (say, in a debug log of the relations of
    /// rejected shows), computes a MAC on ANY message without `dvk`, and shows it. Hence: the
    /// keyed relation builder is a test helper, and `verify_possess` lets out one bit.
    #[test]
    fn three_leaked_verifier_targets_give_a_universal_forgery() {
        let mut rng = StdRng::seed_from_u64(0x3ac22);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let g = pp.g;
        // the leak: the target of the verifier's relation for an attacker-chosen (U', V', φ)
        let leak = |u_prime: G1, v_prime: G1, phi: Fr| -> G1 {
            let chosen = shown(u_prime, v_prime);
            assert!(MAC::verify_possess_public(&pp, &chosen, &phi));
            let (rel, _) = MAC::possession_relation_verifier(&pp, &dvk, &chosen, &phi).unwrap();
            let target = rel.equations()[0].target;
            // `{:?}` of the relation is such a leak: it prints the target
            assert!(format!("{rel:?}").contains(&format!("{target:?}")));
            target
        };
        let x_a = leak(g, g, Fr::zero()); // g^{(1 - x)/y_1}
        let x_b = leak(g, G1::zero(), Fr::zero()); // g^{-x/y_1}
        let x_c = leak(g, G1::zero(), Fr::one()); // g^{-(x + y_2)/y_1}
        let (g_1_y1, g_x_y1, g_y2_y1) = (x_a - x_b, -x_b, x_b - x_c);
        let y1_inverse = dvk.y1.inverse().unwrap();
        assert_eq!(g_1_y1, g * y1_inverse);
        assert_eq!(g_x_y1, g * (dvk.x * y1_inverse));
        assert_eq!(g_y2_y1, g * (dvk.y2 * y1_inverse));

        // a MAC on an arbitrary message from the three leaked elements alone ...
        let (m1, m2) = (Fr::from(0xdead_u64), Fr::from(0xbeef_u64));
        let forged = cred(g_1_y1, g_x_y1 + g * m1 + g_y2_y1 * m2);
        assert!(MAC::verify(&pp, &dvk, &msg(m1, m2), &forged));
        // ... and its show, accepted by the keyed possession verifier
        let (forged_shown, ()) = MAC::rerand(&pp, &msg(m1, m2), &forged, &mut rng).unwrap();
        let pi = MAC::possess(&pp, &forged_shown, &m2, &m1, &(), b"ctx", &mut rng).unwrap();
        assert!(MAC::verify_possess(
            &pp,
            &dvk,
            &forged_shown,
            &m2,
            b"ctx",
            &pi
        ));
        // control: the three inputs themselves are not MACs the attacker could show, i.e. the
        // leak comes from REJECTED shows
        for (v_prime, phi) in [
            (g, Fr::zero()),
            (G1::zero(), Fr::zero()),
            (G1::zero(), Fr::one()),
        ] {
            let pi = MAC::possess(&pp, &shown(g, v_prime), &phi, &m1, &(), b"ctx", &mut rng);
            assert!(!MAC::verify_possess(
                &pp,
                &dvk,
                &shown(g, v_prime),
                &phi,
                b"ctx",
                &pi.unwrap()
            ));
        }

        // Not an artefact of the clause X = (U')^usk: the verifier's side of the box's displayed
        // relation V' (U')^{-x - y_2 φ} = (U')^{y_1 usk} is key-derived too. Its base for U' = g
        // and its targets for (g, 1, 0) and (g, 1, 1) give a MAC with U = g on any message.
        let literal = |v_prime: G1, phi: Fr| (g * dvk.y1, v_prime - g * (dvk.x + dvk.y2 * phi));
        let (base, target_b) = literal(G1::zero(), Fr::zero()); // g^{y_1}, g^{-x}
        let (_, target_c) = literal(G1::zero(), Fr::one()); // g^{-x - y_2}
        let forged = cred(g, -target_b + base * m1 + (target_b - target_c) * m2);
        assert!(MAC::verify(&pp, &dvk, &msg(m1, m2), &forged));
    }

    /// `ctx' = (pp, cred*, φ, ctx)` under the label `/MAC-POSSESS`: every item is bound on its
    /// own. The end-to-end tests cannot show that, because a change of `cred*` or `φ` changes
    /// the STATEMENT as well (`U'` is a base, `X_V` depends on `V'` and `φ`). Hence the direct
    /// test, followed by the one change of `(cred*, φ)` that leaves the verifier's statement
    /// untouched, where the context alone decides.
    #[test]
    fn possess_context_binds_every_item_of_the_public_statement() {
        let mut rng = StdRng::seed_from_u64(0x3ac23);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = MAC::sign(&pp, &dvk, &m, &mut rng).unwrap();
        let (shown, ()) = MAC::rerand(&pp, &m, &cred, &mut rng).unwrap();

        // the label (pinned as a literal; not the label of the public bases' `possess`) and the
        // items, in order
        assert_eq!(POSSESS_SUFFIX, b"/MAC-POSSESS");
        assert_ne!(POSSESS_SUFFIX, crate::cred::POSSESS_SUFFIX);
        let mut transcript = Transcript::new(b"/MAC-POSSESS");
        transcript.append_serializable(b"pp", &pp).unwrap();
        transcript.append_serializable(b"cred*", &shown).unwrap();
        transcript.append_serializable(b"m_pub", &phi).unwrap();
        transcript.append_bytes(b"ctx", b"ctx");
        let full = MAC::possess_context(&pp, &shown, &phi, b"ctx").unwrap();
        assert_eq!(full, transcript.digest().to_vec());
        assert_eq!(
            MAC::possess_context(&pp, &shown, &phi, b"ctx").unwrap(),
            full
        );

        // each item on its own
        let swapped_pp = Pp { g: pp.h, h: pp.g };
        let other_u = self::shown(shown.u_prime + pp.g, shown.v_prime);
        let other_v = self::shown(shown.u_prime, shown.v_prime + pp.g);
        let other_phi = phi + Fr::one();
        let variants = [
            MAC::possess_context(&swapped_pp, &shown, &phi, b"ctx"),
            MAC::possess_context(&pp, &other_u, &phi, b"ctx"),
            MAC::possess_context(&pp, &other_v, &phi, b"ctx"),
            MAC::possess_context(&pp, &shown, &other_phi, b"ctx"),
            MAC::possess_context(&pp, &shown, &phi, b"ctx2"),
            MAC::possess_context(&pp, &shown, &phi, b""),
        ];
        for (i, variant) in variants.into_iter().enumerate() {
            assert_ne!(variant.unwrap(), full, "item {i}");
        }

        // End to end. V'' = V' (U')^{y_2 (φ' - φ)} is a MAC on (usk, φ') for which the verifier
        // derives the SAME statement as for (cred*, φ); computing it takes (U')^{y_2}, i.e. the
        // key. The proof for (cred*, φ) satisfies that statement and is rejected for
        // (cred*'', φ') on the context alone.
        let pi = MAC::possess(&pp, &shown, &phi, &usk, &(), b"ctx", &mut rng).unwrap();
        assert!(MAC::verify_possess(&pp, &dvk, &shown, &phi, b"ctx", &pi));
        let moved = self::shown(
            shown.u_prime,
            shown.v_prime + shown.u_prime * (dvk.y2 * (other_phi - phi)),
        );
        assert!(MAC::verify(
            &pp,
            &dvk,
            &msg(usk, other_phi),
            &moved.clone().into()
        ));
        let (rel, _) = MAC::possession_relation_verifier(&pp, &dvk, &shown, &phi).unwrap();
        let (rel_moved, _) =
            MAC::possession_relation_verifier(&pp, &dvk, &moved, &other_phi).unwrap();
        assert_eq!(rel_moved, rel);
        assert!(fiat_shamir::verify(&rel_moved, &full, &pi));
        assert!(!MAC::verify_possess(
            &pp, &dvk, &moved, &other_phi, b"ctx", &pi
        ));
    }

    // ----- R_issue: C = Com(usk, φ; ρ) ∧ id ∧ T_0, shared usk ------------------------------------

    fn issue_relation(dep: &Dep, c: &G1, phi: &Fr, id: &G1, t0: &G1) -> GroupRelation<G1> {
        let mut rel = GroupRelation::new();
        let usk = rel.alloc_scalar();
        let extra = MAC::issuance_clauses(&dep.pp, c, phi, &mut rel, usk).unwrap();
        assert_eq!(extra.len(), 1);
        let c0 = *dep.tag.identity_point().unwrap();
        let s: Fr = h0_id(DOMAIN, id).unwrap();
        for eq in dep
            .tag
            .tag_equations(usk, id, &c0)
            .into_iter()
            .chain(dep.tag.tag_equations(usk, t0, &s))
        {
            rel.add_equation(eq).unwrap();
        }
        rel
    }

    #[test]
    fn issuance_opening_clause_shares_usk_with_the_tag_clauses() {
        let mut rng = StdRng::seed_from_u64(0x3ac15);
        let dep = dep();
        let phi = phi(b"f");
        let usk = dep.tag.keygen(&mut rng);
        let c0 = *dep.tag.identity_point().unwrap();
        let id = dep.tag.eval(&usk, &c0).unwrap();
        let t0 = dep.tag.eval(&usk, &h0_id(DOMAIN, &id).unwrap()).unwrap();

        let (aux, rho) = MAC::sample_issuance(&dep.pp, &mut rng);
        let m_hid = MAC::hidden_message(&usk, &aux);
        let c = MAC::issuance_encoding(&dep.pp, &m_hid, &phi, &rho).unwrap();
        let rel = issue_relation(&dep, &c, &phi, &id, &t0);
        assert_eq!(rel.num_scalars(), 2);
        assert_eq!(rel.equations().len(), 3);
        // the opening clause: C = g^usk h^ρ with usk the shared variable 0 and ρ the fresh one
        let mut fresh = GroupRelation::<G1>::new();
        let vars = fresh.alloc_scalars(2);
        assert_eq!(
            rel.equations()[0],
            LinearEquation::new(vec![(vars[0], dep.pp.g), (vars[1], dep.pp.h)], c)
        );

        let mut w = Witness::with_capacity(2);
        w.push(usk);
        w.extend_from_slice(&MAC::issuance_witness(&m_hid, &rho));
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
        let other = dep.tag.keygen(&mut rng);
        let c_other = MAC::issuance_encoding(&dep.pp, &other, &phi, &rho).unwrap();
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

    #[test]
    fn clauses_reject_foreign_variables() {
        let mut rng = StdRng::seed_from_u64(0x3ac16);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let cred = MAC::sign(&pp, &dvk, &msg(Fr::one(), Fr::one()), &mut rng).unwrap();
        let shown = shown(cred.u, cred.v);
        let foreign = GroupRelation::<G1>::new().alloc_scalars(3)[2];
        let unallocated = Err(Error::UnallocatedVariable {
            index: 2,
            allocated: 1,
        });

        let mut rel = GroupRelation::<G1>::new();
        rel.alloc_scalar();
        assert_eq!(
            MAC::possession_clauses_prover(
                &pp,
                &shown,
                &Fr::one(),
                &Fr::one(),
                &(),
                &mut rel,
                foreign
            ),
            unallocated
        );
        assert_eq!(
            MAC::possession_clauses_verifier(&pp, &dvk, &shown, &Fr::one(), &mut rel, foreign),
            unallocated
        );
        assert!(rel.equations().is_empty());
        let mut rel = GroupRelation::<G1>::new();
        assert!(matches!(
            MAC::issuance_clauses(&pp, &cred.u, &Fr::one(), &mut rel, foreign),
            Err(Error::UnallocatedVariable { index: 2, .. })
        ));
        assert!(rel.equations().is_empty());

        // The aliasing case: a foreign handle with exactly the index that `ρ` is about to get.
        // Checked only when the equation is added, it would pass (`ρ` is allocated by then) and
        // the clause would silently read C = (g h)^ρ, with `usk` and `ρ` one variable.
        for allocated in 0..3usize {
            let mut rel = GroupRelation::<G1>::new();
            rel.alloc_scalars(allocated);
            let alias = GroupRelation::<G1>::new().alloc_scalars(allocated + 1)[allocated];
            assert_eq!(alias.index(), rel.num_scalars());
            assert_eq!(
                MAC::issuance_clauses(&pp, &cred.u, &Fr::one(), &mut rel, alias),
                Err(Error::UnallocatedVariable {
                    index: allocated,
                    allocated
                })
            );
            // the relation is untouched: no equation, and no variable was allocated
            assert!(rel.equations().is_empty());
            assert_eq!(rel.num_scalars(), allocated);
        }
        // control: the caller's own variable is accepted, and `ρ` is a second, fresh variable
        let mut rel = GroupRelation::<G1>::new();
        let usk = rel.alloc_scalar();
        let allocated = MAC::issuance_clauses(&pp, &cred.u, &Fr::one(), &mut rel, usk).unwrap();
        assert_eq!(allocated.len(), 1);
        assert_ne!(allocated[0], usk);
        assert_eq!(rel.num_scalars(), 2);
    }

    // ----- keys ----------------------------------------------------------------------------------

    #[test]
    fn keygen_outputs_well_formed_keys_only() {
        let mut rng = StdRng::seed_from_u64(0x3ac17);
        let Dep { pp, .. } = dep();
        for _ in 0..8 {
            let dvk = MAC::keygen(&pp, &mut rng);
            assert!(!dvk.y1.is_zero() && !dvk.y2.is_zero());
            assert!(dvk.is_well_formed());
            assert!(MAC::is_well_formed_key(&pp, &dvk));
        }
        // keys are fresh
        let (a, b) = (MAC::keygen(&pp, &mut rng), MAC::keygen(&pp, &mut rng));
        assert!(a.x != b.x && a.y1 != b.y1 && a.y2 != b.y2);
        // the key space is x ∈ Z_q, y_1, y_2 ∈ Z_q^*: x = 0 is a key, y_1 = 0 and y_2 = 0 are not
        // (y_2 = 0 is a key of the BOX; implementation note in the module docs)
        let (one, two, three) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        for (x, y1, y2, well_formed) in [
            (Fr::zero(), two, three, true),
            (one, two, three, true),
            (one, Fr::zero(), three, false),
            (one, two, Fr::zero(), false),
            (one, Fr::zero(), Fr::zero(), false),
            (Fr::zero(), Fr::zero(), Fr::zero(), false),
        ] {
            let dvk = key(x, y1, y2);
            assert_eq!(dvk.is_well_formed(), well_formed);
            assert_eq!(MAC::is_well_formed_key(&pp, &dvk), well_formed);
        }
    }

    /// `y_1 = 0` is outside the key space, decodes fine, and is an ERROR everywhere, never a
    /// panic: the possession verifier would have to invert it, and a MAC under it does not
    /// depend on `usk` at all.
    #[test]
    fn y1_zero_key_is_an_error_not_a_panic() {
        let mut rng = StdRng::seed_from_u64(0x3ac18);
        let dep = dep();
        let pp = &dep.pp;
        let bad = key(Fr::from(5u64), Fr::zero(), Fr::from(7u64));
        assert!(!bad.is_well_formed());
        assert!(!MAC::is_well_formed_key(pp, &bad));

        let (usk, phi) = (Fr::rand(&mut rng), phi(b"f"));
        assert_eq!(
            MAC::sign(pp, &bad, &msg(usk, phi), &mut rng).unwrap_err(),
            Error::InvalidKey
        );
        let c = MAC::issuance_encoding(pp, &usk, &phi, &Fr::one()).unwrap();
        assert_eq!(
            MAC::blind_issue(pp, &bad, &c, &phi, &mut rng).unwrap_err(),
            Error::InvalidKey
        );

        // what such a key would certify: V = U^{x + y_2 φ}, the same for EVERY usk
        let u = pp.g * Fr::rand(&mut rng);
        let vacuous = cred(u, u * (bad.x + bad.y2 * phi));
        assert_eq!(vacuous.v, vacuous.u * bad.exponent(&msg(usk, phi)));
        assert_eq!(
            vacuous.v,
            vacuous.u * bad.exponent(&msg(usk + Fr::one(), phi))
        );
        assert!(!MAC::verify(pp, &bad, &msg(usk, phi), &vacuous));

        // the possession verifier: an error, and nothing is appended
        let shown = shown(vacuous.u, vacuous.v);
        let mut rel = GroupRelation::<G1>::new();
        let var = rel.alloc_scalar();
        assert_eq!(
            MAC::possession_clauses_verifier(pp, &bad, &shown, &phi, &mut rel, var),
            Err(Error::InvalidKey)
        );
        assert!(rel.equations().is_empty());
        assert_eq!(
            MAC::possession_relation_verifier(pp, &bad, &shown, &phi).unwrap_err(),
            Error::InvalidKey
        );
        let pi = MAC::possess(pp, &shown, &phi, &usk, &(), b"ctx", &mut rng).unwrap();
        assert!(!MAC::verify_possess(pp, &bad, &shown, &phi, b"ctx", &pi));
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        let att = attest(&dep, (&usk, &phi, &vacuous), &usk, &id, &mut rng).unwrap();
        assert!(!verify_att(&dep, &bad, &id, &att));
    }

    /// Module docs, "Generators, degenerate parameters and keys" (implementation note): `y_2 = 0`
    /// is a key of the BOX (probability `1/q`) and is not a key here. It decodes fine and is an
    /// ERROR everywhere, because a MAC under it does not depend on `φ`. What the check is for is
    /// mounted at the end: without it, ONE MAC is shown under every `φ`.
    #[test]
    fn y2_zero_key_is_an_error_because_it_would_not_bind_phi() {
        let mut rng = StdRng::seed_from_u64(0x3ac19);
        let dep = dep();
        let pp = &dep.pp;
        let bad = key(Fr::from(5u64), Fr::from(6u64), Fr::zero());
        assert!(!bad.is_well_formed());
        assert!(!MAC::is_well_formed_key(pp, &bad));

        let (usk, phi, other_phi) = (Fr::rand(&mut rng), phi(b"f"), self::phi(b"f'"));
        assert_ne!(phi, other_phi);
        assert_eq!(
            MAC::sign(pp, &bad, &msg(usk, phi), &mut rng).unwrap_err(),
            Error::InvalidKey
        );
        let c = MAC::issuance_encoding(pp, &usk, &phi, &Fr::one()).unwrap();
        assert_eq!(
            MAC::blind_issue(pp, &bad, &c, &phi, &mut rng).unwrap_err(),
            Error::InvalidKey
        );

        // what such a key would certify: V = U^{x + y_1 usk}, the same for EVERY φ
        let u = pp.g * Fr::rand(&mut rng);
        let vacuous = cred(u, u * (bad.x + bad.y1 * usk));
        assert_eq!(vacuous.v, vacuous.u * bad.exponent(&msg(usk, phi)));
        assert_eq!(vacuous.v, vacuous.u * bad.exponent(&msg(usk, other_phi)));
        assert!(!MAC::verify(pp, &bad, &msg(usk, phi), &vacuous));
        assert!(!MAC::verify(pp, &bad, &msg(usk, other_phi), &vacuous));

        // the possession verifier: an error, and nothing is appended
        let shown = shown(vacuous.u, vacuous.v);
        let mut rel = GroupRelation::<G1>::new();
        let var = rel.alloc_scalar();
        assert_eq!(
            MAC::possession_clauses_verifier(pp, &bad, &shown, &phi, &mut rel, var),
            Err(Error::InvalidKey)
        );
        assert!(rel.equations().is_empty());
        assert_eq!(
            MAC::possession_relation_verifier(pp, &bad, &shown, &phi).unwrap_err(),
            Error::InvalidKey
        );
        // a show of the ONE MAC, under its own φ and under another one: both rejected
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        for (i, claimed_phi) in [phi, other_phi].iter().enumerate() {
            let pi = MAC::possess(pp, &shown, claimed_phi, &usk, &(), b"ctx", &mut rng).unwrap();
            assert!(
                !MAC::verify_possess(pp, &bad, &shown, claimed_phi, b"ctx", &pi),
                "φ {i}"
            );
            let att = attest(&dep, (&usk, claimed_phi, &vacuous), &usk, &id, &mut rng).unwrap();
            assert!(!verify_att(&dep, &bad, &id, &att), "φ {i}");
        }

        // What the check is for. WITHOUT it the verifier would derive X = (V' (U')^{-x})^{1/y_1},
        // in which φ does not occur, and the honest keyless proof of a show under ANOTHER φ
        // would verify, under exactly the context the verifier builds for that φ.
        let target = (shown.v_prime - shown.u_prime * bad.x) * bad.y1.inverse().unwrap();
        let mut unchecked = GroupRelation::<G1>::new();
        let var = unchecked.alloc_scalar();
        unchecked
            .add_equation(LinearEquation::dlog(var, shown.u_prime, target))
            .unwrap();
        let pi = MAC::possess(pp, &shown, &other_phi, &usk, &(), b"ctx", &mut rng).unwrap();
        let ctx = MAC::possess_context(pp, &shown, &other_phi, b"ctx").unwrap();
        assert!(fiat_shamir::verify(&unchecked, &ctx, &pi));
        // (usk, in contrast, would stay bound)
        assert!(unchecked.is_satisfied_by(&[usk]));
        assert!(!unchecked.is_satisfied_by(&[usk + Fr::one()]));
    }

    /// Module docs, "Security and limitations" (implementation note): the holder cannot tell
    /// under which key its MAC was computed, so an issuer that uses one key per holder links
    /// every show to the holder it issued to, by testing which key accepts.
    #[test]
    fn an_issuer_with_one_key_per_holder_links_shows() {
        let mut rng = StdRng::seed_from_u64(0x3ac1a);
        let dep = dep();
        let keys = [
            MAC::keygen(&dep.pp, &mut rng),
            MAC::keygen(&dep.pp, &mut rng),
        ];
        let phi = phi(b"f");
        // both holders go through the same blind issuance and see nothing unusual
        let holders: Vec<(Fr, MACCredential<G1>)> = keys
            .iter()
            .map(|dvk| {
                let usk = dep.tag.keygen(&mut rng);
                let (_, rho) = MAC::sample_issuance(&dep.pp, &mut rng);
                let c = MAC::issuance_encoding(&dep.pp, &usk, &phi, &rho).unwrap();
                let pre = MAC::blind_issue(&dep.pp, dvk, &c, &phi, &mut rng).unwrap();
                let cred = MAC::unblind(&dep.pp, &msg(usk, phi), &pre, &rho).unwrap();
                (usk, cred)
            })
            .collect();
        let id = G1::generator() * dep.tag.keygen(&mut rng);
        for (b, (usk, cred)) in holders.iter().enumerate() {
            let att = attest(&dep, (usk, &phi, cred), usk, &id, &mut rng).unwrap();
            let accepting: Vec<usize> = (0..keys.len())
                .filter(|&i| verify_att(&dep, &keys[i], &id, &att))
                .collect();
            assert_eq!(accepting, [b]);
        }
    }

    // ----- encodings and secrets -----------------------------------------------------------------

    #[test]
    fn serialization_sizes_and_round_trips() {
        let mut rng = StdRng::seed_from_u64(0x3ac1b);
        let Dep { pp, .. } = dep();
        let dvk = MAC::keygen(&pp, &mut rng);
        let (usk, phi, rho) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let m = msg(usk, phi);
        let cred = MAC::sign(&pp, &dvk, &m, &mut rng).unwrap();
        let (shown, ()) = MAC::rerand(&pp, &m, &cred, &mut rng).unwrap();
        let c = MAC::issuance_encoding(&pp, &usk, &phi, &rho).unwrap();
        let pre = MAC::blind_issue(&pp, &dvk, &c, &phi, &mut rng).unwrap();

        // BLS12-381 G_1: 48 B per element, Z_q 32 B
        let bytes = cred.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48);
        assert_eq!(MACCredential::<G1>::from_bytes(&bytes).unwrap(), cred);
        let bytes = shown.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48);
        assert_eq!(MACShownCredential::<G1>::from_bytes(&bytes).unwrap(), shown);
        let bytes = pre.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 48);
        assert_eq!(MACPreCredential::<G1>::from_bytes(&bytes).unwrap(), pre);
        let bytes = pp.to_bytes().unwrap();
        assert_eq!(bytes.len(), 2 * 48);
        assert_eq!(Pp::from_bytes(&bytes).unwrap(), pp);
        assert_eq!(MAC::encoding_to_wire(&c).to_bytes().unwrap().len(), 48);
        assert_eq!(().to_bytes().unwrap().len(), 0);

        let bytes = dvk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 32);
        let back = MACKey::<G1>::from_bytes(&bytes).unwrap();
        assert!((back.x, back.y1, back.y2) == (dvk.x, dvk.y1, dvk.y2));
        assert!(MAC::verify(&pp, &back, &m, &cred));

        // trailing bytes and truncation
        let mut long = cred.to_bytes().unwrap();
        long.push(0);
        assert_eq!(
            MACCredential::<G1>::from_bytes(&long),
            Err(Error::TrailingBytes)
        );
        assert!(MACCredential::<G1>::from_bytes(&long[..95]).is_err());

        // the identity decodes fine: rejecting it is the verifiers' job
        let degenerate = self::shown(G1::zero(), G1::zero());
        let back = MACShownCredential::<G1>::from_bytes(&degenerate.to_bytes().unwrap()).unwrap();
        assert_eq!(back, degenerate);
        assert!(!MAC::verify_possess_public(&pp, &back, &phi));
    }

    #[test]
    fn secrets_are_redacted_and_wiped() {
        let mut rng = StdRng::seed_from_u64(0x3ac1c);
        let Dep { pp, .. } = dep();
        let mut dvk = MAC::keygen(&pp, &mut rng);
        assert_eq!(format!("{dvk:?}"), "MACKey(<redacted>)");
        assert!(!dvk.x.is_zero() && !dvk.y1.is_zero() && !dvk.y2.is_zero());
        dvk.zeroize();
        assert!(dvk.x.is_zero() && dvk.y1.is_zero() && dvk.y2.is_zero());

        let mut m = msg(Fr::from(5u64), Fr::from(6u64));
        assert_eq!(format!("{m:?}"), "MACMessage(<redacted>)");
        m.zeroize();
        assert!(m.m1.is_zero() && m.m2.is_zero());

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MACKey<G1>>();
        assert_zeroize_on_drop::<MACMessage<G1>>();
    }

    /// Every randomized algorithm accepts an unsized RNG (`R: ?Sized`), e.g. a trait object.
    #[test]
    fn randomized_algorithms_accept_a_dyn_rng() {
        trait DynRng: RngCore + CryptoRng {}
        impl<T: RngCore + CryptoRng> DynRng for T {}

        let mut std_rng = StdRng::seed_from_u64(0x3ac1d);
        let rng: &mut dyn DynRng = &mut std_rng;
        let Dep { pp, tag } = dep();
        let dvk = MAC::keygen(&pp, rng);
        let usk = tag.keygen(rng);
        let (phi, (_, rho)) = (phi(b"f"), MAC::sample_issuance(&pp, rng));
        let c = MAC::issuance_encoding(&pp, &usk, &phi, &rho).unwrap();
        let pre = MAC::blind_issue(&pp, &dvk, &c, &phi, rng).unwrap();
        let cred = MAC::unblind(&pp, &msg(usk, phi), &pre, &rho).unwrap();
        assert!(MAC::verify(&pp, &dvk, &msg(usk, phi), &cred));
        let direct = MAC::sign(&pp, &dvk, &msg(usk, phi), rng).unwrap();
        assert!(MAC::verify(&pp, &dvk, &msg(usk, phi), &direct));
        let (shown, omega) = MAC::rerand(&pp, &msg(usk, phi), &cred, rng).unwrap();
        let pi = MAC::possess(&pp, &shown, &phi, &usk, &omega, b"ctx", rng).unwrap();
        assert!(MAC::verify_possess(&pp, &dvk, &shown, &phi, b"ctx", &pi));
    }

    // ----- the generic flow of the construction --------------------------------------------------

    const REPORT: FlowReport = FlowReport {
        attestation_responses: 1,
        issuance_responses: 2,
    };

    /// The base-and-tag-generic walk through the designated-verifier variant of the protocol
    /// box (keyless `Attest` and `Prove`, keyed `VerifyAtt`, `Issue`, `Unblind`, `VerifyCred`),
    /// written against the traits only, with the exported forgery list.
    #[test]
    fn conformance_flow_with_tag_ddh() {
        let report = dv_base_flow::<G1, MAC, Tag>(DOMAIN, 0x3ac1e, credential_free_forgeries);
        // |att| = 3 G + 3 Z_q (T, U', V'; φ, c, z) and |π_0| = 3 Z_q (c, z_usk, z_ρ)
        assert_eq!(report, REPORT);
    }

    // ----- genericity ----------------------------------------------------------------------------

    /// The whole base over another group. arkworks ships hash-to-curve for BLS12-381 only, so
    /// the generators come from the INSECURE test oracle (known discrete logarithms: fine for
    /// the algebra, useless for binding).
    fn generic_flow<G: PrimeGroup>(seed: u64) {
        type B<G> = crate::cred::MAC<G, InsecureExponentHasher>;
        type T<G> = DDH<G, InsecureExponentHasher>;
        let one = G::ScalarField::ONE;
        let mut rng = StdRng::seed_from_u64(seed);
        let pp = B::<G>::setup(DOMAIN).unwrap();
        assert!(pp.is_well_formed());
        let dvk = B::<G>::keygen(&pp, &mut rng);
        let (usk, phi) = (
            G::ScalarField::rand(&mut rng),
            G::ScalarField::rand(&mut rng),
        );
        let (aux, rho) = B::<G>::sample_issuance(&pp, &mut rng);
        let m_hid = B::<G>::hidden_message(&usk, &aux);
        let m = B::<G>::encode_message(&pp, &m_hid, &phi).unwrap();
        let c = B::<G>::issuance_encoding(&pp, &m_hid, &phi, &rho).unwrap();
        let pre = B::<G>::blind_issue(&pp, &dvk, &c, &phi, &mut rng).unwrap();
        let cred = B::<G>::unblind(&pp, &m, &pre, &rho).unwrap();
        assert!(B::<G>::verify(&pp, &dvk, &m, &cred));
        let wrong = B::<G>::encode_message(&pp, &(usk + one), &phi).unwrap();
        assert!(!B::<G>::verify(&pp, &dvk, &wrong, &cred));

        let (shown, omega) = B::<G>::rerand(&pp, &m, &cred, &mut rng).unwrap();
        let pi = B::<G>::possess(&pp, &shown, &phi, &usk, &omega, b"ctx", &mut rng).unwrap();
        assert!(B::<G>::verify_possess(&pp, &dvk, &shown, &phi, b"ctx", &pi));
        assert!(!B::<G>::verify_possess(
            &pp,
            &dvk,
            &shown,
            &(phi + one),
            b"ctx",
            &pi
        ));
        let other = B::<G>::keygen(&pp, &mut rng);
        assert!(!B::<G>::verify_possess(
            &pp, &other, &shown, &phi, b"ctx", &pi
        ));

        assert_eq!(
            dv_base_flow::<G, B<G>, T<G>>(DOMAIN, seed, credential_free_forgeries),
            REPORT
        );
    }

    #[test]
    fn generic_over_the_group() {
        generic_flow::<ark_bn254::G1Projective>(0x3ac1f);
        generic_flow::<ark_bls12_381::G2Projective>(0x3ac20);
        generic_flow::<G1>(0x3ac21);
    }
}
