//! The protocol objects of the modular threshold construction (§5.1): public parameters, keys,
//! credentials, attestations, issuance proofs, root requests and the issuance state.
//!
//! "The formats of identities, credentials, attestations, proofs, and local state are left
//! abstract" by Def. "Predicate credential system"; §5.1 fixes them:
//!
//! | paper | here |
//! |---|---|
//! | `pp = (pp_Σ, pp_Tag, EncPred, H_0, H_1, c_0)` | [`PublicParameters`] (the oracles are fixed functions of the deployment label) |
//! | `hvk = vk`, `hsk = (sk, hvk)` | `B::VerificationKey`, [`HelperSecretKey`] |
//! | `id = Tag(usk, c_0)`, `usk` | `E::G1`, [`UserSecretKey`] |
//! | `cred = (cred_Σ, m_aux)` | [`Credential`] |
//! | `att_j = (T_j, cred*_j, φ_j, π_j)` | [`Attestation`] |
//! | `π = ((att_j)_{j ∈ [k]}, C, T_0, π_0)`, without `C` for `Σ-EQ` | [`IssuanceProof`] |
//! | `st_iss = (m_hid, φ, ρ)` | [`IssuanceState`] |
//! | the root request `(C, T_0, π_0)` (Remark "Chaining and the base case") | [`RootRequest`] |
//!
//! Public objects derive the canonical (self-describing) serialization; attestations, proofs and
//! root requests additionally have the fixed-format compact encoding of [`super::codec`], whose
//! sizes are those of the paper's comparison table (§5.3). Secrets are wiped on drop, are neither
//! `Copy` nor `Clone`, and print as `<redacted>`.
//!
//! # Validity of received objects
//!
//! Implementation note. [`Attestation`], [`IssuanceProof`] and [`RootRequest`] have public
//! fields, so a value of these types can be built in any way: decoded with validation (the
//! decoders of this crate), decoded WITHOUT validation (`deserialize_*_unchecked`,
//! `Validate::No`), decoded from an uncompressed encoding (whose validation skips the curve
//! equation for BLS12-381), or assembled by hand. Only the first guarantees that every group
//! element is on its curve and in the prime-order subgroup. **The algorithms of
//! [`PCS`](super::PCS) do not rely on it:** every algorithm that consumes an object of another
//! party re-validates it (`ark_serialize::Valid::check`) before anything else and outputs `⊥`
//! ([`Error::InvalidGroupElement`]; `false` for the three verifiers) otherwise. Decode what
//! arrives from the network with
//! [`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes) or the `from_compact_bytes` functions of [`super::codec`] all the same: they reject such
//! values (and trailing bytes, and non-canonical scalars) at the door.

use core::fmt;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::predicate::AcceptAll;
use crate::{
    cred::{CredentialBase, SigmaFriendlyCredentialBase, issuance_witness_vector},
    error::Error,
    kiprf::PCSTag,
    sigma::{FSProof, Witness},
};

/// The deployment-specific inputs of `Setup`: the deployment label, from which every parameter
/// and every oracle is derived (transparent setup), and the public attribute policy `P` of Def.
/// "Threshold authorization relation".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupParams<P = AcceptAll> {
    /// The deployment label. It separates the oracles `H_0`, `H_2` and the hash-derived
    /// generators of different deployments, and it is part of `pp`.
    pub label: Vec<u8>,
    /// The public attribute policy `P`.
    pub policy: P,
}

impl SetupParams<AcceptAll> {
    /// Parameters for the deployment `label` with the policy `P ≡ 1`.
    #[must_use]
    pub fn new(label: impl Into<Vec<u8>>) -> Self {
        Self::with_policy(label, AcceptAll)
    }
}

impl<P> SetupParams<P> {
    /// Parameters for the deployment `label` with the attribute policy `policy`.
    #[must_use]
    pub fn with_policy(label: impl Into<Vec<u8>>, policy: P) -> Self {
        Self {
            label: label.into(),
            policy,
        }
    }
}

/// The public parameters `pp = (pp_Σ, pp_Tag, EncPred, H_0, H_1, c_0)` (construction box,
/// `Setup` step 5).
///
/// Implementation note: `EncPred`, `H_0`, `H_1` (and `H_2`) are fixed functions of the deployment
/// label ([`crate::hash`]), so the label stands for them here. `Setup` is transparent: all four
/// fields are determined by the label, and
/// [`PCS::from_public_parameters`](super::PCS::from_public_parameters) accepts a received value
/// only if it is what `Setup` derives from the label it carries.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParameters<E, B, T>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    /// The deployment label; it determines `EncPred`, `H_0`, `H_1` and `H_2`.
    pub label: Vec<u8>,
    /// `pp_Σ`, the parameters of the credential base.
    pub pp_sigma: B::PublicParams,
    /// `pp_Tag`, the parameters of the tag.
    pub pp_tag: T,
    /// The identity point `c_0 = H_0("identity")`.
    pub c0: E::ScalarField,
}

/// The helper's secret key `hsk = (sk, hvk)` (construction box, `HKeyGen` step 3). Secret: the
/// signing key is wiped on drop; not `Clone`; redacted in `Debug`.
///
/// Implementation note: **the key is bound to its deployment.** Next to `(sk, hvk)` it records
/// the digest of the `pp` it was generated under
/// ([`PublicParameters::digest`], which covers the deployment label), and
/// [`issue`](super::PredicateCredentialSystem::issue) and
/// [`PCS::issue_root`](super::PCS::issue_root) return [`Error::InvalidKey`] under any other
/// `pp`. In the paper `HKeyGen(pp)` generates a key FOR one `pp`; in code nothing else ties the
/// two together, and a credential of `Σ-PS` or `Σ-EQ` (whose `pp_Σ` is empty) is a signature
/// under `hvk` and nothing more: a helper that served two deployment labels with one key would
/// certify, in each of them, endorsers of the other (`docs/operating-a-helper.md`). The digest
/// is part of the encoding of the key (32 bytes, after `sk` and `hvk`).
#[derive(Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct HelperSecretKey<B: CredentialBase> {
    pub(super) sk: B::SigningKey,
    #[zeroize(skip)]
    pub(super) hvk: B::VerificationKey,
    /// [`PublicParameters::digest`] of the deployment the key belongs to. Public.
    #[zeroize(skip)]
    pub(super) pp_digest: [u8; 32],
}

impl<B: CredentialBase> HelperSecretKey<B> {
    /// `hsk := (sk, hvk)` from a key pair of the base, e.g. one that is kept outside this crate,
    /// bound to the deployment with the parameter digest `pp_digest`
    /// ([`PCS::parameters_digest`](super::PCS::parameters_digest)). Use ONE key pair per
    /// deployment label.
    ///
    /// Implementation note: `sk` and `hvk` have to belong together. `HKeyGen` guarantees it;
    /// neither this constructor nor the decoder
    /// ([`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes)) can check it,
    /// because a credential base has no algorithm that maps `sk` to `vk` (the key types of this
    /// crate offer one, e.g.
    /// [`PSSigningKey::verification_key`](crate::cred::ps::PSSigningKey::verification_key)).
    /// A helper with a mismatched pair verifies proofs under `hvk` and signs with another key:
    /// it issues pre-credentials that every user's `Unblind` rejects
    /// ([`Error::InvalidPreCredential`]). Nobody is harmed but the helper's users are not served.
    #[must_use]
    pub fn new(sk: B::SigningKey, hvk: B::VerificationKey, pp_digest: [u8; 32]) -> Self {
        Self { sk, hvk, pp_digest }
    }

    /// The verification key `hvk` inside `hsk = (sk, hvk)`.
    #[must_use]
    pub fn verification_key(&self) -> &B::VerificationKey {
        &self.hvk
    }

    /// The signing key `sk` of the base inside `hsk = (sk, hvk)`. Secret.
    #[must_use]
    pub fn signing_key(&self) -> &B::SigningKey {
        &self.sk
    }

    /// The digest of the public parameters this key is bound to (implementation note, see the
    /// type docs). Public.
    #[must_use]
    pub fn parameters_digest(&self) -> &[u8; 32] {
        &self.pp_digest
    }

    /// The encoding `sk ‖ hvk ‖ pp-digest` (compressed canonical form) in a buffer that is wiped
    /// on drop. The way back is
    /// [`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes).
    ///
    /// Implementation note: this inherent method takes precedence over the blanket
    /// [`WireFormat::to_bytes`](crate::serialization::WireFormat::to_bytes), which would return
    /// the same bytes in a plain `Vec<u8>` that nobody wipes.
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        secret_bytes(self)
    }
}

/// The compressed canonical encoding of a SECRET in a buffer that is wiped on drop. The buffer
/// is sized up front, so it never moves and no unwiped copy is left behind.
fn secret_bytes<V: CanonicalSerialize>(value: &V) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.compressed_size()));
    value.serialize_compressed(&mut *bytes)?;
    Ok(bytes)
}

impl<B: CredentialBase> fmt::Debug for HelperSecretKey<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HelperSecretKey(<redacted>)")
    }
}

/// A user secret key `usk`: the tag key `K ∈ Z_p` behind the identifier `id = Tag(usk, c_0)`,
/// and the first component of the hidden message `m_hid = (usk, m_aux)` of every credential of
/// its holder. Secret: wiped on drop, neither `Copy` nor `Clone`, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserSecretKey<E: Pairing>(pub(super) E::ScalarField);

impl<E: Pairing> UserSecretKey<E> {
    /// Wraps a scalar as a user key, e.g. one derived from a seed or read back from storage.
    ///
    /// Not every scalar is a key under which `UKeyGen` could have returned:
    /// [`PCS::identity`](super::PCS::identity) runs steps 2-5 of `UKeyGen` on it and tells.
    #[must_use]
    pub fn from_scalar(usk: E::ScalarField) -> Self {
        Self(usk)
    }

    /// The secret scalar. For callers that run the base, the tag or the sigma protocol directly
    /// (the soundness harness compares it with an extracted witness).
    #[must_use]
    pub fn expose_scalar(&self) -> &E::ScalarField {
        &self.0
    }

    /// The encoding of `usk` (one canonical scalar) in a buffer that is wiped on drop. The way
    /// back is [`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes).
    ///
    /// Implementation note: this inherent method takes precedence over the blanket
    /// [`WireFormat::to_bytes`](crate::serialization::WireFormat::to_bytes), which would return
    /// the same bytes in a plain `Vec<u8>` that nobody wipes.
    ///
    /// # Errors
    /// [`Error::Serialization`] if the scalar cannot be serialized (it can).
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        secret_bytes(self)
    }
}

impl<E: Pairing> fmt::Debug for UserSecretKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserSecretKey(<redacted>)")
    }
}

/// A credential `cred = (cred_Σ, m_aux)` (construction box, `Unblind` step 6): "at the PCS
/// layer, `cred` retains precisely the hidden signed component needed to reconstruct" the
/// signed message `Enc_Σ((usk, m_aux), EncPred(f))`. `m_aux` is empty for `Σ-PS` and `Σ-EQ`
/// and is the certified randomizer `ρ` for `Σ-BBS`.
///
/// Private to its holder. Implementation note: `m_aux` is a hidden signed component (for
/// `Σ-BBS` it is also the randomizer that hides `usk` inside the transmitted `C`), so `Debug`
/// redacts it and it is wiped when the credential is dropped.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Credential<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    /// `cred_Σ`: the base credential, a signature on `Enc_Σ(m_hid, φ)`.
    pub cred: B::Credential,
    /// `m_aux`: the base-specific hidden component of `m_hid = (usk, m_aux)`.
    pub aux: B::Aux,
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> Drop for Credential<E, B> {
    fn drop(&mut self) {
        self.aux.zeroize();
    }
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> fmt::Debug for Credential<E, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("cred", &self.cred)
            .field("aux", &"<redacted>")
            .finish()
    }
}

/// An attestation `att_j = (T_j, cred*_j, φ_j, π_j)` for an identifier `id` (construction box,
/// `Attest` step 12): the attester's tag `T_j = Tag(usk_j, H_0(id))`, its shown credential, the
/// predicate label `φ_j = EncPred(f_j)` of that credential ("the one value an attestation leaks
/// by design"), and the Fiat-Shamir proof for `R_att`.
///
/// An attestation binds `id` and the attester's key, "but no session, epoch or predicate"
/// (Remark "Attestations are standing endorsements").
///
/// Implementation note: the fields are public and the verifiers make NO assumption about how a
/// value was built; they re-validate every group element (curve and prime-order subgroup) and
/// reject with [`Error::InvalidGroupElement`] (module docs, "Validity of received objects").
/// Decode received attestations with
/// [`from_compact_bytes`](Self::from_compact_bytes) or
/// [`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "", rename_all = "camelCase", deny_unknown_fields)
)]
pub struct Attestation<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    /// `T_j = Tag(usk_j, H_0(id))`.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub tag: E::G1,
    /// `cred*_j`, the output of `ReRand`.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub shown: B::ShownCredential,
    /// `φ_j = EncPred(f_j)`.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub phi: E::ScalarField,
    /// `π_j`, a compact proof with `1 + POSSESSION_VARIABLES` responses.
    pub proof: FSProof<E::ScalarField>,
}

/// An issuance proof `π = ((att_j)_{j ∈ [k]}, C, T_0, π_0)` (construction box, `Prove` steps
/// 12-13). For `Σ-EQ` the issuance encoding is not transmitted (`B::WireEncoding = ()`, "the
/// verifier reconstructs it rather than parsing it from `π`").
///
/// `T_0` is a mandatory field: a proof without the self-exclusion tag does not exist in this
/// format ("fail closed when `T_0` is absent", §5.5).
///
/// Implementation note: the fields are public and `VerifyProof` makes NO assumption about how a
/// value was built; it re-validates every group element of `π`, the attestations included (curve
/// and prime-order subgroup), and rejects with [`Error::InvalidGroupElement`] (module docs,
/// "Validity of received objects"). Decode received proofs with
/// [`from_compact_bytes`](Self::from_compact_bytes) or
/// [`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "", rename_all = "camelCase", deny_unknown_fields)
)]
pub struct IssuanceProof<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    /// `(att_j)_{j ∈ [k]}`, forwarded verbatim. A verifier accepts EXACTLY `k = f.threshold`.
    pub attestations: Vec<Attestation<E, B>>,
    /// What travels for the issuance encoding `C = Com(m_hid, φ; ρ)`: `C`, or nothing.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub encoding: B::WireEncoding,
    /// The self-exclusion tag `T_0 = Tag(usk, H_0(id))`.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub t0: E::G1,
    /// `π_0`, a compact proof for `R_issue` with `1 + ISSUANCE_VARIABLES` responses.
    pub proof: FSProof<E::ScalarField>,
}

/// The request for a root credential: `(C, T_0, π_0)`, i.e. what `Prove` outputs for ZERO
/// attestations, under a Fiat-Shamir context of its own.
///
/// Remark "Chaining and the base case": the base issuance flow starts from an issuance encoding
/// `C`, and "only the user can compute `C` without revealing `usk`", so the user sends `C` with a
/// proof that `C`, `id` and `T_0` are under ONE key: the relation `R_issue`. A root request is a
/// type of its own and its context `ctx_root` differs from `ctx_0`, so it can never be replayed
/// as an issuance proof for a threshold predicate, nor the other way round.
///
/// The fields are public and the verifier of a root request makes NO assumption about how a
/// value was built; it re-validates every group element (curve and prime-order subgroup) and
/// rejects with [`Error::InvalidGroupElement`] (module docs, "Validity of received objects").
/// Decode received requests with [`from_compact_bytes`](Self::from_compact_bytes) or
/// [`WireFormat::from_bytes`](crate::serialization::WireFormat::from_bytes).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound = "", rename_all = "camelCase", deny_unknown_fields)
)]
pub struct RootRequest<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    /// What travels for the issuance encoding `C`: `C`, or nothing (`Σ-EQ`).
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub encoding: B::WireEncoding,
    /// `T_0 = Tag(usk, H_0(id))`.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::canonical"))]
    pub t0: E::G1,
    /// The proof for `R_issue` under the root context.
    pub proof: FSProof<E::ScalarField>,
}

/// The private issuance state `st_iss = (m_hid, φ, ρ)` that `Prove` hands to `Unblind`
/// (construction box, `Prove` step 14). Secret (`m_hid` contains `usk`): wiped on drop, not
/// `Clone`, redacted in `Debug`. It can be stored until the helper answers
/// ([`Self::to_bytes`], [`Self::from_bytes`]); the encoding is as secret as `usk`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IssuanceState<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    pub(super) m_hid: B::HiddenMessage,
    pub(super) phi: E::ScalarField,
    pub(super) rho: B::IssuanceState,
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> IssuanceState<E, B> {
    /// The witness `(m_hid, ρ)` of `R_issue` for the proof this state was returned with, in the
    /// variable order of [`PCS::issuance_relation`](super::PCS::issuance_relation): `usk`, then
    /// the variables of the opening clause. For the soundness harness, which runs the
    /// interactive protocol on exactly the relation of `π_0`.
    #[must_use]
    pub fn witness(&self) -> Witness<E::ScalarField> {
        issuance_witness_vector::<E, B>(&self.m_hid, &self.rho)
    }
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> fmt::Debug for IssuanceState<E, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuanceState(<redacted>)")
    }
}

/// `st_iss` has to survive between `Prove` and the helper's answer, which may take a while
/// (the paper's deployment issues through "an asynchronous store-and-forward mediator", Remark
/// "Concurrent issuance"), so it can be stored. Implementation note; the encoding is
/// `usk ‖ m_aux ‖ φ ‖ ρ` in compressed canonical form, and it is as secret as `usk`.
impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> IssuanceState<E, B> {
    /// The encoding `usk ‖ m_aux ‖ φ ‖ ρ`, in a buffer that is wiped on drop.
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (usk, aux) = B::split_hidden_message(&self.m_hid);
        let (usk, aux) = (Zeroizing::new(usk), Zeroizing::new(aux));
        let size = usk.compressed_size()
            + aux.compressed_size()
            + self.phi.compressed_size()
            + self.rho.compressed_size();
        // sized up front: the buffer never moves, so no unwiped copy is left behind
        let mut bytes = Zeroizing::new(Vec::with_capacity(size));
        usk.serialize_compressed(&mut *bytes)?;
        aux.serialize_compressed(&mut *bytes)?;
        self.phi.serialize_compressed(&mut *bytes)?;
        self.rho.serialize_compressed(&mut *bytes)?;
        Ok(bytes)
    }

    /// Decodes [`Self::to_bytes`], with validation.
    ///
    /// # Errors
    /// [`Error::Serialization`] on malformed input; [`Error::TrailingBytes`] if `bytes`
    /// continues after the state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = bytes;
        // `usk` and `m_aux` are wiped on every exit; `ρ` is the last part that can fail.
        let usk = Zeroizing::new(E::ScalarField::deserialize_compressed(&mut reader)?);
        let aux = Zeroizing::new(B::Aux::deserialize_compressed(&mut reader)?);
        let phi = E::ScalarField::deserialize_compressed(&mut reader)?;
        let rho = B::IssuanceState::deserialize_compressed(&mut reader)?;
        let state = Self {
            m_hid: B::hidden_message(&usk, &aux),
            phi,
            rho,
        };
        if reader.is_empty() {
            Ok(state)
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{UniformRand, Zero};
    use rand::{SeedableRng, rngs::StdRng};
    use zeroize::ZeroizeOnDrop;

    use super::*;
    use crate::{
        pcs::{
            Predicate, PredicateCredentialSystem,
            test_support::{BBS, DDH, E, Fixture, PS},
        },
        serialization::WireFormat,
    };

    type Fr = ark_bls12_381::Fr;

    /// Compiles only if `T` does NOT implement `Clone`: with a `Clone` impl both blanket impls
    /// apply and the inference of `A` is ambiguous.
    macro_rules! assert_not_clone {
        ($t:ty) => {{
            trait AmbiguousIfClone<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfClone<()> for T {}
            impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
            <$t as AmbiguousIfClone<_>>::check();
        }};
    }

    #[test]
    fn secrets_are_redacted_wiped_and_not_cloneable() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<UserSecretKey<E>>();
        assert_zeroize_on_drop::<HelperSecretKey<PS>>();
        assert_zeroize_on_drop::<HelperSecretKey<BBS>>();
        assert_zeroize_on_drop::<IssuanceState<E, PS>>();
        assert_zeroize_on_drop::<IssuanceState<E, BBS>>();
        assert_not_clone!(UserSecretKey<E>);
        assert_not_clone!(HelperSecretKey<PS>);
        assert_not_clone!(IssuanceState<E, BBS>);

        let mut rng = StdRng::seed_from_u64(0x7e57_0001);
        let secret = Fr::rand(&mut rng);
        let mut usk = UserSecretKey::<E>::from_scalar(secret);
        assert_eq!(usk.expose_scalar(), &secret);
        assert_eq!(format!("{usk:?}"), "UserSecretKey(<redacted>)");
        usk.zeroize();
        assert!(usk.expose_scalar().is_zero());

        let mut fixture = Fixture::<BBS, DDH>::new(b"types/secrets", 0x7e57_0002);
        assert_eq!(format!("{:?}", fixture.hsk), "HelperSecretKey(<redacted>)");
        let holder = fixture.holder();
        let (pcs, hvk) = (&fixture.pcs, &fixture.hvk);
        let (_, mut state) = pcs
            .root_request(
                hvk,
                &fixture.f_root,
                &holder.id,
                &holder.usk,
                &mut fixture.rng,
            )
            .unwrap();
        assert_eq!(format!("{state:?}"), "IssuanceState(<redacted>)");
        // st_iss = (m_hid, φ, ρ) is the witness (usk, ρ) of R_issue, until it is wiped
        let witness = state.witness();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], *holder.usk.expose_scalar());
        assert!(!witness[1].is_zero());
        state.zeroize();
        assert!(state.phi.is_zero() && state.rho.is_zero());
        assert!(state.witness().iter().all(Zero::is_zero));
    }

    /// `m_aux` (the certified randomizer `ρ` of `Σ-BBS`) does not show up in `Debug`.
    #[test]
    fn credential_debug_redacts_the_hidden_component() {
        let mut fixture = Fixture::<BBS, DDH>::new(b"types/credential", 0x7e57_0003);
        let holder = fixture.holder();
        let printed = format!("{:?}", holder.cred);
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(printed.contains(&format!("{:?}", holder.cred.cred)));
        assert!(!printed.contains(&format!("{:?}", holder.cred.aux)));
        // cred = (cred_Σ, m_aux) round-trips, m_aux included: 48 + 32 + 32 bytes
        let bytes = holder.cred.to_bytes().unwrap();
        assert_eq!(bytes.len(), 112);
        assert_eq!(
            Credential::<E, BBS>::from_bytes(&bytes).unwrap(),
            holder.cred
        );
        assert_eq!(holder.cred.clone(), holder.cred);
    }

    #[test]
    fn keys_round_trip() {
        let mut fixture = Fixture::<PS, DDH>::new(b"types/keys", 0x7e57_0004);
        let holder = fixture.holder();
        // The encodings of SECRET keys live in buffers that are wiped on drop: the inherent
        // `to_bytes` of the two key types shadows the blanket `WireFormat::to_bytes`, whose
        // plain `Vec<u8>` nobody wipes. (The type annotations are the assertion.)
        let bytes: Zeroizing<Vec<u8>> = holder.usk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(*bytes, crate::serialization::to_bytes(&holder.usk).unwrap());
        let usk = UserSecretKey::<E>::from_bytes(&bytes).unwrap();
        assert_eq!(usk.expose_scalar(), holder.usk.expose_scalar());
        assert_eq!(fixture.pcs.identity(&usk), Ok(holder.id));

        // hsk = (sk, hvk) and the digest of its pp: (x, y_1, y_2), the 3 G_2 + 1 G_1 elements
        // of hvk, 32 bytes
        let bytes: Zeroizing<Vec<u8>> = fixture.hsk.to_bytes().unwrap();
        assert_eq!(bytes.len(), 3 * 32 + 3 * 96 + 48 + 32);
        assert_eq!(
            *bytes,
            crate::serialization::to_bytes(&fixture.hsk).unwrap()
        );
        assert_eq!(&bytes[bytes.len() - 32..], fixture.pcs.parameters_digest());
        let hsk = HelperSecretKey::<PS>::from_bytes(&bytes).unwrap();
        assert_eq!(hsk.verification_key(), &fixture.hvk);
        assert_eq!(hsk.signing_key().verification_key(), fixture.hvk);
        assert_eq!(hsk.parameters_digest(), fixture.pcs.parameters_digest());
        // ... and so does a key that is assembled from a key pair of the base
        let (vk, sk) = PS::keygen(fixture.pcs.base_parameters(), &mut fixture.rng);
        let assembled =
            HelperSecretKey::<PS>::new(sk, vk.clone(), *fixture.pcs.parameters_digest());
        assert_eq!(assembled.verification_key(), &vk);
        assert_eq!(assembled.signing_key().verification_key(), vk);
        assert_eq!(
            assembled.parameters_digest(),
            fixture.pcs.parameters_digest()
        );
        // the decoded key issues
        let (pcs, hvk, f_root) = (&fixture.pcs, &fixture.hvk, &fixture.f_root);
        let (request, state) = pcs
            .root_request(hvk, f_root, &holder.id, &usk, &mut fixture.rng)
            .unwrap();
        let pre = pcs
            .issue_root(hvk, &hsk, f_root, &holder.id, &request, &mut fixture.rng)
            .unwrap();
        assert!(pcs.unblind(hvk, &usk, f_root, &pre, &state).is_ok());
    }

    /// A helper key belongs to ONE deployment: `hsk` records the digest of the `pp` it was
    /// generated under, and `Issue` and `issue_root` refuse it under any other `pp`.
    #[test]
    fn a_helper_key_is_bound_to_its_deployment() {
        let mut here = Fixture::<PS, DDH>::new(b"types/binding/here", 0x7e57_0005);
        let there = Fixture::<PS, DDH>::new(b"types/binding/there", 0x7e57_0006);
        assert_eq!(here.hsk.parameters_digest(), here.pcs.parameters_digest());
        assert_ne!(here.hsk.parameters_digest(), there.pcs.parameters_digest());

        // the key of `here`, its verification key, the OTHER deployment
        let (id, usk) = there.pcs.user_keygen(&mut here.rng).unwrap();
        let f_root = here.f_root.clone();
        let (request, _) = there
            .pcs
            .root_request(&here.hvk, &f_root, &id, &usk, &mut here.rng)
            .unwrap();
        assert_eq!(
            there
                .pcs
                .check_root_request(&here.hvk, &f_root, &id, &request),
            Ok(())
        );
        assert_eq!(
            there
                .pcs
                .issue_root(&here.hvk, &here.hsk, &f_root, &id, &request, &mut here.rng)
                .err(),
            Some(Error::InvalidKey)
        );
        // the ordinary path: a proof that `there` accepts under hvk of `here` (the endorser holds
        // a root credential that the key of `here` issued for the label φ of `there`; see the
        // control below) is NOT served with the key of `here` under the pp of `there`
        let rebound = {
            let sk_bytes = crate::serialization::to_bytes(here.hsk.signing_key()).unwrap();
            let sk = <PS as CredentialBase>::SigningKey::from_bytes(&sk_bytes).unwrap();
            HelperSecretKey::<PS>::new(sk, here.hvk.clone(), *there.pcs.parameters_digest())
        };
        let (id_j, usk_j) = there.pcs.user_keygen(&mut here.rng).unwrap();
        let (request_j, state_j) = there
            .pcs
            .root_request(&here.hvk, &f_root, &id_j, &usk_j, &mut here.rng)
            .unwrap();
        let pre = there
            .pcs
            .issue_root(
                &here.hvk,
                &rebound,
                &f_root,
                &id_j,
                &request_j,
                &mut here.rng,
            )
            .unwrap();
        let cred_j = there
            .pcs
            .unblind(&here.hvk, &usk_j, &f_root, &pre, &state_j)
            .unwrap();
        let att = there
            .pcs
            .attest(&here.hvk, &usk_j, &f_root, &cred_j, &id, &mut here.rng)
            .unwrap();
        let f = Predicate::new(1, b"members".to_vec());
        let (proof, _) = there
            .pcs
            .prove(&here.hvk, &f, &id, &usk, &[att], &mut here.rng)
            .unwrap();
        assert_eq!(there.pcs.check_proof(&here.hvk, &f, &id, &proof), Ok(()));
        assert_eq!(
            there
                .pcs
                .issue(&here.hvk, &here.hsk, &f, &id, &proof, &mut here.rng)
                .err(),
            Some(Error::InvalidKey)
        );
        // control: the binding is what refuses, nothing else. A key that was deliberately
        // re-bound to `there` issues (which is why `docs/operating-a-helper.md` says: one key per label).
        assert!(
            there
                .pcs
                .issue(&here.hvk, &rebound, &f, &id, &proof, &mut here.rng)
                .is_ok()
        );
        // ... and the key of `here` serves its own deployment
        let holder = here.holder();
        assert!(
            here.pcs
                .verify_cred(&here.hvk, &holder.usk, &here.f_root, &holder.cred)
        );
    }

    /// `st_iss` survives storage: the decoded state unblinds what the original would have.
    #[test]
    fn issuance_state_round_trips() {
        fn check<B: SigmaFriendlyCredentialBase<E>>(label: &[u8], seed: u64, size: usize) {
            let mut fixture = Fixture::<B, DDH>::new(label, seed);
            let (pcs, hvk, f_root, rng) = (
                &fixture.pcs,
                &fixture.hvk,
                &fixture.f_root,
                &mut fixture.rng,
            );
            let (id, usk) = pcs.user_keygen(rng).unwrap();
            let (request, state) = pcs.root_request(hvk, f_root, &id, &usk, rng).unwrap();
            let bytes = state.to_bytes().unwrap();
            assert_eq!(bytes.len(), size);
            let stored = IssuanceState::<E, B>::from_bytes(&bytes).unwrap();
            assert_eq!(&*stored.witness(), &*state.witness());
            assert_eq!(stored.phi, state.phi);
            drop(state);
            let pre = pcs
                .issue_root(hvk, &fixture.hsk, f_root, &id, &request, rng)
                .unwrap();
            let cred = pcs.unblind(hvk, &usk, f_root, &pre, &stored).unwrap();
            assert!(pcs.verify_cred(hvk, &usk, f_root, &cred));
            // strict decoding
            assert!(matches!(
                IssuanceState::<E, B>::from_bytes(&bytes[..bytes.len() - 1]),
                Err(Error::Serialization(_))
            ));
            let mut longer = bytes.to_vec();
            longer.push(0);
            assert!(matches!(
                IssuanceState::<E, B>::from_bytes(&longer),
                Err(Error::TrailingBytes)
            ));
        }
        // usk ‖ m_aux ‖ φ ‖ ρ: Σ-PS (usk, φ, ρ), Σ-BBS (usk, ρ, φ, ρ), Σ-EQ (usk, φ)
        check::<PS>(b"types/state/ps", 0x7e57_0011, 3 * 32);
        check::<BBS>(b"types/state/bbs", 0x7e57_0012, 4 * 32);
        check::<crate::pcs::test_support::SPSEQ>(b"types/state/eq", 0x7e57_0013, 2 * 32);
    }

    #[test]
    fn setup_params() {
        let params = SetupParams::new(b"label".to_vec());
        assert_eq!(
            params,
            SetupParams::with_policy(b"label".to_vec(), AcceptAll)
        );
        assert_eq!(params.label, b"label");
        let f = Predicate::new(1, b"f".to_vec());
        let custom = SetupParams::with_policy(&b"label"[..], vec![f.clone()]);
        assert_eq!(custom.policy, vec![f]);
    }
}
