//! Credential-level interoperability of `Σ-BBS` with IETF BBS, as implemented by the crate
//! `affinidi-bbs` of the Affinidi / OpenVTC stack (ciphersuite BLS12-381-SHA-256, curve backend
//! `bls12_381_plus`).
//!
//! Implementation note: nothing in this module is part of the paper. The paper's `Σ-BBS` takes
//! the generators `h_0, …, h_3` from `pp_Σ`, derived by hashing a public label to `G_1`;
//! [`CredentialBase::setup`](super::CredentialBase::setup) derives them from the deployment
//! label. This module derives them the way the IETF ciphersuite does instead (also by hashing
//! public strings to `G_1`; in addition `h_0` depends on the helper's key and on a header
//! through `domain`), which makes a `Σ-BBS` credential and an IETF BBS signature THE SAME
//! OBJECT.
//!
//! # The mapping
//!
//! An IETF BBS signature is `(A, e)` with `A = B^{1/(SK + e)}` and
//! `B = P_1 · Q_1^{domain} · ∏ G_i^{m_i}`, verified by `e(A, PK · BP_2^e) = e(B, BP_2)`: the
//! `Sign` / `Verify` of the box `Σ-BBS` with `X̃ = PK`, `g̃ = BP_2` and
//!
//! ```text
//! h_0 := P_1 · Q_1^{domain}        (h_1, h_2, h_3) := the generators of (usk, φ, ρ)
//! ```
//!
//! where `domain = hash_to_scalar(PK ‖ L ‖ Q_1 ‖ generators ‖ api_id ‖ header)`. So `h_0` depends
//! on the helper's key and on the header, which is why [`BBSPublicParams::ietf`] takes both.
//! Which generators carry `(usk, φ, ρ)` depends on the [`Interface`]:
//!
//! | [`Interface`] | `usk` | `φ` | `ρ` |
//! |---|---|---|---|
//! | [`Core`](Interface::Core): plain `Sign` over three messages | message 1, `H_1` | message 2, `H_2` | message 3, `H_3` |
//! | [`Blind`](Interface::Blind): blind signing | the committed message, `J_1` | the signer's message, `H_1` | `secret_prover_blind`, `Q_2` |
//! | [`BlindPseudonym`](Interface::BlindPseudonym) | the `nym_secret`, `J_1` | the signer's message, `H_1` | `secret_prover_blind`, `Q_2` |
//!
//! In the blind interfaces the commitment `ρ·Q_2 + usk·J_1` of the IETF user is the target of
//! the opening clause of `R_issue` here (`C = h_0 h_1^usk h_2^φ h_3^ρ` with the public part
//! moved to the other side), so either side's issuance can be answered by the other.
//!
//! The byte encodings agree except for the endianness of scalars: compressed `G_1` / `G_2`
//! points are the same 48 / 96 bytes (ZCash format) in arkworks and in `bls12_381_plus`, while
//! scalars are big-endian (`I2OSP`) in IETF BBS and little-endian in arkworks. The
//! `from_ietf_bytes` / `to_ietf_bytes` methods below are that bridge; the two stacks share no
//! type.
//!
//! # What is NOT covered
//!
//! * **The presentation.** The show of `Σ-BBS` and IETF `ProofGen` prove the same relation
//!   (`ReRand` + generalized Schnorr, and the pseudonym clause is the `Tag_DDH` clause on the
//!   shared key), but the Fiat-Shamir challenge and the byte layout of the proof differ: an
//!   attestation of this crate is not an IETF BBS proof and vice versa. See
//!   `docs/encodings.md`.
//! * **Messages.** IETF BBS signs byte strings, mapped to scalars by
//!   [`message_to_scalar`]; this crate certifies the scalars `(usk, φ, ρ)` themselves. A
//!   credential crosses over only if both sides agree on the scalars.
//! * **The signer's pseudonym entropy.** In the pseudonym interface the IETF signer adds
//!   `signer_nym_entropy` to the committed `nym_secret`. The certified key is then
//!   `usk + entropy`, not the `usk` behind the identifier `id`; it equals `usk` for entropy `0`.
//! * **Their verifier.** A bridge keeps the public checks of THIS crate
//!   ([`verify_possess_public`](super::SigmaFriendlyCredentialBase::verify_possess_public));
//!   it does not defer to another implementation's.
//!
//! The interoperability tests (`tests/bbs_ietf_interop.rs`) run against `affinidi-bbs` 0.3.3;
//! the hashing is pinned by the test vectors of RFC 9380 and by a fixture of the BBS draft.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, g1};
use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
};
use ark_ff::{BigInteger, PrimeField, field_hashers::DefaultFieldHasher};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{BBSCredential, BBSPublicParams, BBSSigningKey, BBSVerificationKey};
use crate::error::Error;

/// The identifier of the ciphersuite BLS12-381-SHA-256 of IETF BBS.
pub const CIPHERSUITE_ID: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// `P_1` of BLS12-381-SHA-256, compressed.
const P1: [u8; 48] = [
    0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46, 0x62,
    0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1, 0xfd, 0x22,
    0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b, 0x4e, 0x28, 0xc9,
];

/// Output length of `expand_message` inside `hash_to_scalar` and `create_generators`.
const EXPAND_LEN: usize = 48;
/// Size of an IETF scalar (`I2OSP(x, 32)`).
const SCALAR_LEN: usize = 32;
/// Size of a compressed `G_1` point.
const G1_LEN: usize = 48;
/// Size of a compressed `G_2` point (an IETF public key).
const G2_LEN: usize = 96;

/// The interface of the BBS draft family that fixes the generators and the domain (module docs,
/// "The mapping").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Interface {
    /// `Sign` / `Verify` of the core draft over the three messages `(usk, φ, ρ)`.
    Core,
    /// Blind signing: the signer's message `φ`, the committed message `usk`, and
    /// `secret_prover_blind = ρ`.
    Blind,
    /// Blind signing with a pseudonym: as [`Blind`](Self::Blind), the committed value being the
    /// `nym_secret`.
    BlindPseudonym,
}

impl Interface {
    /// The `api_id` of the interface.
    #[must_use]
    pub fn api_id(self) -> Vec<u8> {
        let suffix: &[u8] = match self {
            Self::Core => b"H2G_HM2S_",
            Self::Blind => b"BLIND_H2G_HM2S_",
            Self::BlindPseudonym => b"H2G_HM2S_PSEUDONYM_",
        };
        [CIPHERSUITE_ID, suffix].concat()
    }

    /// The `api_id` under which the generators of the COMMITTED part are created (`Q_2` and the
    /// `J_i`); `None` for the core interface.
    #[must_use]
    pub fn blind_generators_api_id(self) -> Option<Vec<u8>> {
        match self {
            Self::Core => None,
            Self::Blind | Self::BlindPseudonym => Some([b"BLIND_", &self.api_id()[..]].concat()),
        }
    }
}

/// `expand_message_xmd` of RFC 9380 §5.3.1 with SHA-256.
///
/// Implementation note: arkworks' own expander is not used, because it differs from the RFC
/// when the output is not a base-field element (`docs/design-notes.md`, "Limitations").
///
/// # Errors
/// [`Error::LengthMismatch`] if `dst` is longer than 255 bytes or more than 255 blocks are
/// requested.
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    const BLOCK: usize = 32;
    let ell = len.div_ceil(BLOCK);
    let (Ok(dst_len), Ok(len_u16), Ok(ell_u8)) = (
        u8::try_from(dst.len()),
        u16::try_from(len),
        u8::try_from(ell),
    ) else {
        return Err(Error::LengthMismatch {
            expected: 255,
            actual: dst.len().max(ell),
        });
    };
    let block = |parts: &[&[u8]]| {
        let mut h = Sha256::new();
        for part in parts {
            h.update(part);
        }
        h.update(dst);
        h.update([dst_len]);
        h.finalize()
    };
    // b_0 = H(Z_pad ‖ msg ‖ I2OSP(len, 2) ‖ 0 ‖ DST'),  b_1 = H(b_0 ‖ 1 ‖ DST')
    let b0 = block(&[&[0u8; 64], msg, &len_u16.to_be_bytes(), &[0u8]]);
    let mut bi = block(&[&b0, &[1u8]]);
    let mut out = bi.to_vec();
    for i in 2..=ell_u8 {
        // b_i = H((b_0 XOR b_{i-1}) ‖ i ‖ DST')
        let xored: Vec<u8> = b0.iter().zip(&bi).map(|(a, b)| a ^ b).collect();
        bi = block(&[&xored, &[i]]);
        out.extend_from_slice(&bi);
    }
    out.truncate(len);
    Ok(out)
}

/// `hash_to_scalar(msg, dst) = OS2IP(expand_message(msg, dst, 48)) mod r`.
///
/// # Errors
/// As [`expand_message_xmd`].
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Fr, Error> {
    Ok(Fr::from_be_bytes_mod_order(&expand_message_xmd(
        msg, dst, EXPAND_LEN,
    )?))
}

/// The scalar that IETF BBS signs for the byte string `message` (`messages_to_scalars`).
///
/// # Errors
/// As [`expand_message_xmd`].
pub fn message_to_scalar(interface: Interface, message: &[u8]) -> Result<Fr, Error> {
    let dst = [&interface.api_id()[..], b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat();
    hash_to_scalar(message, &dst)
}

/// `hash_to_curve_g1` of the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` under the tag `dst`.
fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> Result<G1Projective, Error> {
    type Suite =
        MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;
    let suite = <Suite as HashToCurve<G1Projective>>::new(dst)?;
    Ok(suite.hash(msg)?.into())
}

/// `create_generators(count, api_id)`: the points `(Q_1, H_1, …, H_{count-1})` for the core
/// `api_id`, `(Q_2, J_1, …)` for a blind one.
///
/// # Errors
/// As [`expand_message_xmd`]; [`Error::HashToCurve`] if the suite fails.
pub fn create_generators(count: usize, api_id: &[u8]) -> Result<Vec<G1Projective>, Error> {
    let seed_dst = [api_id, b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id, b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id, b"MESSAGE_GENERATOR_SEED"].concat();
    let mut v = expand_message_xmd(&generator_seed, &seed_dst, EXPAND_LEN)?;
    let mut generators = Vec::with_capacity(count);
    for i in 1..=count as u64 {
        v = expand_message_xmd(&[&v[..], &i.to_be_bytes()].concat(), &seed_dst, EXPAND_LEN)?;
        generators.push(hash_to_curve_g1(&v, &generator_dst)?);
    }
    Ok(generators)
}

/// The fixed point `P_1` of the ciphersuite.
///
/// # Errors
/// Never in practice: the constant is a valid point (pinned by a test).
pub fn p1() -> Result<G1Projective, Error> {
    Ok(G1Affine::deserialize_compressed(&P1[..])?.into())
}

/// `calculate_domain(PK, Q_1, (H_1, …, H_L), header, api_id)`.
///
/// # Errors
/// As [`expand_message_xmd`]; [`Error::Serialization`] if a point cannot be encoded.
pub fn calculate_domain(
    vk: &BBSVerificationKey<Bls12_381>,
    q1: &G1Projective,
    generators: &[G1Projective],
    header: &[u8],
    api_id: &[u8],
) -> Result<Fr, Error> {
    let mut data = vk.to_ietf_bytes()?.to_vec();
    data.extend_from_slice(&(generators.len() as u64).to_be_bytes());
    for point in core::iter::once(q1).chain(generators) {
        point.into_affine().serialize_compressed(&mut data)?;
    }
    data.extend_from_slice(api_id);
    data.extend_from_slice(&(header.len() as u64).to_be_bytes());
    data.extend_from_slice(header);
    hash_to_scalar(&data, &[api_id, b"H2S_"].concat())
}

/// An IETF scalar (`I2OSP(x, 32)`, big-endian) as a field element.
///
/// # Errors
/// [`Error::LengthMismatch`] unless there are 32 bytes; [`Error::Serialization`] if the value is
/// not reduced modulo the group order.
pub fn scalar_from_be_bytes(bytes: &[u8]) -> Result<Fr, Error> {
    let Ok(mut le) = <[u8; SCALAR_LEN]>::try_from(bytes) else {
        return Err(Error::LengthMismatch {
            expected: SCALAR_LEN,
            actual: bytes.len(),
        });
    };
    le.reverse();
    let scalar = Fr::deserialize_compressed(&le[..]);
    le.fill(0);
    Ok(scalar?)
}

/// A field element as an IETF scalar (`I2OSP(x, 32)`, big-endian).
#[must_use]
pub fn scalar_to_be_bytes(scalar: &Fr) -> [u8; SCALAR_LEN] {
    let mut out = [0u8; SCALAR_LEN];
    out.copy_from_slice(&scalar.into_bigint().to_bytes_be());
    out
}

impl BBSPublicParams<Bls12_381> {
    /// The public parameters under which a `Σ-BBS` credential on `(usk, φ, ρ)` IS an IETF BBS
    /// signature of the helper `vk` for `header` (module docs, "The mapping"):
    /// `h_0 = P_1 · Q_1^{domain}` and `(h_1, h_2, h_3)` the generators of `(usk, φ, ρ)` in the
    /// given [`Interface`].
    ///
    /// Like the parameters of [`CredentialBase::setup`](super::CredentialBase::setup) they are
    /// transparent: a function of public constants, the helper's key and the header, which
    /// every party recomputes instead of trusting a received copy. Unlike them they depend on
    /// the key, so the construction is set up with
    /// [`PCS::setup_with_base_parameters`](crate::pcs::PCS::setup_with_base_parameters) AFTER
    /// the helper's key exists.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if `vk` is the identity; [`Error::DegenerateInput`] if a derived
    /// generator is the identity (probability `≈ 1/p` over the header); the errors of
    /// [`create_generators`] and [`calculate_domain`].
    pub fn ietf(
        interface: Interface,
        vk: &BBSVerificationKey<Bls12_381>,
        header: &[u8],
    ) -> Result<Self, Error> {
        use ark_ff::Zero;
        if vk.x_tilde.is_zero() {
            return Err(Error::InvalidKey);
        }
        let api_id = interface.api_id();
        // (Q_1, generator of usk, generator of φ, generator of ρ) and the list the domain covers
        let (q1, h_usk, h_phi, h_rho, covered) = match interface.blind_generators_api_id() {
            None => {
                let g = create_generators(4, &api_id)?;
                (g[0], g[1], g[2], g[3], vec![g[1], g[2], g[3]])
            }
            Some(blind_api_id) => {
                let signer = create_generators(2, &api_id)?; // Q_1, H_1
                let blind = create_generators(2, &blind_api_id)?; // Q_2, J_1
                let (q1, h1, q2, j1) = (signer[0], signer[1], blind[0], blind[1]);
                (q1, j1, h1, q2, vec![h1, q2, j1])
            }
        };
        let domain = calculate_domain(vk, &q1, &covered, header, &api_id)?;
        let pp = Self {
            h0: p1()? + q1 * domain,
            h1: h_usk,
            h2: h_phi,
            h3: h_rho,
        };
        if pp.is_well_formed() {
            Ok(pp)
        } else {
            Err(Error::DegenerateInput("identity generator of Σ-BBS"))
        }
    }
}

impl BBSVerificationKey<Bls12_381> {
    /// The key as an IETF public key: the 96 bytes of the compressed `G_2` point.
    ///
    /// # Errors
    /// [`Error::Serialization`] if the point cannot be encoded.
    pub fn to_ietf_bytes(&self) -> Result<[u8; G2_LEN], Error> {
        let mut out = [0u8; G2_LEN];
        self.x_tilde
            .into_affine()
            .serialize_compressed(&mut out[..])?;
        Ok(out)
    }

    /// An IETF public key as a verification key (validated: on the curve, in the subgroup).
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] unless there are 96 bytes; [`Error::Serialization`] for an
    /// invalid point; [`Error::InvalidKey`] for the identity.
    pub fn from_ietf_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != G2_LEN {
            return Err(Error::LengthMismatch {
                expected: G2_LEN,
                actual: bytes.len(),
            });
        }
        let x_tilde = G2Affine::deserialize_compressed(bytes)?;
        if x_tilde.is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            x_tilde: x_tilde.into(),
        })
    }
}

impl BBSSigningKey<Bls12_381> {
    /// The key as an IETF secret key (`I2OSP(SK, 32)`), in a buffer that is wiped on drop.
    #[must_use]
    pub fn to_ietf_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
        Zeroizing::new(scalar_to_be_bytes(&self.x))
    }

    /// An IETF secret key as a signing key.
    ///
    /// # Errors
    /// As [`scalar_from_be_bytes`].
    pub fn from_ietf_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            x: scalar_from_be_bytes(bytes)?,
        })
    }
}

impl BBSCredential<Bls12_381> {
    /// The credential as an IETF BBS signature: `A` compressed (48 bytes) followed by
    /// `I2OSP(e, 32)`.
    ///
    /// # Errors
    /// [`Error::Serialization`] if the point cannot be encoded.
    pub fn to_ietf_bytes(&self) -> Result<[u8; G1_LEN + SCALAR_LEN], Error> {
        let mut out = [0u8; G1_LEN + SCALAR_LEN];
        self.a
            .into_affine()
            .serialize_compressed(&mut out[..G1_LEN])?;
        out[G1_LEN..].copy_from_slice(&scalar_to_be_bytes(&self.e));
        Ok(out)
    }

    /// An IETF BBS signature as a credential (validated point, reduced scalar). As everywhere,
    /// decoding says nothing about validity: `Verify` does.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] unless there are 80 bytes; [`Error::Serialization`] for an
    /// invalid point or scalar.
    pub fn from_ietf_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != G1_LEN + SCALAR_LEN {
            return Err(Error::LengthMismatch {
                expected: G1_LEN + SCALAR_LEN,
                actual: bytes.len(),
            });
        }
        let (a, e) = bytes.split_at(G1_LEN);
        Ok(Self {
            a: G1Affine::deserialize_compressed(a)?.into(),
            e: scalar_from_be_bytes(e)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::PrimeGroup;
    use ark_ff::Zero;

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9380, Appendix K.1 (`expand_message_xmd`, SHA-256,
    /// DST `QUUX-V01-CS02-with-expander-SHA256-128`, `len_in_bytes = 0x20`).
    #[test]
    fn expand_message_xmd_matches_rfc_9380() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        for (msg, expected) in [
            (
                &b""[..],
                "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
            ),
            (
                &b"abc"[..],
                "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
            ),
        ] {
            assert_eq!(expand_message_xmd(msg, dst, 0x20).unwrap(), hex(expected));
        }
        // several blocks, and the limits of the encoding
        assert_eq!(expand_message_xmd(b"abc", dst, 100).unwrap().len(), 100);
        assert!(expand_message_xmd(b"", &[0u8; 256], 32).is_err());
        assert!(expand_message_xmd(b"", dst, 256 * 32).is_err());
    }

    /// The fixture "valid multi-message signature" (`signature004`) of the ciphersuite
    /// BLS12-381-SHA-256 of draft-irtf-cfrg-bbs-signatures, as vendored by affinidi-bbs 0.3.3:
    /// its trace pins `domain` and `B`, hence `P_1`, `create_generators`, `calculate_domain`
    /// and `message_to_scalar` all at once.
    #[test]
    fn domain_and_b_match_the_draft_fixture() {
        let vk = BBSVerificationKey::from_ietf_bytes(&hex(
            "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d\
             1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649\
             ef3c4f63aebc364cd55ded0c",
        ))
        .unwrap();
        let header = hex("11223344556677889900aabbccddeeff");
        let messages = [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
            "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
            "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
            "496694774c5604ab1b2544eababcf0f53278ff50",
            "515ae153e22aae04ad16f759e07237b4",
            "d183ddc6e2665aa4e2f088af",
            "ac55fb33a75909ed",
            "96012096",
            "",
        ];
        let api_id = Interface::Core.api_id();
        let generators = create_generators(messages.len() + 1, &api_id).unwrap();
        let domain =
            calculate_domain(&vk, &generators[0], &generators[1..], &header, &api_id).unwrap();
        assert_eq!(
            scalar_to_be_bytes(&domain).to_vec(),
            hex("6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47")
        );
        let mut b = p1().unwrap() + generators[0] * domain;
        for (message, generator) in messages.iter().zip(&generators[1..]) {
            b += *generator * message_to_scalar(Interface::Core, &hex(message)).unwrap();
        }
        let mut encoded = Vec::new();
        b.into_affine().serialize_compressed(&mut encoded).unwrap();
        assert_eq!(
            encoded,
            hex(
                "84f48376f7df6af40bc329cf484cdbfd0b19d0b326fccab4e9d8f00d1dbcf48139d498b19667f203cf8a\
                 1d1f8340c522"
            )
        );
        // … and the fixture's signature is a credential of this crate on those ten messages:
        // e(A, X̃ g̃^e) = e(B, g̃)
        let cred = BBSCredential::from_ietf_bytes(&hex(
            "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19c\
             ec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8",
        ))
        .unwrap();
        let g2 = <Bls12_381 as ark_ec::pairing::Pairing>::G2::generator();
        assert!(crate::cred::pairing_product_is_identity::<Bls12_381>(&[
            (cred.a, vk.x_tilde + g2 * cred.e),
            (-b, g2),
        ]));
    }

    #[test]
    fn parameters_depend_on_interface_key_and_header() {
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x1e7f_0001);
        let key = |rng: &mut rand::rngs::StdRng| {
            BBSSigningKey::<Bls12_381> {
                x: <Fr as ark_ff::UniformRand>::rand(rng),
            }
            .verification_key()
        };
        let (vk, other) = (key(&mut rng), key(&mut rng));
        let pp = BBSPublicParams::ietf(Interface::Blind, &vk, b"header").unwrap();
        assert!(pp.is_well_formed());
        // deterministic, and a function of everything the domain covers
        assert_eq!(
            pp,
            BBSPublicParams::ietf(Interface::Blind, &vk, b"header").unwrap()
        );
        assert_ne!(
            pp.h0,
            BBSPublicParams::ietf(Interface::Blind, &other, b"header")
                .unwrap()
                .h0
        );
        assert_ne!(
            pp.h0,
            BBSPublicParams::ietf(Interface::Blind, &vk, b"another header")
                .unwrap()
                .h0
        );
        // the message generators are fixed by the interface alone
        let pseudonym = BBSPublicParams::ietf(Interface::BlindPseudonym, &vk, b"header").unwrap();
        let core = BBSPublicParams::ietf(Interface::Core, &vk, b"header").unwrap();
        assert_eq!((pp.h1, pp.h2, pp.h3), {
            let again = BBSPublicParams::ietf(Interface::Blind, &other, b"x").unwrap();
            (again.h1, again.h2, again.h3)
        });
        assert_ne!(pp.h1, pseudonym.h1);
        assert_ne!(pp.h1, core.h1);
        // the identity is not a key
        let identity = BBSVerificationKey::<Bls12_381> {
            x_tilde: Zero::zero(),
        };
        assert_eq!(
            BBSPublicParams::ietf(Interface::Core, &identity, b"header"),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn byte_bridges_round_trip_and_are_strict() {
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x1e7f_0002);
        let sk = BBSSigningKey::<Bls12_381> {
            x: <Fr as ark_ff::UniformRand>::rand(&mut rng),
        };
        let vk = sk.verification_key();
        // scalars: big-endian, canonical
        let one = scalar_to_be_bytes(&Fr::from(1u64));
        assert_eq!(one[31], 1);
        assert!(one[..31].iter().all(|b| *b == 0));
        assert_eq!(scalar_from_be_bytes(&one).unwrap(), Fr::from(1u64));
        assert!(scalar_from_be_bytes(&[0xff; 32]).is_err());
        assert!(scalar_from_be_bytes(&[0u8; 31]).is_err());
        // keys
        let sk_back = BBSSigningKey::from_ietf_bytes(&sk.to_ietf_bytes()[..]).unwrap();
        assert_eq!(sk_back.verification_key(), vk);
        assert_eq!(
            BBSVerificationKey::from_ietf_bytes(&vk.to_ietf_bytes().unwrap()).unwrap(),
            vk
        );
        assert!(BBSVerificationKey::<Bls12_381>::from_ietf_bytes(&[0u8; 95]).is_err());
        // a credential
        let cred = BBSCredential::<Bls12_381> {
            a: G1Projective::generator() * Fr::from(7u64),
            e: Fr::from(9u64),
        };
        let bytes = cred.to_ietf_bytes().unwrap();
        assert_eq!(bytes.len(), 80);
        assert_eq!(BBSCredential::from_ietf_bytes(&bytes).unwrap(), cred);
        assert!(BBSCredential::<Bls12_381>::from_ietf_bytes(&bytes[..79]).is_err());
    }
}
