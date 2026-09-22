//! The fixed-format compact encoding of attestations, issuance proofs and root requests: the
//! encoding whose sizes are those of the paper's comparison table (§5.3).
//!
//! Implementation note; the paper asks for it in one sentence: "`VerifyProof` has to (i) parse
//! `π` in a fixed format and fail closed when `T_0` is absent" (§5.5).
//!
//! | object | bytes |
//! |---|---|
//! | `att_j` | `T_j ‖ cred*_j ‖ φ_j ‖ c ‖ z_1 ‖ … ‖ z_n`, `n = 1 + POSSESSION_VARIABLES` |
//! | `π` | `att_1 ‖ … ‖ att_k ‖ C ‖ T_0 ‖ c ‖ z_1 ‖ … ‖ z_m`, `m = 1 + ISSUANCE_VARIABLES`, `k = f.threshold` |
//! | root request | `C ‖ T_0 ‖ c ‖ z_1 ‖ … ‖ z_m` |
//!
//! (`C` is absent for `Σ-EQ`, whose `WireEncoding` is `()`.) Every element is in the compressed
//! canonical encoding of arkworks and is decoded WITH validation ([`crate::serialization`]);
//! trailing bytes are rejected. **No length is ever read from the wire**: the number of responses is a
//! constant of the base, and the number of attestations is the threshold of the predicate the
//! verifier is about to check the proof for. A proof with `k − 1` or `k + 1` attestations is
//! therefore not even decodable for `f_k` (it is truncated, resp. has trailing bytes).
//!
//! Over BLS12-381 (`G_1`: 48 B, `G_2`: 96 B, `Z_p`: 32 B) this gives the table's
//! `|att| = 240 / 416 / 480` B and `|π| = 1392 / 2272 / 2512` B at `k = 5` for `Σ-PS`, `Σ-BBS`,
//! `Σ-EQ`. The DERIVED canonical encoding of the same objects is self-describing (it
//! length-prefixes the responses and the attestations) and is `8(k + 1) + 8` bytes longer for
//! a proof; tests say which of the two they measure.

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};

use super::{
    predicate::Predicate,
    types::{Attestation, IssuanceProof, RootRequest},
};
use crate::{cred::SigmaFriendlyCredentialBase, error::Error, sigma::FSProof};

/// Writes `c ‖ z` after checking that the proof has the number of responses the fixed format
/// implies (a proof with another number would not be decodable).
fn write_proof<F: ark_ff::PrimeField, W: Write>(
    proof: &FSProof<F>,
    responses: usize,
    writer: W,
) -> Result<(), Error> {
    if proof.responses.len() != responses {
        return Err(Error::LengthMismatch {
            expected: responses,
            actual: proof.responses.len(),
        });
    }
    proof.serialize_compact(writer)
}

/// [`Error::TrailingBytes`] unless the input was consumed completely.
fn finish<V>(value: V, rest: &[u8]) -> Result<V, Error> {
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(Error::TrailingBytes)
    }
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> Attestation<E, B> {
    /// The number of responses of `π_j`: one for the shared `usk`, and one per variable of the
    /// possession clauses of the base. The tag clause adds none.
    pub const RESPONSES: usize = 1 + B::POSSESSION_VARIABLES;

    /// Size in bytes of the compact encoding.
    #[must_use]
    pub fn compact_size(&self) -> usize {
        self.tag.compressed_size()
            + self.shown.compressed_size()
            + self.phi.compressed_size()
            + self.proof.compact_size()
    }

    /// Writes `T_j ‖ cred*_j ‖ φ_j ‖ c ‖ z_1 ‖ … ‖ z_n`.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] if `π_j` does not have [`Self::RESPONSES`] responses;
    /// [`Error::Serialization`] if the writer fails.
    pub fn serialize_compact<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.tag.serialize_compressed(&mut writer)?;
        self.shown.serialize_compressed(&mut writer)?;
        self.phi.serialize_compressed(&mut writer)?;
        write_proof(&self.proof, Self::RESPONSES, &mut writer)
    }

    /// Reads one attestation, with validation, and leaves the reader behind it.
    ///
    /// # Errors
    /// [`Error::Serialization`] on truncated, malformed or non-canonical input.
    pub fn deserialize_compact<R: Read>(mut reader: R) -> Result<Self, Error> {
        Ok(Self {
            tag: E::G1::deserialize_compressed(&mut reader)?,
            shown: B::ShownCredential::deserialize_compressed(&mut reader)?,
            phi: E::ScalarField::deserialize_compressed(&mut reader)?,
            proof: FSProof::deserialize_compact(&mut reader, Self::RESPONSES)?,
        })
    }

    /// The compact encoding.
    ///
    /// # Errors
    /// As [`Self::serialize_compact`].
    pub fn to_compact_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.compact_size());
        self.serialize_compact(&mut bytes)?;
        Ok(bytes)
    }

    /// Decodes the compact encoding, with validation.
    ///
    /// # Errors
    /// As [`Self::deserialize_compact`]; [`Error::TrailingBytes`] if `bytes` continues after
    /// the attestation.
    pub fn from_compact_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = bytes;
        let attestation = Self::deserialize_compact(&mut reader)?;
        finish(attestation, reader)
    }
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> IssuanceProof<E, B> {
    /// The number of responses of `π_0`: one for the shared `usk`, and one per variable of the
    /// opening clause of the base. The two tag clauses add none.
    pub const RESPONSES: usize = 1 + B::ISSUANCE_VARIABLES;

    /// Size in bytes of the compact encoding.
    #[must_use]
    pub fn compact_size(&self) -> usize {
        self.attestations
            .iter()
            .map(Attestation::compact_size)
            .sum::<usize>()
            + self.encoding.compressed_size()
            + self.t0.compressed_size()
            + self.proof.compact_size()
    }

    /// Writes `att_1 ‖ … ‖ att_k ‖ C ‖ T_0 ‖ c ‖ z_1 ‖ … ‖ z_m`. The number of attestations is
    /// not written: the decoder takes it from the predicate.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] if `π_0` does not have [`Self::RESPONSES`] responses or an
    /// attestation does not have [`Attestation::RESPONSES`]; [`Error::Serialization`] if the
    /// writer fails.
    pub fn serialize_compact<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        for attestation in &self.attestations {
            attestation.serialize_compact(&mut writer)?;
        }
        self.encoding.serialize_compressed(&mut writer)?;
        self.t0.serialize_compressed(&mut writer)?;
        write_proof(&self.proof, Self::RESPONSES, &mut writer)
    }

    /// Reads a proof for the predicate `f`, i.e. with EXACTLY `f.threshold` attestations, with
    /// validation, and leaves the reader behind it.
    ///
    /// # Errors
    /// [`Error::ZeroThreshold`] for a root predicate (there is no issuance proof for it);
    /// [`Error::Serialization`] on truncated, malformed or non-canonical input.
    pub fn deserialize_compact<R: Read>(mut reader: R, f: &Predicate) -> Result<Self, Error> {
        if f.is_root() {
            return Err(Error::ZeroThreshold);
        }
        // Not `with_capacity(f.threshold)`: the threshold may be large and the input short. Every
        // attestation consumes input, so the vector never outgrows the input.
        let mut attestations = Vec::new();
        for _ in 0..f.threshold {
            attestations.push(Attestation::deserialize_compact(&mut reader)?);
        }
        Ok(Self {
            attestations,
            encoding: B::WireEncoding::deserialize_compressed(&mut reader)?,
            t0: E::G1::deserialize_compressed(&mut reader)?,
            proof: FSProof::deserialize_compact(&mut reader, Self::RESPONSES)?,
        })
    }

    /// The compact encoding.
    ///
    /// # Errors
    /// As [`Self::serialize_compact`].
    pub fn to_compact_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.compact_size());
        self.serialize_compact(&mut bytes)?;
        Ok(bytes)
    }

    /// Decodes the compact encoding of a proof for the predicate `f`, with validation.
    ///
    /// # Errors
    /// As [`Self::deserialize_compact`]; [`Error::TrailingBytes`] if `bytes` continues after
    /// the proof (in particular for a proof with more than `f.threshold` attestations).
    pub fn from_compact_bytes(bytes: &[u8], f: &Predicate) -> Result<Self, Error> {
        let mut reader = bytes;
        let proof = Self::deserialize_compact(&mut reader, f)?;
        finish(proof, reader)
    }
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> RootRequest<E, B> {
    /// The number of responses of the proof: as for [`IssuanceProof::RESPONSES`].
    pub const RESPONSES: usize = 1 + B::ISSUANCE_VARIABLES;

    /// Size in bytes of the compact encoding.
    #[must_use]
    pub fn compact_size(&self) -> usize {
        self.encoding.compressed_size() + self.t0.compressed_size() + self.proof.compact_size()
    }

    /// Writes `C ‖ T_0 ‖ c ‖ z_1 ‖ … ‖ z_m`.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] if the proof does not have [`Self::RESPONSES`] responses;
    /// [`Error::Serialization`] if the writer fails.
    pub fn serialize_compact<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.encoding.serialize_compressed(&mut writer)?;
        self.t0.serialize_compressed(&mut writer)?;
        write_proof(&self.proof, Self::RESPONSES, &mut writer)
    }

    /// Reads one root request, with validation, and leaves the reader behind it.
    ///
    /// # Errors
    /// [`Error::Serialization`] on truncated, malformed or non-canonical input.
    pub fn deserialize_compact<R: Read>(mut reader: R) -> Result<Self, Error> {
        Ok(Self {
            encoding: B::WireEncoding::deserialize_compressed(&mut reader)?,
            t0: E::G1::deserialize_compressed(&mut reader)?,
            proof: FSProof::deserialize_compact(&mut reader, Self::RESPONSES)?,
        })
    }

    /// The compact encoding.
    ///
    /// # Errors
    /// As [`Self::serialize_compact`].
    pub fn to_compact_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.compact_size());
        self.serialize_compact(&mut bytes)?;
        Ok(bytes)
    }

    /// Decodes the compact encoding, with validation.
    ///
    /// # Errors
    /// As [`Self::deserialize_compact`]; [`Error::TrailingBytes`] if `bytes` continues after
    /// the request.
    pub fn from_compact_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = bytes;
        let request = Self::deserialize_compact(&mut reader)?;
        finish(request, reader)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{BigInteger, PrimeField};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        pcs::test_support::{
            BBS, E, G1, PS, RandomShown, SPSEQ, random_attestation, random_proof,
            random_root_request,
        },
        serialization::WireFormat,
    };

    type Fr = ark_bls12_381::Fr;

    /// The sizes of the paper's comparison table (§5.3) over BLS12-381, in THIS encoding:
    /// `|att|`, `|π|` at `k = 5`, and the root request `(C, T_0, π_0)`.
    #[test]
    fn compact_sizes_over_bls12_381() {
        fn sizes<B: RandomShown>(seed: u64) -> (usize, usize, usize) {
            let mut rng = StdRng::seed_from_u64(seed);
            let att = random_attestation::<B>(&mut rng);
            let proof = random_proof::<B>(5, &mut rng);
            let request = random_root_request::<B>(&mut rng);
            let sizes = (
                att.to_compact_bytes().unwrap().len(),
                proof.to_compact_bytes().unwrap().len(),
                request.to_compact_bytes().unwrap().len(),
            );
            assert_eq!(
                sizes,
                (
                    att.compact_size(),
                    proof.compact_size(),
                    request.compact_size()
                )
            );
            // the derived encoding is self-describing: 8 bytes per response vector and 8 for the
            // vector of attestations
            assert_eq!(att.to_bytes().unwrap().len(), sizes.0 + 8);
            assert_eq!(proof.to_bytes().unwrap().len(), sizes.1 + 8 * 6 + 8);
            assert_eq!(request.to_bytes().unwrap().len(), sizes.2 + 8);
            sizes
        }
        assert_eq!(sizes::<PS>(0xc0de_c001), (240, 1392, 192));
        assert_eq!(sizes::<BBS>(0xc0de_c002), (416, 2272, 192));
        assert_eq!(sizes::<SPSEQ>(0xc0de_c003), (480, 2512, 112));
        assert_eq!(
            (
                Attestation::<E, PS>::RESPONSES,
                Attestation::<E, BBS>::RESPONSES,
                Attestation::<E, SPSEQ>::RESPONSES
            ),
            (1, 5, 1)
        );
        assert_eq!(
            (
                IssuanceProof::<E, PS>::RESPONSES,
                IssuanceProof::<E, BBS>::RESPONSES,
                IssuanceProof::<E, SPSEQ>::RESPONSES,
                RootRequest::<E, SPSEQ>::RESPONSES
            ),
            (2, 2, 1, 1)
        );
    }

    fn is_serialization_error<V>(result: Result<V, Error>) -> bool {
        matches!(result, Err(Error::Serialization(_)))
    }

    /// Round trips, and the strictness of the decoder: truncation, trailing bytes, and a number
    /// of attestations that is taken from the predicate and from nowhere else.
    #[test]
    fn round_trips_and_strict_decoding() {
        fn check<B: RandomShown>(seed: u64) {
            let mut rng = StdRng::seed_from_u64(seed);
            let f = |k: u32| Predicate::new(k, b"f".to_vec());

            let att = random_attestation::<B>(&mut rng);
            let bytes = att.to_compact_bytes().unwrap();
            assert_eq!(
                Attestation::<E, B>::from_compact_bytes(&bytes).unwrap(),
                att
            );
            for cut in [0, 1, 47, 48, bytes.len() - 32, bytes.len() - 1] {
                assert!(is_serialization_error(
                    Attestation::<E, B>::from_compact_bytes(&bytes[..cut])
                ));
            }
            let mut longer = bytes.clone();
            longer.push(0);
            assert_eq!(
                Attestation::<E, B>::from_compact_bytes(&longer),
                Err(Error::TrailingBytes)
            );
            // the streaming decoder leaves the reader right behind the attestation
            let mut reader = &longer[..];
            assert_eq!(
                Attestation::<E, B>::deserialize_compact(&mut reader).unwrap(),
                att
            );
            assert_eq!(reader, &[0]);

            for k in [1usize, 2, 5] {
                let proof = random_proof::<B>(k, &mut rng);
                let bytes = proof.to_compact_bytes().unwrap();
                let k32 = u32::try_from(k).unwrap();
                assert_eq!(
                    IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f(k32)).unwrap(),
                    proof
                );
                // the label of the predicate plays no role for the FORMAT
                assert!(
                    IssuanceProof::<E, B>::from_compact_bytes(
                        &bytes,
                        &Predicate::new(k32, b"g".to_vec())
                    )
                    .is_ok()
                );
                // k + 1: truncated. k − 1: trailing bytes, or garbage where C was expected.
                assert!(is_serialization_error(
                    IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f(k32 + 1))
                ));
                if k > 1 {
                    assert!(
                        IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f(k32 - 1)).is_err()
                    );
                }
                assert_eq!(
                    IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f(0)),
                    Err(Error::ZeroThreshold)
                );
                assert!(is_serialization_error(
                    IssuanceProof::<E, B>::from_compact_bytes(&bytes[..bytes.len() - 1], &f(k32))
                ));
                let mut longer = bytes.clone();
                longer.push(0);
                assert_eq!(
                    IssuanceProof::<E, B>::from_compact_bytes(&longer, &f(k32)),
                    Err(Error::TrailingBytes)
                );
            }

            let request = random_root_request::<B>(&mut rng);
            let bytes = request.to_compact_bytes().unwrap();
            assert_eq!(
                RootRequest::<E, B>::from_compact_bytes(&bytes).unwrap(),
                request
            );
            assert!(is_serialization_error(
                RootRequest::<E, B>::from_compact_bytes(&bytes[..bytes.len() - 1])
            ));
            let mut longer = bytes;
            longer.push(7);
            assert_eq!(
                RootRequest::<E, B>::from_compact_bytes(&longer),
                Err(Error::TrailingBytes)
            );
            // a root request is not decodable as a proof: a proof has at least one attestation
            assert!(
                IssuanceProof::<E, B>::from_compact_bytes(&longer[..longer.len() - 1], &f(1))
                    .is_err()
            );
        }
        check::<PS>(0xc0de_c011);
        check::<BBS>(0xc0de_c012);
        check::<SPSEQ>(0xc0de_c013);
    }

    /// An object whose proof does not have the number of responses of the fixed format has no
    /// compact encoding (it would decode as something else, or not at all).
    #[test]
    fn a_wrong_number_of_responses_is_not_encodable() {
        let mut rng = StdRng::seed_from_u64(0xc0de_c021);
        for delta in [-1isize, 1] {
            let resize = |responses: &mut Vec<Fr>| {
                let len = responses.len().checked_add_signed(delta).unwrap();
                responses.resize(len, Fr::from(1u64));
            };
            let mut att = random_attestation::<BBS>(&mut rng);
            resize(&mut att.proof.responses);
            let mismatch = |expected: usize| Error::LengthMismatch {
                expected,
                actual: expected.checked_add_signed(delta).unwrap(),
            };
            assert_eq!(att.to_compact_bytes(), Err(mismatch(5)));

            let mut proof = random_proof::<PS>(2, &mut rng);
            resize(&mut proof.proof.responses);
            assert_eq!(proof.to_compact_bytes(), Err(mismatch(2)));
            let mut proof = random_proof::<PS>(2, &mut rng);
            resize(&mut proof.attestations[1].proof.responses);
            assert_eq!(proof.to_compact_bytes(), Err(mismatch(1)));

            let mut request = random_root_request::<SPSEQ>(&mut rng);
            resize(&mut request.proof.responses);
            assert_eq!(request.to_compact_bytes(), Err(mismatch(1)));
        }
    }

    /// Decoding validates: non-canonical scalars and invalid points are rejected wherever they
    /// occur. The identity point is a VALID encoding; rejecting it is the verifiers' job.
    #[test]
    fn decoding_validates_every_element() {
        let mut rng = StdRng::seed_from_u64(0xc0de_c031);
        let att = random_attestation::<PS>(&mut rng);
        let bytes = att.to_compact_bytes().unwrap();
        // layout: T (48) ‖ σ'_1 (48) ‖ σ'_2 (48) ‖ φ (32) ‖ c (32) ‖ z (32)
        let modulus = Fr::MODULUS.to_bytes_le();
        for scalar_at in [144, 176, 208] {
            let mut bad = bytes.clone();
            bad[scalar_at..scalar_at + 32].copy_from_slice(&modulus);
            assert!(is_serialization_error(
                Attestation::<E, PS>::from_compact_bytes(&bad)
            ));
        }
        for point_at in [0, 48, 96] {
            // all-zero bytes are not a compressed BLS12-381 point
            let mut bad = bytes.clone();
            bad[point_at..point_at + 48].fill(0);
            assert!(is_serialization_error(
                Attestation::<E, PS>::from_compact_bytes(&bad)
            ));
            // the canonical encoding of the identity is, and it round-trips
            let identity = crate::serialization::to_bytes(&<G1 as ark_ff::Zero>::zero()).unwrap();
            let mut degenerate = bytes.clone();
            degenerate[point_at..point_at + 48].copy_from_slice(&identity);
            let decoded = Attestation::<E, PS>::from_compact_bytes(&degenerate).unwrap();
            assert_eq!(decoded.to_compact_bytes().unwrap(), degenerate);
        }
    }

    /// The threshold is attacker-independent, but it may be large: decoding fails on the first
    /// missing byte and does not allocate for `f.threshold` attestations up front.
    #[test]
    fn a_huge_threshold_fails_fast() {
        let mut rng = StdRng::seed_from_u64(0xc0de_c041);
        let bytes = random_proof::<PS>(3, &mut rng).to_compact_bytes().unwrap();
        let huge = Predicate::new(u32::MAX, b"f".to_vec());
        assert!(is_serialization_error(
            IssuanceProof::<E, PS>::from_compact_bytes(&bytes, &huge)
        ));
        assert!(is_serialization_error(
            IssuanceProof::<E, SPSEQ>::from_compact_bytes(&[], &huge)
        ));
    }
}
