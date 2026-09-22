//! The Fiat-Shamir transform of the generalized Schnorr protocol (§2.3, last paragraph; §5.1,
//! `zkPoK_ctx{(X, W) ∈ R}`).
//!
//! The paper replaces the verifier's challenge by `c = H_1(ctx, A)`, "where `ctx` contains the
//! public statement and the protocol context", and notes that "the verifier reconstructs the
//! commitments and hashes the complete public statement". Accordingly:
//!
//! * Proofs are **compact**: [`FSProof`] is `(c, z)`. The verifier recomputes
//!   `A' = φ(z) − c·Y` and accepts iff `H_1(ctx, statement, A') = c`.
//! * The challenge absorbs `ctx` **and** the full statement of the relation (every base and
//!   every target, via [`LinearRelation::absorb_statement`]) **and** the commitment. This is the
//!   *strong* Fiat-Shamir transform in the terminology of Bernhard, Pereira and Warinschi ("How
//!   not to prove yourself", ASIACRYPT 2012). Hashing the statement inside this module, rather
//!   than trusting each caller to put it into `ctx`, defeats the *weak* Fiat-Shamir attack in
//!   which a target (a tag) or a base (a shown credential) is chosen after the challenge; the
//!   test-suite mounts that attack. (Implementation note: the attack broke earlier reference
//!   code that hashed a thin context; the paper's `ctx_j`, `ctx_0` do contain these values.)
//! * `ctx` must be rebuilt by the verifier from the public statement and never be taken from
//!   the prover.
//! * `ctx` is also the ONLY deployment-specific input of `H_1`: this module does not know the
//!   public parameters. A caller that wants its proofs bound to a deployment puts (a digest of)
//!   `pp` into `ctx`, as `ctx_j` and `ctx_0` of the construction box do. Statements whose bases
//!   are deployment independent (`id = g_1^usk`) replay across deployments otherwise.
//!
//! Security of the transform is in the random-oracle model for `H_1`. Knowledge extraction from
//! a Fiat-Shamir proof is by rewinding; the paper's straight-line alternatives are out of scope
//! of this crate.
//!
//! # In formulas
//!
//! For the relation $`Y_i = \prod_j G_{ij}^{\,x_j}`$ of [`crate::sigma`] with commitment $`A = (A_i)_i`$:
//!
//! ```math
//! c = H_1(\mathsf{ctx},\ \mathsf{statement},\ A), \qquad z_j = r_j + c\, x_j, \qquad \pi = (c, z)
//! ```
//!
//! ```math
//! \mathsf{Verify}_{\mathsf{FS}}(\mathsf{ctx}, \pi) = \Bigl[\, H_1\Bigl(\mathsf{ctx},\ \mathsf{statement},\ \bigl(\textstyle\prod_{j} G_{ij}^{\,z_j} \cdot Y_i^{-c}\bigr)_i\Bigr) = c \,\Bigr]
//! ```

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use ark_std::rand::{CryptoRng, RngCore};

use super::{
    protocol::{commit, respond},
    relation::LinearRelation,
};
use crate::{error::Error, hash::h1_transcript};

/// A compact non-interactive proof `(c, z)`: the challenge and one response per witness
/// coordinate. No group element is transmitted.
///
/// The derived canonical encoding is self-describing (`c ‖ len ‖ z`). Protocol objects with a
/// fixed format can use [`Self::serialize_compact`] / [`Self::deserialize_compact`], which omit
/// the length because the statement determines it.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FSProof<F: PrimeField> {
    /// The challenge `c = H_1(ctx, statement, A)`.
    pub challenge: F,
    /// The responses `z_j = r_j + c·x_j`, in variable order.
    pub responses: Vec<F>,
}

impl<F: PrimeField> FSProof<F> {
    /// Size in bytes of the compact fixed-format encoding: `(1 + #responses)` scalars.
    #[must_use]
    pub fn compact_size(&self) -> usize {
        self.challenge.compressed_size() * (1 + self.responses.len())
    }

    /// Writes `c ‖ z_1 ‖ … ‖ z_n` as canonical scalars, without a length prefix.
    ///
    /// # Errors
    /// [`Error::Serialization`] if the writer fails.
    pub fn serialize_compact<W: Write>(&self, mut writer: W) -> Result<(), Error> {
        self.challenge.serialize_compressed(&mut writer)?;
        for response in &self.responses {
            response.serialize_compressed(&mut writer)?;
        }
        Ok(())
    }

    /// Reads `c ‖ z_1 ‖ … ‖ z_n` for the number of responses `n` fixed by the statement
    /// (`n = rel.num_scalars()`; never a number taken from the wire). Scalars must be canonical.
    ///
    /// # Errors
    /// [`Error::Serialization`] on truncated input or a non-canonical scalar.
    pub fn deserialize_compact<R: Read>(
        mut reader: R,
        num_responses: usize,
    ) -> Result<Self, Error> {
        let challenge = F::deserialize_compressed(&mut reader)?;
        let responses = (0..num_responses)
            .map(|_| F::deserialize_compressed(&mut reader))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            challenge,
            responses,
        })
    }
}

/// The Fiat-Shamir challenge `c = H_1(ctx ‖ statement(rel) ‖ A)` for the commitment `A`.
///
/// A public function of public data. It is exposed so that the test harness can play a cheating
/// prover who picks its commitment first (the weak Fiat-Shamir attack must fail against it).
///
/// # Errors
/// [`Error::Serialization`] if an element of the statement or the commitment cannot be
/// serialized.
pub fn challenge<R: LinearRelation>(
    rel: &R,
    ctx: &[u8],
    commitment: &R::Image,
) -> Result<R::Scalar, Error> {
    let mut transcript = h1_transcript(ctx);
    rel.absorb_statement(&mut transcript)?;
    transcript.append_serializable(b"commitment", commitment)?;
    Ok(transcript.challenge_scalar())
}

/// `π ← zkPoK_ctx{(rel, witness) ∈ R}`: commits, derives `c = H_1(ctx, statement, A)` and
/// responds.
///
/// # Errors
/// [`Error::WitnessDoesNotSatisfyRelation`] if `witness` does not satisfy `rel` (including a
/// wrong length): the honest prover is only defined on `(x, w) ∈ R`, and a proof for a false
/// statement would not verify anyway.
pub fn prove<R, Rng>(
    rel: &R,
    witness: &[R::Scalar],
    ctx: &[u8],
    rng: &mut Rng,
) -> Result<FSProof<R::Scalar>, Error>
where
    R: LinearRelation,
    Rng: RngCore + CryptoRng + ?Sized,
{
    if !rel.is_satisfied_by(witness) {
        return Err(Error::WitnessDoesNotSatisfyRelation);
    }
    let (commitment, state) = commit(rel, rng)?;
    let c = challenge(rel, ctx, &commitment)?;
    let responses = respond(state, witness, &c)?;
    Ok(FSProof {
        challenge: c,
        responses,
    })
}

/// `Verify_FS(ctx, π)` for the statement `rel`: recomputes `A' = φ(z) − c·Y` and accepts iff
/// `H_1(ctx, statement, A') = c`.
///
/// Returns `false`, without panicking, on any malformed proof, in particular when the number of
/// responses differs from the number of witness coordinates. The witness-independent validity
/// checks of the statement (`ValidTag`, the public part of `VerifyPossess`) are the caller's
/// job, as is rebuilding `ctx` from public data.
#[must_use]
pub fn verify<R: LinearRelation>(rel: &R, ctx: &[u8], proof: &FSProof<R::Scalar>) -> bool {
    if proof.responses.len() != rel.num_scalars() {
        return false;
    }
    let Ok(commitment) = rel.recompute_commitment(&proof.challenge, &proof.responses) else {
        return false;
    };
    challenge(rel, ctx, &commitment).is_ok_and(|c| c == proof.challenge)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        serialization::WireFormat,
        sigma::relation::{GroupRelation, LinearEquation},
    };

    fn statement(rng: &mut StdRng) -> (GroupRelation<G1Projective>, Vec<Fr>) {
        let g = G1Projective::generator();
        let h = g * Fr::rand(rng);
        let (x, y) = (Fr::rand(rng), Fr::rand(rng));
        let mut rel = GroupRelation::new();
        let (vx, vy) = (rel.alloc_scalar(), rel.alloc_scalar());
        rel.add_equation(LinearEquation::new(vec![(vx, g), (vy, h)], g * x + h * y))
            .unwrap();
        (rel, vec![x, y])
    }

    #[test]
    fn prove_verify_and_both_encodings() {
        let mut rng = StdRng::seed_from_u64(11);
        let (rel, w) = statement(&mut rng);
        let proof = prove(&rel, &w, b"ctx", &mut rng).unwrap();
        assert!(verify(&rel, b"ctx", &proof));
        assert!(!verify(&rel, b"ctx2", &proof));

        // self-describing canonical encoding: c ‖ len ‖ z
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(bytes.len(), 32 + 8 + 2 * 32);
        assert_eq!(FSProof::<Fr>::from_bytes(&bytes).unwrap(), proof);

        // compact fixed-format encoding: c ‖ z, length taken from the statement
        let mut compact = Vec::new();
        proof.serialize_compact(&mut compact).unwrap();
        assert_eq!(compact.len(), proof.compact_size());
        assert_eq!(compact.len(), 3 * 32);
        let mut reader = &compact[..];
        let back = FSProof::<Fr>::deserialize_compact(&mut reader, 2).unwrap();
        assert!(reader.is_empty());
        assert_eq!(back, proof);
        assert!(FSProof::<Fr>::deserialize_compact(&compact[..], 3).is_err());
        // a non-canonical scalar (all ones) is rejected
        compact[..32].fill(0xff);
        assert!(FSProof::<Fr>::deserialize_compact(&compact[..], 2).is_err());
    }
}
