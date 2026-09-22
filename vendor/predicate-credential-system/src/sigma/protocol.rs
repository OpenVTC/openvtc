//! The interactive generalized Schnorr protocol (Defs. "Sigma protocol" and "Schnorr sigma
//! protocol", §2.3) for any [`LinearRelation`] `φ(x) = Y`.
//!
//! | paper | here |
//! |---|---|
//! | `(a, st) ← P_1(x, w)`: `A = P^r` | [`commit`]: `A = φ(r)` for a uniform mask vector `r` |
//! | `c ← C` | any scalar; the challenge space is `C = Z_p` |
//! | `z ← P_2(x, w, st, c)`: `z = r + c·x` | [`respond`] (consumes the state) |
//! | `V(x, a, c, z)`: `P^z = A·T^c` | [`verify`]: `φ(z) − c·Y = A` |
//! | HVZK simulator: `A = P^z T^{-c}` | [`simulate`] |
//! | special-soundness extractor: `x = (z − z')/(c − c')` | [`extract`] |
//!
//! The protocol is explicit (rather than hidden inside the Fiat-Shamir transform) so that the
//! test harness can exercise completeness, the simulator and the extractor on exactly the
//! relations the credential system proves. "Rewinding" a prover means running [`commit`] twice
//! with identically seeded RNGs, which is why [`ProverState`] needs no `Clone`.

use core::fmt;
use core::ops::Deref;

use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::relation::LinearRelation;
use crate::error::Error;

/// The prover's secret state `st` between its two moves: the mask vector `r`.
///
/// Wiped on drop, not `Clone`, and consumed by [`respond`]: answering two challenges with the
/// same masks reveals the witness (that is exactly what [`extract`] does).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProverState<F: PrimeField> {
    masks: Vec<F>,
}

impl<F: PrimeField> fmt::Debug for ProverState<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProverState(<redacted>)")
    }
}

/// A witness vector `x ∈ F^n` that is wiped on drop.
///
/// Dereferences to `[F]`, which is what the provers take. Build it in the variable order of the
/// relation: first the shared `usk`, then the values of the variables each clause allocated.
///
/// Implementation note (secret hygiene): a plain `Vec` that outgrows its capacity moves to a new
/// allocation and frees the old one *without* wiping it, and `ZeroizeOnDrop` only ever sees the
/// final buffer. This container therefore never lets the `Vec` reallocate: when it has to grow,
/// it copies the scalars into a fresh buffer and wipes the old one before releasing it. Sizing
/// the witness up front ([`Self::with_capacity`] with [`LinearRelation::num_scalars`]) avoids
/// even that copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Witness<F: PrimeField> {
    scalars: Vec<F>,
}

impl<F: PrimeField> Witness<F> {
    /// The empty witness.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scalars: Vec::new(),
        }
    }

    /// The empty witness with room for `capacity` scalars, typically
    /// [`LinearRelation::num_scalars`] of the relation it is built for: filling it up to that
    /// size never moves the buffer.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            scalars: Vec::with_capacity(capacity),
        }
    }

    /// Appends the value of the next variable.
    pub fn push(&mut self, scalar: F) {
        self.make_room(1);
        debug_assert!(self.scalars.len() < self.scalars.capacity());
        self.scalars.push(scalar);
    }

    /// Appends the values of the next variables, in order.
    pub fn extend_from_slice(&mut self, scalars: &[F]) {
        self.make_room(scalars.len());
        debug_assert!(self.scalars.len() + scalars.len() <= self.scalars.capacity());
        self.scalars.extend_from_slice(scalars);
    }

    /// Ensures room for `additional` more scalars without ever letting the `Vec` reallocate.
    fn make_room(&mut self, additional: usize) {
        let needed = self.scalars.len().saturating_add(additional);
        if needed > self.scalars.capacity() {
            // amortized doubling, like `Vec`
            let capacity = needed.max(self.scalars.capacity().saturating_mul(2));
            let mut old = self.migrate(capacity);
            // clears the emptied buffer and wipes its spare capacity as well
            old.zeroize();
        }
    }

    /// Moves the scalars into a fresh buffer of capacity `capacity ≥ len` and returns the OLD
    /// buffer with every scalar overwritten by zero (still at its old length, so that the wipe
    /// is observable).
    fn migrate(&mut self, capacity: usize) -> Vec<F> {
        let mut fresh = Vec::with_capacity(capacity.max(self.scalars.len()));
        // within capacity: this does not reallocate `fresh`
        fresh.extend_from_slice(&self.scalars);
        let mut old = core::mem::replace(&mut self.scalars, fresh);
        old.iter_mut().for_each(Zeroize::zeroize);
        old
    }
}

impl<F: PrimeField> Default for Witness<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> From<Vec<F>> for Witness<F> {
    fn from(scalars: Vec<F>) -> Self {
        Self { scalars }
    }
}

impl<F: PrimeField> FromIterator<F> for Witness<F> {
    /// Collects through [`Witness::push`], so an iterator with an inexact size hint cannot
    /// leave an unwiped buffer behind either.
    fn from_iter<I: IntoIterator<Item = F>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut witness = Self::with_capacity(iter.size_hint().0);
        for scalar in iter {
            witness.push(scalar);
        }
        witness
    }
}

impl<F: PrimeField> Deref for Witness<F> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.scalars
    }
}

impl<F: PrimeField> fmt::Debug for Witness<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Witness(<redacted; {} scalars>)", self.scalars.len())
    }
}

/// First prover move `P_1`: samples a uniform mask `r_j` per witness coordinate and returns the
/// commitment `A = φ(r)` with the secret state. A coordinate shared by several equations has
/// ONE mask (§2.3, generalized Schnorr).
///
/// The witness is not needed before [`respond`]; it is not checked against the relation here
/// (the Fiat-Shamir prover does that).
///
/// # Errors
/// Propagates an evaluation error of the relation (none for the relations of this crate).
pub fn commit<R, Rng>(rel: &R, rng: &mut Rng) -> Result<(R::Image, ProverState<R::Scalar>), Error>
where
    R: LinearRelation,
    Rng: RngCore + CryptoRng + ?Sized,
{
    let state = ProverState {
        masks: (0..rel.num_scalars())
            .map(|_| R::Scalar::rand(rng))
            .collect(),
    };
    let commitment = rel.evaluate(&state.masks)?;
    Ok((commitment, state))
}

/// Second prover move `P_2`: the responses `z_j = r_j + c·x_j`. Consumes (and thereby wipes) the
/// state, so a mask vector answers exactly one challenge.
///
/// # Errors
/// [`Error::LengthMismatch`] if the witness does not have one value per mask.
// By value on purpose: taking the state away from the caller is what enforces single use.
#[allow(clippy::needless_pass_by_value)]
pub fn respond<F: PrimeField>(
    state: ProverState<F>,
    witness: &[F],
    c: &F,
) -> Result<Vec<F>, Error> {
    if witness.len() != state.masks.len() {
        return Err(Error::LengthMismatch {
            expected: state.masks.len(),
            actual: witness.len(),
        });
    }
    Ok(state
        .masks
        .iter()
        .zip(witness)
        .map(|(r, x)| *r + *c * *x)
        .collect())
}

/// The decision predicate `V(x, a, c, z)`: accepts iff `φ(z) − c·Y = A`.
///
/// Never panics; malformed transcripts (wrong number of responses, wrong commitment shape) are
/// rejected. The witness-independent validity checks of a statement (`ValidTag`, the public
/// part of `VerifyPossess`) are not part of the linear relation and must be run by the caller.
#[must_use]
pub fn verify<R: LinearRelation>(rel: &R, a: &R::Image, c: &R::Scalar, z: &[R::Scalar]) -> bool {
    rel.recompute_commitment(c, z)
        .is_ok_and(|recomputed| recomputed == *a)
}

/// The special honest-verifier zero-knowledge simulator: for the given challenge `c` it samples
/// uniform responses `z` and sets `A = φ(z) − c·Y` (Def. "Schnorr sigma protocol", HVZK:
/// `A = P^z T^{-c}`). The transcript `(A, c, z)` always verifies. For a TRUE statement it is
/// distributed exactly like an honest transcript with challenge `c`: in both, `z` is uniform
/// and `A` is determined by `(c, z)`. Needs no witness, and therefore also "works" for false
/// statements.
///
/// # Errors
/// Propagates an evaluation error of the relation (none for the relations of this crate).
pub fn simulate<R, Rng>(
    rel: &R,
    c: &R::Scalar,
    rng: &mut Rng,
) -> Result<(R::Image, Vec<R::Scalar>), Error>
where
    R: LinearRelation,
    Rng: RngCore + CryptoRng + ?Sized,
{
    let z: Vec<R::Scalar> = (0..rel.num_scalars())
        .map(|_| R::Scalar::rand(rng))
        .collect();
    let a = rel.recompute_commitment(c, &z)?;
    Ok((a, z))
}

/// The special-soundness extractor: from two accepting transcripts `(A, c_1, z_1)`,
/// `(A, c_2, z_2)` with `c_1 ≠ c_2` it returns the witness `x_j = (z_1j − z_2j)/(c_1 − c_2)`.
///
/// A coordinate shared by several equations has one response per transcript, so ONE value is
/// extracted for it and it satisfies every equation it occurs in (witness-preserving AND
/// composition).
///
/// Returns `None` if the challenges are equal, if a transcript does not verify (this covers
/// wrong lengths), or if the extracted vector does not satisfy the relation. For linear
/// relations the last case cannot occur (`φ(z_1 − z_2) = (c_1 − c_2)·Y` by linearity); the check
/// is kept as a guard.
#[must_use]
pub fn extract<R: LinearRelation>(
    rel: &R,
    a: &R::Image,
    (c1, z1): (&R::Scalar, &[R::Scalar]),
    (c2, z2): (&R::Scalar, &[R::Scalar]),
) -> Option<Vec<R::Scalar>> {
    // `inverse` is `None` exactly for `c1 == c2`; field division by zero would panic.
    let inv = (*c1 - *c2).inverse()?;
    if !verify(rel, a, c1, z1) || !verify(rel, a, c2, z2) {
        return None;
    }
    let witness: Vec<R::Scalar> = z1.iter().zip(z2).map(|(u, v)| (*u - *v) * inv).collect();
    rel.is_satisfied_by(&witness).then_some(witness)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::{UniformRand, Zero};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::sigma::relation::{GroupRelation, LinearEquation};

    fn schnorr(x: Fr) -> GroupRelation<G1Projective> {
        let g = G1Projective::generator();
        let mut rel = GroupRelation::new();
        let var = rel.alloc_scalar();
        rel.add_equation(LinearEquation::dlog(var, g, g * x))
            .unwrap();
        rel
    }

    #[test]
    fn schnorr_round_trip_matches_the_textbook_equation() {
        let mut rng = StdRng::seed_from_u64(1);
        let x = Fr::rand(&mut rng);
        let rel = schnorr(x);
        let (a, st) = commit(&rel, &mut rng).unwrap();
        let c = Fr::rand(&mut rng);
        let z = respond(st, &[x], &c).unwrap();
        assert!(verify(&rel, &a, &c, &z));
        // P^z = A · T^c
        let g = G1Projective::generator();
        assert_eq!(g * z[0], a[0] + (g * x) * c);
    }

    #[test]
    fn respond_checks_the_witness_length() {
        let mut rng = StdRng::seed_from_u64(2);
        let rel = schnorr(Fr::from(3u64));
        let (_, st) = commit(&rel, &mut rng).unwrap();
        assert_eq!(
            respond(st, &[], &Fr::from(1u64)),
            Err(Error::LengthMismatch {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn secrets_are_redacted_and_wiped() {
        let mut rng = StdRng::seed_from_u64(3);
        let rel = schnorr(Fr::from(3u64));
        let (_, mut st) = commit(&rel, &mut rng).unwrap();
        assert_eq!(format!("{st:?}"), "ProverState(<redacted>)");
        assert!(!st.masks[0].is_zero());
        st.zeroize();
        assert!(st.masks.is_empty());

        let mut w: Witness<Fr> = vec![Fr::from(5u64)].into();
        w.push(Fr::from(6u64));
        w.extend_from_slice(&[Fr::from(7u64)]);
        assert_eq!(w.len(), 3);
        assert_eq!(w[1], Fr::from(6u64));
        assert_eq!(format!("{w:?}"), "Witness(<redacted; 3 scalars>)");
        w.zeroize();
        assert!(w.is_empty());

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ProverState<Fr>>();
        assert_zeroize_on_drop::<Witness<Fr>>();
    }

    /// A witness sized from the relation never moves its buffer (the `Σ-BBS` possession witness
    /// `(usk, e, ρ, r_1, r_3)` has 5 scalars, more than the initial capacity 4 of a `Vec` of
    /// 32-byte scalars).
    #[test]
    fn presized_witness_never_moves() {
        let values: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        let mut w = Witness::<Fr>::with_capacity(5);
        let buffer = w.as_ptr();
        w.push(values[0]);
        w.extend_from_slice(&values[1..]);
        assert_eq!(w.as_ptr(), buffer);
        assert_eq!(&*w, &values[..]);

        // an exact-size iterator is collected into one allocation as well
        let w: Witness<Fr> = values.iter().copied().collect();
        assert_eq!((w.len(), w.scalars.capacity()), (5, 5));
    }

    /// Growing beyond the capacity moves the scalars, and the buffer left behind is wiped
    /// before it is released. (A `Vec` growing on its own frees the old buffer as it is.)
    #[test]
    fn growing_witness_wipes_the_buffer_it_leaves() {
        let values: Vec<Fr> = (1..=9u64).map(Fr::from).collect();

        // the mechanism: `migrate` hands back the OLD buffer, zeroed at its old length
        let mut w = Witness::<Fr>::with_capacity(2);
        w.extend_from_slice(&values[..2]);
        let before = w.as_ptr();
        let old = w.migrate(8);
        assert_eq!(old.as_ptr(), before);
        assert_eq!(old, vec![Fr::zero(); 2]);
        assert_ne!(w.as_ptr(), before);
        assert_eq!(&*w, &values[..2]);
        assert!(w.scalars.capacity() >= 8);

        // `push` and `extend_from_slice` go through it and keep contents and order. That the
        // growth is ours shows in the capacity: a `Vec` of 32-byte scalars growing on its own
        // jumps from 0 to 4.
        let mut w = Witness::<Fr>::new();
        w.push(values[0]);
        assert!(w.scalars.capacity() < 4);
        for chunk in values[1..].chunks(3) {
            w.extend_from_slice(chunk);
        }
        w.push(Fr::from(10u64));
        let expected: Vec<Fr> = (1..=10u64).map(Fr::from).collect();
        assert_eq!(&*w, &expected[..]);

        // an iterator with an inexact size hint is collected through `push`
        let w: Witness<Fr> = expected
            .iter()
            .copied()
            .filter(|x| *x != Fr::from(4u64))
            .collect();
        assert_eq!(w.len(), 9);
        assert_eq!(w[3], Fr::from(5u64));
    }
}
