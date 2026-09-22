//! Statements of generalized Schnorr proofs: linear relations over prime-order groups.
//!
//! The paper (§2.3, "Generalized Schnorr protocols") proves conjunctions of discrete-logarithm
//! representation statements `T_i = ∏_j B_ij^{x_j}`. We use the equivalent "preimage of a group
//! homomorphism" view: a statement is a linear map `φ : F^n → H` into a product `H` of
//! prime-order groups with common scalar field `F`, together with a target `Y ∈ H`; a witness is
//! `x ∈ F^n` with `φ(x) = Y`. In additive notation equation `i` reads
//! `target_i = Σ_j x[var_ij] · base_ij`.
//!
//! A witness coordinate is a [`ScalarVar`]. A coordinate that occurs in several equations is
//! *one* variable, so it gets one mask and one response: the witness-preserving AND composition
//! of Def. "Sigma protocol" holds by construction.

use core::fmt::Debug;

use ark_ec::{
    CurveGroup, PrimeGroup,
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{error::Error, hash::Transcript};

/// Handle to a witness coordinate `x_j` of a relation (its index `j`).
///
/// Handles are created by `alloc_scalar` of a relation and are only meaningful for the relation
/// that allocated them (or one with at least as many variables).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalarVar(usize);

impl ScalarVar {
    /// The index of the coordinate in witness and response vectors.
    #[must_use]
    pub fn index(self) -> usize {
        self.0
    }
}

/// One linear representation statement `target = Σ_i x[var_i] · base_i` in the group `G`
/// (multiplicatively: `T = ∏_i B_i^{x_i}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearEquation<G> {
    /// The pairs `(var_i, base_i)`. A variable may occur several times.
    pub terms: Vec<(ScalarVar, G)>,
    /// The public target `T`.
    pub target: G,
}

impl<G: PrimeGroup> LinearEquation<G> {
    /// The equation `target = Σ_i x[var_i] · base_i`.
    #[must_use]
    pub fn new(terms: Vec<(ScalarVar, G)>, target: G) -> Self {
        Self { terms, target }
    }

    /// The Schnorr statement `target = x[var] · base` of Def. "Schnorr sigma protocol"
    /// (`T = P^x`).
    #[must_use]
    pub fn dlog(var: ScalarVar, base: G, target: G) -> Self {
        Self::new(vec![(var, base)], target)
    }

    fn check_vars(&self, allocated: usize) -> Result<(), Error> {
        check_vars(self.terms.iter().map(|(var, _)| *var), allocated)
    }

    /// `Σ_i scalars[var_i] · base_i`.
    fn evaluate(&self, scalars: &[G::ScalarField]) -> Result<G, Error> {
        let mut acc = G::zero();
        for (var, base) in &self.terms {
            acc += *base * *lookup(scalars, *var)?;
        }
        Ok(acc)
    }

    fn absorb(&self, t: &mut Transcript) -> Result<(), Error> {
        t.append_u64(b"num-terms", self.terms.len() as u64);
        for (var, base) in &self.terms {
            t.append_u64(b"var", var.0 as u64);
            t.append_serializable(b"base", base)?;
        }
        t.append_serializable(b"target", &self.target)
    }
}

/// A formal sum of pairings `Σ_k e(P_k, Q_k)` (multiplicatively `∏_k e(P_k, Q_k)`), kept
/// unevaluated.
pub type PairingProduct<E> = Vec<(<E as Pairing>::G1, <E as Pairing>::G2)>;

/// One linear representation statement in `G_T`, in **lazy pairing-product form**:
/// `Σ e(target) = Σ_i x[var_i] · Σ e(product_i)`.
///
/// Bases and target are given by their pairing preimages, so neither prover nor verifier ever
/// exponentiates in `G_T`: a scalar is multiplied into the `G_1` side of a product and the whole
/// equation costs a single multi-pairing (one final exponentiation). Example: the `Σ-PS`
/// possession clause `e(σ'_1, Ỹ_1)^usk = e(σ'_2, g̃) · e(σ'_1, X̃ Ỹ_2^φ)^{-1}` is
/// `terms = [(usk, [(σ'_1, Ỹ_1)])]`, `target = [(σ'_2, g̃), (-σ'_1, X̃ + φ·Ỹ_2)]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtEquation<E: Pairing> {
    /// The pairs `(var_i, product_i)`; the base of `x[var_i]` is `Σ e(product_i)`.
    pub terms: Vec<(ScalarVar, PairingProduct<E>)>,
    /// The target `Σ e(target)`.
    pub target: PairingProduct<E>,
}

impl<E: Pairing> GtEquation<E> {
    /// The equation `Σ e(target) = Σ_i x[var_i] · Σ e(product_i)`.
    #[must_use]
    pub fn new(terms: Vec<(ScalarVar, PairingProduct<E>)>, target: PairingProduct<E>) -> Self {
        Self { terms, target }
    }

    fn check_vars(&self, allocated: usize) -> Result<(), Error> {
        check_vars(self.terms.iter().map(|(var, _)| *var), allocated)
    }

    /// The pairs `(scalars[var_i] · P, Q)` over all products of all terms.
    fn scaled_pairs(
        &self,
        scalars: &[E::ScalarField],
        pairs: &mut PairingProduct<E>,
    ) -> Result<(), Error> {
        for (var, product) in &self.terms {
            let x = lookup(scalars, *var)?;
            pairs.extend(product.iter().map(|(p, q)| (*p * *x, *q)));
        }
        Ok(())
    }

    /// `Σ_i scalars[var_i] · Σ e(product_i)` with ONE multi-pairing.
    fn evaluate(&self, scalars: &[E::ScalarField]) -> Result<PairingOutput<E>, Error> {
        let mut pairs = Vec::new();
        self.scaled_pairs(scalars, &mut pairs)?;
        pairing_product::<E>(&pairs)
    }

    /// `Σ_i z[var_i] · Σ e(product_i) − c · Σ e(target)` with ONE multi-pairing.
    fn recompute_commitment(
        &self,
        c: &E::ScalarField,
        z: &[E::ScalarField],
    ) -> Result<PairingOutput<E>, Error> {
        let mut pairs = Vec::new();
        self.scaled_pairs(z, &mut pairs)?;
        let minus_c = -*c;
        pairs.extend(self.target.iter().map(|(p, q)| (*p * minus_c, *q)));
        pairing_product::<E>(&pairs)
    }

    fn absorb(&self, t: &mut Transcript) -> Result<(), Error> {
        t.append_u64(b"num-terms", self.terms.len() as u64);
        for (var, product) in &self.terms {
            t.append_u64(b"var", var.0 as u64);
            absorb_product::<E>(t, product)?;
        }
        absorb_product::<E>(t, &self.target)
    }
}

fn absorb_product<E: Pairing>(t: &mut Transcript, product: &[(E::G1, E::G2)]) -> Result<(), Error> {
    t.append_u64(b"num-pairs", product.len() as u64);
    for (p, q) in product {
        t.append_serializable(b"p", p)?;
        t.append_serializable(b"q", q)?;
    }
    Ok(())
}

/// `Σ_k e(P_k, Q_k)` (multiplicatively `∏_k e(P_k, Q_k)`) with one Miller loop per pair and ONE
/// final exponentiation. The empty product is the identity of `G_T`.
///
/// This is the panic-free form of `Pairing::multi_pairing`, shared by the `G_T` equations of
/// this module and by the pairing-product verification equations of the credential bases.
///
/// # Errors
/// [`Error::DegenerateInput`] if the final exponentiation is undefined (a zero Miller-loop
/// value). Implementation note: this does not happen for points of `G_1 × G_2`, identity
/// included; the error exists so that no input can cause a panic.
pub fn pairing_product<E: Pairing>(pairs: &[(E::G1, E::G2)]) -> Result<PairingOutput<E>, Error> {
    let (ps, qs): (Vec<E::G1>, Vec<E::G2>) = pairs.iter().copied().unzip();
    let ps = E::G1::normalize_batch(&ps);
    let qs = E::G2::normalize_batch(&qs);
    // `multi_pairing` unwraps the final exponentiation; going through the `Option` keeps this
    // path panic-free whatever the inputs are.
    E::final_exponentiation(E::multi_miller_loop(ps, qs)).ok_or(Error::DegenerateInput(
        "final exponentiation of a zero Miller loop value",
    ))
}

fn check_vars(vars: impl Iterator<Item = ScalarVar>, allocated: usize) -> Result<(), Error> {
    for var in vars {
        if var.0 >= allocated {
            return Err(Error::UnallocatedVariable {
                index: var.0,
                allocated,
            });
        }
    }
    Ok(())
}

fn lookup<F>(scalars: &[F], var: ScalarVar) -> Result<&F, Error> {
    scalars.get(var.0).ok_or(Error::UnallocatedVariable {
        index: var.0,
        allocated: scalars.len(),
    })
}

fn check_len(expected: usize, actual: usize) -> Result<(), Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::LengthMismatch { expected, actual })
    }
}

/// The statement interface the sigma protocol ([`crate::sigma::protocol`]) and its Fiat-Shamir
/// transform ([`crate::sigma::fiat_shamir`]) are written against: a linear map `φ : F^n → H`
/// and a target `Y ∈ H`.
pub trait LinearRelation {
    /// The common scalar field `F = Z_p` of all groups of the statement; also the challenge
    /// space `C` of the protocol.
    type Scalar: PrimeField;
    /// An element of the image group `H` (one group element per equation).
    type Image: Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize;

    /// The number `n` of witness coordinates.
    fn num_scalars(&self) -> usize;

    /// `φ(scalars)`.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] unless `scalars.len() == self.num_scalars()`.
    fn evaluate(&self, scalars: &[Self::Scalar]) -> Result<Self::Image, Error>;

    /// `φ(z) − c·Y`: the commitment a verifier reconstructs from challenge and responses
    /// (multiplicatively `∏ B_i^{z_i} · T^{-c}`).
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] unless `z.len() == self.num_scalars()`.
    fn recompute_commitment(
        &self,
        c: &Self::Scalar,
        z: &[Self::Scalar],
    ) -> Result<Self::Image, Error>;

    /// Whether `φ(witness) = Y`, i.e. `(statement, witness) ∈ R`. `false` on a wrong length.
    fn is_satisfied_by(&self, witness: &[Self::Scalar]) -> bool;

    /// Absorbs a canonical, injective encoding of the **whole** statement: its shape and every
    /// base and every target.
    ///
    /// This is what makes the Fiat-Shamir transform *strong*: a proof is bound to each group
    /// element of its statement, so none of them can be chosen after the challenge.
    ///
    /// # Errors
    /// [`Error::Serialization`] if an element cannot be serialized.
    fn absorb_statement(&self, t: &mut Transcript) -> Result<(), Error>;
}

// ---------------------------------------------------------------------------------------------
// Equations in one group
// ---------------------------------------------------------------------------------------------

/// A conjunction of linear equations in ONE prime-order group `G` over a shared variable space
/// (`Σ-MAC`, stand-alone tag proofs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRelation<G: PrimeGroup> {
    num_scalars: usize,
    equations: Vec<LinearEquation<G>>,
}

impl<G: PrimeGroup> Default for GroupRelation<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: PrimeGroup> GroupRelation<G> {
    /// The empty relation: no variables, no equations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_scalars: 0,
            equations: Vec::new(),
        }
    }

    /// Allocates a fresh witness coordinate.
    pub fn alloc_scalar(&mut self) -> ScalarVar {
        let var = ScalarVar(self.num_scalars);
        self.num_scalars += 1;
        var
    }

    /// Allocates `n` fresh witness coordinates.
    pub fn alloc_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        (0..n).map(|_| self.alloc_scalar()).collect()
    }

    /// Adds an equation to the conjunction.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if the equation refers to a variable that was not
    /// allocated in this relation; the relation is unchanged then.
    pub fn add_equation(&mut self, equation: LinearEquation<G>) -> Result<(), Error> {
        equation.check_vars(self.num_scalars)?;
        self.equations.push(equation);
        Ok(())
    }

    /// The equations added so far.
    #[must_use]
    pub fn equations(&self) -> &[LinearEquation<G>] {
        &self.equations
    }
}

impl<G: PrimeGroup> LinearRelation for GroupRelation<G> {
    type Scalar = G::ScalarField;
    type Image = Vec<G>;

    fn num_scalars(&self) -> usize {
        self.num_scalars
    }

    fn evaluate(&self, scalars: &[Self::Scalar]) -> Result<Self::Image, Error> {
        check_len(self.num_scalars, scalars.len())?;
        self.equations
            .iter()
            .map(|eq| eq.evaluate(scalars))
            .collect()
    }

    fn recompute_commitment(
        &self,
        c: &Self::Scalar,
        z: &[Self::Scalar],
    ) -> Result<Self::Image, Error> {
        check_len(self.num_scalars, z.len())?;
        self.equations
            .iter()
            .map(|eq| Ok(eq.evaluate(z)? - eq.target * *c))
            .collect()
    }

    fn is_satisfied_by(&self, witness: &[Self::Scalar]) -> bool {
        self.recompute_commitment(&Self::Scalar::one(), witness)
            .is_ok_and(|image| image.iter().all(Zero::is_zero))
    }

    fn absorb_statement(&self, t: &mut Transcript) -> Result<(), Error> {
        t.append_bytes(b"relation", b"group");
        t.append_u64(b"num-scalars", self.num_scalars as u64);
        t.append_u64(b"num-equations", self.equations.len() as u64);
        self.equations.iter().try_for_each(|eq| eq.absorb(t))
    }
}

// ---------------------------------------------------------------------------------------------
// Equations in G_1, G_2 and G_T
// ---------------------------------------------------------------------------------------------

/// An element of the image group `G_1^a × G_2^b × G_T^c` of a [`PairingRelation`]: one group
/// element per equation, in insertion order within each group.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PairingImage<E: Pairing> {
    /// Components of the `G_1` equations.
    pub g1: Vec<E::G1>,
    /// Components of the `G_2` equations.
    pub g2: Vec<E::G2>,
    /// Components of the `G_T` equations.
    pub gt: Vec<PairingOutput<E>>,
}

impl<E: Pairing> PairingImage<E> {
    /// Whether every component is the identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.g1.iter().all(Zero::is_zero)
            && self.g2.iter().all(Zero::is_zero)
            && self.gt.iter().all(Zero::is_zero)
    }
}

/// A conjunction of linear equations in `G_1`, `G_2` and `G_T` of a pairing `E` over ONE shared
/// variable space; the statement type of `R_att` and `R_issue` (§5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRelation<E: Pairing> {
    num_scalars: usize,
    g1: Vec<LinearEquation<E::G1>>,
    g2: Vec<LinearEquation<E::G2>>,
    gt: Vec<GtEquation<E>>,
}

impl<E: Pairing> Default for PairingRelation<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Pairing> PairingRelation<E> {
    /// The empty relation: no variables, no equations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_scalars: 0,
            g1: Vec::new(),
            g2: Vec::new(),
            gt: Vec::new(),
        }
    }

    /// Allocates a fresh witness coordinate.
    pub fn alloc_scalar(&mut self) -> ScalarVar {
        let var = ScalarVar(self.num_scalars);
        self.num_scalars += 1;
        var
    }

    /// Allocates `n` fresh witness coordinates.
    pub fn alloc_scalars(&mut self, n: usize) -> Vec<ScalarVar> {
        (0..n).map(|_| self.alloc_scalar()).collect()
    }

    /// Adds an equation in `G_1`.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if the equation refers to an unallocated variable.
    pub fn add_g1(&mut self, equation: LinearEquation<E::G1>) -> Result<(), Error> {
        equation.check_vars(self.num_scalars)?;
        self.g1.push(equation);
        Ok(())
    }

    /// Adds an equation in `G_2`.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if the equation refers to an unallocated variable.
    pub fn add_g2(&mut self, equation: LinearEquation<E::G2>) -> Result<(), Error> {
        equation.check_vars(self.num_scalars)?;
        self.g2.push(equation);
        Ok(())
    }

    /// Adds an equation in `G_T`, in lazy pairing-product form.
    ///
    /// # Errors
    /// [`Error::UnallocatedVariable`] if the equation refers to an unallocated variable.
    pub fn add_gt(&mut self, equation: GtEquation<E>) -> Result<(), Error> {
        equation.check_vars(self.num_scalars)?;
        self.gt.push(equation);
        Ok(())
    }

    /// The `G_1` equations added so far.
    #[must_use]
    pub fn g1_equations(&self) -> &[LinearEquation<E::G1>] {
        &self.g1
    }

    /// The `G_2` equations added so far.
    #[must_use]
    pub fn g2_equations(&self) -> &[LinearEquation<E::G2>] {
        &self.g2
    }

    /// The `G_T` equations added so far.
    #[must_use]
    pub fn gt_equations(&self) -> &[GtEquation<E>] {
        &self.gt
    }
}

impl<E: Pairing> LinearRelation for PairingRelation<E> {
    type Scalar = E::ScalarField;
    type Image = PairingImage<E>;

    fn num_scalars(&self) -> usize {
        self.num_scalars
    }

    fn evaluate(&self, scalars: &[Self::Scalar]) -> Result<Self::Image, Error> {
        check_len(self.num_scalars, scalars.len())?;
        Ok(PairingImage {
            g1: self
                .g1
                .iter()
                .map(|eq| eq.evaluate(scalars))
                .collect::<Result<_, _>>()?,
            g2: self
                .g2
                .iter()
                .map(|eq| eq.evaluate(scalars))
                .collect::<Result<_, _>>()?,
            gt: self
                .gt
                .iter()
                .map(|eq| eq.evaluate(scalars))
                .collect::<Result<_, _>>()?,
        })
    }

    fn recompute_commitment(
        &self,
        c: &Self::Scalar,
        z: &[Self::Scalar],
    ) -> Result<Self::Image, Error> {
        check_len(self.num_scalars, z.len())?;
        Ok(PairingImage {
            g1: self
                .g1
                .iter()
                .map(|eq| Ok(eq.evaluate(z)? - eq.target * *c))
                .collect::<Result<_, Error>>()?,
            g2: self
                .g2
                .iter()
                .map(|eq| Ok(eq.evaluate(z)? - eq.target * *c))
                .collect::<Result<_, Error>>()?,
            gt: self
                .gt
                .iter()
                .map(|eq| eq.recompute_commitment(c, z))
                .collect::<Result<_, _>>()?,
        })
    }

    fn is_satisfied_by(&self, witness: &[Self::Scalar]) -> bool {
        self.recompute_commitment(&Self::Scalar::one(), witness)
            .is_ok_and(|image| image.is_zero())
    }

    fn absorb_statement(&self, t: &mut Transcript) -> Result<(), Error> {
        t.append_bytes(b"relation", b"pairing");
        t.append_u64(b"num-scalars", self.num_scalars as u64);
        t.append_u64(b"num-g1-equations", self.g1.len() as u64);
        self.g1.iter().try_for_each(|eq| eq.absorb(t))?;
        t.append_u64(b"num-g2-equations", self.g2.len() as u64);
        self.g2.iter().try_for_each(|eq| eq.absorb(t))?;
        t.append_u64(b"num-gt-equations", self.gt.len() as u64);
        self.gt.iter().try_for_each(|eq| eq.absorb(t))
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
    use ark_ff::UniformRand;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    type G1 = G1Projective;
    type G2 = G2Projective;

    #[test]
    fn unallocated_variables_are_rejected() {
        let mut big = GroupRelation::<G1>::new();
        let vars = big.alloc_scalars(3);
        assert_eq!(
            vars.iter().map(|v| v.index()).collect::<Vec<_>>(),
            [0, 1, 2]
        );

        let mut small = GroupRelation::<G1>::new();
        let x = small.alloc_scalar();
        let g = G1::generator();
        assert_eq!(
            small.add_equation(LinearEquation::dlog(vars[2], g, g)),
            Err(Error::UnallocatedVariable {
                index: 2,
                allocated: 1
            })
        );
        assert!(small.equations().is_empty());
        assert_eq!(small.add_equation(LinearEquation::dlog(x, g, g)), Ok(()));

        let mut rel = PairingRelation::<Bls12_381>::new();
        let h = G2::generator();
        let unallocated = Err(Error::UnallocatedVariable {
            index: 0,
            allocated: 0,
        });
        assert_eq!(rel.add_g1(LinearEquation::dlog(x, g, g)), unallocated);
        assert_eq!(rel.add_g2(LinearEquation::dlog(x, h, h)), unallocated);
        assert_eq!(
            rel.add_gt(GtEquation::new(vec![(x, vec![(g, h)])], vec![(g, h)])),
            unallocated
        );
        assert_eq!(rel, PairingRelation::new());
    }

    #[test]
    fn wrong_lengths_are_errors_not_panics() {
        let mut rng = StdRng::seed_from_u64(0x5e1a);
        let mut rel = PairingRelation::<Bls12_381>::new();
        let x = rel.alloc_scalar();
        let y = rel.alloc_scalar();
        let (g, h) = (G1::generator(), G2::generator());
        let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        rel.add_g1(LinearEquation::new(
            vec![(x, g), (y, g * a)],
            g * (a + a * b),
        ))
        .unwrap();
        rel.add_gt(GtEquation::new(vec![(y, vec![(g, h)])], vec![(g * b, h)]))
            .unwrap();
        assert!(rel.is_satisfied_by(&[a, b]));
        assert!(!rel.is_satisfied_by(&[b, a]));
        for bad in [&[][..], &[a][..], &[a, b, a][..]] {
            let mismatch = Error::LengthMismatch {
                expected: 2,
                actual: bad.len(),
            };
            assert_eq!(rel.evaluate(bad).unwrap_err(), mismatch);
            assert_eq!(rel.recompute_commitment(&a, bad).unwrap_err(), mismatch);
            assert!(!rel.is_satisfied_by(bad));
        }
    }

    #[test]
    fn empty_relation_is_trivially_satisfied() {
        let rel = GroupRelation::<G1>::new();
        assert!(rel.is_satisfied_by(&[]));
        assert_eq!(rel.evaluate(&[]).unwrap(), Vec::<G1>::new());
        let rel = PairingRelation::<Bls12_381>::new();
        assert!(rel.is_satisfied_by(&[]));
        assert!(rel.evaluate(&[]).unwrap().is_zero());
    }

    /// Identity bases, identity targets and empty pairing products are legal inputs of the
    /// algebra: they must be evaluated without panicking (rejecting degenerate statements is the
    /// job of the public checks of the caller, not of the relation).
    #[test]
    fn degenerate_statements_do_not_panic() {
        use crate::sigma::{FSProof, fiat_shamir};

        let mut rng = StdRng::seed_from_u64(0x5e1b);
        let (o1, o2) = (G1::zero(), G2::zero());
        let (g, h) = (G1::generator(), G2::generator());
        let mut rel = PairingRelation::<Bls12_381>::new();
        let x = rel.alloc_scalar();
        rel.add_g1(LinearEquation::dlog(x, o1, o1)).unwrap();
        rel.add_g1(LinearEquation::new(vec![], o1)).unwrap();
        rel.add_g2(LinearEquation::dlog(x, o2, o2)).unwrap();
        // the vacuous Σ-PS clause of a degenerate shown credential σ' = (1, 1)
        rel.add_gt(GtEquation::new(
            vec![(x, vec![(o1, h)])],
            vec![(o1, h), (o1, h)],
        ))
        .unwrap();
        rel.add_gt(GtEquation::new(vec![(x, vec![(g, o2)])], vec![]))
            .unwrap();
        rel.add_gt(GtEquation::new(vec![], vec![])).unwrap();
        rel.add_gt(GtEquation::new(vec![(x, vec![])], vec![(o1, o2)]))
            .unwrap();

        // vacuous: EVERY scalar is a witness, which is exactly why verifiers must run the
        // non-degeneracy checks themselves
        let any = Fr::rand(&mut rng);
        assert!(rel.is_satisfied_by(&[any]));
        assert!(rel.evaluate(&[any]).unwrap().is_zero());
        let proof = fiat_shamir::prove(&rel, &[any], b"ctx", &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, b"ctx", &proof));
        let garbage = FSProof {
            challenge: any,
            responses: vec![Fr::rand(&mut rng)],
        };
        assert!(!fiat_shamir::verify(&rel, b"ctx", &garbage));
    }

    #[test]
    fn statement_encoding_separates_shapes() {
        let digest = |rel: &dyn Fn(&mut Transcript)| {
            let mut t = Transcript::new(b"/TEST");
            rel(&mut t);
            t.digest()
        };
        let g = G1::generator();

        // one equation with two terms vs two equations with one term each
        let mut r1 = GroupRelation::<G1>::new();
        let x = r1.alloc_scalar();
        r1.add_equation(LinearEquation::new(vec![(x, g), (x, g)], g))
            .unwrap();
        let mut r2 = GroupRelation::<G1>::new();
        let x = r2.alloc_scalar();
        r2.add_equation(LinearEquation::dlog(x, g, g)).unwrap();
        r2.add_equation(LinearEquation::dlog(x, g, g)).unwrap();
        assert_ne!(
            digest(&|t| r1.absorb_statement(t).unwrap()),
            digest(&|t| r2.absorb_statement(t).unwrap())
        );

        // same equations, an additional (unused) variable
        let mut r3 = r2.clone();
        r3.alloc_scalar();
        assert_ne!(
            digest(&|t| r2.absorb_statement(t).unwrap()),
            digest(&|t| r3.absorb_statement(t).unwrap())
        );

        // the same G_1 equation in a group relation and in a pairing relation
        let mut r4 = PairingRelation::<Bls12_381>::new();
        let x = r4.alloc_scalar();
        r4.add_g1(LinearEquation::dlog(x, g, g)).unwrap();
        let mut r5 = GroupRelation::<G1>::new();
        let x = r5.alloc_scalar();
        r5.add_equation(LinearEquation::dlog(x, g, g)).unwrap();
        assert_ne!(
            digest(&|t| r4.absorb_statement(t).unwrap()),
            digest(&|t| r5.absorb_statement(t).unwrap())
        );

        // which variable a base belongs to is part of the statement
        let mut r6 = GroupRelation::<G1>::new();
        let (x, y) = (r6.alloc_scalar(), r6.alloc_scalar());
        let mut r7 = r6.clone();
        r6.add_equation(LinearEquation::new(vec![(x, g), (y, g + g)], g))
            .unwrap();
        r7.add_equation(LinearEquation::new(vec![(y, g), (x, g + g)], g))
            .unwrap();
        assert_ne!(
            digest(&|t| r6.absorb_statement(t).unwrap()),
            digest(&|t| r7.absorb_statement(t).unwrap())
        );
    }
}
