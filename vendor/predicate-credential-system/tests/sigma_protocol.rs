//! Sigma-layer harness (paper §2.3): completeness, special honest-verifier zero knowledge,
//! special soundness with witness-preserving AND composition, and the Fiat-Shamir transform,
//! exercised on relations over `G_1`, `G_2`, `G_T` and mixtures of them.
//!
//! All randomness is seeded (`StdRng::seed_from_u64`, seed recorded in each test), so every run
//! is reproducible. "Rewinding" a prover = running `commit` twice with identically seeded RNGs.
//!
//! What these tests can and cannot show: completeness, simulation and extraction are checked as
//! *algebraic facts on sampled instances*; they are evidence for, not proofs of, the properties
//! of Def. "Sigma protocol". Zero knowledge in particular is only checked in the form "simulated
//! transcripts verify", not as a distributional statement.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::{
    PrimeGroup,
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{Field, One, UniformRand, Zero};
use predicate_credential_system::{
    Error,
    hash::{Transcript, h1_transcript},
    serialization::WireFormat,
    sigma::{
        FSProof, GroupRelation, GtEquation, LinearEquation, LinearRelation, PairingRelation,
        ScalarVar, commit, extract, fiat_shamir, respond, simulate, verify,
    },
};
use rand::{SeedableRng, rngs::StdRng};

// ---------------------------------------------------------------------------------------------
// Statements in "source form", so that a test can change any single element and rebuild
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Statement<E: Pairing> {
    num_scalars: usize,
    g1: Vec<LinearEquation<E::G1>>,
    g2: Vec<LinearEquation<E::G2>>,
    gt: Vec<GtEquation<E>>,
}

impl<E: Pairing> Statement<E> {
    fn build(&self) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        rel.alloc_scalars(self.num_scalars);
        for eq in &self.g1 {
            rel.add_g1(eq.clone()).unwrap();
        }
        for eq in &self.g2 {
            rel.add_g2(eq.clone()).unwrap();
        }
        for eq in &self.gt {
            rel.add_gt(eq.clone()).unwrap();
        }
        rel
    }
}

struct Fixture<E: Pairing> {
    stmt: Statement<E>,
    witness: Vec<E::ScalarField>,
}

/// Variable handles `x_0, …, x_{n-1}`; valid in every relation with at least `n` variables.
fn vars<E: Pairing>(n: usize) -> Vec<ScalarVar> {
    PairingRelation::<E>::new().alloc_scalars(n)
}

fn rand_g1<E: Pairing>(rng: &mut StdRng) -> E::G1 {
    E::G1::rand(rng)
}

fn rand_g2<E: Pairing>(rng: &mut StdRng) -> E::G2 {
    E::G2::rand(rng)
}

/// A Pointcheval-Sanders signature `(σ_1, σ_2)` on `(usk, φ)` and its possession clause
/// `e(σ_1, Ỹ_1)^usk = e(σ_2, g̃) · e(σ_1, X̃ Ỹ_2^φ)^{-1}` in lazy form (§3.2.1, `Possess`).
fn ps_possession_clause<E: Pairing>(
    usk_var: ScalarVar,
    usk: E::ScalarField,
    rng: &mut StdRng,
) -> GtEquation<E> {
    let g2 = E::G2::generator();
    let (x, y1, y2, phi) = (
        E::ScalarField::rand(rng),
        E::ScalarField::rand(rng),
        E::ScalarField::rand(rng),
        E::ScalarField::rand(rng),
    );
    let sigma1 = rand_g1::<E>(rng);
    let sigma2 = sigma1 * (x + y1 * usk + y2 * phi);
    GtEquation::new(
        vec![(usk_var, vec![(sigma1, g2 * y1)])],
        vec![(sigma2, g2), (-sigma1, g2 * x + g2 * (y2 * phi))],
    )
}

/// Two `G_1` equations sharing `x`: `T_1 = P_1^x`, `T_2 = P_2^x P_3^y`.
fn g1_only<E: Pairing>(rng: &mut StdRng) -> Fixture<E> {
    let v = vars::<E>(2);
    let (x, y) = (E::ScalarField::rand(rng), E::ScalarField::rand(rng));
    let (p1, p2, p3) = (rand_g1::<E>(rng), rand_g1::<E>(rng), rand_g1::<E>(rng));
    Fixture {
        stmt: Statement {
            num_scalars: 2,
            g1: vec![
                LinearEquation::dlog(v[0], p1, p1 * x),
                LinearEquation::new(vec![(v[0], p2), (v[1], p3)], p2 * x + p3 * y),
            ],
            g2: vec![],
            gt: vec![],
        },
        witness: vec![x, y],
    }
}

/// Two `G_2` equations sharing `y`.
fn g2_only<E: Pairing>(rng: &mut StdRng) -> Fixture<E> {
    let v = vars::<E>(2);
    let (x, y) = (E::ScalarField::rand(rng), E::ScalarField::rand(rng));
    let (q1, q2) = (rand_g2::<E>(rng), rand_g2::<E>(rng));
    Fixture {
        stmt: Statement {
            num_scalars: 2,
            g1: vec![],
            g2: vec![
                LinearEquation::new(vec![(v[0], q1), (v[1], q2)], q1 * x + q2 * y),
                LinearEquation::dlog(v[1], q1, q1 * y),
            ],
            gt: vec![],
        },
        witness: vec![x, y],
    }
}

/// One `G_T` equation: the `Σ-PS` possession clause.
fn gt_only<E: Pairing>(rng: &mut StdRng) -> Fixture<E> {
    let v = vars::<E>(1);
    let usk = E::ScalarField::rand(rng);
    Fixture {
        stmt: Statement {
            num_scalars: 1,
            g1: vec![],
            g2: vec![],
            gt: vec![ps_possession_clause::<E>(v[0], usk, rng)],
        },
        witness: vec![usk],
    }
}

/// Index of the shared variable `usk` in [`mixed`].
const USK: usize = 0;

/// Equations in all three groups over the variables `(usk, r, e)`; `usk` is shared between two
/// `G_1` equations, a `G_2` equation and two `G_T` equations:
///
/// * `T = H^usk`                                   (a tag clause)
/// * `C = G^r Y_1^usk`                             (a commitment opening)
/// * `W = Q_1^usk Q_2^e`
/// * the `Σ-PS` possession clause in `usk`
/// * `Z = (e(P_1, Q_1) e(P_2, Q_2))^usk · e(P_3, Q_3)^e` with two multi-pair products.
fn mixed<E: Pairing>(rng: &mut StdRng) -> Fixture<E> {
    let v = vars::<E>(3);
    let (usk, r, e) = (
        E::ScalarField::rand(rng),
        E::ScalarField::rand(rng),
        E::ScalarField::rand(rng),
    );
    let (h, g, y1) = (rand_g1::<E>(rng), rand_g1::<E>(rng), rand_g1::<E>(rng));
    let (q1, q2, q3) = (rand_g2::<E>(rng), rand_g2::<E>(rng), rand_g2::<E>(rng));
    let (p1, p2, p3) = (rand_g1::<E>(rng), rand_g1::<E>(rng), rand_g1::<E>(rng));
    let general_gt = GtEquation::new(
        vec![(v[0], vec![(p1, q1), (p2, q2)]), (v[2], vec![(p3, q3)])],
        // the target is given by *different* pairing preimages of the same G_T element
        vec![(p1, q1 * usk), (p2 * usk, q2), (p3 * e, q3)],
    );
    Fixture {
        stmt: Statement {
            num_scalars: 3,
            g1: vec![
                LinearEquation::dlog(v[0], h, h * usk),
                LinearEquation::new(vec![(v[1], g), (v[0], y1)], g * r + y1 * usk),
            ],
            g2: vec![LinearEquation::new(
                vec![(v[0], q1), (v[2], q2)],
                q1 * usk + q2 * e,
            )],
            gt: vec![ps_possession_clause::<E>(v[0], usk, rng), general_gt],
        },
        witness: vec![usk, r, e],
    }
}

fn all_fixtures<E: Pairing>(rng: &mut StdRng) -> Vec<(&'static str, Fixture<E>)> {
    vec![
        ("G1 only", g1_only(rng)),
        ("G2 only", g2_only(rng)),
        ("GT only", gt_only(rng)),
        ("mixed", mixed(rng)),
    ]
}

// ---------------------------------------------------------------------------------------------
// Completeness
// ---------------------------------------------------------------------------------------------

fn completeness<E: Pairing>(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    for (name, Fixture { stmt, witness }) in all_fixtures::<E>(&mut rng) {
        let rel = stmt.build();
        assert!(rel.is_satisfied_by(&witness), "{name}: fixture is broken");

        // interactive, including the degenerate challenges 0 and 1
        for c in [
            E::ScalarField::rand(&mut rng),
            E::ScalarField::zero(),
            E::ScalarField::one(),
        ] {
            let (a, st) = commit(&rel, &mut rng).unwrap();
            let z = respond(st, &witness, &c).unwrap();
            assert_eq!(z.len(), rel.num_scalars());
            assert!(
                verify(&rel, &a, &c, &z),
                "{name}: honest transcript rejected"
            );
        }

        // Fiat-Shamir
        let proof = fiat_shamir::prove(&rel, &witness, b"ctx", &mut rng).unwrap();
        assert_eq!(proof.responses.len(), rel.num_scalars());
        assert!(
            fiat_shamir::verify(&rel, b"ctx", &proof),
            "{name}: honest proof rejected"
        );
    }
}

#[test]
fn completeness_bls12_381() {
    completeness::<Bls12_381>(0xC0_0001);
}

/// Generic-curve check: the identical test over a second pairing engine.
#[test]
fn completeness_bn254() {
    completeness::<Bn254>(0xC0_0002);
}

#[test]
fn proving_is_reproducible_from_the_seed() {
    let make = || {
        let mut rng = StdRng::seed_from_u64(0xC0_0003);
        let Fixture { stmt, witness } = mixed::<Bls12_381>(&mut rng);
        fiat_shamir::prove(&stmt.build(), &witness, b"ctx", &mut rng).unwrap()
    };
    assert_eq!(make(), make());
}

// ---------------------------------------------------------------------------------------------
// Special honest-verifier zero knowledge: simulated transcripts verify
// ---------------------------------------------------------------------------------------------

fn simulator<E: Pairing>(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    for (name, Fixture { stmt, .. }) in all_fixtures::<E>(&mut rng) {
        let rel = stmt.build(); // the simulator never sees the witness
        let mut challenges = vec![
            E::ScalarField::zero(),
            E::ScalarField::one(),
            -E::ScalarField::one(),
        ];
        challenges.extend((0..4).map(|_| E::ScalarField::rand(&mut rng)));
        for c in challenges {
            let (a, z) = simulate(&rel, &c, &mut rng).unwrap();
            assert!(
                verify(&rel, &a, &c, &z),
                "{name}: simulated transcript rejected"
            );
            // ... and it is bound to its challenge
            assert!(
                !verify(&rel, &a, &(c + E::ScalarField::one()), &z),
                "{name}"
            );
        }
    }
}

#[test]
fn simulated_transcripts_verify_bls12_381() {
    simulator::<Bls12_381>(0x51_0001);
}

#[test]
fn simulated_transcripts_verify_bn254() {
    simulator::<Bn254>(0x51_0002);
}

/// The simulator also works for FALSE statements (it must: it has no witness to tell them
/// apart), which is why `verify` alone says nothing without a fresh challenge.
#[test]
fn simulator_works_for_false_statements() {
    let mut rng = StdRng::seed_from_u64(0x51_0003);
    let Fixture { mut stmt, witness } = g1_only::<Bls12_381>(&mut rng);
    stmt.g1[0].target += <Bls12_381 as Pairing>::G1::generator();
    let rel = stmt.build();
    assert!(!rel.is_satisfied_by(&witness));
    let c = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let (a, z) = simulate(&rel, &c, &mut rng).unwrap();
    assert!(verify(&rel, &a, &c, &z));
}

// ---------------------------------------------------------------------------------------------
// Special soundness: the extractor, by rewinding
// ---------------------------------------------------------------------------------------------

/// Two accepting transcripts with the same commitment: `commit` is run twice on identically
/// seeded RNGs (the same random tape) and answered with two challenges.
#[allow(clippy::type_complexity)]
fn rewind<R: LinearRelation>(
    rel: &R,
    witness: &[R::Scalar],
    tape: u64,
    c1: R::Scalar,
    c2: R::Scalar,
) -> (R::Image, Vec<R::Scalar>, Vec<R::Scalar>) {
    let (a1, st1) = commit(rel, &mut StdRng::seed_from_u64(tape)).unwrap();
    let (a2, st2) = commit(rel, &mut StdRng::seed_from_u64(tape)).unwrap();
    assert_eq!(a1, a2, "same tape, same commitment");
    let z1 = respond(st1, witness, &c1).unwrap();
    let z2 = respond(st2, witness, &c2).unwrap();
    (a1, z1, z2)
}

fn extraction<E: Pairing>(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    for (name, Fixture { stmt, witness }) in all_fixtures::<E>(&mut rng) {
        let rel = stmt.build();
        let (c1, c2) = (
            E::ScalarField::rand(&mut rng),
            E::ScalarField::rand(&mut rng),
        );
        assert_ne!(c1, c2);
        let (a, z1, z2) = rewind(&rel, &witness, seed ^ 0xABCD, c1, c2);
        assert!(verify(&rel, &a, &c1, &z1) && verify(&rel, &a, &c2, &z2));

        let extracted = extract(&rel, &a, (&c1, &z1), (&c2, &z2)).expect(name);
        assert_eq!(extracted, witness, "{name}: extracted witness differs");
        assert!(rel.is_satisfied_by(&extracted));
        // symmetric in the two transcripts
        assert_eq!(extract(&rel, &a, (&c2, &z2), (&c1, &z1)), Some(witness));
    }
}

#[test]
fn extractor_recovers_the_witness_bls12_381() {
    extraction::<Bls12_381>(0xE7_0001);
}

#[test]
fn extractor_recovers_the_witness_bn254() {
    extraction::<Bn254>(0xE7_0002);
}

/// Witness-preserving AND composition: the variable shared by `G_1`, `G_2` and `G_T` equations
/// is extracted as ONE value, and that value satisfies each of those equations on its own.
#[test]
fn extractor_recovers_one_value_for_the_shared_variable() {
    type E = Bls12_381;
    let mut rng = StdRng::seed_from_u64(0xE7_0003);
    let Fixture { stmt, witness } = mixed::<E>(&mut rng);
    let rel = stmt.build();
    let (c1, c2) = (
        <E as Pairing>::ScalarField::rand(&mut rng),
        <E as Pairing>::ScalarField::rand(&mut rng),
    );
    let (a, z1, z2) = rewind(&rel, &witness, 0xE7_0004, c1, c2);
    let extracted = extract(&rel, &a, (&c1, &z1), (&c2, &z2)).unwrap();
    assert_eq!(
        extracted.len(),
        3,
        "one coordinate per variable, not per occurrence"
    );
    assert_eq!(extracted[USK], witness[USK]);

    // the single extracted usk satisfies the tag clause and the possession clause separately
    let mut tag_only = Statement::<E> {
        num_scalars: 3,
        g1: vec![stmt.g1[0].clone()],
        g2: vec![],
        gt: vec![],
    };
    assert!(tag_only.build().is_satisfied_by(&extracted));
    tag_only.g1.clear();
    tag_only.gt.push(stmt.gt[0].clone());
    assert!(tag_only.build().is_satisfied_by(&extracted));
}

/// A statement whose clauses are individually true but for DIFFERENT values of the "shared"
/// variable has no witness: nothing can be proven and nothing accepting can be produced from
/// either value.
#[test]
fn shared_variable_binds_one_value() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xE7_0005);
    let v = vars::<E>(1);
    let (x, x_other) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let (p1, p2) = (rand_g1::<E>(&mut rng), rand_g1::<E>(&mut rng));
    let stmt = Statement::<E> {
        num_scalars: 1,
        g1: vec![
            LinearEquation::dlog(v[0], p1, p1 * x),
            LinearEquation::dlog(v[0], p2, p2 * x_other),
        ],
        g2: vec![],
        gt: vec![],
    };
    let rel = stmt.build();
    for w in [x, x_other] {
        assert!(!rel.is_satisfied_by(&[w]));
        assert_eq!(
            fiat_shamir::prove(&rel, &[w], b"ctx", &mut rng),
            Err(Error::WitnessDoesNotSatisfyRelation)
        );
        let (a, st) = commit(&rel, &mut rng).unwrap();
        let c = Fr::rand(&mut rng);
        let z = respond(st, &[w], &c).unwrap();
        assert!(!verify(&rel, &a, &c, &z));
    }
}

#[test]
fn extractor_rejects_unusable_transcript_pairs() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xE7_0006);
    let Fixture { stmt, witness } = mixed::<E>(&mut rng);
    let rel = stmt.build();
    let (c1, c2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let (a, z1, z2) = rewind(&rel, &witness, 0xE7_0007, c1, c2);
    assert!(extract(&rel, &a, (&c1, &z1), (&c2, &z2)).is_some());

    // equal challenges (would be a division by zero)
    assert_eq!(extract(&rel, &a, (&c1, &z1), (&c1, &z1)), None);

    // a transcript that does not verify: tampered response ...
    let mut bad = z2.clone();
    bad[1] += Fr::one();
    assert_eq!(extract(&rel, &a, (&c1, &z1), (&c2, &bad)), None);
    assert_eq!(extract(&rel, &a, (&c2, &bad), (&c1, &z1)), None);
    // ... wrong challenge ...
    assert_eq!(
        extract(&rel, &a, (&c1, &z1), (&(c2 + Fr::one()), &z2)),
        None
    );
    // ... wrong number of responses (no panic) ...
    assert_eq!(extract(&rel, &a, (&c1, &z1), (&c2, &z2[..2])), None);
    assert_eq!(extract(&rel, &a, (&c1, &[]), (&c2, &z2)), None);
    let mut long = z2.clone();
    long.push(Fr::one());
    assert_eq!(extract(&rel, &a, (&c1, &z1), (&c2, &long)), None);
    // ... or transcripts for a different commitment
    let (other_a, other_st) = commit(&rel, &mut rng).unwrap();
    let other_z = respond(other_st, &witness, &c2).unwrap();
    assert!(verify(&rel, &other_a, &c2, &other_z));
    assert_eq!(extract(&rel, &a, (&c1, &z1), (&c2, &other_z)), None);
    // ... or a commitment of the wrong shape
    let mut short_a = a.clone();
    short_a.gt.pop();
    assert_eq!(extract(&rel, &short_a, (&c1, &z1), (&c2, &z2)), None);
}

// ---------------------------------------------------------------------------------------------
// Interactive verifier: robustness
// ---------------------------------------------------------------------------------------------

#[test]
fn interactive_verifier_rejects_malformed_transcripts_without_panicking() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0x1A_0001);
    let Fixture { stmt, witness } = mixed::<E>(&mut rng);
    let rel = stmt.build();
    let (a, st) = commit(&rel, &mut rng).unwrap();
    let c = Fr::rand(&mut rng);
    let z = respond(st, &witness, &c).unwrap();
    assert!(verify(&rel, &a, &c, &z));

    assert!(!verify(&rel, &a, &c, &[]));
    assert!(!verify(&rel, &a, &c, &z[..2]));
    assert!(!verify(
        &rel,
        &a,
        &c,
        &[z.clone(), vec![Fr::one()]].concat()
    ));
    for i in 0..z.len() {
        let mut bad = z.clone();
        bad[i] += Fr::one();
        assert!(!verify(&rel, &a, &c, &bad), "response {i}");
    }
    // every component of the commitment matters
    for i in 0..a.g1.len() {
        let mut bad = a.clone();
        bad.g1[i] += <E as Pairing>::G1::generator();
        assert!(!verify(&rel, &bad, &c, &z));
    }
    for i in 0..a.g2.len() {
        let mut bad = a.clone();
        bad.g2[i] += <E as Pairing>::G2::generator();
        assert!(!verify(&rel, &bad, &c, &z));
    }
    for i in 0..a.gt.len() {
        let mut bad = a.clone();
        bad.gt[i] += PairingOutput::<E>::generator();
        assert!(!verify(&rel, &bad, &c, &z));
    }
    // a wrong witness does not convince the verifier
    let (a, st) = commit(&rel, &mut rng).unwrap();
    let mut wrong = witness.clone();
    wrong[USK] += Fr::one();
    let z = respond(st, &wrong, &c).unwrap();
    assert!(!verify(&rel, &a, &c, &z));
}

// ---------------------------------------------------------------------------------------------
// Lazy G_T evaluation = naive evaluation with explicit pairings and G_T exponentiations
// ---------------------------------------------------------------------------------------------

fn naive_product<E: Pairing>(product: &[(E::G1, E::G2)]) -> PairingOutput<E> {
    product.iter().map(|(p, q)| E::pairing(*p, *q)).sum()
}

fn naive_gt_eval<E: Pairing>(eq: &GtEquation<E>, x: &[E::ScalarField]) -> PairingOutput<E> {
    eq.terms
        .iter()
        .map(|(var, product)| naive_product::<E>(product) * x[var.index()])
        .sum()
}

fn lazy_equals_naive<E: Pairing>(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let Fixture { stmt, witness } = mixed::<E>(&mut rng);
    let rel = stmt.build();
    assert_eq!(rel.gt_equations().len(), 2);

    let random: Vec<E::ScalarField> = (0..3).map(|_| E::ScalarField::rand(&mut rng)).collect();
    let zeros = vec![E::ScalarField::zero(); 3];
    let c = E::ScalarField::rand(&mut rng);
    for x in [&witness, &random, &zeros] {
        let image = rel.evaluate(x).unwrap();
        let recomputed = rel.recompute_commitment(&c, x).unwrap();
        for (i, eq) in stmt.gt.iter().enumerate() {
            let naive = naive_gt_eval::<E>(eq, x);
            let target = naive_product::<E>(&eq.target);
            assert_eq!(image.gt[i], naive, "evaluate, G_T equation {i}");
            assert_eq!(
                recomputed.gt[i],
                naive - target * c,
                "recompute, G_T equation {i}"
            );
        }
        // the G_1 / G_2 components against the defining formula
        for (i, eq) in stmt.g1.iter().enumerate() {
            let naive: E::G1 = eq.terms.iter().map(|(v, b)| *b * x[v.index()]).sum();
            assert_eq!(image.g1[i], naive);
            assert_eq!(recomputed.g1[i], naive - eq.target * c);
        }
        for (i, eq) in stmt.g2.iter().enumerate() {
            let naive: E::G2 = eq.terms.iter().map(|(v, b)| *b * x[v.index()]).sum();
            assert_eq!(image.g2[i], naive);
            assert_eq!(recomputed.g2[i], naive - eq.target * c);
        }
    }
    // on the witness the image is the target
    let image = rel.evaluate(&witness).unwrap();
    for (i, eq) in stmt.gt.iter().enumerate() {
        assert_eq!(image.gt[i], naive_product::<E>(&eq.target));
    }
}

#[test]
fn lazy_gt_evaluation_equals_naive_bls12_381() {
    lazy_equals_naive::<Bls12_381>(0x6F_0001);
}

#[test]
fn lazy_gt_evaluation_equals_naive_bn254() {
    lazy_equals_naive::<Bn254>(0x6F_0002);
}

/// The same `G_T` statement once in lazy pairing-product form and once as a plain
/// `GroupRelation` over `PairingOutput` with explicitly computed bases: identical masks give
/// identical commitments, and responses are interchangeable.
#[test]
fn lazy_gt_relation_agrees_with_explicit_gt_group_relation() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0x6F_0003);
    let Fixture { stmt, witness } = gt_only::<E>(&mut rng);
    let lazy = stmt.build();

    let eq = &stmt.gt[0];
    let mut explicit = GroupRelation::<PairingOutput<E>>::new();
    let x = explicit.alloc_scalar();
    explicit
        .add_equation(LinearEquation::dlog(
            x,
            naive_product::<E>(&eq.terms[0].1),
            naive_product::<E>(&eq.target),
        ))
        .unwrap();
    assert!(explicit.is_satisfied_by(&witness));

    let (a_lazy, st_lazy) = commit(&lazy, &mut StdRng::seed_from_u64(99)).unwrap();
    let (a_explicit, st_explicit) = commit(&explicit, &mut StdRng::seed_from_u64(99)).unwrap();
    assert_eq!(a_lazy.gt, a_explicit);

    let c = Fr::rand(&mut rng);
    let z_lazy = respond(st_lazy, &witness, &c).unwrap();
    let z_explicit = respond(st_explicit, &witness, &c).unwrap();
    assert_eq!(z_lazy, z_explicit);
    assert!(verify(&lazy, &a_lazy, &c, &z_explicit));
    assert!(verify(&explicit, &a_explicit, &c, &z_lazy));
}

// ---------------------------------------------------------------------------------------------
// Fiat-Shamir: binding to the context, to the proof and to the WHOLE statement
// ---------------------------------------------------------------------------------------------

#[test]
fn fs_rejects_wrong_context_and_any_tampering() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xF5_0001);
    for (name, Fixture { stmt, witness }) in all_fixtures::<E>(&mut rng) {
        let rel = stmt.build();
        let proof = fiat_shamir::prove(&rel, &witness, b"ctx-a", &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, b"ctx-a", &proof));

        // context
        assert!(!fiat_shamir::verify(&rel, b"ctx-b", &proof), "{name}");
        assert!(!fiat_shamir::verify(&rel, b"", &proof), "{name}");
        assert!(!fiat_shamir::verify(&rel, b"ctx-a\0", &proof), "{name}");

        // challenge
        let mut bad = proof.clone();
        bad.challenge += Fr::one();
        assert!(!fiat_shamir::verify(&rel, b"ctx-a", &bad), "{name}");
        bad.challenge = Fr::zero();
        assert!(!fiat_shamir::verify(&rel, b"ctx-a", &bad), "{name}");

        // every single response
        for i in 0..proof.responses.len() {
            let mut bad = proof.clone();
            bad.responses[i] += Fr::one();
            assert!(
                !fiat_shamir::verify(&rel, b"ctx-a", &bad),
                "{name}: response {i}"
            );
            bad.responses[i] = Fr::zero();
            assert!(
                !fiat_shamir::verify(&rel, b"ctx-a", &bad),
                "{name}: response {i}"
            );
        }
        if proof.responses.len() >= 2 {
            let mut bad = proof.clone();
            bad.responses.swap(0, 1);
            assert!(
                !fiat_shamir::verify(&rel, b"ctx-a", &bad),
                "{name}: swapped"
            );
        }

        // a proof for another statement of the same shape
        let other = all_fixtures::<E>(&mut rng)
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1;
        assert!(
            !fiat_shamir::verify(&other.stmt.build(), b"ctx-a", &proof),
            "{name}"
        );
    }
}

#[test]
fn fs_wrong_number_of_responses_is_rejected_without_panicking() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xF5_0002);
    let Fixture { stmt, witness } = mixed::<E>(&mut rng);
    let rel = stmt.build();
    let proof = fiat_shamir::prove(&rel, &witness, b"ctx", &mut rng).unwrap();

    for len in [0usize, 1, 2, 4, 64] {
        let mut bad = proof.clone();
        bad.responses.resize(len, Fr::one());
        assert!(!fiat_shamir::verify(&rel, b"ctx", &bad), "{len} responses");
    }
    // ... also against the empty relation, and an empty proof against a real one
    let empty = PairingRelation::<E>::new();
    assert!(!fiat_shamir::verify(&empty, b"ctx", &proof));
    let nothing = FSProof {
        challenge: Fr::zero(),
        responses: vec![],
    };
    assert!(!fiat_shamir::verify(&rel, b"ctx", &nothing));
}

#[test]
fn fs_prover_refuses_a_non_satisfying_witness() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xF5_0003);
    for (name, Fixture { stmt, witness }) in all_fixtures::<E>(&mut rng) {
        let rel = stmt.build();
        let refused = Err(Error::WitnessDoesNotSatisfyRelation);
        for i in 0..witness.len() {
            let mut wrong = witness.clone();
            wrong[i] += Fr::one();
            assert_eq!(
                fiat_shamir::prove(&rel, &wrong, b"ctx", &mut rng),
                refused,
                "{name}"
            );
        }
        // wrong lengths
        assert_eq!(
            fiat_shamir::prove(&rel, &[], b"ctx", &mut rng),
            refused,
            "{name}"
        );
        let long = [witness.clone(), vec![Fr::one()]].concat();
        assert_eq!(
            fiat_shamir::prove(&rel, &long, b"ctx", &mut rng),
            refused,
            "{name}"
        );
    }
}

/// Every statement obtained from `stmt` by changing ONE base, ONE target, one variable
/// assignment, or the shape.
fn single_element_mutations<E: Pairing>(stmt: &Statement<E>) -> Vec<(String, Statement<E>)> {
    let (d1, d2) = (E::G1::generator(), E::G2::generator());
    let mut out = Vec::new();
    let mut push = |label: String, f: &dyn Fn(&mut Statement<E>)| {
        let mut mutated = stmt.clone();
        f(&mut mutated);
        out.push((label, mutated));
    };

    for i in 0..stmt.g1.len() {
        for j in 0..stmt.g1[i].terms.len() {
            push(format!("g1[{i}].base[{j}]"), &|s| s.g1[i].terms[j].1 += d1);
        }
        push(format!("g1[{i}].target"), &|s| s.g1[i].target += d1);
    }
    for i in 0..stmt.g2.len() {
        for j in 0..stmt.g2[i].terms.len() {
            push(format!("g2[{i}].base[{j}]"), &|s| s.g2[i].terms[j].1 += d2);
        }
        push(format!("g2[{i}].target"), &|s| s.g2[i].target += d2);
    }
    for i in 0..stmt.gt.len() {
        for j in 0..stmt.gt[i].terms.len() {
            for k in 0..stmt.gt[i].terms[j].1.len() {
                push(format!("gt[{i}].term[{j}].pair[{k}].P"), &|s| {
                    s.gt[i].terms[j].1[k].0 += d1;
                });
                push(format!("gt[{i}].term[{j}].pair[{k}].Q"), &|s| {
                    s.gt[i].terms[j].1[k].1 += d2;
                });
            }
        }
        for k in 0..stmt.gt[i].target.len() {
            push(format!("gt[{i}].target.pair[{k}].P"), &|s| {
                s.gt[i].target[k].0 += d1
            });
            push(format!("gt[{i}].target.pair[{k}].Q"), &|s| {
                s.gt[i].target[k].1 += d2
            });
        }
        // Same G_T element, different pairing preimage: e(2P, Q) = e(P, 2Q). The statement is
        // bound at the level of the preimages, so this is a different statement too.
        push(format!("gt[{i}].target.pair[0] re-balanced"), &|s| {
            let (p, q) = s.gt[i].target[0];
            s.gt[i].target[0] = (p + p, q);
        });
    }

    // shape and variable assignment
    push("one more variable".into(), &|s| s.num_scalars += 1);
    if stmt.num_scalars >= 2 {
        let v = vars::<E>(stmt.num_scalars);
        if let Some(eq) = stmt.g1.first() {
            let current = eq.terms[0].0;
            let other = *v.iter().find(|var| **var != current).unwrap();
            push(
                "g1[0].term[0] re-assigned to another variable".into(),
                &|s| {
                    s.g1[0].terms[0].0 = other;
                },
            );
        }
    }
    if stmt.g1.len() >= 2 {
        push("g1 equations swapped".into(), &|s| s.g1.swap(0, 1));
        push("g1 equation dropped".into(), &|s| {
            s.g1.pop();
        });
    }
    if let Some(eq) = stmt.g1.first() {
        push("g1 equation duplicated".into(), &|s| s.g1.push(eq.clone()));
    }
    if stmt.gt.len() >= 2 {
        push("gt equations swapped".into(), &|s| s.gt.swap(0, 1));
    }
    out
}

/// Regression test for the weak Fiat-Shamir break (W1 in the reference-implementation review,
/// F1 in the hostile review of the specification): a proof is bound to EVERY base and EVERY
/// target of its statement, so none of them can be replaced after proving.
#[test]
fn fs_rejects_every_change_of_the_statement() {
    type E = Bls12_381;
    let mut rng = StdRng::seed_from_u64(0xF5_0004);
    let mut checked = Vec::new();
    for (name, Fixture { stmt, witness }) in all_fixtures::<E>(&mut rng) {
        let rel = stmt.build();
        let proof = fiat_shamir::prove(&rel, &witness, b"ctx", &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, b"ctx", &proof));
        let mutations = single_element_mutations(&stmt);
        for (label, mutated) in &mutations {
            assert!(
                !fiat_shamir::verify(&mutated.build(), b"ctx", &proof),
                "{name}: proof survived the mutation {label}"
            );
        }
        checked.push(mutations.len());
    }
    // Guard against a silently empty loop. Per fixture: one mutation per base, per target and
    // per side of every pairing preimage, one re-balancing per G_T equation, plus the shape
    // mutations that apply (G1: 5+5, G2: 5+1, GT: 7+1, mixed: 5+3+7+13 and 6).
    assert_eq!(checked, [10, 6, 8, 34]);
}

/// The "weak" transform that hashes `ctx` and the commitment but NOT the statement.
fn weak_challenge<R: LinearRelation>(ctx: &[u8], commitment: &R::Image) -> R::Scalar {
    let mut t: Transcript = h1_transcript(ctx);
    t.append_serializable(b"commitment", commitment).unwrap();
    t.challenge_scalar()
}

fn weak_verify<R: LinearRelation>(rel: &R, ctx: &[u8], proof: &FSProof<R::Scalar>) -> bool {
    rel.recompute_commitment(&proof.challenge, &proof.responses)
        .is_ok_and(|a| weak_challenge::<R>(ctx, &a) == proof.challenge)
}

/// MOUNTS the weak Fiat-Shamir attack on an attestation-shaped relation
/// `{ T = H^usk  ∧  Σ-PS possession clause in usk }`.
///
/// The adversary holds ONE credential (on `usk_A`). It commits the tag clause with an
/// independent mask `r'`, learns `c`, answers `z = q + c·usk_A` for the possession clause and
/// only THEN picks the tag `T := H^{(z − r')/c}`, a valid tag of the unrelated key
/// `usk_B = usk_A + (q − r')/c`. Repeating this yields arbitrarily many pairwise-distinct
/// "attesters" from a single credential.
///
/// Against the weak transform the forgery verifies; against `fiat_shamir` it must fail,
/// because `T` is part of the hashed statement and would have to be fixed before `c`.
#[test]
fn weak_fiat_shamir_attack_is_mounted_and_fails() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xF5_0005);

    let v = vars::<E>(1);
    let usk_a = Fr::rand(&mut rng);
    let h = rand_g1::<E>(&mut rng); // htag(H_0(id))
    let possession = ps_possession_clause::<E>(v[0], usk_a, &mut rng);
    let statement_with_tag = |tag: <E as Pairing>::G1| {
        Statement::<E> {
            num_scalars: 1,
            g1: vec![LinearEquation::dlog(v[0], h, tag)],
            g2: vec![],
            gt: vec![possession.clone()],
        }
        .build()
    };
    let honest_tag = h * usk_a;

    // The adversary's commitment: possession clause with mask q, tag clause with mask r' ≠ q.
    let (q, r_prime) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let mut commitment = statement_with_tag(honest_tag).evaluate(&[q]).unwrap();
    commitment.g1[0] = h * r_prime;
    let forge_tag = |c: Fr| {
        let z = q + c * usk_a;
        // z·H − c·T = r'·H  ⇔  T = ((z − r')/c)·H ;  c ≠ 0 except with negligible probability
        let tag = h * ((z - r_prime) * c.inverse().expect("challenge is non-zero"));
        (tag, z)
    };

    // (1) The attack is real: it breaks the weak transform.
    let c_weak = weak_challenge::<PairingRelation<E>>(b"ctx", &commitment);
    let (forged_tag, z) = forge_tag(c_weak);
    assert_ne!(
        forged_tag, honest_tag,
        "a tag of a key the adversary holds no credential on"
    );
    let forged_rel = statement_with_tag(forged_tag);
    let forgery = FSProof {
        challenge: c_weak,
        responses: vec![z],
    };
    assert!(verify(&forged_rel, &commitment, &c_weak, &z_vec(z)));
    assert!(
        weak_verify(&forged_rel, b"ctx", &forgery),
        "sanity: weak FS is broken"
    );
    // ... and the forged statement is FALSE for the only key the adversary has a credential on
    assert!(!forged_rel.is_satisfied_by(&[usk_a]));

    // (2) Against the real transform the adversary must fix a tag before it sees c. Whatever
    // tag it starts from, solving for the tag afterwards changes the statement and with it c.
    assert!(!fiat_shamir::verify(&forged_rel, b"ctx", &forgery));
    let mut tag = honest_tag;
    for round in 0..8 {
        let c = fiat_shamir::challenge(&statement_with_tag(tag), b"ctx", &commitment).unwrap();
        let (next_tag, z) = forge_tag(c);
        let rel = statement_with_tag(next_tag);
        // the algebra of the forgery is fine for the interactive verifier with THIS c ...
        assert!(verify(&rel, &commitment, &c, &z_vec(z)));
        // ... but c is not the Fiat-Shamir challenge of the statement containing the new tag
        let forgery = FSProof {
            challenge: c,
            responses: vec![z],
        };
        assert!(
            !fiat_shamir::verify(&rel, b"ctx", &forgery),
            "round {round}"
        );
        tag = next_tag; // chase the fixed point; it never arrives
    }
}

fn z_vec<F: Field>(z: F) -> Vec<F> {
    vec![z]
}

/// Same attack on a BASE instead of a target: the statement `T = B^x` with an
/// adversary-controlled base (the role `cred*` plays in an attestation).
#[test]
fn weak_fiat_shamir_attack_on_a_base_fails() {
    type G = <Bls12_381 as Pairing>::G1;
    type Fr = <Bls12_381 as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xF5_0006);
    let target = G::rand(&mut rng);
    let relation_with_base = |base: G| {
        let mut rel = GroupRelation::<G>::new();
        let x = rel.alloc_scalar();
        rel.add_equation(LinearEquation::dlog(x, base, target))
            .unwrap();
        rel
    };
    // Adversary knows no discrete logarithm of `target`. It fixes A and z, and solves
    // z·B − c·T = A for the base: B = (A + c·T)/z.
    let (a, z) = (G::rand(&mut rng), Fr::rand(&mut rng));
    let forge_base = |c: Fr| (a + target * c) * z.inverse().expect("z is non-zero");

    let c_weak = weak_challenge::<GroupRelation<G>>(b"ctx", &vec![a]);
    let rel = relation_with_base(forge_base(c_weak));
    let forgery = FSProof {
        challenge: c_weak,
        responses: vec![z],
    };
    assert!(
        weak_verify(&rel, b"ctx", &forgery),
        "sanity: weak FS is broken"
    );
    assert!(!fiat_shamir::verify(&rel, b"ctx", &forgery));

    let mut base = G::generator();
    for round in 0..8 {
        let c = fiat_shamir::challenge(&relation_with_base(base), b"ctx", &vec![a]).unwrap();
        base = forge_base(c);
        let forgery = FSProof {
            challenge: c,
            responses: vec![z],
        };
        assert!(verify(&relation_with_base(base), &vec![a], &c, &[z]));
        assert!(
            !fiat_shamir::verify(&relation_with_base(base), b"ctx", &forgery),
            "round {round}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Proof encoding
// ---------------------------------------------------------------------------------------------

#[test]
fn fs_proofs_survive_the_wire_and_reject_malformed_bytes() {
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xF5_0007);
    let Fixture { stmt, witness } = mixed::<E>(&mut rng);
    let rel = stmt.build();
    let proof = fiat_shamir::prove(&rel, &witness, b"ctx", &mut rng).unwrap();

    let bytes = proof.to_bytes().unwrap();
    let decoded = FSProof::<Fr>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, proof);
    assert!(fiat_shamir::verify(&rel, b"ctx", &decoded));

    // trailing byte, truncation, non-canonical scalar, hostile length prefix
    assert_eq!(
        FSProof::<Fr>::from_bytes(&[bytes.clone(), vec![0]].concat()),
        Err(Error::TrailingBytes)
    );
    assert!(FSProof::<Fr>::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut non_canonical = bytes.clone();
    non_canonical[..32].fill(0xff);
    assert!(FSProof::<Fr>::from_bytes(&non_canonical).is_err());
    let mut hostile = bytes.clone();
    hostile[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(FSProof::<Fr>::from_bytes(&hostile).is_err());

    // a flipped bit anywhere in the scalars either fails to decode or fails to verify
    for position in [0usize, 31, 40, 71, bytes.len() - 1] {
        let mut flipped = bytes.clone();
        flipped[position] ^= 0x01;
        let accepted = FSProof::<Fr>::from_bytes(&flipped)
            .is_ok_and(|p| fiat_shamir::verify(&rel, b"ctx", &p));
        assert!(!accepted, "bit flip at byte {position}");
    }

    // compact fixed-format encoding: (1 + n) scalars, n taken from the statement
    let mut compact = Vec::new();
    proof.serialize_compact(&mut compact).unwrap();
    assert_eq!(compact.len(), 32 * (1 + rel.num_scalars()));
    let decoded = FSProof::<Fr>::deserialize_compact(&compact[..], rel.num_scalars()).unwrap();
    assert_eq!(decoded, proof);
}

// ---------------------------------------------------------------------------------------------
// Designated-verifier statements (the Σ-MAC pattern of §3.2.4)
// ---------------------------------------------------------------------------------------------

/// Prover and designated verifier build the SAME statement from different knowledge: the
/// prover computes the target `X = (U')^usk` from its witness, the verifier derives it from
/// `dvk = (x, y_1, y_2)` as `X = (V' (U')^{-x-y_2 φ})^{1/y_1}`. Compact proofs then verify, and
/// a pair `(U', V')` that is not a MAC on the proven `usk` is rejected.
#[test]
fn designated_verifier_statement_is_rebuilt_from_the_key() {
    type G = <Bls12_381 as Pairing>::G1;
    type Fr = <Bls12_381 as Pairing>::ScalarField;
    let mut rng = StdRng::seed_from_u64(0xD7_0001);

    let (x, y1, y2) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
    let (usk, phi) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let h = G::rand(&mut rng); // htag(s)
    let tag = h * usk;
    let u = G::rand(&mut rng);
    let v = u * (x + y1 * usk + y2 * phi); // a MAC on (usk, φ), already re-randomized

    let relation = |u: G, target: G| {
        let mut rel = GroupRelation::<G>::new();
        let k = rel.alloc_scalar();
        rel.add_equation(LinearEquation::dlog(k, h, tag)).unwrap();
        rel.add_equation(LinearEquation::dlog(k, u, target))
            .unwrap();
        rel
    };
    let verifier_target =
        |u: G, v: G| (v - u * (x + y2 * phi)) * y1.inverse().expect("y_1 is non-zero by KeyGen");

    // prover: no key material
    let prover_rel = relation(u, u * usk);
    let proof = fiat_shamir::prove(&prover_rel, &[usk], b"ctx", &mut rng).unwrap();

    // verifier: derives the target from dvk
    let verifier_rel = relation(u, verifier_target(u, v));
    assert_eq!(prover_rel, verifier_rel);
    assert!(fiat_shamir::verify(&verifier_rel, b"ctx", &proof));

    // a MAC on a different key, or a mauled V', changes the verifier's target: rejected
    let v_other = u * (x + y1 * (usk + Fr::one()) + y2 * phi);
    assert!(!fiat_shamir::verify(
        &relation(u, verifier_target(u, v_other)),
        b"ctx",
        &proof
    ));
    let v_mauled = v + G::generator();
    assert!(!fiat_shamir::verify(
        &relation(u, verifier_target(u, v_mauled)),
        b"ctx",
        &proof
    ));
}
