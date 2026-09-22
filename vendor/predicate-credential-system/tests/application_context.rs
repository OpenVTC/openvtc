//! Application contexts (implementation note, not in the paper): `attest_in_context`,
//! `check_attestation_in_context`, `prove_in_context`, `check_proof_in_context` and
//! `issue_in_context`, through the PUBLIC API only.
//!
//! What has to hold, for every base with `Tag_DDH`:
//!
//! * The round trip: attestations under their own contexts, a proof under its own context,
//!   verification, proof-gated issuance and `Unblind`.
//! * Binding: an attestation or a proof verifies under the context it was made under and under
//!   no other one, including "no context" (`None` and `Some(&[])` are different contexts).
//! * The prover cannot move an attestation to another context: `prove_in_context` runs
//!   `CheckAtts_P` under the contexts it is given, and the verifier rebuilds them.
//! * Tags do not depend on the context: one attester for one `id` counts once, whatever
//!   contexts its attestations carry (`DuplicateAttester`).
//! * Backward compatibility: without an application context the Fiat-Shamir contexts are the
//!   paper's, byte for byte.
//!
//! All runs are seeded.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
use ark_bls12_381::{Bls12_381, G1Projective};
use predicate_credential_system::{
    Error,
    cred::{self, EQ, SigmaFriendlyCredentialBase},
    hash::bls12_381::G1Hasher,
    kiprf,
    pcs::{
        AllowList, Credential, PCS, Predicate, PredicateCredentialSystem, SetupParams,
        UserSecretKey,
    },
};
use rand::{SeedableRng, rngs::StdRng};

type E = Bls12_381;
type G1 = G1Projective;
type Fr = ark_bls12_381::Fr;
type DDH = kiprf::DDH<G1, G1Hasher>;

/// A deployment whose helper admits only the class `vetter/2026-09` as attesters, with three
/// vetters holding root credentials and one applicant.
struct World<B: SigmaFriendlyCredentialBase<E>> {
    pcs: PCS<E, B, DDH, AllowList<Fr>>,
    hvk: B::VerificationKey,
    hsk: predicate_credential_system::pcs::HelperSecretKey<B>,
    f_vetter: Predicate,
    vetters: Vec<(G1, UserSecretKey<E>, Credential<E, B>)>,
    applicant: (G1, UserSecretKey<E>),
}

fn world<B: SigmaFriendlyCredentialBase<E>>(rng: &mut StdRng) -> World<B> {
    let open = PCS::<E, B, DDH>::setup(SetupParams::new(b"test/app-context".to_vec())).unwrap();
    let f_vetter = Predicate::root(b"vetter/2026-09".to_vec());
    let policy = open.allow_list([&f_vetter]).unwrap();
    let pcs = PCS::<E, B, DDH, AllowList<Fr>>::from_public_parameters(
        open.public_parameters().clone(),
        policy,
    )
    .unwrap();
    let (hvk, hsk) = pcs.helper_keygen(rng);
    let vetters = (0..3)
        .map(|_| {
            let (id, usk) = pcs.user_keygen(rng).unwrap();
            let (request, state) = pcs.root_request(&hvk, &f_vetter, &id, &usk, rng).unwrap();
            let pre = pcs
                .issue_root(&hvk, &hsk, &f_vetter, &id, &request, rng)
                .unwrap();
            let cred = pcs.unblind(&hvk, &usk, &f_vetter, &pre, &state).unwrap();
            (id, usk, cred)
        })
        .collect();
    let applicant = pcs.user_keygen(rng).unwrap();
    World {
        pcs,
        hvk,
        hsk,
        f_vetter,
        vetters,
        applicant,
    }
}

fn run<B: SigmaFriendlyCredentialBase<E>>(seed: u64) {
    let rng = &mut StdRng::seed_from_u64(seed);
    let w = world::<B>(rng);
    let (pcs, hvk) = (&w.pcs, &w.hvk);
    let (id, usk) = (&w.applicant.0, &w.applicant.1);
    let f = Predicate::new(2, b"hidden-vetting".to_vec());

    let app_a: &[u8] = b"method=inPerson;serial=01";
    let app_b: &[u8] = b"method=video;serial=02";
    let app_0: &[u8] = b"challenge=7f3a;audience=did:example:vtc";

    let att = |j: usize, app: &[u8], rng: &mut StdRng| {
        let (_, vusk, vcred) = &w.vetters[j];
        pcs.attest_in_context(hvk, vusk, &w.f_vetter, vcred, id, app, rng)
            .unwrap()
    };
    let att_a = att(0, app_a, rng);
    let att_b = att(1, app_b, rng);

    // Attestations: bound to their context, and to no other one.
    assert_eq!(
        pcs.check_attestation_in_context(hvk, id, &att_a, app_a),
        Ok(())
    );
    assert_eq!(
        pcs.check_attestation_in_context(hvk, id, &att_a, app_b),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        pcs.check_attestation(hvk, id, &att_a),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        pcs.check_attestation_in_context(hvk, id, &att_a, b""),
        Err(Error::InvalidProof)
    );
    // ... and an attestation made WITHOUT a context does not verify under the empty one.
    let (_, vusk, vcred) = &w.vetters[2];
    let plain = pcs.attest(hvk, vusk, &w.f_vetter, vcred, id, rng).unwrap();
    assert!(pcs.verify_attestation(hvk, id, &plain));
    assert_eq!(
        pcs.check_attestation_in_context(hvk, id, &plain, b""),
        Err(Error::InvalidProof)
    );

    // The round trip.
    let atts = [att_a.clone(), att_b.clone()];
    let apps: [&[u8]; 2] = [app_a, app_b];
    let (proof, state) = pcs
        .prove_in_context(hvk, &f, id, usk, &atts, &apps, app_0, rng)
        .unwrap();
    assert_eq!(
        pcs.check_proof_in_context(hvk, &f, id, &proof, &apps, app_0),
        Ok(())
    );

    // The proof is bound to its own context and to the attestations' contexts.
    assert_eq!(
        pcs.check_proof_in_context(hvk, &f, id, &proof, &apps, b"challenge=other"),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        pcs.check_proof_in_context(hvk, &f, id, &proof, &[app_b, app_a], app_0),
        Err(Error::InvalidAttestation)
    );
    assert_eq!(
        pcs.check_proof_in_context(hvk, &f, id, &proof, &[app_a], app_0),
        Err(Error::WrongAttestationCount {
            expected: 2,
            actual: 1
        })
    );
    assert!(!pcs.verify_proof(hvk, &f, id, &proof));

    // The prover cannot claim another context for an attestation.
    assert_eq!(
        pcs.prove_in_context(hvk, &f, id, usk, &atts, &[app_a, app_a], app_0, rng)
            .err(),
        Some(Error::InvalidAttestation)
    );

    // Tags ignore the context: the same vetter under two contexts counts once.
    let att_a2 = att(0, app_b, rng);
    assert_eq!(att_a2.tag, att_a.tag);
    assert_eq!(
        pcs.prove_in_context(
            hvk,
            &f,
            id,
            usk,
            &[att_a.clone(), att_a2],
            &[app_a, app_b],
            app_0,
            rng
        )
        .err(),
        Some(Error::DuplicateAttester)
    );

    // Proof-gated issuance under the same contexts, then Unblind (fails closed).
    assert_eq!(
        pcs.issue_in_context(hvk, &w.hsk, &f, id, &proof, &apps, b"challenge=other", rng)
            .err(),
        Some(Error::InvalidProof)
    );
    let pre = pcs
        .issue_in_context(hvk, &w.hsk, &f, id, &proof, &apps, app_0, rng)
        .unwrap();
    let cred = pcs.unblind(hvk, usk, &f, &pre, &state).unwrap();
    assert!(pcs.verify_cred(hvk, usk, &f, &cred));
}

/// Without an application context the contexts are exactly the paper's.
fn backward_compatible<B: SigmaFriendlyCredentialBase<E>>(seed: u64) {
    let rng = &mut StdRng::seed_from_u64(seed);
    let w = world::<B>(rng);
    let (pcs, hvk) = (&w.pcs, &w.hvk);
    let id = &w.applicant.0;
    let (_, vusk, vcred) = &w.vetters[0];
    let att = pcs.attest(hvk, vusk, &w.f_vetter, vcred, id, rng).unwrap();

    let paper = pcs
        .attestation_context(hvk, id, &att.phi, &att.tag, &att.shown)
        .unwrap();
    let none = pcs
        .attestation_context_with_app(hvk, id, &att.phi, &att.tag, &att.shown, None)
        .unwrap();
    let empty = pcs
        .attestation_context_with_app(hvk, id, &att.phi, &att.tag, &att.shown, Some(b""))
        .unwrap();
    assert_eq!(paper, none);
    assert_ne!(paper, empty);

    let f = Predicate::new(1, b"hidden-vetting".to_vec());
    let (proof, _) = pcs
        .prove(hvk, &f, id, &w.applicant.1, std::slice::from_ref(&att), rng)
        .unwrap();
    let c = B::encoding_from_wire(pcs.base_parameters(), &proof.encoding, id).unwrap();
    let paper = pcs
        .issuance_context(hvk, &f, id, &c, &proof.t0, &proof.attestations)
        .unwrap();
    let none = pcs
        .issuance_context_with_app(hvk, &f, id, &c, &proof.t0, &proof.attestations, None, None)
        .unwrap();
    let att_only = pcs
        .issuance_context_with_app(
            hvk,
            &f,
            id,
            &c,
            &proof.t0,
            &proof.attestations,
            Some(&[b""]),
            None,
        )
        .unwrap();
    let app_only = pcs
        .issuance_context_with_app(
            hvk,
            &f,
            id,
            &c,
            &proof.t0,
            &proof.attestations,
            None,
            Some(b""),
        )
        .unwrap();
    assert_eq!(paper, none);
    assert_ne!(paper, att_only);
    assert_ne!(paper, app_only);
    // "att-app" and "app" are different items: moving bytes between them changes the context.
    assert_ne!(att_only, app_only);
    assert!(pcs.verify_proof(hvk, &f, id, &proof));
}

#[test]
fn ps_round_trip_and_binding() {
    run::<cred::PS<E>>(0xA11C_E001);
}

#[test]
fn bbs_round_trip_and_binding() {
    run::<cred::BBS<E, G1Hasher>>(0xA11C_E002);
}

#[test]
fn eq_round_trip_and_binding() {
    run::<EQ<E>>(0xA11C_E003);
}

#[test]
fn ps_backward_compatible() {
    backward_compatible::<cred::PS<E>>(0xA11C_E004);
}

#[test]
fn bbs_backward_compatible() {
    backward_compatible::<cred::BBS<E, G1Hasher>>(0xA11C_E005);
}

#[test]
fn eq_backward_compatible() {
    backward_compatible::<EQ<E>>(0xA11C_E006);
}
