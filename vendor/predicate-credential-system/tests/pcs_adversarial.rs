//! Independent ADVERSARIAL suite for the modular threshold construction (§5.1). Every attack of
//! the reference-implementation catalogue (A1, A3-A8) and of the hostile-referee report (weak
//! Fiat-Shamir W1/F1, threshold count W2/F2, threshold-0 and path confusion F3) is MOUNTED
//! against the real code and required to fail, with the exact rejecting check asserted through
//! `check_attestation` / `check_proof` / `check_root_request`. Robustness: no verifier or decoder
//! panics on adversarial input.
//!
//! Each attack states what the adversary holds, what it does, and which check stops it. Where the
//! honest algorithm refuses to build the offending object, a cheating prover builds it from the
//! public relation and context builders so that everything about the proof verifies except the
//! one check under test. All runs are seeded.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
mod common;

use ark_bls12_381::Fr;
use ark_ec::PrimeGroup;
use ark_ff::{One, UniformRand, Zero};
use common::{
    BBS, BaseTest, DDH, DY, Deployment, E, G1, PS, SPSEQ, assert_proof_rejected,
    random_attestation, random_proof, random_root_request,
};
use predicate_credential_system::{
    Error,
    cred::{
        CredentialBase, SigmaFriendlyCredentialBase,
        conformance::Forgery,
        eq::{EQCredential, EQShownCredential},
        ps::PSPreCredential,
    },
    kiprf::{KIPRF, PCSTag},
    pcs::{
        AllowList, Attestation, Credential, IssuanceProof, PCS, Predicate,
        PredicateCredentialSystem, PublicParameters, RootRequest, SetupParams, UserSecretKey,
    },
    serialization::WireFormat,
    sigma::{FSProof, LinearRelation, fiat_shamir},
};
use rand::{SeedableRng, rngs::StdRng};

// ---------------------------------------------------------------------------------------------
// A1 — credential-free attestations from degenerate shows (per base)
// ---------------------------------------------------------------------------------------------

/// A1 / W4. The adversary holds NO credential. Per base it picks a degenerate shown credential
/// for which the possession CLAUSES of `R_att` are satisfiable under a key of its choice
/// (`σ' = (1,1)` for `Σ-PS`; `Ā = B̄ = 1`, `D = 1` for `Σ-BBS`; `M' = (1,1,1)`, `Z' = 1` for
/// `Σ-EQ`) and proves `R_att` honestly under `ctx_j`, for `k` pairwise-distinct fresh keys. The
/// bare Fiat-Shamir proof verifies; the public checks of `VerifyPossess` are what reject it, so
/// `check_attestation` returns [`Error::InvalidCredential`] and no issuance proof can carry it
/// (Theorem "Knowledge soundness": "without those checks the representation clauses are
/// satisfiable with a degenerate credential encoding under any usk_j").
fn a1_credential_free<B, T>(
    label: &[u8],
    seed: u64,
    forgeries: impl Fn(
        &B::PublicParams,
        &B::VerificationKey,
        &Fr,
        &Fr,
    ) -> Vec<Forgery<B::ShownCredential, Fr>>,
) where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    // a control: an honest attestation IS accepted
    let member = dep.root_member();
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let honest = dep.attest(&member, &id);
    assert_eq!(dep.pcs.check_attestation(&dep.hvk, &id, &honest), Ok(()));

    let pcs = &dep.pcs;
    let hvk = &dep.hvk;
    let pp = pcs.base_parameters();
    let s = pcs.tag_point(&id).unwrap();
    let phi = pcs
        .enc_pred(&Predicate::new(5, b"members".to_vec()))
        .unwrap();

    let mut forged: Vec<Attestation<E, B>> = Vec::new();
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA1);
    while forged.len() < 5 {
        let key = pcs.tag().keygen(&mut rng); // a key no credential certifies
        let tag = pcs.tag().eval(&key, &s).unwrap();
        // take the first credential-free show whose clauses are satisfiable under `key`
        for f in forgeries(pp, hvk, &phi, &key) {
            let relation = pcs
                .attestation_relation(hvk, &f.shown, &phi, &tag, &s)
                .unwrap();
            let mut witness = vec![key];
            witness.extend(&f.extra_witness);
            if !relation.is_satisfied_by(&witness) {
                continue;
            }
            let ctx = pcs
                .attestation_context(hvk, &id, &phi, &tag, &f.shown)
                .unwrap();
            let proof = fiat_shamir::prove(&relation, &witness, &ctx, &mut rng).unwrap();
            // the bare Fiat-Shamir relation IS satisfied ...
            assert!(fiat_shamir::verify(&relation, &ctx, &proof));
            assert!(pcs.tag().valid_tag(&tag, &s));
            let att = Attestation {
                tag,
                shown: f.shown,
                phi,
                proof,
            };
            // ... but the public checks of VerifyPossess reject the attestation
            assert_eq!(
                pcs.check_attestation(hvk, &id, &att),
                Err(Error::InvalidCredential)
            );
            forged.push(att);
            break;
        }
    }
    // k = 5 pairwise-distinct tags, and no issuance proof can be built on them
    let tags: std::collections::HashSet<_> =
        forged.iter().map(|a| a.tag.to_bytes().unwrap()).collect();
    assert_eq!(tags.len(), 5);
    let f5 = Predicate::new(5, b"members".to_vec());
    assert_eq!(
        dep.pcs
            .prove(&dep.hvk, &f5, &id, &usk, &forged, &mut dep.rng)
            .err(),
        Some(Error::InvalidAttestation)
    );
}

#[test]
fn a1_credential_free_ps() {
    a1_credential_free::<PS, DDH>(
        b"adv/a1/ps",
        0xad01_0001,
        predicate_credential_system::cred::ps::credential_free_forgeries,
    );
}
#[test]
fn a1_credential_free_bbs() {
    a1_credential_free::<BBS, DY>(
        b"adv/a1/bbs",
        0xad01_0002,
        predicate_credential_system::cred::bbs::credential_free_forgeries,
    );
}
#[test]
fn a1_credential_free_eq() {
    a1_credential_free::<SPSEQ, DDH>(
        b"adv/a1/eq",
        0xad01_0003,
        predicate_credential_system::cred::eq::credential_free_forgeries,
    );
}

// ---------------------------------------------------------------------------------------------
// A3 / A8 — one credential cannot back a tag under another key
// ---------------------------------------------------------------------------------------------

/// A3 (`Σ-EQ`) and A8 (`Σ-BBS`). The adversary holds ONE real credential and re-randomizes it
/// honestly, but wants attestations whose tags belong to OTHER keys. Because `R_att` shares the
/// single variable `usk` between the possession clauses (bound to the credential's key by the
/// SIGNED base `M'_1` / the opening `h_1^{-usk}`) and the tag clause, no single witness satisfies
/// both for a foreign tag: the honest prover cannot produce the proof.
fn one_credential_foreign_tags<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let member = dep.root_member();
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    let witness = PCS::<E, B, T>::attestation_witness(&show.m_hid, &show.show_state);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);

    // control: the attester's own tag has a witness
    let honest = pcs
        .attestation_relation(hvk, &show.shown, &show.phi, &show.tag, &show.s)
        .unwrap();
    assert!(honest.is_satisfied_by(&witness));

    let mut rng = StdRng::seed_from_u64(seed ^ 0x3A8);
    let mut tried = 0;
    while tried < 5 {
        let key = pcs.tag().keygen(&mut rng);
        if key == *member.usk.expose_scalar() {
            continue;
        }
        tried += 1;
        let foreign_tag = pcs.tag().eval(&key, &show.s).unwrap();
        let rel = pcs
            .attestation_relation(hvk, &show.shown, &show.phi, &foreign_tag, &show.s)
            .unwrap();
        // neither the credential's key nor the tag's key is a witness
        assert!(!rel.is_satisfied_by(&witness));
        let mut with_key = witness.to_vec();
        with_key[0] = key;
        assert!(!rel.is_satisfied_by(&with_key));
        let ctx = pcs
            .attestation_context(hvk, &id, &show.phi, &foreign_tag, &show.shown)
            .unwrap();
        assert_eq!(
            fiat_shamir::prove(&rel, &witness, &ctx, &mut rng).err(),
            Some(Error::WitnessDoesNotSatisfyRelation)
        );
    }
}

#[test]
fn a3_eq_one_credential_distinct_tag_keys() {
    one_credential_foreign_tags::<SPSEQ, DDH>(b"adv/a3/eq", 0xad03_0001);
}
#[test]
fn a8_bbs_tag_under_a_key_the_credential_is_not_for() {
    one_credential_foreign_tags::<BBS, DDH>(b"adv/a8/bbs", 0xad08_0001);
}

/// A4 (`Σ-EQ`). On a re-randomized honest signature `(M', cred')` the adversary swaps the class
/// invariant, showing `M_B = (M'_1, (M'_1)^{k_B}, M'_3)` for a fresh key `k_B` it holds no
/// credential on. The possession clause `M'_2 = (M'_1)^usk` would then "prove" `usk = k_B`, but
/// the first pairing equation of the SPS-EQ `Verify` inside `verify_possess_public` no longer
/// holds (the signed target `Z'` certifies `M'_2 = (M'_1)^usk`, not `k_B`), so `check_attestation`
/// returns [`Error::InvalidCredential`]. 100 seeded trials.
#[test]
fn a4_eq_forged_key_vector_on_an_adapted_signature() {
    let mut dep = Deployment::<SPSEQ, DDH>::open(b"adv/a4/eq", 0xad04_0001);
    let member = dep.root_member();
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);
    let real: &EQShownCredential<E> = &show.shown;

    // control: the honest, unmodified show passes the public checks
    assert!(SPSEQ::verify_possess_public(
        pcs.base_parameters(),
        hvk,
        real,
        &show.phi
    ));

    let mut rng = StdRng::seed_from_u64(0xad04_0002);
    for _ in 0..100 {
        let k_b = Fr::rand(&mut rng);
        let forged = EQShownCredential {
            message: predicate_credential_system::cred::eq::EQMessage {
                m1: real.message.m1,
                m2: real.message.m1 * k_b, // claim usk = k_B against the signed base M'_1
                m3: real.message.m3,
            },
            credential: EQCredential {
                z: real.credential.z,
                y: real.credential.y,
                y_tilde: real.credential.y_tilde,
            },
        };
        // the public checks reject it (the signature does not certify M'_2 = (M'_1)^{k_B})
        assert!(!SPSEQ::verify_possess_public(
            pcs.base_parameters(),
            hvk,
            &forged,
            &show.phi
        ));
        let tag = pcs.tag().eval(&k_b, &show.s).unwrap();
        let att = Attestation {
            tag,
            shown: forged,
            phi: show.phi,
            proof: FSProof {
                challenge: Fr::rand(&mut rng),
                responses: vec![Fr::rand(&mut rng)],
            },
        };
        assert_eq!(
            pcs.check_attestation(hvk, &id, &att),
            Err(Error::InvalidCredential)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// W1 / F1 — weak Fiat-Shamir AT THE PCS LEVEL (the regression test for hazard D1)
// ---------------------------------------------------------------------------------------------

/// W1 / W1b / F1. An adversary holding ONE valid credential plays a cheating prover: it commits
/// and derives the challenge `c = H_1(ctx_j ‖ statement ‖ A)` for an HONEST attestation on its own
/// tag `T_A`, obtaining an accepting `(A, c, z)`. It then tries to reuse that `(A, c, z)` for a
/// DIFFERENT tag `T_B` chosen AFTER the challenge (W1) — the reference-implementation break that
/// minted `k` pairwise-distinct tags from one credential — or for a different shown credential
/// (W1b). It fails because the challenge absorbs `ctx_j` (which contains `T_j` and `cred*_j`) AND
/// the full statement (whose tag clause target is `T_j`): the verifier recomputes a different
/// challenge and returns [`Error::InvalidProof`]. This is the regression test for divergence D1
/// (the reference implementations hashed a thin `[hvk, id, φ]` context and were fully broken).
fn weak_fiat_shamir<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let member = dep.root_member();
    let member_2 = dep.root_member();
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    let show_2 = dep.att_show(&member_2, &id);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);

    // the adversary's honest, accepting attestation on its OWN tag T_A
    let rel_a = pcs
        .attestation_relation(hvk, &show.shown, &show.phi, &show.tag, &show.s)
        .unwrap();
    let ctx_a = pcs
        .attestation_context(hvk, &id, &show.phi, &show.tag, &show.shown)
        .unwrap();
    let witness = PCS::<E, B, T>::attestation_witness(&show.m_hid, &show.show_state);
    let mut prove_rng = StdRng::seed_from_u64(seed ^ 0x717);
    let stolen = fiat_shamir::prove(&rel_a, &witness, &ctx_a, &mut prove_rng).unwrap();
    // control: it verifies for T_A
    let control = Attestation {
        tag: show.tag,
        shown: show.shown.clone(),
        phi: show.phi,
        proof: stolen.clone(),
    };
    assert_eq!(pcs.check_attestation(hvk, &id, &control), Ok(()));

    // W1: retarget the SAME (A, c, z) to k = 5 distinct FOREIGN tags chosen after the challenge.
    let mut rng = StdRng::seed_from_u64(seed ^ 0x1B1);
    for _ in 0..5 {
        let key = pcs.tag().keygen(&mut rng);
        let foreign = pcs.tag().eval(&key, &show.s).unwrap();
        let att = Attestation {
            tag: foreign,
            shown: show.shown.clone(),
            phi: show.phi,
            proof: stolen.clone(),
        };
        assert_eq!(
            pcs.check_attestation(hvk, &id, &att),
            Err(Error::InvalidProof),
            "the challenge is bound to T_j, so a tag chosen after it is rejected"
        );
    }

    // W1b: swap the shown credential after the challenge (cred*_j is in ctx_j and its bases are
    // in the statement, so the challenge no longer matches).
    let att = Attestation {
        tag: show.tag,
        shown: show_2.shown.clone(),
        phi: show.phi,
        proof: stolen,
    };
    assert_eq!(
        pcs.check_attestation(hvk, &id, &att),
        Err(Error::InvalidProof)
    );

    // and the honest algorithm cannot mint two distinct tags for one credential either: the tag
    // is deterministic, so a second attestation for the same id repeats it (Theorem "Attester
    // anonymity"); a subject cannot assemble k distinct tags from one endorser.
    let a = dep.attest(&member, &id);
    let b = dep.attest(&member, &id);
    assert_eq!(a.tag, b.tag);
    // a self-consistent proof would need k distinct credentialed keys; one endorser gives one tag
    let f2 = Predicate::new(2, b"members".to_vec());
    assert_eq!(
        dep.pcs
            .prove(&dep.hvk, &f2, &id, &usk, &[a, b], &mut dep.rng)
            .err(),
        Some(Error::DuplicateAttester)
    );
}

#[test]
fn weak_fiat_shamir_ps_ddh() {
    weak_fiat_shamir::<PS, DDH>(b"adv/w1/ps+ddh", 0xad11_0001);
}
#[test]
fn weak_fiat_shamir_bbs_ddh() {
    weak_fiat_shamir::<BBS, DDH>(b"adv/w1/bbs+ddh", 0xad11_0002);
}
#[test]
fn weak_fiat_shamir_eq_ddh() {
    weak_fiat_shamir::<SPSEQ, DDH>(b"adv/w1/eq+ddh", 0xad11_0003);
}

// ---------------------------------------------------------------------------------------------
// W2 / F2 — the threshold count is bound to the predicate
// ---------------------------------------------------------------------------------------------

/// W2 / F2 / D4. A proof carries EXACTLY `k = f.threshold` attestations, and `f_k` itself (not
/// only `φ = EncPred(f_k)`, which is a hash) enters `ctx_0`. So a 0/`k-1`/`k+1`-attestation proof
/// is [`Error::WrongAttestationCount`]; a proof for `f_3` presented for `f_5` or `f_2` is a count
/// mismatch; and a proof with the right count but a different LABEL fails Fiat-Shamir
/// ([`Error::InvalidProof`]). The reference implementations checked no count and issued
/// under-threshold credentials.
#[test]
fn threshold_count_is_bound_to_the_predicate() {
    let mut dep = Deployment::<PS, DDH>::open(b"adv/w2", 0xad20_0001);
    let roots = dep.root_members(3);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts3 = dep.attestations(&roots, &id);
    let members = |k| Predicate::new(k, b"members".to_vec());

    // real proofs at thresholds 1, 2, 3
    let (proof1, _) = dep.prove_ok(&members(1), &id, &usk, &atts3[..1]);
    let (proof2, _) = dep.prove_ok(&members(2), &id, &usk, &atts3[..2]);
    let (proof3, _) = dep.prove_ok(&members(3), &id, &usk, &atts3[..3]);

    // wrong counts: 0 / k-1 / k+1 for f_2 (the honest prover refuses too)
    for wrong in [&atts3[..0], &atts3[..1], &atts3[..3]] {
        assert_eq!(
            dep.pcs
                .prove(&dep.hvk, &members(2), &id, &usk, wrong, &mut dep.rng)
                .err(),
            Some(Error::WrongAttestationCount {
                expected: 2,
                actual: wrong.len()
            })
        );
    }
    // a proof for f_3 presented for f_5 and for f_2 (a count mismatch, checked before the proof)
    assert_proof_rejected(
        &mut dep,
        &members(5),
        &id,
        &proof3,
        &Error::WrongAttestationCount {
            expected: 5,
            actual: 3,
        },
    );
    assert_proof_rejected(
        &mut dep,
        &members(2),
        &id,
        &proof3,
        &Error::WrongAttestationCount {
            expected: 2,
            actual: 3,
        },
    );
    // same label, different threshold, the other way round
    assert_proof_rejected(
        &mut dep,
        &members(2),
        &id,
        &proof1,
        &Error::WrongAttestationCount {
            expected: 2,
            actual: 1,
        },
    );
    // same threshold, DIFFERENT label: the count matches, but f enters ctx_0
    assert_proof_rejected(
        &mut dep,
        &Predicate::new(2, b"guests".to_vec()),
        &id,
        &proof2,
        &Error::InvalidProof,
    );
    // control: each proof verifies under its own predicate
    assert!(dep.pcs.verify_proof(&dep.hvk, &members(1), &id, &proof1));
    assert!(dep.pcs.verify_proof(&dep.hvk, &members(2), &id, &proof2));
    assert!(dep.pcs.verify_proof(&dep.hvk, &members(3), &id, &proof3));
}

// ---------------------------------------------------------------------------------------------
// F3 — threshold-0 and the root/ordinary path do not mix
// ---------------------------------------------------------------------------------------------

/// F3. Threshold 0 is rejected on the ordinary `Prove → VerifyProof → Issue` path
/// ([`Error::ZeroThreshold`]); a root request and an ordinary proof are not interchangeable (their
/// contexts use different oracle labels); and a root request is bound to its `id`.
#[test]
fn threshold_zero_and_the_two_paths_do_not_mix() {
    let mut dep = Deployment::<PS, DDH>::open(b"adv/f3", 0xad30_0001);
    let roots = dep.root_members(2);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let (id_prime, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);
    let f2 = Predicate::new(2, b"members".to_vec());
    let (proof2, _) = dep.prove_ok(&f2, &id, &usk, &atts);

    // f_0 on the ordinary path
    let f0 = Predicate::new(0, b"members".to_vec());
    assert_eq!(
        dep.pcs
            .prove(&dep.hvk, &f0, &id, &usk, &[], &mut dep.rng)
            .err(),
        Some(Error::ZeroThreshold)
    );
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f0, &id, &proof2),
        Err(Error::ZeroThreshold)
    );
    assert_eq!(
        dep.pcs
            .prove(&dep.hvk, &dep.f_root.clone(), &id, &usk, &[], &mut dep.rng)
            .err(),
        Some(Error::ZeroThreshold)
    );

    // a root request replayed as an ordinary issuance proof (zero attestations)
    let (request, _) = dep
        .pcs
        .root_request(&dep.hvk, &dep.f_root.clone(), &id, &usk, &mut dep.rng)
        .unwrap();
    let as_proof = IssuanceProof {
        attestations: Vec::new(),
        encoding: request.encoding,
        t0: request.t0,
        proof: request.proof.clone(),
    };
    assert_eq!(
        dep.pcs
            .check_proof(&dep.hvk, &dep.f_root.clone(), &id, &as_proof),
        Err(Error::ZeroThreshold)
    );
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id, &as_proof),
        Err(Error::WrongAttestationCount {
            expected: 2,
            actual: 0
        })
    );

    // an ordinary proof replayed as a root request (the root context differs)
    let as_request = RootRequest {
        encoding: proof2.encoding,
        t0: proof2.t0,
        proof: proof2.proof.clone(),
    };
    assert_eq!(
        dep.pcs
            .check_root_request(&dep.hvk, &dep.f_root.clone(), &id, &as_request),
        Err(Error::InvalidProof)
    );

    // a root request for id is not one for id'
    assert!(
        dep.pcs
            .verify_root_request(&dep.hvk, &dep.f_root.clone(), &id, &request)
    );
    assert!(
        !dep.pcs
            .verify_root_request(&dep.hvk, &dep.f_root.clone(), &id_prime, &request)
    );
}

// ---------------------------------------------------------------------------------------------
// A5 — self-attestation cannot be hidden
// ---------------------------------------------------------------------------------------------

/// A5. A credentialed user requests a further credential and endorses ITSELF (its own tag among
/// the attesters). `CheckAtts_P` requires `T_0 ∉ {T_j}` and `π_0` binds `T_0` to `usk`, so the
/// self-attestation is caught ([`Error::SelfAttestation`]) and cannot be hidden by substituting a
/// fake `T_0`: a random or another user's `T_0` breaks `π_0` ([`Error::InvalidProof`]), and
/// `T_0 = 1` fails `ValidTag` ([`Error::InvalidTag`]).
#[test]
fn self_attestation_cannot_be_hidden() {
    let mut dep = Deployment::<PS, DDH>::open(b"adv/a5", 0xad50_0001);
    let roots = dep.root_members(3);
    let id_0 = roots[0].id;
    let usk_0 = UserSecretKey::<E>::from_scalar(*roots[0].usk.expose_scalar());
    let own = dep.attest(&roots[0], &id_0); // the requester's own attester tag
    let other1 = dep.attest(&roots[1], &id_0);
    let other2 = dep.attest(&roots[2], &id_0);
    let f2 = Predicate::new(2, b"members".to_vec());

    // honest prove refuses a set that contains the requester's own attestation (either order)
    for list in [
        vec![own.clone(), other1.clone()],
        vec![other1.clone(), own.clone()],
    ] {
        assert_eq!(
            dep.pcs
                .prove(&dep.hvk, &f2, &id_0, &usk_0, &list, &mut dep.rng)
                .err(),
            Some(Error::SelfAttestation)
        );
    }
    // control: two OTHER endorsers are fine, and the proof's T_0 IS the requester's own tag
    let (good, _) = dep
        .pcs
        .prove(
            &dep.hvk,
            &f2,
            &id_0,
            &usk_0,
            &[other1.clone(), other2.clone()],
            &mut dep.rng,
        )
        .unwrap();
    assert!(dep.pcs.verify_proof(&dep.hvk, &f2, &id_0, &good));
    assert_eq!(
        good.t0, own.tag,
        "T_0 = Tag(usk_0, H_0(id_0)) is the requester's own attester tag"
    );

    // a cheating proof that USES the own attestation and carries the honest T_0 = own.tag
    let self_set = vec![own.clone(), other1.clone()];
    let cheat = dep.cheat_proof(&f2, &id_0, &usk_0, &self_set);
    assert_eq!(cheat.t0, own.tag);
    // T_0 ∈ {T_j}: self-attestation is caught
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id_0, &cheat),
        Err(Error::SelfAttestation)
    );

    // hide it by substituting T_0. π_0 binds T_0 to usk_0, so a random or another user's tag
    // breaks π_0 (InvalidProof), and the identity fails ValidTag (InvalidTag).
    let s = dep.pcs.tag_point(&id_0).unwrap();
    let mut random_t0 = cheat.clone();
    random_t0.t0 = dep.pcs.tag().eval(&Fr::rand(&mut dep.rng), &s).unwrap();
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id_0, &random_t0),
        Err(Error::InvalidProof)
    );
    let mut others_t0 = cheat.clone();
    others_t0.t0 = other2.tag; // another user's tag, not in {T_j}
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id_0, &others_t0),
        Err(Error::InvalidProof)
    );
    let mut identity_t0 = cheat;
    identity_t0.t0 = G1::zero();
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id_0, &identity_t0),
        Err(Error::InvalidTag)
    );
}

// ---------------------------------------------------------------------------------------------
// A6 — a proof is bound to its context (id, hvk, predicate, deployment)
// ---------------------------------------------------------------------------------------------

/// A6. `π_0` is bound to `ctx_0 = (pp, hvk, f_k, id, C, T_0, (att_j)_j)`, which the verifier
/// REBUILDS. A proof made for one statement is worthless for another: presenting it for another
/// `id`, another `hvk` or another predicate is rejected, and a `π_0` produced over an attacker's
/// context does not verify.
#[test]
fn a_proof_is_bound_to_its_context() {
    let mut dep = Deployment::<PS, DDH>::open(b"adv/a6", 0xad60_0001);
    let roots = dep.root_members(2);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let (id_prime, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);
    let f2 = Predicate::new(2, b"members".to_vec());
    let (proof, state) = dep.prove_ok(&f2, &id, &usk, &atts);

    // another id: the attestations were made for id, so they do not verify for id'
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id_prime, &proof),
        Err(Error::InvalidAttestation)
    );
    // another helper key
    let (hvk2, _) = dep.pcs.helper_keygen(&mut dep.rng);
    assert!(!dep.pcs.verify_proof(&hvk2, &f2, &id, &proof));
    // another predicate label (same threshold)
    assert!(!dep.pcs.verify_proof(
        &dep.hvk,
        &Predicate::new(2, b"admins".to_vec()),
        &id,
        &proof
    ));

    // π_0 produced over an attacker-chosen context is worth nothing: the verifier rebuilds ctx_0
    let mut bogus = proof.clone();
    let c = <PS as SigmaFriendlyCredentialBase<E>>::encoding_from_wire(
        dep.pcs.base_parameters(),
        &bogus.encoding,
        &id,
    )
    .unwrap();
    let s = dep.pcs.tag_point(&id).unwrap();
    let phi = dep.pcs.enc_pred(&f2).unwrap();
    let rel = dep
        .pcs
        .issuance_relation(&dep.hvk, &c, &phi, &id, &bogus.t0, &s)
        .unwrap();
    bogus.proof = fiat_shamir::prove(
        &rel,
        &state.witness(),
        b"a context of the prover's choosing",
        &mut dep.rng,
    )
    .unwrap();
    assert!(fiat_shamir::verify(
        &rel,
        b"a context of the prover's choosing",
        &bogus.proof
    ));
    assert_eq!(
        dep.pcs.check_proof(&dep.hvk, &f2, &id, &bogus),
        Err(Error::InvalidProof)
    );
}

// ---------------------------------------------------------------------------------------------
// Duplicate attester, reordering, non-transferability
// ---------------------------------------------------------------------------------------------

/// One attester attesting twice with two re-randomized shows carries the SAME tag (the tag is
/// deterministic in `(usk, id)`), so `CheckAtts_P` rejects the set with [`Error::DuplicateAttester`]
/// — and reordering does not hide the duplicate (tags are compared as a set).
fn duplicate_attester<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let roots = dep.root_members(1);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let att = dep.attest(&roots[0], &id);
    let again = dep.attest(&roots[0], &id);
    assert_eq!(att.tag, again.tag);
    assert_ne!(att.shown, again.shown, "a fresh re-randomization each time");
    let f2 = Predicate::new(2, b"members".to_vec());
    for list in [
        vec![att.clone(), again.clone()],
        vec![again.clone(), att.clone()],
        vec![att.clone(), att.clone()],
    ] {
        assert_eq!(
            dep.pcs
                .prove(&dep.hvk, &f2, &id, &usk, &list, &mut dep.rng)
                .err(),
            Some(Error::DuplicateAttester)
        );
    }
}

#[test]
fn duplicate_attester_ps() {
    duplicate_attester::<PS, DDH>(b"adv/dup/ps", 0xadd0_0001);
}
#[test]
fn duplicate_attester_bbs() {
    duplicate_attester::<BBS, DY>(b"adv/dup/bbs", 0xadd0_0002);
}

/// Remark "Non-transferability of proofs". An attestation made for `id'` grafted into a proof for
/// `id` is rejected (its tag and challenge are bound to `id'`), a whole proof for `id` is not a
/// proof for `id'`, and a thief holding another key cannot redeem attestations meant for `id`
/// (`π_0` requires knowledge of the `usk` behind `id`).
#[test]
fn attestations_are_not_transferable() {
    let mut dep = Deployment::<PS, DDH>::open(b"adv/xfer", 0xadf0_0001);
    let roots = dep.root_members(2);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let (id_prime, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);
    let f2 = Predicate::new(2, b"members".to_vec());

    // an attestation for id' does not verify for id
    let for_prime = dep.attest(&roots[0], &id_prime);
    assert!(!dep.pcs.verify_attestation(&dep.hvk, &id, &for_prime));
    assert_eq!(
        dep.pcs.check_attestation(&dep.hvk, &id, &for_prime),
        Err(Error::InvalidProof)
    );
    // grafting it into a proof for id fails
    let grafted = vec![atts[0].clone(), for_prime];
    assert_eq!(
        dep.pcs
            .prove(&dep.hvk, &f2, &id, &usk, &grafted, &mut dep.rng)
            .err(),
        Some(Error::InvalidAttestation)
    );

    // a thief with another key cannot prove for id (π_0 clause id = Tag(usk, c_0))
    let (_, usk_thief) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    assert_eq!(
        dep.pcs
            .prove(&dep.hvk, &f2, &id, &usk_thief, &atts, &mut dep.rng)
            .err(),
        Some(Error::IdentifierMismatch)
    );
}

// ---------------------------------------------------------------------------------------------
// Replay across deployments and helpers
// ---------------------------------------------------------------------------------------------

/// A proof / attestation is bound to its deployment (`pp`, including the label, leads every
/// context) and its helper key, and a credential issued by ANOTHER helper is not shown under this
/// one. `Σ-PS + Tag_DY` is the pair whose ALGEBRAIC parameters are identical across deployments,
/// so it isolates the role of the label in the context digest.
#[test]
fn proofs_do_not_cross_deployments_or_helpers() {
    let mut here = Deployment::<PS, DY>::open(b"adv/replay/here", 0xadae_0001);
    let there = PCS::<E, PS, DY>::setup(SetupParams::new(b"adv/replay/there".to_vec())).unwrap();
    assert_eq!(here.pcs.base_parameters(), there.base_parameters());
    assert_eq!(here.pcs.tag(), there.tag());
    assert_ne!(here.pcs.parameters_digest(), there.parameters_digest());

    let roots = here.root_members(1);
    let (id, usk) = here.pcs.user_keygen(&mut here.rng).unwrap();
    let atts = here.attestations(&roots, &id);
    let f1 = Predicate::new(1, b"members".to_vec());
    let (proof, _) = here.prove_ok(&f1, &id, &usk, &atts);

    // same helper key, same id, other deployment
    assert!(!there.verify_attestation(&here.hvk, &id, &atts[0]));
    assert!(!there.verify_proof(&here.hvk, &f1, &id, &proof));
    // same deployment, other helper key
    let (hvk2, hsk2) = here.pcs.helper_keygen(&mut here.rng);
    assert!(!here.pcs.verify_attestation(&hvk2, &id, &atts[0]));
    assert!(!here.pcs.verify_proof(&hvk2, &f1, &id, &proof));

    // a credential issued by ANOTHER helper cannot be shown under this one: its rerand does not
    // satisfy R_att for hvk, so attest refuses or the attestation is rejected.
    let (id_b, usk_b) = here.pcs.user_keygen(&mut here.rng).unwrap();
    let (req_b, st_b) = here
        .pcs
        .root_request(&hvk2, &here.f_root.clone(), &id_b, &usk_b, &mut here.rng)
        .unwrap();
    let pre_b = here
        .pcs
        .issue_root(
            &hvk2,
            &hsk2,
            &here.f_root.clone(),
            &id_b,
            &req_b,
            &mut here.rng,
        )
        .unwrap();
    let cred_b = here
        .pcs
        .unblind(&hvk2, &usk_b, &here.f_root.clone(), &pre_b, &st_b)
        .unwrap();
    let member_b = common::Member {
        id: id_b,
        usk: usk_b,
        f: here.f_root.clone(),
        cred: cred_b,
    };
    let (id_c, _) = here.pcs.user_keygen(&mut here.rng).unwrap();
    match here.pcs.attest(
        &here.hvk,
        &member_b.usk,
        &member_b.f,
        &member_b.cred,
        &id_c,
        &mut here.rng,
    ) {
        Ok(att) => assert!(!here.pcs.verify_attestation(&here.hvk, &id_c, &att)),
        Err(e) => assert!(matches!(
            e,
            Error::WitnessDoesNotSatisfyRelation | Error::InvalidCredential
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Policy attacks
// ---------------------------------------------------------------------------------------------

/// The public attribute policy `P` of `CheckAtts_P` (Def. "Threshold authorization relation") is
/// the VERIFIER's input, not part of any context. A verifier whose allow-list excludes `φ_root`
/// rejects a proof backed by root credentials ([`Error::PolicyRejected`]), and its helper does not
/// issue on it, even though the same proof is accepted under `P ≡ 1`.
#[test]
fn the_attribute_policy_is_enforced() {
    let label = b"adv/policy";
    let mut open = Deployment::<PS, DDH>::open(label, 0xad90_0001);
    let roots = open.root_members(2);
    let (id, usk) = open.pcs.user_keygen(&mut open.rng).unwrap();
    let f2 = Predicate::new(2, b"members".to_vec());
    let root_atts = open.attestations(&roots, &id);
    let (by_roots, _) = open.prove_ok(&f2, &id, &usk, &root_atts);

    // a stricter verifier over the SAME pp/helper key: only members count
    let members_only = AllowList::<Fr>::from_predicates(label, [&f2]).unwrap();
    let strict = PCS::<E, PS, DDH, _>::from_public_parameters(
        open.pcs.public_parameters().clone(),
        members_only,
    )
    .unwrap();
    assert_eq!(strict.parameters_digest(), open.pcs.parameters_digest());

    assert_eq!(open.pcs.check_proof(&open.hvk, &f2, &id, &by_roots), Ok(()));
    assert_eq!(
        strict.check_proof(&open.hvk, &f2, &id, &by_roots),
        Err(Error::PolicyRejected)
    );
    assert!(!strict.verify_proof(&open.hvk, &f2, &id, &by_roots));
    assert_eq!(
        strict
            .issue(&open.hvk, &open.hsk, &f2, &id, &by_roots, &mut open.rng)
            .err(),
        Some(Error::InvalidProof)
    );
    // the strict prover refuses to build a root-backed proof at all
    let (id_c, usk_c) = open.pcs.user_keygen(&mut open.rng).unwrap();
    let mixed = open.attestations(&roots[..2], &id_c);
    assert_eq!(
        strict
            .prove(&open.hvk, &f2, &id_c, &usk_c, &mixed, &mut open.rng)
            .err(),
        Some(Error::PolicyRejected)
    );
}

// ---------------------------------------------------------------------------------------------
// Malicious helper: Unblind fails closed
// ---------------------------------------------------------------------------------------------

/// A malicious or buggy helper is caught at `Unblind`, which fails closed (returns
/// [`Error::InvalidPreCredential`], module docs "Rules the construction has to keep"): a garbage
/// pre-credential, a pre-credential that signs the WRONG predicate `φ'`, and an identity
/// pre-credential all fail `VerifyCred` on the credential `Unblind` would return.
fn unblind_fails_closed<B, T>(
    label: &[u8],
    seed: u64,
    garbage: impl Fn(&mut StdRng) -> B::PreCredential,
    identity: B::PreCredential,
) where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let (request, state) = dep
        .pcs
        .root_request(&dep.hvk, &dep.f_root.clone(), &id, &usk, &mut dep.rng)
        .unwrap();

    // garbage pre-credential
    for _ in 0..3 {
        let g = garbage(&mut dep.rng);
        assert_eq!(
            dep.pcs
                .unblind(&dep.hvk, &usk, &dep.f_root.clone(), &g, &state)
                .err(),
            Some(Error::InvalidPreCredential)
        );
    }
    // identity pre-credential
    assert_eq!(
        dep.pcs
            .unblind(&dep.hvk, &usk, &dep.f_root.clone(), &identity, &state)
            .err(),
        Some(Error::InvalidPreCredential)
    );
    // a pre-credential the helper produced for a DIFFERENT request (another key's issuance
    // encoding C'): unblinding it with THIS user's state fails closed, because the resulting
    // credential is not a signature on the user's message Enc_Σ(usk, EncPred(f_root)). (Note: the
    // point at which φ enters differs per base — hazard F5 — so a "wrong φ" passed to BlindIssue
    // is a no-op for Σ-BBS, where φ is bound inside C and by π_0's opening clause, not injected by
    // the helper; a mismatched C is the base-uniform malicious answer.)
    let f_root = dep.f_root.clone();
    let phi_root = dep.pcs.enc_pred(&f_root).unwrap();
    let (_id2, usk2) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let (aux2, rho2) = B::sample_issuance(dep.pcs.base_parameters(), &mut dep.rng);
    let m_hid2 = B::hidden_message(usk2.expose_scalar(), &aux2);
    let c2 = B::issuance_encoding(
        dep.pcs.base_parameters(),
        &dep.hvk,
        &m_hid2,
        &phi_root,
        &rho2,
    )
    .unwrap();
    let wrong_pre = B::blind_issue(
        dep.pcs.base_parameters(),
        dep.hsk.signing_key(),
        &c2,
        &phi_root,
        &mut dep.rng,
    )
    .unwrap();
    assert_eq!(
        dep.pcs
            .unblind(&dep.hvk, &usk, &f_root, &wrong_pre, &state)
            .err(),
        Some(Error::InvalidPreCredential)
    );

    // control: the honest pre-credential unblinds
    let pre = dep
        .pcs
        .issue_root(
            &dep.hvk,
            &dep.hsk,
            &dep.f_root.clone(),
            &id,
            &request,
            &mut dep.rng,
        )
        .unwrap();
    assert!(
        dep.pcs
            .unblind(&dep.hvk, &usk, &dep.f_root.clone(), &pre, &state)
            .is_ok()
    );
}

#[test]
fn unblind_fails_closed_ps() {
    unblind_fails_closed::<PS, DDH>(
        b"adv/unblind/ps",
        0xadb0_0001,
        |rng| PSPreCredential {
            sigma_1: G1::rand(rng),
            sigma_2: G1::rand(rng),
        },
        PSPreCredential {
            sigma_1: G1::zero(),
            sigma_2: G1::zero(),
        },
    );
}
#[test]
fn unblind_fails_closed_bbs() {
    use predicate_credential_system::cred::bbs::BBSPreCredential;
    unblind_fails_closed::<BBS, DDH>(
        b"adv/unblind/bbs",
        0xadb0_0002,
        |rng| BBSPreCredential {
            a: G1::rand(rng),
            e: Fr::rand(rng),
        },
        BBSPreCredential {
            a: G1::zero(),
            e: Fr::zero(),
        },
    );
}
#[test]
fn unblind_fails_closed_eq() {
    use predicate_credential_system::cred::eq::EQPreCredential;
    unblind_fails_closed::<SPSEQ, DDH>(
        b"adv/unblind/eq",
        0xadb0_0003,
        |rng| EQPreCredential {
            z: G1::rand(rng),
            y: G1::rand(rng),
            y_tilde: <E as ark_ec::pairing::Pairing>::G2::rand(rng),
        },
        EQPreCredential {
            z: G1::zero(),
            y: G1::zero(),
            y_tilde: <E as ark_ec::pairing::Pairing>::G2::zero(),
        },
    );
}

// ---------------------------------------------------------------------------------------------
// Malformed helper keys
// ---------------------------------------------------------------------------------------------

/// A helper key outside the range of `KeyGen` is refused by every verifier that takes the
/// statement seriously ([`Error::InvalidKey`] / `false`). `Σ-PS` with `Ỹ_1 = 1` (a credential
/// then does not depend on `usk`) or an inconsistent `Y_1`, and `Σ-EQ` with `X̃_i = 1` (the
/// signature does not cover `M_i`). `Σ-BBS` has no such key (`X̃ = g̃^x` for any `x`), which the
/// crate documents.
#[test]
fn malformed_helper_keys_are_refused() {
    // Σ-PS
    let mut dep = Deployment::<PS, DDH>::open(b"adv/keys/ps", 0xadc0_0001);
    let roots = dep.root_members(1);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);
    let f1 = Predicate::new(1, b"members".to_vec());
    let (proof, _) = dep.prove_ok(&f1, &id, &usk, &atts);

    let mut no_usk = dep.hvk.clone();
    no_usk.y1_tilde = <E as ark_ec::pairing::Pairing>::G2::zero();
    let mut inconsistent = dep.hvk.clone();
    inconsistent.y1 = G1::generator();
    for bad in [&no_usk, &inconsistent] {
        assert!(!<PS as CredentialBase>::is_well_formed_key(
            dep.pcs.base_parameters(),
            bad
        ));
        assert_eq!(
            dep.pcs.check_attestation(bad, &id, &atts[0]),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            dep.pcs.check_proof(bad, &f1, &id, &proof),
            Err(Error::InvalidKey)
        );
        assert!(
            !dep.pcs
                .verify_cred(bad, &roots[0].usk, &roots[0].f, &roots[0].cred)
        );
    }

    // Σ-EQ: X̃_1 = 1
    let mut eq = Deployment::<SPSEQ, DDH>::open(b"adv/keys/eq", 0xadc0_0002);
    let eqroots = eq.root_members(1);
    let (eqid, _) = eq.pcs.user_keygen(&mut eq.rng).unwrap();
    let eqatt = eq.attest(&eqroots[0], &eqid);
    let mut bad_eq = eq.hvk.clone();
    bad_eq.x1_tilde = <E as ark_ec::pairing::Pairing>::G2::zero();
    assert!(!<SPSEQ as CredentialBase>::is_well_formed_key(
        eq.pcs.base_parameters(),
        &bad_eq
    ));
    assert_eq!(
        eq.pcs.check_attestation(&bad_eq, &eqid, &eqatt),
        Err(Error::InvalidKey)
    );
}

// ---------------------------------------------------------------------------------------------
// Tag_DY undefined points
// ---------------------------------------------------------------------------------------------

/// `Tag_DY`: `Attest` returns `⊥` on a later undefined evaluation (§5.1), i.e. `usk_j = −H_0(id)`,
/// and `UKeyGen` never returns the two then-known undefined keys `−c_0`, `−H_0(id)`.
#[test]
fn tag_dy_undefined_points() {
    let mut dep = Deployment::<PS, DY>::open(b"adv/dy", 0xadd1_0001);
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();

    // an attester whose key is exactly −H_0(id): its own identifier is fine, Attest for id is ⊥
    let s = dep.pcs.tag_point(&id).unwrap();
    let usk_j = UserSecretKey::<E>::from_scalar(-s);
    assert_eq!(dep.pcs.tag().eval(usk_j.expose_scalar(), &s), None);
    let id_j = dep.pcs.identity(&usk_j).unwrap();
    let unlucky = dep.admit(id_j, usk_j);
    assert_eq!(
        dep.pcs
            .attest(
                &dep.hvk,
                &unlucky.usk,
                &unlucky.f,
                &unlucky.cred,
                &id,
                &mut dep.rng
            )
            .err(),
        Some(Error::UndefinedTag)
    );
    // for any other identifier it attests like everyone else
    let (id_2, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let att = dep.attest(&unlucky, &id_2);
    assert!(dep.pcs.verify_attestation(&dep.hvk, &id_2, &att));

    // UKeyGen never returns −c_0 (id would be ⊥)
    let minus_c0 = UserSecretKey::<E>::from_scalar(-*dep.pcs.identity_point());
    assert_eq!(dep.pcs.identity(&minus_c0), Err(Error::UndefinedTag));
}

// ---------------------------------------------------------------------------------------------
// from_public_parameters refuses parameters that are not Setup(label)
// ---------------------------------------------------------------------------------------------

/// An honest user rebuilding from received `pp` accepts it only if it equals what `Setup` derives
/// from the label it carries (transparent setup): a changed `c_0`, a changed generator, or a
/// changed label are all refused ([`Error::InvalidPublicParameters`]).
#[test]
fn from_public_parameters_refuses_non_derived_parameters() {
    let pcs = PCS::<E, BBS, DDH>::setup(SetupParams::new(b"adv/frompp".to_vec())).unwrap();
    let pp = pcs.public_parameters().clone();
    let invalid = |pp: PublicParameters<E, BBS, DDH>| match PCS::from_public_parameters(
        pp,
        predicate_credential_system::pcs::AcceptAll,
    ) {
        Err(Error::InvalidPublicParameters(what)) => what,
        other => panic!("accepted or refused for another reason: {other:?}"),
    };
    // a changed c_0
    let mut bad = pp.clone();
    bad.c0 += Fr::one();
    assert!(invalid(bad).starts_with("c_0"));
    // a generator with a known discrete-log relation (well formed, but not the hash-derived one)
    let mut bad = pp.clone();
    bad.pp_sigma.h3 = bad.pp_sigma.h1 * Fr::from(2u64);
    assert!(bad.pp_sigma.is_well_formed());
    assert!(invalid(bad).starts_with("pp_Σ"));
    // another label on the same parameters
    let mut bad = pp.clone();
    bad.label = b"adv/frompp/other".to_vec();
    assert!(invalid(bad).starts_with("c_0"));
    // control: the derived parameters are accepted, over the wire
    let received = PublicParameters::<E, BBS, DDH>::from_bytes(&pp.to_bytes().unwrap()).unwrap();
    assert!(
        PCS::from_public_parameters(received, predicate_credential_system::pcs::AcceptAll).is_ok()
    );
}

// ---------------------------------------------------------------------------------------------
// Documented behaviour: attestations are standing endorsements
// ---------------------------------------------------------------------------------------------

/// Remark "Attestations are standing endorsements" (a MODELLING CHOICE, not a bug): an attestation
/// binds an identifier and an attester key, but no session, epoch or predicate. So one collected
/// set `{att_j}` is accepted in issuance requests for the SAME `id` under DIFFERENT predicates.
/// This is the paper's stated "collect once, join several communities" semantics; the crate
/// implements neither of the Remark's optional remedies.
#[test]
fn attestations_are_standing_endorsements() {
    let mut dep = Deployment::<PS, DDH>::open(b"adv/standing", 0xadf1_0001);
    let roots = dep.root_members(2);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);

    // the SAME attestation set backs two different threshold-2 predicates (two communities)
    let members = Predicate::new(2, b"members".to_vec());
    let guests = Predicate::new(2, b"guests".to_vec());
    let (p_members, _) = dep
        .pcs
        .prove(&dep.hvk, &members, &id, &usk, &atts, &mut dep.rng)
        .unwrap();
    let (p_guests, _) = dep
        .pcs
        .prove(&dep.hvk, &guests, &id, &usk, &atts, &mut dep.rng)
        .unwrap();
    assert!(dep.pcs.verify_proof(&dep.hvk, &members, &id, &p_members));
    assert!(dep.pcs.verify_proof(&dep.hvk, &guests, &id, &p_guests));
    assert_eq!(p_members.attestations, atts);
    assert_eq!(p_guests.attestations, atts);
}

// ---------------------------------------------------------------------------------------------
// Robustness: no verifier or decoder panics on adversarial input
// ---------------------------------------------------------------------------------------------

/// Verifiers return `false` (never panic) on well-typed garbage — random elements, the identity in
/// every position, proofs with the wrong number of responses — and decoders return `Err` (never
/// panic) on flipped, truncated, extended, all-zero and all-`0xff` byte strings, for the compact
/// and the derived encodings of every object.
fn robustness<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let mut rng = StdRng::seed_from_u64(seed ^ 0xF0F0);
    let (hvk, f) = (dep.hvk.clone(), Predicate::new(2, b"members".to_vec()));

    for id in [G1::rand(&mut rng), G1::zero(), G1::generator()] {
        // random and identity-everywhere objects: verifiers return false without panicking
        let att = random_attestation::<B>(&mut rng);
        assert!(!dep.pcs.verify_attestation(&hvk, &id, &att));
        let mut proof = random_proof::<B>(2, &mut rng);
        assert!(!dep.pcs.verify_proof(&hvk, &f, &id, &proof));
        let request = random_root_request::<B>(&mut rng);
        assert!(
            !dep.pcs
                .verify_root_request(&hvk, &dep.f_root.clone(), &id, &request)
        );
        assert!(
            dep.pcs
                .issue(&hvk, &dep.hsk, &f, &id, &proof, &mut rng)
                .is_err()
        );

        // wrong number of responses
        for responses in [Vec::new(), vec![Fr::one(); 32]] {
            proof.proof.responses.clone_from(&responses);
            proof.attestations[0].proof.responses.clone_from(&responses);
            assert!(!dep.pcs.verify_proof(&hvk, &f, &id, &proof));
            assert!(
                !dep.pcs
                    .verify_attestation(&hvk, &id, &proof.attestations[0])
            );
        }
        // the identity in every position of a proof
        let mut degenerate = random_proof::<B>(2, &mut rng);
        degenerate.t0 = G1::zero();
        for a in &mut degenerate.attestations {
            a.tag = G1::zero();
            a.phi = Fr::zero();
            a.proof.challenge = Fr::zero();
            a.proof.responses.fill(Fr::zero());
        }
        degenerate.proof.challenge = Fr::zero();
        degenerate.proof.responses.fill(Fr::zero());
        assert!(!dep.pcs.verify_proof(&hvk, &f, &id, &degenerate));
        assert!(
            !dep.pcs
                .verify_attestation(&hvk, &id, &degenerate.attestations[0])
        );
    }

    // byte fuzzing: every mutation of a valid encoding decodes to Err, or to an object the
    // verifier rejects — never a panic.
    let att = random_attestation::<B>(&mut rng);
    let proof = random_proof::<B>(2, &mut rng);
    let request = random_root_request::<B>(&mut rng);
    let id = G1::rand(&mut rng);
    for bytes in mutations(&att.to_compact_bytes().unwrap()) {
        if let Ok(a) = Attestation::<E, B>::from_compact_bytes(&bytes) {
            assert!(!dep.pcs.verify_attestation(&hvk, &id, &a));
        }
    }
    for bytes in mutations(&proof.to_compact_bytes().unwrap()) {
        if let Ok(p) = IssuanceProof::<E, B>::from_compact_bytes(&bytes, &f) {
            assert!(!dep.pcs.verify_proof(&hvk, &f, &id, &p));
        }
    }
    for bytes in mutations(&request.to_compact_bytes().unwrap()) {
        if let Ok(r) = RootRequest::<E, B>::from_compact_bytes(&bytes) {
            assert!(
                !dep.pcs
                    .verify_root_request(&hvk, &dep.f_root.clone(), &id, &r)
            );
        }
    }
    // derived (self-describing) encodings, including for a real credential and pre-credential
    let (cred, pre) = {
        let roots = dep.root_members(1);
        let (sid, susk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
        let satts = dep.attestations(&roots, &sid);
        let (p, st) = dep.prove_ok(&Predicate::new(1, b"members".to_vec()), &sid, &susk, &satts);
        let pre = dep
            .pcs
            .issue(
                &dep.hvk,
                &dep.hsk,
                &Predicate::new(1, b"members".to_vec()),
                &sid,
                &p,
                &mut dep.rng,
            )
            .unwrap();
        let cred = dep
            .pcs
            .unblind(
                &dep.hvk,
                &susk,
                &Predicate::new(1, b"members".to_vec()),
                &pre,
                &st,
            )
            .unwrap();
        (cred, pre)
    };
    for bytes in mutations(&att.to_bytes().unwrap()) {
        let _ = Attestation::<E, B>::from_bytes(&bytes);
    }
    for bytes in mutations(&proof.to_bytes().unwrap()) {
        let _ = IssuanceProof::<E, B>::from_bytes(&bytes);
    }
    for bytes in mutations(&cred.to_bytes().unwrap()) {
        let _ = Credential::<E, B>::from_bytes(&bytes);
    }
    for bytes in mutations(&pre.to_bytes().unwrap()) {
        let _ = B::PreCredential::from_bytes(&bytes);
    }
}

/// A handful of adversarial byte-string mutations of `bytes`: a flipped byte near the front, the
/// middle and the end; truncation to half; a trailing byte; all-zero and all-`0xff`.
fn mutations(bytes: &[u8]) -> Vec<Vec<u8>> {
    let n = bytes.len().max(1);
    let mut out = Vec::new();
    for at in [0usize, n / 2, n - 1] {
        let mut b = bytes.to_vec();
        if let Some(byte) = b.get_mut(at) {
            *byte ^= 0xff;
        }
        out.push(b);
    }
    out.push(bytes[..n / 2].to_vec()); // truncated
    let mut extended = bytes.to_vec();
    extended.push(0x00); // trailing byte
    out.push(extended);
    out.push(vec![0u8; bytes.len()]); // all-zero
    out.push(vec![0xffu8; bytes.len()]); // all-0xff
    out.push(Vec::new()); // empty
    out
}

#[test]
fn robustness_ps() {
    robustness::<PS, DDH>(b"adv/robust/ps", 0xad70_0001);
}
#[test]
fn robustness_bbs() {
    robustness::<BBS, DY>(b"adv/robust/bbs", 0xad70_0002);
}
#[test]
fn robustness_eq() {
    robustness::<SPSEQ, DDH>(b"adv/robust/eq", 0xad70_0003);
}
