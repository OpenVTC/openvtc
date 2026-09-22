//! Regression tests from a hostile review of the construction (`src/pcs`). Self-contained; all
//! runs seeded. Three groups:
//!
//! * `group_membership_*`: a group element OUTSIDE the prime-order subgroup, at every position of
//!   an attestation / issuance proof / root request, is rejected by the decoders (both encodings)
//!   AND, when the object is built in memory, by the verifiers, with [`Error::InvalidGroupElement`]
//!   and with `issue` returning `Err`. This is finding F1 of the review.
//! * `small_subgroup_*`: the actual attacks the check exists for, turned around. Pre-fix
//!   (recorded in the comments, measured in `<scratchpad>/review-pcs/prefix-observed.txt`) a tag
//!   `T + P_3` with `P_3` of order 3 let ONE attester pass `CheckAtts_P` as two, and `T_0 + P_3`
//!   let a requester pass self-exclusion with its own attestation; each verified after a few
//!   attempts and issuance succeeded. Now the shifted objects are rejected before any Schnorr
//!   check, for every base and tag (the `Σ-EQ` case the review left unverified included).
//! * `root_path_refuses_thresholds`: the root path refuses threshold predicates on both sides,
//!   for `k ∈ {1, 2, u32::MAX}` (finding F3).

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{UniformRand, Zero};
use predicate_credential_system::{
    Error,
    cred::{self, CredentialBase, EQ, SigmaFriendlyCredentialBase},
    hash::bls12_381::G1Hasher,
    kiprf::{self, KIPRF, PCSTag},
    pcs::{
        Attestation, Credential, HelperSecretKey, IssuanceProof, PCS, Predicate,
        PredicateCredentialSystem, RootRequest, SetupParams, UserSecretKey,
    },
    serialization::WireFormat,
    sigma::{FSProof, LinearRelation, PairingRelation, commit, fiat_shamir, respond},
};
use rand::{SeedableRng, rngs::StdRng};

type E = Bls12_381;
type G1 = G1Projective;
type PS = cred::PS<E>;
type BBS = cred::BBS<E, G1Hasher>;
type SPSEQ = EQ<E>;
type DDH = kiprf::DDH<G1, G1Hasher>;
type DY = kiprf::DY<G1>;

/// A `G_1` point on the curve but OUTSIDE the prime-order subgroup (the cofactor is not cleared).
fn g1_outside_subgroup() -> Vec<u8> {
    let p: G1Affine = (1u64..=64)
        .filter_map(|x| G1Affine::get_point_from_x_unchecked(Fq::from(x), false))
        .find(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        .expect("a curve point outside the subgroup among 64 abscissae");
    assert!(p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve());
    p.into_group().to_bytes().unwrap()
}

/// A `G_2` point on the curve but OUTSIDE the prime-order subgroup.
fn g2_outside_subgroup() -> Vec<u8> {
    let mut x = ark_bls12_381::Fq2::from(1u64);
    loop {
        if let Some(p) = G2Affine::get_point_from_x_unchecked(x, false)
            && p.is_on_curve()
            && !p.is_in_correct_subgroup_assuming_on_curve()
        {
            return p.into_group().to_bytes().unwrap();
        }
        x += ark_bls12_381::Fq2::from(1u64);
    }
}

/// `P_3 = (0, 2)`: a point of order 3 on `E(F_q): y² = x³ + 4`, outside `G_1`.
fn p3() -> G1 {
    let p = G1Affine::new_unchecked(Fq::zero(), Fq::from(2u64));
    assert!(p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve());
    let p: G1 = p.into_group();
    assert!((p + p + p).is_zero() && !p.is_zero());
    p
}

fn is_group_element_error<V>(result: &Result<V, Error>) -> bool {
    matches!(result, Err(Error::InvalidGroupElement(_)))
}

// -------------------------------------------------------------------------------------------------
// A deployment with two members and a subject, for one base and tag.
// -------------------------------------------------------------------------------------------------

struct World<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>> {
    pcs: PCS<E, B, T>,
    hvk: B::VerificationKey,
    hsk: HelperSecretKey<B>,
    f_root: Predicate,
    rng: StdRng,
}

impl<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>> World<B, T> {
    fn new(label: &[u8], seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let pcs = PCS::setup(SetupParams::new(label.to_vec())).unwrap();
        let (hvk, hsk) = pcs.helper_keygen(&mut rng);
        Self {
            pcs,
            hvk,
            hsk,
            f_root: Predicate::root(b"root".to_vec()),
            rng,
        }
    }

    fn member(&mut self) -> (G1, UserSecretKey<E>, Credential<E, B>) {
        let (pcs, hvk, f_root, rng) = (&self.pcs, &self.hvk, &self.f_root, &mut self.rng);
        let (id, usk) = pcs.user_keygen(rng).unwrap();
        let (req, st) = pcs.root_request(hvk, f_root, &id, &usk, rng).unwrap();
        let pre = pcs
            .issue_root(hvk, &self.hsk, f_root, &id, &req, rng)
            .unwrap();
        let cred = pcs.unblind(hvk, &usk, f_root, &pre, &st).unwrap();
        (id, usk, cred)
    }
}

// -------------------------------------------------------------------------------------------------
// F1: a non-subgroup point at every position is rejected by the decoders AND the verifiers.
// -------------------------------------------------------------------------------------------------

fn group_membership<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>>(
    label: &[u8],
    seed: u64,
    g1_positions_att: &[usize],
) {
    let mut w = World::<B, T>::new(label, seed);
    let (_id_1, usk_1, cred_1) = w.member();
    let (id_2, usk_2, cred_2) = w.member();
    let (id, usk) = w.pcs.user_keygen(&mut w.rng).unwrap();
    let a1 = w
        .pcs
        .attest(&w.hvk, &usk_1, &w.f_root, &cred_1, &id, &mut w.rng)
        .unwrap();
    let a2 = w
        .pcs
        .attest(&w.hvk, &usk_2, &w.f_root, &cred_2, &id, &mut w.rng)
        .unwrap();
    let f = Predicate::new(2, b"members".to_vec());
    let (proof, _) = w
        .pcs
        .prove(&w.hvk, &f, &id, &usk, &[a1.clone(), a2], &mut w.rng)
        .unwrap();
    let (request, _) = w
        .pcs
        .root_request(&w.hvk, &w.f_root, &id_2, &usk_2, &mut w.rng)
        .unwrap();

    let bad_g1 = g1_outside_subgroup();
    let bad_g2 = g2_outside_subgroup();

    // ----- attestation: every G_1 position, and (Σ-EQ) the G_2 slot -----
    let att_bytes = a1.to_compact_bytes().unwrap();
    for &at in g1_positions_att {
        // compact decoder
        let mut bad = att_bytes.clone();
        bad[at..at + 48].copy_from_slice(&bad_g1);
        assert!(
            is_serialization_or_group_error(&Attestation::<E, B>::from_compact_bytes(&bad)),
            "compact attestation decoder accepted a non-subgroup point at {at}"
        );
    }
    // the G_2 slot of Σ-EQ (Ỹ' inside cred*): search it out of the layout by name below
    if let Some(at) = g2_slot_of_attestation::<B>() {
        let mut bad = att_bytes.clone();
        bad[at..at + 96].copy_from_slice(&bad_g2);
        assert!(
            is_serialization_or_group_error(&Attestation::<E, B>::from_compact_bytes(&bad)),
            "compact attestation decoder accepted a non-subgroup G_2 point at {at}"
        );
    }
    // in memory: a shifted tag makes the whole attestation not a group element
    let mut att_shifted = a1.clone();
    att_shifted.tag += p3();
    assert!(is_group_element_error(&w.pcs.check_attestation(
        &w.hvk,
        &id,
        &att_shifted
    )));
    assert!(!w.pcs.verify_attestation(&w.hvk, &id, &att_shifted));

    // ----- issuance proof: T_1, T_2, C, T_0, and the G_2 slots inside cred* -----
    let proof_bytes = proof.to_compact_bytes().unwrap();
    let att_len = a1.compact_size();
    let mut g1_positions_proof: Vec<usize> = Vec::new();
    for att_idx in 0..2 {
        for &p in g1_positions_att {
            g1_positions_proof.push(att_idx * att_len + p);
        }
    }
    // C (for bases that carry one) and T_0 sit after the k attestations
    let after_atts = 2 * att_len;
    if base_has_c::<B>() {
        g1_positions_proof.push(after_atts); // C
        g1_positions_proof.push(after_atts + 48); // T_0
    } else {
        g1_positions_proof.push(after_atts); // T_0 (no C for Σ-EQ)
    }
    for at in g1_positions_proof {
        let mut bad = proof_bytes.clone();
        bad[at..at + 48].copy_from_slice(&bad_g1);
        assert!(
            is_serialization_or_group_error(&IssuanceProof::<E, B>::from_compact_bytes(&bad, &f)),
            "compact proof decoder accepted a non-subgroup point at {at}"
        );
    }
    // in memory: a proof whose T_0 is shifted is not a group element
    let mut proof_shifted = proof.clone();
    proof_shifted.t0 += p3();
    assert!(is_group_element_error(&w.pcs.check_proof(
        &w.hvk,
        &f,
        &id,
        &proof_shifted
    )));
    assert!(!w.pcs.verify_proof(&w.hvk, &f, &id, &proof_shifted));
    assert!(
        w.pcs
            .issue(&w.hvk, &w.hsk, &f, &id, &proof_shifted, &mut w.rng)
            .is_err()
    );
    // and one whose first attestation's tag is shifted
    let mut proof_att_shifted = proof.clone();
    proof_att_shifted.attestations[0].tag += p3();
    assert!(is_group_element_error(&w.pcs.check_proof(
        &w.hvk,
        &f,
        &id,
        &proof_att_shifted
    )));
    assert!(
        w.pcs
            .issue(&w.hvk, &w.hsk, &f, &id, &proof_att_shifted, &mut w.rng)
            .is_err()
    );

    // ----- root request: C (if any) and T_0 -----
    let req_bytes = request.to_compact_bytes().unwrap();
    let req_g1: Vec<usize> = if base_has_c::<B>() {
        vec![0, 48]
    } else {
        vec![0]
    };
    for at in req_g1 {
        let mut bad = req_bytes.clone();
        bad[at..at + 48].copy_from_slice(&bad_g1);
        assert!(
            is_serialization_or_group_error(&RootRequest::<E, B>::from_compact_bytes(&bad)),
            "compact root-request decoder accepted a non-subgroup point at {at}"
        );
    }
    let mut req_shifted = request.clone();
    req_shifted.t0 += p3();
    assert!(is_group_element_error(&w.pcs.check_root_request(
        &w.hvk,
        &w.f_root,
        &id_2,
        &req_shifted
    )));
    assert!(
        w.pcs
            .issue_root(&w.hvk, &w.hsk, &w.f_root, &id_2, &req_shifted, &mut w.rng)
            .is_err()
    );

    // ----- the DERIVED (WireFormat) encoding rejects the same points -----
    let derived = proof.to_bytes().unwrap();
    let evil = g1_outside_subgroup();
    // len(8) ‖ att_1 (att_len+8) ‖ att_2 ‖ C? ‖ T_0 ‖ π_0(+8): the first tag is at offset 16
    let mut bad = derived.clone();
    bad[16..16 + 48].copy_from_slice(&evil);
    assert!(IssuanceProof::<E, B>::from_bytes(&bad).is_err());

    // control
    assert!(Attestation::<E, B>::from_compact_bytes(&att_bytes).is_ok());
    assert!(IssuanceProof::<E, B>::from_compact_bytes(&proof_bytes, &f).is_ok());
    assert!(RootRequest::<E, B>::from_compact_bytes(&req_bytes).is_ok());
    assert!(IssuanceProof::<E, B>::from_bytes(&derived).is_ok());
    assert_eq!(w.pcs.check_proof(&w.hvk, &f, &id, &proof), Ok(()));
}

fn is_serialization_or_group_error<V>(result: &Result<V, Error>) -> bool {
    matches!(
        result,
        Err(Error::Serialization(_)) | Err(Error::TrailingBytes)
    )
}

/// Whether the base transmits a `C` inside `π` (`Σ-PS`, `Σ-BBS`: yes; `Σ-EQ`: no, `C := id`).
fn base_has_c<B: SigmaFriendlyCredentialBase<E>>() -> bool {
    !core::any::type_name::<B>().contains("::EQ<")
}

/// The byte offset of the single `G_2` element (`Ỹ'`) inside the compact encoding of a `Σ-EQ`
/// attestation, or `None` for a base without one. Layout of `Σ-EQ` `att`:
/// `T(48) ‖ M'_1(48) ‖ M'_2(48) ‖ M'_3(48) ‖ Z'(48) ‖ Y'(48) ‖ Ỹ'(96) ‖ φ(32) ‖ c(32) ‖ z(32)`.
fn g2_slot_of_attestation<B: SigmaFriendlyCredentialBase<E>>() -> Option<usize> {
    (core::any::type_name::<B>().contains("::EQ<")).then_some(6 * 48)
}

#[test]
fn group_membership_is_enforced_at_every_position() {
    // Σ-PS att: T ‖ σ'_1 ‖ σ'_2 ‖ φ ‖ c ‖ z  → G_1 at 0, 48, 96
    group_membership::<PS, DDH>(b"reg/gm/ps+ddh", 0x9e9_0001, &[0, 48, 96]);
    group_membership::<PS, DY>(b"reg/gm/ps+dy", 0x9e9_0002, &[0, 48, 96]);
    // Σ-BBS att: T ‖ Ā ‖ B̄ ‖ D ‖ φ ‖ 5 scalars → G_1 at 0, 48, 96, 144
    group_membership::<BBS, DDH>(b"reg/gm/bbs+ddh", 0x9e9_0003, &[0, 48, 96, 144]);
    group_membership::<BBS, DY>(b"reg/gm/bbs+dy", 0x9e9_0004, &[0, 48, 96, 144]);
    // Σ-EQ att: T ‖ M'_1 ‖ M'_2 ‖ M'_3 ‖ Z' ‖ Y' (G_1) ‖ Ỹ' (G_2) ‖ φ ‖ c ‖ z
    group_membership::<SPSEQ, DDH>(b"reg/gm/eq+ddh", 0x9e9_0005, &[0, 48, 96, 144, 192, 240]);
}

// -------------------------------------------------------------------------------------------------
// F1: the narrow codec regression. A non-subgroup point ONLY in the C slot or the T_0 slot of a
// compact IssuanceProof must be rejected by from_compact_bytes. This kills the mutant "C and T_0
// of IssuanceProof::deserialize_compact decoded unchecked".
// -------------------------------------------------------------------------------------------------

#[test]
fn compact_proof_decoder_checks_the_c_and_t0_slots() {
    let mut w = World::<PS, DDH>::new(b"reg/codec/ps", 0x9e9_0101);
    let (id_1, usk_1, cred_1) = w.member();
    let (id, usk) = w.pcs.user_keygen(&mut w.rng).unwrap();
    let att = w
        .pcs
        .attest(&w.hvk, &usk_1, &w.f_root, &cred_1, &id, &mut w.rng)
        .unwrap();
    let f = Predicate::new(1, b"members".to_vec());
    let (proof, _) = w
        .pcs
        .prove(&w.hvk, &f, &id, &usk, &[att], &mut w.rng)
        .unwrap();
    let bytes = proof.to_compact_bytes().unwrap();
    // layout for k = 1, Σ-PS: att (240) ‖ C (48) ‖ T_0 (48) ‖ π_0
    let c_at = 240;
    let t0_at = 240 + 48;
    let evil = g1_outside_subgroup();
    for at in [c_at, t0_at] {
        let mut bad = bytes.clone();
        bad[at..at + 48].copy_from_slice(&evil);
        assert!(
            IssuanceProof::<E, PS>::from_compact_bytes(&bad, &f).is_err(),
            "compact proof decoder accepted a non-subgroup point in the {} slot",
            if at == c_at { "C" } else { "T_0" }
        );
    }
    // the same on the root request (C ‖ T_0 ‖ π_0)
    let (request, _) = w
        .pcs
        .root_request(&w.hvk, &w.f_root, &id_1, &usk_1, &mut w.rng)
        .unwrap();
    let req_bytes = request.to_compact_bytes().unwrap();
    for at in [0usize, 48] {
        let mut bad = req_bytes.clone();
        bad[at..at + 48].copy_from_slice(&evil);
        assert!(RootRequest::<E, PS>::from_compact_bytes(&bad).is_err());
    }
}

// -------------------------------------------------------------------------------------------------
// F1: the attacks the checks exist for, turned around, for every base and tag.
// -------------------------------------------------------------------------------------------------

/// Build a Fiat-Shamir proof for a statement whose defect `φ(w) − Y` has order 3 (guess `c mod 3`),
/// or the honest proof if the shifted statement happens to be satisfied. `PRE-FIX` these verified;
/// now the object carrying the shifted tag is rejected before the proof is ever checked.
fn forge(
    relation: &PairingRelation<E>,
    witness: &[Fr],
    ctx: &[u8],
    rng: &mut StdRng,
) -> FSProof<Fr> {
    if relation.is_satisfied_by(witness) {
        return fiat_shamir::prove(relation, witness, ctx, rng).unwrap();
    }
    let defect = relation
        .recompute_commitment(&Fr::from(1u64), witness)
        .unwrap();
    let mut attempts = 0u64;
    loop {
        attempts += 1;
        assert!(attempts < 1000, "defect is not order 3");
        let guess = Fr::from(attempts % 3);
        let (mut a, state) = commit(relation, rng).unwrap();
        for (a_i, d_i) in a.g1.iter_mut().zip(&defect.g1) {
            *a_i += *d_i * guess;
        }
        let c = fiat_shamir::challenge(relation, ctx, &a).unwrap();
        if defect.g1.iter().all(|d| *d * c == *d * guess) {
            return FSProof {
                challenge: c,
                responses: respond(state, witness, &c).unwrap(),
            };
        }
    }
}

fn small_subgroup_attack<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>>(
    label: &[u8],
    seed: u64,
) {
    let mut w = World::<B, T>::new(label, seed);
    let (id_j, usk_j, cred_j) = w.member();
    let (id, usk) = w.pcs.user_keygen(&mut w.rng).unwrap();
    let honest = w
        .pcs
        .attest(&w.hvk, &usk_j, &w.f_root, &cred_j, &id, &mut w.rng)
        .unwrap();
    // a valid k = 2 proof to splice the forged attestation into, built before pp is borrowed
    let good_proof = {
        let honest_2 = w_second_honest(&mut w, &id);
        let f2 = Predicate::new(2, b"members".to_vec());
        w.pcs
            .prove(
                &w.hvk,
                &f2,
                &id,
                &usk,
                &[honest.clone(), honest_2],
                &mut w.rng,
            )
            .unwrap()
            .0
    };

    // (1) ONE endorser, a SECOND "attestation" with the tag T + P_3. Pre-fix: accepted, and a
    //     k = 2 credential was issued on this single endorser (see prefix-observed.txt).
    let phi = w.pcs.enc_pred(&w.f_root).unwrap();
    let s = w.pcs.tag_point(&id).unwrap();
    let tag = w.pcs.tag().eval(usk_j.expose_scalar(), &s).unwrap() + p3();
    let pp = w.pcs.base_parameters();
    let m_hid = B::hidden_message(usk_j.expose_scalar(), &cred_j.aux);
    let m = B::encode_message(pp, &m_hid, &phi).unwrap();
    let (shown, omega) = B::rerand(pp, &w.hvk, &m, &cred_j.cred, &mut w.rng).unwrap();
    let relation = w
        .pcs
        .attestation_relation(&w.hvk, &shown, &phi, &tag, &s)
        .unwrap();
    let witness = PCS::<E, B, T>::attestation_witness(&m_hid, &omega);
    let ctx = w
        .pcs
        .attestation_context(&w.hvk, &id, &phi, &tag, &shown)
        .unwrap();
    let forged_proof = forge(&relation, &witness, &ctx, &mut w.rng);
    let second = Attestation::<E, B> {
        tag,
        shown,
        phi,
        proof: forged_proof,
    };
    // NOW: the shifted tag is not a group element, rejected before the Schnorr check
    assert!(is_group_element_error(
        &w.pcs.check_attestation(&w.hvk, &id, &second)
    ));
    let f = Predicate::new(2, b"members".to_vec());
    let attempt = w.pcs.prove(
        &w.hvk,
        &f,
        &id,
        &usk,
        &[honest.clone(), second.clone()],
        &mut w.rng,
    );
    // prove re-validates the attestations too
    assert!(is_group_element_error(&attempt));
    // and even if a proof is assembled around it by hand, VerifyProof and Issue reject it
    let mut spliced = good_proof.clone();
    spliced.attestations[1] = second.clone();
    assert!(is_group_element_error(
        &w.pcs.check_proof(&w.hvk, &f, &id, &spliced)
    ));
    assert!(
        w.pcs
            .issue(&w.hvk, &w.hsk, &f, &id, &spliced, &mut w.rng)
            .is_err()
    );
    // the decoders reject the forged attestation outright
    assert!(Attestation::<E, B>::from_compact_bytes(&second.to_compact_bytes().unwrap()).is_err());

    // (2) self-attestation with T_0 + P_3. Pre-fix (Tag_DDH): a k = 1 credential on the requester's
    //     OWN endorsement. Now the proof carrying T_0 + P_3 is rejected before the Schnorr check.
    let f1 = Predicate::new(1, b"members".to_vec());
    let own = w
        .pcs
        .attest(&w.hvk, &usk_j, &w.f_root, &cred_j, &id_j, &mut w.rng)
        .unwrap();
    assert_eq!(
        w.pcs
            .prove(
                &w.hvk,
                &f1,
                &id_j,
                &usk_j,
                std::slice::from_ref(&own),
                &mut w.rng
            )
            .err(),
        Some(Error::SelfAttestation)
    );
    let s0 = w.pcs.tag_point(&id_j).unwrap();
    let t0 = w.pcs.tag().eval(usk_j.expose_scalar(), &s0).unwrap() + p3();
    let (aux, rho) = B::sample_issuance(pp, &mut w.rng);
    let m_hid0 = B::hidden_message(usk_j.expose_scalar(), &aux);
    let c = B::issuance_encoding(pp, &w.hvk, &m_hid0, &phi, &rho).unwrap();
    let wire = B::encoding_to_wire(&c);
    let c = B::encoding_from_wire(pp, &wire, &id_j).unwrap();
    let relation0 = w
        .pcs
        .issuance_relation(&w.hvk, &c, &phi, &id_j, &t0, &s0)
        .unwrap();
    let witness0 = PCS::<E, B, T>::issuance_witness(&m_hid0, &rho);
    let ctx0 = w
        .pcs
        .issuance_context(&w.hvk, &f1, &id_j, &c, &t0, std::slice::from_ref(&own))
        .unwrap();
    let pi0 = forge(&relation0, &witness0, &ctx0, &mut w.rng);
    let self_proof = IssuanceProof::<E, B> {
        attestations: vec![own],
        encoding: wire,
        t0,
        proof: pi0,
    };
    assert!(is_group_element_error(&w.pcs.check_proof(
        &w.hvk,
        &f1,
        &id_j,
        &self_proof
    )));
    assert!(
        w.pcs
            .issue(&w.hvk, &w.hsk, &f1, &id_j, &self_proof, &mut w.rng)
            .is_err()
    );
    assert!(
        IssuanceProof::<E, B>::from_compact_bytes(&self_proof.to_compact_bytes().unwrap(), &f1)
            .is_err()
    );
}

/// A fresh honest attestation of a NEW member for `id`, so that a two-attestation proof can be
/// built to splice the forged one into.
fn w_second_honest<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>>(
    w: &mut World<B, T>,
    id: &G1,
) -> Attestation<E, B> {
    let (_, usk_j, cred_j) = w.member();
    w.pcs
        .attest(&w.hvk, &usk_j, &w.f_root, &cred_j, id, &mut w.rng)
        .unwrap()
}

#[test]
fn small_subgroup_tags_are_rejected_for_every_base_and_tag() {
    small_subgroup_attack::<PS, DDH>(b"reg/ss/ps+ddh", 0x9e9_0201);
    small_subgroup_attack::<PS, DY>(b"reg/ss/ps+dy", 0x9e9_0202);
    small_subgroup_attack::<BBS, DDH>(b"reg/ss/bbs+ddh", 0x9e9_0203);
    small_subgroup_attack::<BBS, DY>(b"reg/ss/bbs+dy", 0x9e9_0204);
    small_subgroup_attack::<SPSEQ, DDH>(b"reg/ss/eq+ddh", 0x9e9_0205);
}

// -------------------------------------------------------------------------------------------------
// F3: the root path refuses threshold predicates, on both sides, for k in {1, 2, u32::MAX}.
// -------------------------------------------------------------------------------------------------

/// Each `validate(...)` call at the top of an algorithm is load-bearing on its OWN argument, not
/// only via the tag: the BLS12-381 pairing is blind to a component of order 3 (`e(P_3, ·) = 1`
/// after final exponentiation), so `is_well_formed_key`, the base's `Verify` and the possession
/// pairing all accept a value shifted by `P_3` (checked pre-fix: `PS::verify` and
/// `is_well_formed_key` both returned `true` on the shifted value). Feeding `P_3` into `hvk`,
/// `id`, the pre-credential and the credential must therefore be caught by `validate` alone. The
/// Result-returning paths return the exact [`Error::InvalidGroupElement`]; `verify_cred` returns
/// `false` where the base `Verify` would (and does) return `true`.
#[test]
fn every_argument_is_revalidated() {
    let mut w = World::<PS, DDH>::new(b"reg/args/ps", 0x9e9_0401);
    let (id_j, usk_j, cred_j) = w.member();
    let (id, usk) = w.pcs.user_keygen(&mut w.rng).unwrap();
    let att = w
        .pcs
        .attest(&w.hvk, &usk_j, &w.f_root, &cred_j, &id, &mut w.rng)
        .unwrap();
    let att2 = {
        let (_, k, c) = w.member();
        w.pcs
            .attest(&w.hvk, &k, &w.f_root, &c, &id, &mut w.rng)
            .unwrap()
    };
    let f = Predicate::new(2, b"members".to_vec());
    let (proof, _) = w
        .pcs
        .prove(&w.hvk, &f, &id, &usk, &[att.clone(), att2], &mut w.rng)
        .unwrap();
    let (request, _) = w
        .pcs
        .root_request(&w.hvk, &w.f_root, &id_j, &usk_j, &mut w.rng)
        .unwrap();
    let (pre, state) = {
        let (rq, st) = w
            .pcs
            .root_request(&w.hvk, &w.f_root, &id_j, &usk_j, &mut w.rng)
            .unwrap();
        (
            w.pcs
                .issue_root(&w.hvk, &w.hsk, &w.f_root, &id_j, &rq, &mut w.rng)
                .unwrap(),
            st,
        )
    };

    // ----- hvk: a G_1 component shifted by P_3 (is_well_formed_key would accept it) -----
    let mut bad_hvk = w.hvk.clone();
    bad_hvk.y1 += p3();
    assert_eq!(
        w.pcs.check_attestation(&bad_hvk, &id, &att),
        Err(Error::InvalidGroupElement("hvk"))
    );
    assert_eq!(
        w.pcs.check_proof(&bad_hvk, &f, &id, &proof),
        Err(Error::InvalidGroupElement("hvk"))
    );
    assert_eq!(
        w.pcs
            .check_root_request(&bad_hvk, &w.f_root, &id_j, &request),
        Err(Error::InvalidGroupElement("hvk"))
    );
    assert_eq!(
        w.pcs
            .prove(
                &bad_hvk,
                &f,
                &id,
                &usk,
                &[att.clone(), att.clone()],
                &mut w.rng
            )
            .err(),
        Some(Error::InvalidGroupElement("hvk"))
    );
    assert_eq!(
        w.pcs
            .unblind(&bad_hvk, &usk_j, &w.f_root, &pre, &state)
            .err(),
        Some(Error::InvalidGroupElement("hvk"))
    );
    assert!(!w.pcs.verify_cred(&bad_hvk, &usk_j, &w.f_root, &cred_j));

    // ----- id: shifted by P_3, in Attest and in VerifyAtt -----
    let bad_id = id + p3();
    assert_eq!(
        w.pcs
            .attest(&w.hvk, &usk_j, &w.f_root, &cred_j, &bad_id, &mut w.rng)
            .err(),
        Some(Error::InvalidGroupElement("id"))
    );
    // an attestation built by hand FOR the shifted id (so the context matches): still rejected,
    // by validate(id), before the proof is looked at
    let phi = w.pcs.enc_pred(&w.f_root).unwrap();
    let s = w.pcs.tag_point(&bad_id).unwrap();
    let tag = w.pcs.tag().eval(usk_j.expose_scalar(), &s).unwrap();
    let pp = w.pcs.base_parameters();
    let m = <PS as CredentialBase>::encode_message(pp, usk_j.expose_scalar(), &phi).unwrap();
    let (shown, omega) =
        <PS as CredentialBase>::rerand(pp, &w.hvk, &m, &cred_j.cred, &mut w.rng).unwrap();
    let relation = w
        .pcs
        .attestation_relation(&w.hvk, &shown, &phi, &tag, &s)
        .unwrap();
    let witness = PCS::<E, PS, DDH>::attestation_witness(usk_j.expose_scalar(), &omega);
    let ctx = w
        .pcs
        .attestation_context(&w.hvk, &bad_id, &phi, &tag, &shown)
        .unwrap();
    let att_for_bad = Attestation::<E, PS> {
        tag,
        shown,
        phi,
        proof: fiat_shamir::prove(&relation, &witness, &ctx, &mut w.rng).unwrap(),
    };
    assert_eq!(
        w.pcs.check_attestation(&w.hvk, &bad_id, &att_for_bad),
        Err(Error::InvalidGroupElement("id"))
    );

    // ----- pre-credential: a G_1 component shifted by P_3 (Unblind multiplies it by ρ) -----
    let mut bad_pre = pre.clone();
    bad_pre.sigma_1 += p3();
    assert_eq!(
        w.pcs
            .unblind(&w.hvk, &usk_j, &w.f_root, &bad_pre, &state)
            .err(),
        Some(Error::InvalidGroupElement("ĉred"))
    );

    // ----- credential: a G_1 component shifted by P_3 (the base Verify accepts it) -----
    let mut bad_cred = cred_j.clone();
    bad_cred.cred.sigma_1 += p3();
    let m_root = <PS as CredentialBase>::encode_message(pp, usk_j.expose_scalar(), &phi).unwrap();
    assert!(
        <PS as CredentialBase>::verify(pp, &w.hvk, &m_root, &bad_cred.cred),
        "the base pairing is expected to be blind to the order-3 component"
    );
    assert!(!w.pcs.verify_cred(&w.hvk, &usk_j, &w.f_root, &bad_cred));
}

#[test]
fn root_path_refuses_threshold_predicates() {
    let mut w = World::<PS, DDH>::new(b"reg/root/ps", 0x9e9_0301);
    let (id, usk) = w.pcs.user_keygen(&mut w.rng).unwrap();
    for k in [1u32, 2, u32::MAX] {
        let f = Predicate::new(k, b"members".to_vec());
        // an honest root request refers to f_root; here we hand `f` to the root path directly
        let (real_request, _) = w
            .pcs
            .root_request(&w.hvk, &w.f_root, &id, &usk, &mut w.rng)
            .unwrap();
        assert_eq!(
            w.pcs.check_root_request(&w.hvk, &f, &id, &real_request),
            Err(Error::NotARootPredicate)
        );
        assert_eq!(
            w.pcs
                .issue_root(&w.hvk, &w.hsk, &f, &id, &real_request, &mut w.rng)
                .err(),
            Some(Error::NotARootPredicate)
        );
        // and a request whose π_0 was actually built under the ROOT context for `f` (so the only
        // thing wrong is the threshold) is refused just the same
        let phi = w.pcs.enc_pred(&f).unwrap();
        let s = w.pcs.tag_point(&id).unwrap();
        let t0 = w.pcs.tag().eval(usk.expose_scalar(), &s).unwrap();
        let rho = Fr::rand(&mut w.rng);
        let c = PS::issuance_encoding(&(), &w.hvk, usk.expose_scalar(), &phi, &rho).unwrap();
        let relation = w
            .pcs
            .issuance_relation(&w.hvk, &c, &phi, &id, &t0, &s)
            .unwrap();
        let ctx = w.pcs.root_context(&w.hvk, &f, &id, &c, &t0).unwrap();
        let witness = PCS::<E, PS, DDH>::issuance_witness(usk.expose_scalar(), &rho);
        let proof = fiat_shamir::prove(&relation, &witness, &ctx, &mut w.rng).unwrap();
        let request = RootRequest::<E, PS> {
            encoding: c,
            t0,
            proof,
        };
        assert_eq!(
            w.pcs.check_root_request(&w.hvk, &f, &id, &request),
            Err(Error::NotARootPredicate)
        );
        assert_eq!(
            w.pcs
                .issue_root(&w.hvk, &w.hsk, &f, &id, &request, &mut w.rng)
                .err(),
            Some(Error::NotARootPredicate)
        );
    }
    // control: a real root request is served
    let (id_r, usk_r) = w.pcs.user_keygen(&mut w.rng).unwrap();
    let (request, state) = w
        .pcs
        .root_request(&w.hvk, &w.f_root, &id_r, &usk_r, &mut w.rng)
        .unwrap();
    let pre = w
        .pcs
        .issue_root(&w.hvk, &w.hsk, &w.f_root, &id_r, &request, &mut w.rng)
        .unwrap();
    assert!(
        w.pcs
            .unblind(&w.hvk, &usk_r, &w.f_root, &pre, &state)
            .is_ok()
    );
}
