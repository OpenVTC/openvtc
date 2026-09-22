//! Independent KNOWLEDGE-SOUNDNESS and ZERO-KNOWLEDGE harness for the modular threshold
//! construction (§5.1), against the Theorems "Knowledge soundness", "Attester anonymity",
//! "Subject privacy" and the Definition "Proof-gated issuance".
//!
//! What this harness DOES exercise, and what it cannot:
//!
//! * **Knowledge soundness** (Theorem "Knowledge soundness"): on a real accepting attestation /
//!   issuance proof, we run the INTERACTIVE sigma protocol on exactly the relation the proof uses
//!   (`R_att` / `R_issue`, built by the crate's public builders), rewind it (two `commit` calls
//!   with identically seeded RNGs answered on two distinct challenges), and check the
//!   special-soundness extractor recovers the real `usk` and a satisfying witness. This is the
//!   algebraic core of the theorem (special soundness of the sigma protocols); it is NOT the
//!   full theorem, which is about extraction from a Fiat-Shamir proof by rewinding / straight-line
//!   extraction of the random oracle.
//! * **Zero knowledge** (Attester anonymity / Subject privacy): we check the special-HVZK
//!   simulator produces transcripts that verify interactively for arbitrary challenges, and the
//!   structural facts a harness can see (tags are deterministic in `(usk, id)`; a re-randomized
//!   show shares no other group element; the helper cannot de-anonymise a `Σ-BBS` attester from
//!   its recorded `e`s). We do NOT test the computational (DDH / `q`-DDHI / class-hiding)
//!   indistinguishability, nor the reductions.
//! * **Proof-gated issuance** (Definition "Proof-gated issuance"): every single-field mutation of
//!   a valid proof is rejected by `VerifyProof` AND makes `Issue` output `⊥`.
//!
//! Every claim in a doc comment about why something must hold is an algebraic / structural fact
//! on the seeded sample at hand, not a proof of the theorem. All runs are seeded.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
mod common;

use ark_bls12_381::Fr;
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, One, UniformRand};
use common::{BBS, BaseTest, DDH, DY, Deployment, E, G1, G2, PS, SPSEQ};
use predicate_credential_system::{
    Error,
    cred::{
        CredentialBase,
        bbs::{BBSCredential, BBSMessage, BBSShownCredential},
    },
    kiprf::PCSTag,
    pcs::{Attestation, IssuanceProof, PCS, Predicate, PredicateCredentialSystem, UserSecretKey},
    sigma::{LinearRelation, commit, extract, fiat_shamir, respond, simulate, verify},
};
use rand::{SeedableRng, rngs::StdRng};

/// Two accepting transcripts on the same commitment (a rewound prover) and the special-soundness
/// extractor's output. "Rewinding" is two `commit` calls with identically seeded RNGs.
fn rewind_and_extract<R>(rel: &R, witness: &[Fr], seed: u64) -> Vec<Fr>
where
    R: LinearRelation<Scalar = Fr>,
{
    let mut challenge_rng = StdRng::seed_from_u64(seed ^ 0xE0E0);
    let (a, state_1) = commit(rel, &mut StdRng::seed_from_u64(seed)).unwrap();
    let (a_again, state_2) = commit(rel, &mut StdRng::seed_from_u64(seed)).unwrap();
    assert_eq!(a, a_again, "same random tape must give the same commitment");
    let (c_1, c_2) = (Fr::rand(&mut challenge_rng), Fr::rand(&mut challenge_rng));
    assert_ne!(c_1, c_2);
    let z_1 = respond(state_1, witness, &c_1).unwrap();
    let z_2 = respond(state_2, witness, &c_2).unwrap();
    assert!(verify(rel, &a, &c_1, &z_1));
    assert!(verify(rel, &a, &c_2, &z_2));
    extract(rel, &a, (&c_1, &z_1), (&c_2, &z_2)).expect("special soundness recovers a witness")
}

// ---------------------------------------------------------------------------------------------
// (a) Rewinding extractor on R_att
// ---------------------------------------------------------------------------------------------

/// Theorem "Knowledge soundness", attestation clause. For an honest attester, rebuild `R_att`
/// with the public builder, rewind the interactive protocol, and check: the extracted variable 0
/// is the attester's `usk`; the extracted vector satisfies `R_att`; the extracted key reproduces
/// `T_j = Tag(usk_j, H_0(id))`; and `VerifyCred` accepts the attester's credential under the
/// EXTRACTED key (an accepting attestation yields a valid credential on the extracted key).
fn extractor_on_att<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let member = dep.root_member();
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);

    // control: the honest attestation this show belongs to IS accepted.
    let ctx = pcs
        .attestation_context(hvk, &id, &show.phi, &show.tag, &show.shown)
        .unwrap();
    let relation = pcs
        .attestation_relation(hvk, &show.shown, &show.phi, &show.tag, &show.s)
        .unwrap();
    let witness = PCS::<E, B, T>::attestation_witness(&show.m_hid, &show.show_state);
    let proof = fiat_shamir::prove(&relation, &witness, &ctx, &mut dep.rng).unwrap();
    let att = Attestation {
        tag: show.tag,
        shown: show.shown.clone(),
        phi: show.phi,
        proof,
    };
    assert_eq!(pcs.check_attestation(hvk, &id, &att), Ok(()));

    // rewind + extract on exactly this relation
    let extracted = rewind_and_extract(&relation, &witness, seed);
    assert_eq!(extracted[0], *member.usk.expose_scalar(), "extracted usk");
    assert!(relation.is_satisfied_by(&extracted));
    // the extracted key reproduces T_j
    assert_eq!(pcs.tag().eval(&extracted[0], &show.s), Some(show.tag));
    // an accepting attestation yields a valid credential on the extracted key
    let extracted_usk = UserSecretKey::<E>::from_scalar(extracted[0]);
    assert!(pcs.verify_cred(hvk, &extracted_usk, &member.f, &member.cred));
    // a different value in usk's place satisfies no part of R_att
    let mut wrong = witness.to_vec();
    wrong[0] += Fr::one();
    assert!(!relation.is_satisfied_by(&wrong));
}

#[test]
fn extractor_on_att_ps_ddh() {
    extractor_on_att::<PS, DDH>(b"snd/att/ps+ddh", 0x5d01_0001);
}
#[test]
fn extractor_on_att_ps_dy() {
    extractor_on_att::<PS, DY>(b"snd/att/ps+dy", 0x5d01_0002);
}
#[test]
fn extractor_on_att_bbs_ddh() {
    extractor_on_att::<BBS, DDH>(b"snd/att/bbs+ddh", 0x5d01_0003);
}
#[test]
fn extractor_on_att_bbs_dy() {
    extractor_on_att::<BBS, DY>(b"snd/att/bbs+dy", 0x5d01_0004);
}
#[test]
fn extractor_on_att_eq_ddh() {
    extractor_on_att::<SPSEQ, DDH>(b"snd/att/eq+ddh", 0x5d01_0005);
}

/// Σ-BBS additionally (Lemma on `Σ-BBS`): from the extracted `(usk, e, ρ, r_1, r_3)` and the
/// shown `Ā`, reconstruct the signature `A = Ā^{r_3/r_1}` and verify it on `(usk, φ, ρ)`; it is
/// the attester's own credential.
fn bbs_reconstruct<T: PCSTag<G1>>(label: &[u8], seed: u64) {
    let mut dep = Deployment::<BBS, T>::open(label, seed);
    let member = dep.root_member();
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    let pp = dep.pcs.base_parameters();
    let relation = dep
        .pcs
        .attestation_relation(&dep.hvk, &show.shown, &show.phi, &show.tag, &show.s)
        .unwrap();
    let witness = PCS::<E, BBS, T>::attestation_witness(&show.m_hid, &show.show_state);
    let extracted = rewind_and_extract(&relation, &witness, seed);
    // R_att witness order for Σ-BBS: usk, e, ρ, r_1, r_3
    let (usk, e, rho, r1, r3) = (
        extracted[0],
        extracted[1],
        extracted[2],
        extracted[3],
        extracted[4],
    );
    let a_bar: G1 = downcast_bbs_shown(&show.shown).a_bar;
    let rebuilt = BBSCredential {
        a: a_bar * (r3 * r1.inverse().unwrap()),
        e,
    };
    assert!(BBS::verify(
        pp,
        &dep.hvk,
        &BBSMessage::new(usk, show.phi, rho),
        &rebuilt
    ));
    assert_eq!(rebuilt, member.cred.cred);
}

/// `B::ShownCredential` is `BBSShownCredential` for `BBS`; this makes the field accessible in the
/// monomorphic `Σ-BBS` reconstruction above without a base-specific trait method.
fn downcast_bbs_shown(shown: &<BBS as CredentialBase>::ShownCredential) -> &BBSShownCredential<E> {
    shown
}

#[test]
fn bbs_extractor_rebuilds_the_signature_ddh() {
    bbs_reconstruct::<DDH>(b"snd/bbs-recon/ddh", 0x5d02_0001);
}
#[test]
fn bbs_extractor_rebuilds_the_signature_dy() {
    bbs_reconstruct::<DY>(b"snd/bbs-recon/dy", 0x5d02_0002);
}

// ---------------------------------------------------------------------------------------------
// (b) Rewinding extractor on R_issue (issuance proof AND root request)
// ---------------------------------------------------------------------------------------------

/// Theorem "Knowledge soundness", issuance clause. From an accepting `π_0` the extractor recovers
/// `usk` with `id = Tag(usk, c_0)` and `T_0 = Tag(usk, H_0(id))`, and (for `Σ-PS` / `Σ-BBS`) the
/// extracted opening `ρ` recomputes `C`. Checked on both the ordinary issuance proof and the root
/// request (which run the same `R_issue`, under different contexts).
fn extractor_on_issue<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let roots = dep.root_members(1);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);
    let f = Predicate::new(1, b"members".to_vec());
    let (proof, state) = dep.prove_ok(&f, &id, &usk, &atts);

    // The predicate's φ enters C for Σ-BBS (opening clause target C·h₀⁻¹·h₂⁻φ), so the relation
    // has to be rebuilt with the SAME predicate the proof was made under.
    let check = |dep: &Deployment<B, T>,
                 pred: &Predicate,
                 encoding: &B::WireEncoding,
                 t0: &G1,
                 witness: &[Fr],
                 seed: u64| {
        let pcs = &dep.pcs;
        let s = pcs.tag_point(&id).unwrap();
        let phi = pcs.enc_pred(pred).unwrap();
        let c = B::encoding_from_wire(pcs.base_parameters(), encoding, &id).unwrap();
        let relation = pcs
            .issuance_relation(&dep.hvk, &c, &phi, &id, t0, &s)
            .unwrap();
        let extracted = rewind_and_extract(&relation, witness, seed);
        assert_eq!(extracted[0], *usk.expose_scalar(), "extracted usk");
        assert_eq!(
            pcs.tag().eval(&extracted[0], pcs.identity_point()),
            Some(id)
        );
        assert_eq!(pcs.tag().eval(&extracted[0], &s), Some(*t0));
        // (Σ-PS / Σ-BBS) the extracted opening recomputes C; (Σ-EQ) C = id, already checked above.
        let (aux, rho) = B::issuance_aux_rho(&extracted);
        let m_hid = B::hidden_message(&extracted[0], &aux);
        let recomputed =
            B::issuance_encoding(pcs.base_parameters(), &dep.hvk, &m_hid, &phi, &rho).unwrap();
        assert_eq!(B::encoding_to_wire(&recomputed), *encoding);
    };

    // issuance proof
    check(&dep, &f, &proof.encoding, &proof.t0, &state.witness(), seed);

    // root request: same R_issue, different context, and its own root predicate
    let (request, root_state) = dep
        .pcs
        .root_request(&dep.hvk, &dep.f_root, &id, &usk, &mut dep.rng)
        .unwrap();
    let f_root = dep.f_root.clone();
    check(
        &dep,
        &f_root,
        &request.encoding,
        &request.t0,
        &root_state.witness(),
        seed ^ 0x99,
    );
}

#[test]
fn extractor_on_issue_ps_ddh() {
    extractor_on_issue::<PS, DDH>(b"snd/iss/ps+ddh", 0x5d03_0001);
}
#[test]
fn extractor_on_issue_ps_dy() {
    extractor_on_issue::<PS, DY>(b"snd/iss/ps+dy", 0x5d03_0002);
}
#[test]
fn extractor_on_issue_bbs_ddh() {
    extractor_on_issue::<BBS, DDH>(b"snd/iss/bbs+ddh", 0x5d03_0003);
}
#[test]
fn extractor_on_issue_bbs_dy() {
    extractor_on_issue::<BBS, DY>(b"snd/iss/bbs+dy", 0x5d03_0004);
}
#[test]
fn extractor_on_issue_eq_ddh() {
    extractor_on_issue::<SPSEQ, DDH>(b"snd/iss/eq+ddh", 0x5d03_0005);
}

// ---------------------------------------------------------------------------------------------
// (c) The shared witness: one usk for the possession clause and the tag clause
// ---------------------------------------------------------------------------------------------

/// `R_att` shares the SAME variable `usk` between the possession clauses (which bind the
/// credential's key) and the tag clause (which binds `T_j`). A statement whose tag belongs to a
/// DIFFERENT key than the credential therefore has no witness at all: neither the credential's
/// key nor the tag's key satisfies both clauses, so the honest prover refuses and no accepting
/// transcript exists (a forged one would extract to a satisfying witness, of which there is none).
fn shared_witness<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let member = dep.root_member();
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    // a tag under a DIFFERENT key
    let other_key = loop {
        let k = dep.pcs.tag().keygen(&mut dep.rng);
        if k != *member.usk.expose_scalar() {
            break k;
        }
    };
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);
    let foreign_tag = pcs.tag().eval(&other_key, &show.s).unwrap();

    // control: with the attester's own tag, the relation is satisfied
    let honest = pcs
        .attestation_relation(hvk, &show.shown, &show.phi, &show.tag, &show.s)
        .unwrap();
    let witness = PCS::<E, B, T>::attestation_witness(&show.m_hid, &show.show_state);
    assert!(honest.is_satisfied_by(&witness));

    // the statement for the foreign tag has no witness
    let foreign = pcs
        .attestation_relation(hvk, &show.shown, &show.phi, &foreign_tag, &show.s)
        .unwrap();
    // neither candidate key satisfies both clauses
    assert!(
        !foreign.is_satisfied_by(&witness),
        "credential's key fails the tag clause"
    );
    let mut with_other = witness.to_vec();
    with_other[0] = other_key;
    assert!(
        !foreign.is_satisfied_by(&with_other),
        "the tag's key fails the possession clause"
    );
    // so the honest prover cannot produce a proof for it
    let ctx = pcs
        .attestation_context(hvk, &id, &show.phi, &foreign_tag, &show.shown)
        .unwrap();
    assert_eq!(
        fiat_shamir::prove(&foreign, &witness, &ctx, &mut dep.rng).err(),
        Some(Error::WitnessDoesNotSatisfyRelation)
    );
    assert_eq!(
        fiat_shamir::prove(&foreign, &with_other, &ctx, &mut dep.rng).err(),
        Some(Error::WitnessDoesNotSatisfyRelation)
    );
}

#[test]
fn shared_witness_ps_ddh() {
    shared_witness::<PS, DDH>(b"snd/shared/ps+ddh", 0x5d04_0001);
}
#[test]
fn shared_witness_bbs_dy() {
    shared_witness::<BBS, DY>(b"snd/shared/bbs+dy", 0x5d04_0002);
}
#[test]
fn shared_witness_eq_ddh() {
    shared_witness::<SPSEQ, DDH>(b"snd/shared/eq+ddh", 0x5d04_0003);
}

// ---------------------------------------------------------------------------------------------
// (d) The simulators (special HVZK) and the Fiat-Shamir binding
// ---------------------------------------------------------------------------------------------

/// The special-HVZK simulator produces transcripts that verify INTERACTIVELY for an arbitrary
/// challenge (`A = φ(z) − c·Y`), yet the same simulated `(A, z)` is NOT a valid Fiat-Shamir proof:
/// `verify_attestation` recomputes `c' = H_1(ctx ‖ statement ‖ A)` and rejects unless `c' = c`,
/// which a challenge chosen before `A` meets only with negligible probability. Without programming
/// the random oracle, a simulated attestation is rejected.
fn simulator_att_and_issue<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let member = dep.root_member();
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let show = dep.att_show(&member, &id);
    let mut sim_rng = StdRng::seed_from_u64(seed ^ 0x515);

    // R_att
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);
    let relation = pcs
        .attestation_relation(hvk, &show.shown, &show.phi, &show.tag, &show.s)
        .unwrap();
    let ctx = pcs
        .attestation_context(hvk, &id, &show.phi, &show.tag, &show.shown)
        .unwrap();
    for _ in 0..4 {
        let c = Fr::rand(&mut sim_rng);
        let (a, z) = simulate(&relation, &c, &mut sim_rng).unwrap();
        // special HVZK: the simulated transcript verifies interactively for this challenge
        assert!(verify(&relation, &a, &c, &z));
        // but it is not a Fiat-Shamir proof: c ≠ H_1(ctx ‖ statement ‖ A) except negligibly
        let sim_proof = predicate_credential_system::sigma::FSProof {
            challenge: c,
            responses: z,
        };
        assert!(!fiat_shamir::verify(&relation, &ctx, &sim_proof));
        let att = Attestation {
            tag: show.tag,
            shown: show.shown.clone(),
            phi: show.phi,
            proof: sim_proof,
        };
        assert_eq!(
            pcs.check_attestation(hvk, &id, &att),
            Err(Error::InvalidProof)
        );
    }

    // R_issue: a simulated π_0 does not verify under the issuance context either
    let s = pcs.tag_point(&id).unwrap();
    let phi = pcs.enc_pred(&member.f).unwrap();
    let t0 = pcs.tag().eval(usk.expose_scalar(), &s).unwrap();
    // a real C (so the statement is admissible); its opening is not needed by the simulator
    let (aux, rho) = B::sample_issuance(pcs.base_parameters(), &mut dep.rng);
    let m_hid = B::hidden_message(usk.expose_scalar(), &aux);
    let c_enc = B::issuance_encoding(pcs.base_parameters(), hvk, &m_hid, &phi, &rho).unwrap();
    let relation = pcs
        .issuance_relation(hvk, &c_enc, &phi, &id, &t0, &s)
        .unwrap();
    let ctx = pcs.root_context(hvk, &member.f, &id, &c_enc, &t0).unwrap();
    for _ in 0..4 {
        let c = Fr::rand(&mut sim_rng);
        let (a, z) = simulate(&relation, &c, &mut sim_rng).unwrap();
        assert!(verify(&relation, &a, &c, &z));
        let sim_proof = predicate_credential_system::sigma::FSProof {
            challenge: c,
            responses: z,
        };
        assert!(!fiat_shamir::verify(&relation, &ctx, &sim_proof));
    }
}

#[test]
fn simulator_ps_ddh() {
    simulator_att_and_issue::<PS, DDH>(b"snd/sim/ps+ddh", 0x5d05_0001);
}
#[test]
fn simulator_bbs_ddh() {
    simulator_att_and_issue::<BBS, DDH>(b"snd/sim/bbs+ddh", 0x5d05_0002);
}
#[test]
fn simulator_eq_ddh() {
    simulator_att_and_issue::<SPSEQ, DDH>(b"snd/sim/eq+ddh", 0x5d05_0003);
}

// ---------------------------------------------------------------------------------------------
// (e) Structural anonymity / privacy facts that ARE testable
// ---------------------------------------------------------------------------------------------

/// The structural facts behind Attester anonymity (Theorem "Attester anonymity"): an attester's
/// tag for a fixed identifier is deterministic — two attestations by the same attester for the
/// same `id` share the tag and NOTHING else (this is why the anonymity game forbids a prior query
/// at `id*`); the same attester's tags for two different ids differ; two DIFFERENT attesters under
/// the same predicate expose an equal `φ`, distinct tags, and no equal group element.
fn structural_anonymity<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let member_a = dep.root_member();
    let member_b = dep.root_member();
    let (id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let (id2, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();

    // same attester, same id, two shows: same tag, different everything else
    let a1 = dep.attest(&member_a, &id);
    let a2 = dep.attest(&member_a, &id);
    assert_eq!(a1.tag, a2.tag, "the tag is deterministic in (usk, id)");
    assert_ne!(a1.shown, a2.shown, "a fresh re-randomization");
    assert_ne!(a1.proof, a2.proof);
    assert!(dep.pcs.verify_attestation(&dep.hvk, &id, &a1));
    assert!(dep.pcs.verify_attestation(&dep.hvk, &id, &a2));

    // same attester, two ids: different tags
    let a3 = dep.attest(&member_a, &id2);
    assert_ne!(a1.tag, a3.tag);

    // two attesters, same predicate (hence same φ): distinct tags, no equal group element
    let b1 = dep.attest(&member_b, &id);
    assert_eq!(
        a1.phi, b1.phi,
        "the one value an attestation leaks by design"
    );
    assert_ne!(a1.tag, b1.tag);
    assert_ne!(a1.shown, b1.shown);
    assert_ne!(a1.proof, b1.proof);
}

#[test]
fn structural_anonymity_ps_ddh() {
    structural_anonymity::<PS, DDH>(b"snd/anon/ps+ddh", 0x5d06_0001);
}
#[test]
fn structural_anonymity_bbs_ddh() {
    structural_anonymity::<BBS, DDH>(b"snd/anon/bbs+ddh", 0x5d06_0002);
}
#[test]
fn structural_anonymity_eq_ddh() {
    structural_anonymity::<SPSEQ, DDH>(b"snd/anon/eq+ddh", 0x5d06_0003);
}

/// Attack A7 at the PCS level (Theorem "Attester anonymity", the `Σ-BBS` case; the two-randomizer
/// show of the Lemma on `Σ-BBS`). A helper that issued every credential — so it holds `x` (via
/// `X̃`) and recorded every `e_i` — cannot recognise the attester of a two-randomizer show with
/// the pairing test `e(Ā, X̃ g̃^{e_i}) = e(D, g̃)` or the anchor test `D B̄^{-1} = Ā^{e_i}`, while
/// the single-randomizer show it replaced is identified by both, for the right `i`. The issuance
/// proof hands the helper only `(id, T_0, C)` and `Issue` takes only the proof (never `usk` or
/// `ρ`), which is why the helper cannot do better than these tests.
#[test]
fn bbs_helper_cannot_deanonymize_at_pcs_level() {
    let mut dep = Deployment::<BBS, DDH>::open(b"snd/a7", 0x5d07_0001);
    let members = dep.root_members(6);
    let issued_e: Vec<Fr> = members.iter().map(|m| m.cred.cred.e).collect();
    let x_tilde = dep.hvk.x_tilde;
    let pp = dep.pcs.base_parameters().clone();

    let helper_tests = |shown: &BBSShownCredential<E>| -> Vec<(usize, &'static str)> {
        let g2 = G2::generator();
        let mut fired = Vec::new();
        for (i, e) in issued_e.iter().enumerate() {
            if E::pairing(shown.a_bar, x_tilde + g2 * *e) == E::pairing(shown.d, g2) {
                fired.push((i, "pairing"));
            }
            if shown.d - shown.b_bar == shown.a_bar * *e {
                fired.push((i, "anchor"));
            }
        }
        fired
    };

    for attester in [0usize, 3, 5] {
        let (fresh_id, _) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
        // three two-randomizer shows: none is recognised
        for _ in 0..3 {
            let att = dep.attest(&members[attester], &fresh_id);
            assert!(dep.pcs.verify_attestation(&dep.hvk, &fresh_id, &att));
            assert_eq!(helper_tests(&att.shown), vec![]);
        }
        // control: the single-randomizer show passes the same public checks but is identified,
        // for the right i only
        let m = &members[attester];
        let msg = BBSMessage::new(
            *m.usk.expose_scalar(),
            dep.pcs.enc_pred(&m.f).unwrap(),
            m.cred.aux,
        );
        let r2 = Fr::rand(&mut dep.rng);
        let (a_bar, d) = (m.cred.cred.a * r2, pp.b(&msg) * r2);
        let single = BBSShownCredential::<E> {
            a_bar,
            b_bar: d - a_bar * m.cred.cred.e,
            d,
        };
        let fired = helper_tests(&single);
        assert!(!fired.is_empty());
        assert!(fired.iter().all(|(i, _)| *i == attester));
        assert!(fired.contains(&(attester, "pairing")));
        assert!(fired.contains(&(attester, "anchor")));
    }
}

// ---------------------------------------------------------------------------------------------
// (f) Proof-gated issuance, exhaustively
// ---------------------------------------------------------------------------------------------

/// Definition "Proof-gated issuance", exhaustively: take a valid proof and mutate EVERY field in
/// turn — each attestation's tag, every group element of every shown credential, every `φ_j`,
/// every attestation challenge and response, `C`, `T_0`, the `π_0` challenge and every `π_0`
/// response, the ORDER of the attestations, and the NUMBER of attestations. Each mutant must make
/// `VerifyProof` return `0` AND `Issue` output `⊥`. The mutant count is asserted against a formula
/// so the loop cannot silently shrink.
fn proof_gated_exhaustive<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    const K: usize = 2;
    let g = G1::generator();
    let g2 = G2::generator();
    let mut dep = Deployment::<B, T>::open(label, seed);
    let roots = dep.root_members(K);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots, &id);
    let f = Predicate::new(K as u32, b"members".to_vec());
    let (proof, _) = dep.prove_ok(&f, &id, &usk, &atts);

    // control: the unmodified proof verifies and issues
    assert!(dep.pcs.verify_proof(&dep.hvk, &f, &id, &proof));
    assert!(
        dep.pcs
            .issue(&dep.hvk, &dep.hsk, &f, &id, &proof, &mut dep.rng)
            .is_ok()
    );

    let mut mutants: Vec<IssuanceProof<E, B>> = Vec::new();
    // each attestation's tag
    for j in 0..K {
        let mut m = proof.clone();
        m.attestations[j].tag += g;
        mutants.push(m);
    }
    // every group element of every shown credential
    for j in 0..K {
        for variant in B::shown_variants(&proof.attestations[j].shown, g, g2) {
            let mut m = proof.clone();
            m.attestations[j].shown = variant;
            mutants.push(m);
        }
    }
    // every φ_j
    for j in 0..K {
        let mut m = proof.clone();
        m.attestations[j].phi += Fr::one();
        mutants.push(m);
    }
    // every attestation challenge
    for j in 0..K {
        let mut m = proof.clone();
        m.attestations[j].proof.challenge += Fr::one();
        mutants.push(m);
    }
    // every attestation response
    for j in 0..K {
        for r in 0..B::ATT_RESPONSES {
            let mut m = proof.clone();
            m.attestations[j].proof.responses[r] += Fr::one();
            mutants.push(m);
        }
    }
    // C (only for the bases that transmit it)
    let has_c = if let Some(bumped) = B::bump_wire(&proof.encoding, g) {
        let mut m = proof.clone();
        m.encoding = bumped;
        mutants.push(m);
        1
    } else {
        0
    };
    // T_0
    {
        let mut m = proof.clone();
        m.t0 += g;
        mutants.push(m);
    }
    // π_0 challenge
    {
        let mut m = proof.clone();
        m.proof.challenge += Fr::one();
        mutants.push(m);
    }
    // every π_0 response
    for r in 0..B::ISSUE_RESPONSES {
        let mut m = proof.clone();
        m.proof.responses[r] += Fr::one();
        mutants.push(m);
    }
    // order of the attestations
    {
        let mut m = proof.clone();
        m.attestations.swap(0, 1);
        mutants.push(m);
    }
    // number of attestations: one fewer, one more
    {
        let mut m = proof.clone();
        m.attestations.pop();
        mutants.push(m);
        let mut m = proof.clone();
        let last = m.attestations[K - 1].clone();
        m.attestations.push(last);
        mutants.push(m);
    }

    let expected = K            // tags
        + K * B::NUM_SHOWN_ELEMENTS // shown elements
        + K                     // φ_j
        + K                     // attestation challenges
        + K * B::ATT_RESPONSES  // attestation responses
        + has_c                 // C
        + 1                     // T_0
        + 1                     // π_0 challenge
        + B::ISSUE_RESPONSES    // π_0 responses
        + 1                     // order swap
        + 2; // count ±1
    assert_eq!(
        mutants.len(),
        expected,
        "the mutation loop must not silently shrink"
    );

    for (n, mutant) in mutants.iter().enumerate() {
        assert!(
            !dep.pcs.verify_proof(&dep.hvk, &f, &id, mutant),
            "mutant {n} was accepted by VerifyProof"
        );
        assert!(
            dep.pcs
                .issue(&dep.hvk, &dep.hsk, &f, &id, mutant, &mut dep.rng)
                .is_err(),
            "mutant {n} was issued on"
        );
    }
}

#[test]
fn proof_gated_exhaustive_ps_ddh() {
    proof_gated_exhaustive::<PS, DDH>(b"snd/gated/ps+ddh", 0x5d08_0001);
}
#[test]
fn proof_gated_exhaustive_ps_dy() {
    proof_gated_exhaustive::<PS, DY>(b"snd/gated/ps+dy", 0x5d08_0002);
}
#[test]
fn proof_gated_exhaustive_bbs_ddh() {
    proof_gated_exhaustive::<BBS, DDH>(b"snd/gated/bbs+ddh", 0x5d08_0003);
}
#[test]
fn proof_gated_exhaustive_bbs_dy() {
    proof_gated_exhaustive::<BBS, DY>(b"snd/gated/bbs+dy", 0x5d08_0004);
}
#[test]
fn proof_gated_exhaustive_eq_ddh() {
    proof_gated_exhaustive::<SPSEQ, DDH>(b"snd/gated/eq+ddh", 0x5d08_0005);
}
