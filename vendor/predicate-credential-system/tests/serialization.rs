//! Independent serialization / encoding suite for the PCS construction (§5.1, §5.3, §5.5).
//!
//! Round trips (the derived canonical [`WireFormat`] and the fixed-format compact encoding of
//! [`predicate_credential_system::pcs::codec`]) of every public protocol object, for every compatible base × tag; the
//! byte sizes of the paper's comparison table (\cref{tab:comparison}) over BLS12-381, with the
//! decomposition into group elements and scalars spelled out; and the strictness of the decoder
//! (§5.5, "parse `π` in a fixed format"): trailing bytes, non-canonical scalars, points outside
//! the prime-order subgroup, and uncompressed encodings are all refused, and no length is ever
//! read from the wire.
//!
//! All runs are seeded (`StdRng::seed_from_u64`, the seed at each call site). What a size test
//! measures (compact vs. derived) is stated at the assertion, following the crate's convention.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
mod common;

use ark_bls12_381::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{BigInteger, One, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use common::{
    BBS, BaseTest, DDH, DY, Deployment, E, G1, PS, SPSEQ, random_proof, random_root_request,
};
use predicate_credential_system::{
    Error,
    kiprf::PCSTag,
    pcs::{
        Attestation, Credential, IssuanceProof, IssuanceState, PCS, Predicate,
        PredicateCredentialSystem, PublicParameters, RootRequest, SetupParams,
    },
    serialization::WireFormat,
    sigma::FSProof,
};
use rand::{SeedableRng, rngs::StdRng};

/// Real, verifying protocol objects of a deployment: a `k`-attestation issuance proof, its
/// attestations, a root request, and the subject's issued credential.
struct Artifacts<B: BaseTest> {
    id: G1,
    attestation: Attestation<E, B>,
    proof: IssuanceProof<E, B>,
    request: RootRequest<E, B>,
    credential: Credential<E, B>,
    f: Predicate,
    state: IssuanceState<E, B>,
}

fn artifacts<B, T>(label: &[u8], seed: u64, k: u32) -> (Deployment<B, T>, Artifacts<B>)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let mut dep = Deployment::<B, T>::open(label, seed);
    let roots = dep.root_members(k as usize + 1);
    let (id, usk) = dep.pcs.user_keygen(&mut dep.rng).unwrap();
    let atts = dep.attestations(&roots[..k as usize], &id);
    let f = Predicate::new(k, b"members".to_vec());
    let attestation = atts[0].clone();
    let (proof, state) = dep.prove_ok(&f, &id, &usk, &atts);
    let pre = dep
        .pcs
        .issue(&dep.hvk, &dep.hsk, &f, &id, &proof, &mut dep.rng)
        .unwrap();
    let credential = dep.pcs.unblind(&dep.hvk, &usk, &f, &pre, &state).unwrap();
    let (request, _) = dep
        .pcs
        .root_request(&dep.hvk, &dep.f_root, &id, &usk, &mut dep.rng)
        .unwrap();
    (
        dep,
        Artifacts {
            id,
            attestation,
            proof,
            request,
            credential,
            f,
            state,
        },
    )
}

fn is_serde_err<V>(r: &Result<V, Error>) -> bool {
    matches!(r, Err(Error::Serialization(_)))
}

// ---------------------------------------------------------------------------------------------
// Round trips of every public type, both encodings, for every compatible pair
// ---------------------------------------------------------------------------------------------

/// Every public protocol object round-trips through the derived canonical encoding and (for the
/// three objects that have one) the fixed-format compact encoding; the decoded objects still
/// verify. Run at `k = 2` for each compatible base × tag pair.
fn round_trips<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest,
    T: PCSTag<G1>,
{
    let (dep, art) = artifacts::<B, T>(label, seed, 2);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);

    // Attestation: both encodings, and the decoded value verifies.
    let compact = art.attestation.to_compact_bytes().unwrap();
    let decoded = Attestation::<E, B>::from_compact_bytes(&compact).unwrap();
    assert_eq!(decoded, art.attestation);
    assert!(pcs.verify_attestation(hvk, &art.id, &decoded));
    let derived = art.attestation.to_bytes().unwrap();
    assert_eq!(
        Attestation::<E, B>::from_bytes(&derived).unwrap(),
        art.attestation
    );
    // the derived encoding length-prefixes the response vector: 8 bytes more
    assert_eq!(derived.len(), compact.len() + 8);

    // IssuanceProof: both encodings, decoded proof verifies; derived is longer by 8·(k+1)+8.
    let compact = art.proof.to_compact_bytes().unwrap();
    let decoded = IssuanceProof::<E, B>::from_compact_bytes(&compact, &art.f).unwrap();
    assert_eq!(decoded, art.proof);
    assert!(pcs.verify_proof(hvk, &art.f, &art.id, &decoded));
    let derived = art.proof.to_bytes().unwrap();
    assert_eq!(
        IssuanceProof::<E, B>::from_bytes(&derived).unwrap(),
        art.proof
    );
    assert_eq!(derived.len(), compact.len() + 8 * (2 + 1) + 8);

    // RootRequest: both encodings, decoded request verifies.
    let compact = art.request.to_compact_bytes().unwrap();
    let decoded = RootRequest::<E, B>::from_compact_bytes(&compact).unwrap();
    assert_eq!(decoded, art.request);
    assert!(pcs.verify_root_request(hvk, &dep.f_root, &art.id, &decoded));
    let derived = art.request.to_bytes().unwrap();
    assert_eq!(
        RootRequest::<E, B>::from_bytes(&derived).unwrap(),
        art.request
    );
    assert_eq!(derived.len(), compact.len() + 8);

    // Credential: derived encoding only, and the decoded value still verifies.
    let bytes = art.credential.to_bytes().unwrap();
    assert_eq!(
        Credential::<E, B>::from_bytes(&bytes).unwrap(),
        art.credential
    );

    // PublicParameters: round-trips, and the rebuilt system agrees on the digest.
    let pp_bytes = pcs.public_parameters().to_bytes().unwrap();
    let received = PublicParameters::<E, B, T>::from_bytes(&pp_bytes).unwrap();
    let rebuilt = PCS::<E, B, T>::from_public_parameters(
        received,
        predicate_credential_system::pcs::AcceptAll,
    )
    .unwrap();
    assert_eq!(rebuilt.parameters_digest(), pcs.parameters_digest());

    // IssuanceState (secret): round-trips through its own encoding, Debug is redacted.
    let bytes = art.state.to_bytes().unwrap();
    let stored = IssuanceState::<E, B>::from_bytes(&bytes).unwrap();
    assert_eq!(&*stored.witness(), &*art.state.witness());
    assert_eq!(format!("{:?}", art.state), "IssuanceState(<redacted>)");
    assert_eq!(format!("{stored:?}"), "IssuanceState(<redacted>)");
}

#[test]
fn round_trips_ps_ddh() {
    round_trips::<PS, DDH>(b"ser/ps+ddh", 0x5e21_0001);
}
#[test]
fn round_trips_ps_dy() {
    round_trips::<PS, DY>(b"ser/ps+dy", 0x5e21_0002);
}
#[test]
fn round_trips_bbs_ddh() {
    round_trips::<BBS, DDH>(b"ser/bbs+ddh", 0x5e21_0003);
}
#[test]
fn round_trips_bbs_dy() {
    round_trips::<BBS, DY>(b"ser/bbs+dy", 0x5e21_0004);
}
#[test]
fn round_trips_eq_ddh() {
    round_trips::<SPSEQ, DDH>(b"ser/eq+ddh", 0x5e21_0005);
}

// ---------------------------------------------------------------------------------------------
// Byte sizes of the comparison table (§5.3) over BLS12-381
// ---------------------------------------------------------------------------------------------

/// The sizes of the paper's comparison table, in the fixed-format COMPACT encoding, with the
/// decomposition into `G_1` (48 B), `G_2` (96 B) and `Z_p` (32 B) written out. Measured on
/// format-only random objects (the byte length is a function of the format, not of the values;
/// the correctness suite pins the same numbers on verifying objects).
#[test]
fn compact_sizes_match_the_table() {
    const G1B: usize = 48;
    const G2B: usize = 96;
    const ZP: usize = 32;

    fn att_size<B: BaseTest>(seed: u64) -> usize {
        let mut rng = StdRng::seed_from_u64(seed);
        common::random_attestation::<B>(&mut rng)
            .to_compact_bytes()
            .unwrap()
            .len()
    }
    fn proof_size<B: BaseTest>(k: usize, seed: u64) -> usize {
        let mut rng = StdRng::seed_from_u64(seed);
        random_proof::<B>(k, &mut rng)
            .to_compact_bytes()
            .unwrap()
            .len()
    }
    fn request_size<B: BaseTest>(seed: u64) -> usize {
        let mut rng = StdRng::seed_from_u64(seed);
        random_root_request::<B>(&mut rng)
            .to_compact_bytes()
            .unwrap()
            .len()
    }

    // |att|: Σ-PS = 3 G_1 (T, σ'_1, σ'_2) + 3 Z_p (φ, c, z) = 240.
    assert_eq!(att_size::<PS>(1), 3 * G1B + 3 * ZP);
    assert_eq!(att_size::<PS>(1), 240);
    // Σ-BBS = 4 G_1 (T, Ā, B̄, D) + 7 Z_p (φ, c, z_usk, z_e, z_ρ, z_{r_1}, z_{r_3}) = 416.
    assert_eq!(att_size::<BBS>(2), 4 * G1B + 7 * ZP);
    assert_eq!(att_size::<BBS>(2), 416);
    // Σ-EQ = 6 G_1 (M'_1, M'_2, M'_3, Z', Y', T) + 1 G_2 (Ỹ') + 3 Z_p (φ, c, z) = 480.
    assert_eq!(att_size::<SPSEQ>(3), 6 * G1B + G2B + 3 * ZP);
    assert_eq!(att_size::<SPSEQ>(3), 480);

    // |π| = k·|att| + |C| + |T_0| + |π_0|. π_0 has 1 + ISSUANCE_VARIABLES scalars.
    // Σ-PS / Σ-BBS carry C (48 B); Σ-EQ does not. π_0: PS/BBS 3 Z_p (c, z_usk, z_ρ), EQ 2 (c, z_usk).
    for &k in &[1usize, 2, 5] {
        assert_eq!(proof_size::<PS>(k, 10), k * 240 + G1B + G1B + 3 * ZP);
        assert_eq!(proof_size::<BBS>(k, 20), k * 416 + G1B + G1B + 3 * ZP);
        // Σ-EQ carries no C
        assert_eq!(proof_size::<SPSEQ>(k, 30), k * 480 + G1B + 2 * ZP);
    }
    // the table's k = 5 column
    assert_eq!(proof_size::<PS>(5, 10), 1392);
    assert_eq!(proof_size::<BBS>(5, 20), 2272);
    assert_eq!(proof_size::<SPSEQ>(5, 30), 2512);

    // root request (C, T_0, π_0): PS/BBS 48 + 48 + 3·32 = 192; EQ 0 + 48 + 2·32 = 112.
    assert_eq!(request_size::<PS>(40), G1B + G1B + 3 * ZP);
    assert_eq!(request_size::<PS>(40), 192);
    assert_eq!(request_size::<BBS>(41), 192);
    assert_eq!(request_size::<SPSEQ>(42), 112);

    // credentials: Σ-PS cred = (σ_1, σ_2) = 2 G_1 = 96; Σ-BBS cred = (cred_Σ = (A, e), m_aux = ρ)
    // = G_1 + Z_p + Z_p = 112 (the box's cred_Σ alone is 80); Σ-EQ cred = (Z, Y, Ỹ) = 2 G_1 + G_2
    // = 192.
    let (_, ps) = artifacts::<PS, DDH>(b"ser/size/ps", 0x5e22_0001, 1);
    assert_eq!(ps.credential.to_bytes().unwrap().len(), 2 * G1B);
    let (_, bbs) = artifacts::<BBS, DDH>(b"ser/size/bbs", 0x5e22_0002, 1);
    assert_eq!(bbs.credential.to_bytes().unwrap().len(), G1B + ZP + ZP);
    assert_eq!(bbs.credential.cred.to_bytes().unwrap().len(), G1B + ZP);
    let (_, eq) = artifacts::<SPSEQ, DDH>(b"ser/size/eq", 0x5e22_0003, 1);
    assert_eq!(eq.credential.to_bytes().unwrap().len(), 2 * G1B + G2B);
}

// ---------------------------------------------------------------------------------------------
// Decoder strictness
// ---------------------------------------------------------------------------------------------

/// Trailing bytes after a compact object are rejected (each accepted byte string is the unique
/// encoding of its value, §5.5).
#[test]
fn trailing_bytes_are_rejected() {
    fn check<B: BaseTest>(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let f = Predicate::new(2, b"f".to_vec());

        let mut b = common::random_attestation::<B>(&mut rng)
            .to_compact_bytes()
            .unwrap();
        b.push(0);
        assert_eq!(
            Attestation::<E, B>::from_compact_bytes(&b),
            Err(Error::TrailingBytes)
        );

        let mut b = random_proof::<B>(2, &mut rng).to_compact_bytes().unwrap();
        b.push(0);
        assert_eq!(
            IssuanceProof::<E, B>::from_compact_bytes(&b, &f),
            Err(Error::TrailingBytes)
        );

        let mut b = random_root_request::<B>(&mut rng)
            .to_compact_bytes()
            .unwrap();
        b.push(0);
        assert_eq!(
            RootRequest::<E, B>::from_compact_bytes(&b),
            Err(Error::TrailingBytes)
        );
    }
    check::<PS>(0x5e23_0001);
    check::<BBS>(0x5e23_0002);
    check::<SPSEQ>(0x5e23_0003);
}

/// A non-canonical scalar (a 32-byte little-endian value `≥ r`) is rejected in every scalar slot
/// (arkworks canonical decoding refuses `≥ r`; the reference JS reduced mod `r`, which made `z`
/// and `z + r` decode equal — proof malleability, hazard W3).
#[test]
fn non_canonical_scalars_are_rejected() {
    let mut rng = StdRng::seed_from_u64(0x5e24_0001);
    let att = common::random_attestation::<PS>(&mut rng);
    let bytes = att.to_compact_bytes().unwrap();
    // Σ-PS layout: T (48) ‖ σ'_1 (48) ‖ σ'_2 (48) ‖ φ (32) ‖ c (32) ‖ z (32).
    let modulus = Fr::MODULUS.to_bytes_le();
    for scalar_at in [144usize, 176, 208] {
        let mut bad = bytes.clone();
        bad[scalar_at..scalar_at + 32].copy_from_slice(&modulus);
        assert!(is_serde_err(&Attestation::<E, PS>::from_compact_bytes(
            &bad
        )));
        // and the all-ones scalar (also ≥ r)
        let mut bad = bytes.clone();
        bad[scalar_at..scalar_at + 32].fill(0xff);
        assert!(is_serde_err(&Attestation::<E, PS>::from_compact_bytes(
            &bad
        )));
    }
    // control: the unmodified attestation decodes
    assert!(Attestation::<E, PS>::from_compact_bytes(&bytes).is_ok());
    // the modulus itself is the smallest non-canonical scalar, refused on its own
    assert!(is_serde_err(&Fr::from_bytes(&modulus)));
    assert!(Fr::from_bytes(&Fr::one().into_bigint().to_bytes_le()).is_ok());
}

/// A `G_1` point that is on the curve but OUTSIDE the prime-order subgroup is rejected by every
/// compact decoder (compressed validated decoding checks subgroup membership; BLS12-381 `G_1`
/// has a nontrivial cofactor). The point is built as a curve point whose cofactor has not been
/// cleared.
#[test]
fn points_outside_the_prime_order_subgroup_are_rejected() {
    // a curve point of E(F_q) that is not in the order-r subgroup
    let outside: Affine<_> = (1u64..=64)
        .filter_map(|x| G1Affine::get_point_from_x_unchecked(Fq::from(x), false))
        .find(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        .expect("a curve point outside the subgroup among 64 abscissae");
    assert!(outside.is_on_curve() && !outside.is_in_correct_subgroup_assuming_on_curve());
    let bad_point = outside.to_bytes().unwrap();
    assert_eq!(bad_point.len(), 48);

    // control: validated decoding refuses it, unchecked decoding accepts it (the gap the crate
    // avoids by always decoding WITH validation, cf. wire.rs).
    assert!(is_serde_err(&G1Projective::from_bytes(&bad_point)));
    assert!(G1Affine::deserialize_compressed_unchecked(&bad_point[..]).is_ok());

    // in the tag slot of a Σ-PS attestation (the first 48 bytes of the compact encoding)
    let mut rng = StdRng::seed_from_u64(0x5e25_0001);
    let mut bytes = common::random_attestation::<PS>(&mut rng)
        .to_compact_bytes()
        .unwrap();
    bytes[0..48].copy_from_slice(&bad_point);
    assert!(is_serde_err(&Attestation::<E, PS>::from_compact_bytes(
        &bytes
    )));
    // and in the T_0 slot of a root request (C ‖ T_0 ‖ π_0): T_0 starts at offset 48
    let mut bytes = random_root_request::<PS>(&mut rng)
        .to_compact_bytes()
        .unwrap();
    bytes[48..96].copy_from_slice(&bad_point);
    assert!(is_serde_err(&RootRequest::<E, PS>::from_compact_bytes(
        &bytes
    )));
}

/// The compact decoders accept only the compressed canonical encoding; the (longer) uncompressed
/// encoding of the same elements is refused (uncompressed BLS12-381 validation skips the curve
/// equation, so the crate never accepts it, cf. wire.rs).
#[test]
fn uncompressed_encodings_are_not_accepted_by_the_compact_decoders() {
    let mut rng = StdRng::seed_from_u64(0x5e26_0001);
    let att = common::random_attestation::<PS>(&mut rng);
    // the compact layout with each group element written UNCOMPRESSED (96 B) instead of
    // compressed (48 B): T ‖ σ'_1 ‖ σ'_2 ‖ φ ‖ c ‖ z
    let mut unc = Vec::new();
    att.tag.serialize_uncompressed(&mut unc).unwrap();
    att.shown.sigma_1.serialize_uncompressed(&mut unc).unwrap();
    att.shown.sigma_2.serialize_uncompressed(&mut unc).unwrap();
    att.phi.serialize_compressed(&mut unc).unwrap();
    att.proof.challenge.serialize_compressed(&mut unc).unwrap();
    att.proof.responses[0]
        .serialize_compressed(&mut unc)
        .unwrap();
    assert_eq!(unc.len(), 3 * 96 + 3 * 32);
    // the compact decoder reads 48 compressed bytes where a 96-byte uncompressed point sits.
    assert!(Attestation::<E, PS>::from_compact_bytes(&unc).is_err());
    // the derived (uncompressed) encoding is likewise refused by the compressed WireFormat decoder
    let mut derived_unc = Vec::new();
    att.serialize_uncompressed(&mut derived_unc).unwrap();
    assert!(Attestation::<E, PS>::from_bytes(&derived_unc).is_err());
}

/// The number of attestations is taken from the predicate and from nowhere on the wire (§5.5): a
/// compact proof for `f_k` does not decode under `f_{k'}` (`k' ≠ k`), and even the same `k` under
/// a different LABEL, though it decodes, does not verify (the label is bound into `ctx_0`).
#[test]
fn the_attestation_count_is_never_read_from_the_wire() {
    let (dep, art) = artifacts::<PS, DDH>(b"ser/count", 0x5e27_0001, 2);
    let bytes = art.proof.to_compact_bytes().unwrap();

    // f_3: the decoder wants a third attestation and runs off the end.
    assert!(is_serde_err(&IssuanceProof::<E, PS>::from_compact_bytes(
        &bytes,
        &Predicate::new(3, b"members".to_vec())
    )));
    // f_1: one attestation is decoded, then C/T_0/π_0 land on the second attestation's bytes and
    // fail to decode or leave trailing bytes.
    assert!(
        IssuanceProof::<E, PS>::from_compact_bytes(&bytes, &Predicate::new(1, b"members".to_vec()))
            .is_err()
    );
    // f_0: a root predicate has no issuance proof.
    assert_eq!(
        IssuanceProof::<E, PS>::from_compact_bytes(&bytes, &Predicate::new(0, b"members".to_vec())),
        Err(Error::ZeroThreshold)
    );

    // same threshold, different label: the format is identical, so it decodes ...
    let other_label = Predicate::new(2, b"guests".to_vec());
    let decoded = IssuanceProof::<E, PS>::from_compact_bytes(&bytes, &other_label).unwrap();
    assert_eq!(decoded, art.proof);
    // ... but it does not verify, because f enters ctx_0 (not only φ = EncPred(f)).
    assert!(
        !dep.pcs
            .verify_proof(&dep.hvk, &other_label, &art.id, &decoded)
    );
    // control: under its own predicate it verifies.
    assert!(dep.pcs.verify_proof(&dep.hvk, &art.f, &art.id, &decoded));
}

/// `IssuanceState` (secret) survives storage and never prints its contents, and its decoder is
/// strict (truncation and trailing bytes).
#[test]
fn issuance_state_round_trips_and_is_redacted() {
    let (_, art) = artifacts::<BBS, DDH>(b"ser/state", 0x5e28_0001, 2);
    let bytes = art.state.to_bytes().unwrap();
    // usk ‖ m_aux ‖ φ ‖ ρ = 4 scalars for Σ-BBS
    assert_eq!(bytes.len(), 4 * 32);
    let stored = IssuanceState::<E, BBS>::from_bytes(&bytes).unwrap();
    assert_eq!(&*stored.witness(), &*art.state.witness());
    assert_eq!(format!("{stored:?}"), "IssuanceState(<redacted>)");
    // strict decoding (IssuanceState is secret and not PartialEq, so match the error)
    assert!(is_serde_err(&IssuanceState::<E, BBS>::from_bytes(
        &bytes[..bytes.len() - 1]
    )));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        IssuanceState::<E, BBS>::from_bytes(&longer),
        Err(Error::TrailingBytes)
    ));
}

/// `Setup` is transparent, so `pp` round-trips and its digest is stable. The digest of
/// `Setup("kat")` for `Σ-PS + Tag_DDH` is pinned as a known answer: an accidental change of the
/// context format (oracle suffixes, item labels or order, the format constants) changes it and
/// this test catches it. The digest leads every Fiat-Shamir context, so a change would also
/// silently break proof interoperability between versions.
#[test]
fn public_parameters_round_trip_and_the_digest_is_a_known_answer() {
    let pcs = PCS::<E, PS, DDH>::setup(SetupParams::new(b"kat".to_vec())).unwrap();
    // round trip over the wire and rebuild
    let bytes = pcs.public_parameters().to_bytes().unwrap();
    let received = PublicParameters::<E, PS, DDH>::from_bytes(&bytes).unwrap();
    let rebuilt = PCS::<E, PS, DDH>::from_public_parameters(
        received,
        predicate_credential_system::pcs::AcceptAll,
    )
    .unwrap();
    assert_eq!(rebuilt.public_parameters(), pcs.public_parameters());
    assert_eq!(rebuilt.parameters_digest(), pcs.parameters_digest());
    // deterministic
    let again = PCS::<E, PS, DDH>::setup(SetupParams::new(b"kat".to_vec())).unwrap();
    assert_eq!(again.parameters_digest(), pcs.parameters_digest());
    // pinned known answer (see the test's doc comment)
    let kat: [u8; 32] = KAT_PP_DIGEST_PS_DDH;
    assert_eq!(pcs.parameters_digest(), &kat);
    // trailing bytes on pp are refused too
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        PublicParameters::<E, PS, DDH>::from_bytes(&longer),
        Err(Error::TrailingBytes)
    );
}

/// Pinned digest of `Setup("kat")` for `Σ-PS + Tag_DDH` (the value `Setup` derives; recomputed
/// and pinned so that any change to the context digest format is caught).
const KAT_PP_DIGEST_PS_DDH: [u8; 32] = [
    118, 232, 12, 208, 26, 242, 89, 136, 223, 176, 162, 220, 178, 250, 111, 161, 214, 168, 58, 24,
    26, 255, 233, 6, 46, 25, 146, 62, 212, 199, 216, 251,
];

/// A stand-alone [`FSProof`] round-trips through both its self-describing derived encoding and
/// its compact fixed-format encoding (the two encodings the proofs inside `π` and `att` use).
#[test]
fn fs_proof_encodings_round_trip() {
    let mut rng = StdRng::seed_from_u64(0x5e29_0001);
    let proof = FSProof {
        challenge: Fr::rand(&mut rng),
        responses: (0..5).map(|_| Fr::rand(&mut rng)).collect(),
    };
    let derived = proof.to_bytes().unwrap();
    assert_eq!(derived.len(), 32 + 8 + 5 * 32); // c ‖ len ‖ z
    assert_eq!(FSProof::<Fr>::from_bytes(&derived).unwrap(), proof);
    let mut compact = Vec::new();
    proof.serialize_compact(&mut compact).unwrap();
    assert_eq!(compact.len(), 6 * 32); // c ‖ z, no length prefix
    let mut reader = &compact[..];
    assert_eq!(
        FSProof::<Fr>::deserialize_compact(&mut reader, 5).unwrap(),
        proof
    );
    assert!(reader.is_empty());
}
