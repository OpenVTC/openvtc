//! Integration tests of the credential bases through the PUBLIC API only (DESIGN §6).
//!
//! The generic conformance flows and the INSECURE test oracle live in the library behind the
//! cargo feature `test-utils`, which the crate's dev-dependency on itself switches on for
//! `cargo test`. This file is also the regression test for that wiring: it does not compile if
//! an integration test cannot reach `predicate_credential_system::cred::conformance` or
//! `predicate_credential_system::hash::testing`.
//!
//! Every COMPATIBLE pair of a base and a tag runs the flow of the protocol box here:
//!
//! | base | `Tag_DDH` | `Tag_DY` |
//! |---|---|---|
//! | `Σ-PS` | BLS12-381, BN254 | BLS12-381, BN254 |
//! | `Σ-BBS` | BLS12-381, BN254 | BLS12-381, BN254 |
//! | `Σ-EQ` | BLS12-381, BN254 | refused by `Setup` (it needs `id = g_1^usk`) |
//! | `Σ-MAC` (designated verifier) | BLS12-381 `G_1`, BN254 `G_1` | BLS12-381 `G_1`, BN254 `G_1` |
//!
//! arkworks ships no hash-to-curve suite for BN254, so those runs put the INSECURE test oracle
//! behind `htag` and behind the generators of `Σ-BBS` and `Σ-MAC`. They show that the library
//! code is generic over the pairing, not that BN254 is a supported deployment. All runs are
//! seeded; the seed is the second argument of a flow.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
use ark_bls12_381::{Bls12_381, G1Projective};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use predicate_credential_system::{
    Error,
    cred::{
        self, BBS, EQ, MAC, PS, SigmaFriendlyCredentialBase, SigmaFriendlyDVCredentialBase, bbs,
        conformance::{FlowReport, dv_base_flow, public_base_flow},
        eq, mac, ps,
    },
    hash::{bls12_381::G1Hasher, h0_identity_point, testing::InsecureExponentHasher},
    kiprf::{self, DDH, DY, PCSTag},
    pcs::{check_compatibility, check_dv_compatibility},
};

/// `G_1` of BN254.
type Bn254G1 = <Bn254 as Pairing>::G1;

// ----- Σ-PS ------------------------------------------------------------------------------------

/// `|att| = 3 G_1 + 3 Z_p` and `|π_0| = 3 Z_p`: one response for `R_att`, two for `R_issue`.
const PS_REPORT: FlowReport = FlowReport {
    attestation_responses: 1,
    issuance_responses: 2,
};

#[test]
fn ps_with_tag_ddh_over_bls12_381() {
    type E = Bls12_381;
    let report = public_base_flow::<E, PS<E>, DDH<G1Projective, G1Hasher>>(
        b"integration/ps+ddh/bls12-381",
        0xc0de_0001,
        ps::credential_free_forgeries,
    );
    assert_eq!(report, PS_REPORT);
}

/// The generic-curve run: the same library code over BN254, for which arkworks ships no
/// hash-to-curve suite, with the INSECURE test oracle behind `htag`.
#[test]
fn ps_with_tag_ddh_over_bn254() {
    type E = Bn254;
    let report = public_base_flow::<E, PS<E>, DDH<Bn254G1, InsecureExponentHasher>>(
        b"integration/ps+ddh/bn254",
        0xc0de_0002,
        ps::credential_free_forgeries,
    );
    assert_eq!(report, PS_REPORT);
}

#[test]
fn ps_with_tag_dy_over_bls12_381() {
    type E = Bls12_381;
    let report = public_base_flow::<E, PS<E>, DY<G1Projective>>(
        b"integration/ps+dy/bls12-381",
        0xc0de_0005,
        ps::credential_free_forgeries,
    );
    assert_eq!(report, PS_REPORT);
}

/// `Tag_DY` needs no hash-to-group oracle, so this run over BN254 uses no test oracle at all.
#[test]
fn ps_with_tag_dy_over_bn254() {
    type E = Bn254;
    let report = public_base_flow::<E, PS<E>, DY<Bn254G1>>(
        b"integration/ps+dy/bn254",
        0xc0de_0006,
        ps::credential_free_forgeries,
    );
    assert_eq!(report, PS_REPORT);
}

/// The constants that fix the compact proof format agree with the flow's observations.
#[test]
fn ps_proof_sizes_are_constants_of_the_base() {
    type PS = cred::PS<Bls12_381>;
    assert_eq!(
        1 + <PS as SigmaFriendlyCredentialBase<Bls12_381>>::POSSESSION_VARIABLES,
        PS_REPORT.attestation_responses
    );
    assert_eq!(
        1 + <PS as SigmaFriendlyCredentialBase<Bls12_381>>::ISSUANCE_VARIABLES,
        PS_REPORT.issuance_responses
    );
    // |att| over BLS12-381: T, σ'_1, σ'_2 (48 B each), φ, c and one response (32 B each)
    let att = 3 * 48 + (2 + PS_REPORT.attestation_responses) * 32;
    assert_eq!(att, 240);
    // |π| at k = 5: five attestations, C, T_0, and π_0 = (c, z_usk, z_ρ); the fixed format of the
    // paper's comparison table (§5.3), no length prefixes
    assert_eq!(
        5 * att + 2 * 48 + (1 + PS_REPORT.issuance_responses) * 32,
        1392
    );
}

// ----- Σ-BBS -----------------------------------------------------------------------------------

/// `|att| = 4 G_1 + 7 Z_p` and `|π_0| = 3 Z_p`: five responses for `R_att`, two for `R_issue`.
const BBS_REPORT: FlowReport = FlowReport {
    attestation_responses: 5,
    issuance_responses: 2,
};

#[test]
fn bbs_with_tag_ddh_over_bls12_381() {
    type E = Bls12_381;
    let report = public_base_flow::<E, BBS<E, G1Hasher>, DDH<G1Projective, G1Hasher>>(
        b"integration/bbs+ddh/bls12-381",
        0xc0de_0003,
        bbs::credential_free_forgeries,
    );
    assert_eq!(report, BBS_REPORT);
}

#[test]
fn bbs_with_tag_ddh_over_bn254() {
    type E = Bn254;
    let report = public_base_flow::<
        E,
        BBS<E, InsecureExponentHasher>,
        DDH<Bn254G1, InsecureExponentHasher>,
    >(
        b"integration/bbs+ddh/bn254",
        0xc0de_0004,
        bbs::credential_free_forgeries,
    );
    assert_eq!(report, BBS_REPORT);
}

#[test]
fn bbs_with_tag_dy_over_bls12_381() {
    type E = Bls12_381;
    let report = public_base_flow::<E, BBS<E, G1Hasher>, DY<G1Projective>>(
        b"integration/bbs+dy/bls12-381",
        0xc0de_0007,
        bbs::credential_free_forgeries,
    );
    assert_eq!(report, BBS_REPORT);
}

#[test]
fn bbs_with_tag_dy_over_bn254() {
    type E = Bn254;
    let report = public_base_flow::<E, BBS<E, InsecureExponentHasher>, DY<Bn254G1>>(
        b"integration/bbs+dy/bn254",
        0xc0de_0008,
        bbs::credential_free_forgeries,
    );
    assert_eq!(report, BBS_REPORT);
}

#[test]
fn bbs_proof_sizes_are_constants_of_the_base() {
    type BBS = cred::BBS<Bls12_381, G1Hasher>;
    assert_eq!(
        1 + <BBS as SigmaFriendlyCredentialBase<Bls12_381>>::POSSESSION_VARIABLES,
        BBS_REPORT.attestation_responses
    );
    assert_eq!(
        1 + <BBS as SigmaFriendlyCredentialBase<Bls12_381>>::ISSUANCE_VARIABLES,
        BBS_REPORT.issuance_responses
    );
    // |att| over BLS12-381: T, Ā, B̄, D (48 B each), φ, c and five responses (32 B each)
    let att = 4 * 48 + (2 + BBS_REPORT.attestation_responses) * 32;
    assert_eq!(att, 416);
    // |π| at k = 5: five attestations, C, T_0, and π_0 = (c, z_usk, z_ρ)
    assert_eq!(
        5 * att + 2 * 48 + (1 + BBS_REPORT.issuance_responses) * 32,
        2272
    );
}

// ----- Σ-EQ ------------------------------------------------------------------------------------

/// `|att| = 6 G_1 + G_2 + 3 Z_p` and `π_0 = (c, z_usk)`: one response each; `C` is not sent.
const EQ_REPORT: FlowReport = FlowReport {
    attestation_responses: 1,
    issuance_responses: 1,
};

#[test]
fn eq_with_tag_ddh_over_bls12_381() {
    type E = Bls12_381;
    let report = public_base_flow::<E, EQ<E>, DDH<G1Projective, G1Hasher>>(
        b"integration/eq+ddh/bls12-381",
        0xc0de_0e01,
        eq::credential_free_forgeries,
    );
    assert_eq!(report, EQ_REPORT);
}

#[test]
fn eq_with_tag_ddh_over_bn254() {
    type E = Bn254;
    let report = public_base_flow::<E, EQ<E>, DDH<Bn254G1, InsecureExponentHasher>>(
        b"integration/eq+ddh/bn254",
        0xc0de_0e02,
        eq::credential_free_forgeries,
    );
    assert_eq!(report, EQ_REPORT);
}

/// `Σ-EQ` needs `id = g_1^usk`, which `Tag_DY` does not provide: `Setup` must refuse the pair
/// (proof sketch of the Lemma on `Σ-EQ`, §3.2.3: compatible with `Tag_DDH` under
/// `htag(c_0) = g_1`, "not with `Tag_DY`").
#[test]
fn eq_refuses_tag_dy() {
    type E = Bls12_381;
    let domain = b"integration/eq+dy";
    let c0 = h0_identity_point(domain);
    let tag = DY::<G1Projective>::setup(domain, c0).unwrap();
    assert!(tag.is_well_formed());
    assert_eq!(
        check_compatibility::<E, EQ<E>, DY<G1Projective>>(&tag, &c0),
        Err(Error::IncompatibleBaseAndTag)
    );
    // the refusal is about Σ-EQ, not about the tag: the other bases take it
    assert_eq!(
        check_compatibility::<E, PS<E>, DY<G1Projective>>(&tag, &c0),
        Ok(())
    );
}

/// ... and the flow, which starts with that check, stops there.
#[test]
#[should_panic(expected = "Setup must refuse this base/tag pair")]
fn eq_flow_with_tag_dy_stops_at_setup() {
    type E = Bls12_381;
    public_base_flow::<E, EQ<E>, DY<G1Projective>>(
        b"integration/eq+dy/bls12-381",
        0xc0de_0e03,
        eq::credential_free_forgeries,
    );
}

#[test]
fn eq_proof_sizes_are_constants_of_the_base() {
    type Eq = EQ<Bls12_381>;
    assert_eq!(
        1 + <Eq as SigmaFriendlyCredentialBase<Bls12_381>>::POSSESSION_VARIABLES,
        EQ_REPORT.attestation_responses
    );
    assert_eq!(
        1 + <Eq as SigmaFriendlyCredentialBase<Bls12_381>>::ISSUANCE_VARIABLES,
        EQ_REPORT.issuance_responses
    );
    // |att|: T, M'_1, M'_2, M'_3, Z', Y' (48 B each), Ỹ' (96 B), φ, c and one response (32 B each)
    let att = 6 * 48 + 96 + (2 + EQ_REPORT.attestation_responses) * 32;
    assert_eq!(att, 480);
    // |π| at k = 5: five attestations, T_0 and π_0 = (c, z_usk); no C
    assert_eq!(5 * att + 48 + (1 + EQ_REPORT.issuance_responses) * 32, 2512);
}

// ----- Σ-MAC (designated verifier) -------------------------------------------------------------

/// One response for the verifier-derived clause of `R_att`, two for `R_issue` (`usk`, `ρ`).
const MAC_REPORT: FlowReport = FlowReport {
    attestation_responses: 1,
    issuance_responses: 2,
};

#[test]
fn mac_with_tag_ddh_over_bls12_381() {
    type G = G1Projective;
    let report = dv_base_flow::<G, MAC<G, G1Hasher>, DDH<G, G1Hasher>>(
        b"integration/mac+ddh/bls12-381",
        0xc0de_0010,
        mac::credential_free_forgeries,
    );
    assert_eq!(report, MAC_REPORT);
}

#[test]
fn mac_with_tag_dy_over_bls12_381() {
    type G = G1Projective;
    let report = dv_base_flow::<G, MAC<G, G1Hasher>, DY<G>>(
        b"integration/mac+dy/bls12-381",
        0xc0de_0011,
        mac::credential_free_forgeries,
    );
    assert_eq!(report, MAC_REPORT);
}

/// The base is generic over a prime-order group: the same code over `G_1` of BN254, with the
/// INSECURE test oracle behind the generators `g, h` and behind `htag`.
#[test]
fn mac_with_tag_ddh_over_bn254() {
    type G = Bn254G1;
    let report = dv_base_flow::<G, MAC<G, InsecureExponentHasher>, DDH<G, InsecureExponentHasher>>(
        b"integration/mac+ddh/bn254",
        0xc0de_0012,
        mac::credential_free_forgeries,
    );
    assert_eq!(report, MAC_REPORT);
}

#[test]
fn mac_with_tag_dy_over_bn254() {
    type G = Bn254G1;
    let report = dv_base_flow::<G, MAC<G, InsecureExponentHasher>, DY<G>>(
        b"integration/mac+dy/bn254",
        0xc0de_0013,
        mac::credential_free_forgeries,
    );
    assert_eq!(report, MAC_REPORT);
}

#[test]
fn mac_proof_sizes_are_constants_of_the_base() {
    type G = G1Projective;
    type MAC = cred::MAC<G, G1Hasher>;
    assert_eq!(
        1 + <MAC as SigmaFriendlyDVCredentialBase<G>>::POSSESSION_VARIABLES,
        MAC_REPORT.attestation_responses
    );
    assert_eq!(
        1 + <MAC as SigmaFriendlyDVCredentialBase<G>>::ISSUANCE_VARIABLES,
        MAC_REPORT.issuance_responses
    );
    // The paper's comparison table (§5.3) counts a group with 32-byte elements and scalars:
    // |att| = T, U', V', φ, c and one response; the verifier-derived target X is never sent.
    let att = 3 * 32 + (2 + MAC_REPORT.attestation_responses) * 32;
    assert_eq!(att, 192);
    // |π| at k = 5: five attestations, C, T_0, and π_0 = (c, z_usk, z_ρ)
    assert_eq!(
        5 * att + 2 * 32 + (1 + MAC_REPORT.issuance_responses) * 32,
        1120
    );
}

// ----- degenerate tag parameters ---------------------------------------------------------------

/// A `pp_Tag` that was decoded WITHOUT validation can be degenerate (`Tag_DY` with the identity
/// in the place of `g_1`): every tag evaluation is `⊥`, and a `UKeyGen` loop that restarts on
/// `⊥` would never terminate. Validated decoding refuses the encoding, and for everything else
/// the compatibility check of `Setup` answers with `DegenerateInput`, for every base, so that
/// no restart loop runs under such parameters.
#[test]
fn degenerate_tag_parameters_are_refused_before_any_restart_loop() {
    type E = Bls12_381;
    type G = G1Projective;
    type DY = kiprf::DY<G>;
    let c0 = h0_identity_point(b"integration/degenerate-pp-tag");

    // the encoding of the identity in the place of g_1
    let mut identity = Vec::new();
    G::zero().serialize_compressed(&mut identity).unwrap();

    // validated decoding (the decoder of this crate) refuses it ...
    assert!(predicate_credential_system::serialization::from_bytes::<DY>(&identity).is_err());
    assert!(DY::deserialize_compressed(&identity[..]).is_err());
    // ... unvalidated decoding does not
    let degenerate = DY::deserialize_compressed_unchecked(&identity[..]).unwrap();
    assert!(!degenerate.is_well_formed());
    assert!(!PCSTag::<G>::is_well_formed(&degenerate));

    let refused: Result<(), Error> = Err(Error::DegenerateInput("pp_Tag"));
    assert_eq!(
        check_compatibility::<E, PS<E>, DY>(&degenerate, &c0),
        refused
    );
    assert_eq!(
        check_compatibility::<E, BBS<E, G1Hasher>, DY>(&degenerate, &c0),
        refused
    );
    assert_eq!(
        check_compatibility::<E, EQ<E>, DY>(&degenerate, &c0),
        refused
    );
    assert_eq!(
        check_dv_compatibility::<G, MAC<G, G1Hasher>, DY>(&degenerate, &c0),
        refused
    );

    // control: the honest instance passes wherever the base allows the tag
    let honest = DY::setup(b"integration/degenerate-pp-tag", c0).unwrap();
    assert_eq!(check_compatibility::<E, PS<E>, DY>(&honest, &c0), Ok(()));
    assert_eq!(
        check_dv_compatibility::<G, MAC<G, G1Hasher>, DY>(&honest, &c0),
        Ok(())
    );
    // Tag_DDH has no degenerate parameters
    let ddh = DDH::<G, G1Hasher>::setup(b"integration/degenerate-pp-tag", c0).unwrap();
    assert!(PCSTag::<G>::is_well_formed(&ddh));
}
