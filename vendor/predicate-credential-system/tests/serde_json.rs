//! The `serde` feature (`predicate_credential_system::serialization`) through `serde_json`, for every compatible public
//! base/tag pair: JSON round trips of every protocol object, the JSON SHAPES (they are an
//! interface a consumer writes policies and message schemas against), a join that travels as
//! JSON end to end, and the strictness of decoding.
//!
//! All runs are seeded. The tests say nothing about security; they pin an encoding.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
mod common;

use common::{BBS, BaseTest, DDH, DY, Deployment, E, G1, PS, SPSEQ};
use predicate_credential_system::{
    cred::{self, CredentialBase, DVCredentialBase},
    hash::bls12_381::G1Hasher,
    kiprf::PCSTag,
    pcs::{
        Attestation, Credential, HelperSecretKey, IssuanceProof, IssuanceState, PCS, Predicate,
        PredicateCredentialSystem, PublicParameters, RootRequest, UserSecretKey,
    },
    serialization,
    sigma::FSProof,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const K: u32 = 2;

/// `value` → JSON text → value, asserting equality; returns the JSON tree.
fn round_trip<T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug>(value: &T) -> Value {
    let text = serde_json::to_string(value).expect("serialize");
    let back: T = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(&back, value);
    serde_json::from_str(&text).expect("JSON")
}

/// An opaque value is ONE base58btc multibase string.
fn assert_opaque(tree: &Value) {
    let text = tree.as_str().expect("an opaque value is a JSON string");
    assert!(
        text.starts_with('z'),
        "multibase base58btc has the prefix z"
    );
    assert!(serialization::from_multibase(text).is_ok());
}

/// A structured value is an object with EXACTLY these members, each of them opaque.
fn assert_members(tree: &Value, members: &[&str]) {
    let object = tree
        .as_object()
        .expect("a structured value is a JSON object");
    let mut found: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut expected = members.to_vec();
    found.sort_unstable();
    expected.sort_unstable();
    assert_eq!(found, expected);
}

fn flow<B, T>(label: &[u8], seed: u64)
where
    B: BaseTest + JsonBase,
    T: PCSTag<G1>,
{
    let mut d = Deployment::<B, T>::open(label, seed);
    let f = Predicate::new(K, b"members".to_vec());
    let founders = d.root_members(K as usize);
    let (id, usk) = d.pcs.user_keygen(&mut d.rng).expect("user key");

    // ----- public parameters and the helper key: opaque ------------------------------------------
    let pp: &PublicParameters<E, B, T> = d.pcs.public_parameters();
    assert_opaque(&round_trip(pp));
    let received: PublicParameters<E, B, T> =
        serde_json::from_value(serde_json::to_value(pp).unwrap()).unwrap();
    // what arrives as JSON is accepted as the parameters of its label
    assert!(
        PCS::<E, B, T>::from_public_parameters(
            received,
            predicate_credential_system::pcs::AcceptAll
        )
        .is_ok()
    );
    let hvk_tree = B::hvk_to_json(&d.hvk);
    assert_opaque(&hvk_tree);
    assert!(B::hvk_from_json(&hvk_tree) == d.hvk);

    // ----- predicates: structured, readable --------------------------------------------------------
    assert_eq!(
        serde_json::to_value(&f).unwrap(),
        json!({ "threshold": K, "label": "members" })
    );
    round_trip(&f);

    // ----- attestations: structured, and they still verify after the JSON hop ---------------------
    let attestations: Vec<Attestation<E, B>> = d
        .attestations(&founders, &id)
        .iter()
        .map(|att| {
            let tree = round_trip(att);
            assert_members(&tree, &["tag", "shown", "phi", "proof"]);
            for member in ["tag", "shown", "phi", "proof"] {
                assert_opaque(&tree[member]);
            }
            // `phi` is readable without decoding the attestation: a policy can work on it
            let phi: String = serde_json::from_value(tree["phi"].clone()).unwrap();
            assert_eq!(
                serialization::from_multibase(&phi).unwrap(),
                predicate_credential_system::serialization::to_bytes(&att.phi).unwrap()
            );
            serde_json::from_value(tree).expect("attestation from JSON")
        })
        .collect();
    for att in &attestations {
        assert!(d.pcs.verify_attestation(&d.hvk, &id, att));
    }

    // ----- the join: proof → JSON → helper; pre-credential → JSON → user ---------------------------
    let (proof, state) = d.prove_ok(&f, &id, &usk, &attestations);
    let tree = round_trip(&proof);
    assert_members(&tree, &["attestations", "encoding", "t0", "proof"]);
    assert_eq!(
        tree["attestations"].as_array().map(Vec::len),
        Some(K as usize)
    );
    let proof: IssuanceProof<E, B> = serde_json::from_value(tree).expect("proof from JSON");

    // the state outlives the request: it is stored (as a secret) until the helper answers
    let stored = serde_json::to_string(&state).expect("state");
    drop(state);
    let state: IssuanceState<E, B> = serde_json::from_str(&stored).expect("state from JSON");

    let pre = d
        .pcs
        .issue(&d.hvk, &d.hsk, &f, &id, &proof, &mut d.rng)
        .expect("issue");
    let pre_tree = B::pre_to_json(&pre);
    assert_opaque(&pre_tree);
    let pre: B::PreCredential = B::pre_from_json(&pre_tree);
    let cred = d
        .pcs
        .unblind(&d.hvk, &usk, &f, &pre, &state)
        .expect("unblind");
    assert!(d.pcs.verify_cred(&d.hvk, &usk, &f, &cred));

    // ----- what the user keeps: credential and key, as secrets ---------------------------------------
    let cred_text = serde_json::to_string(&cred).expect("credential");
    let cred_back: Credential<E, B> = serde_json::from_str(&cred_text).expect("credential");
    assert!(cred_back == cred);
    assert!(d.pcs.verify_cred(&d.hvk, &usk, &f, &cred_back));
    let usk_text = serde_json::to_string(&usk).expect("usk");
    let usk_back: UserSecretKey<E> = serde_json::from_str(&usk_text).expect("usk");
    assert_eq!(usk_back.expose_scalar(), usk.expose_scalar());
    assert_eq!(d.pcs.identity(&usk_back).expect("id"), id);
    let hsk_text = serde_json::to_string(&d.hsk).expect("hsk");
    let hsk_back: HelperSecretKey<B> = serde_json::from_str(&hsk_text).expect("hsk");
    assert!(hsk_back.verification_key() == &d.hvk);

    // ----- root requests ----------------------------------------------------------------------------
    let (id_r, usk_r) = d.pcs.user_keygen(&mut d.rng).expect("user key");
    let (request, _state) = d
        .pcs
        .root_request(&d.hvk, &d.f_root, &id_r, &usk_r, &mut d.rng)
        .expect("root request");
    let tree = round_trip(&request);
    assert_members(&tree, &["encoding", "t0", "proof"]);
    let request: RootRequest<E, B> = serde_json::from_value(tree).unwrap();
    assert!(
        d.pcs
            .verify_root_request(&d.hvk, &d.f_root, &id_r, &request)
    );
}

/// The two associated types of a base that travel on their own. Their `Serialize` /
/// `Deserialize` impls exist per base (`PSVerificationKey`, …) and not on the associated type, so
/// the generic flow reaches them through this trait.
trait JsonBase: CredentialBase {
    fn hvk_to_json(hvk: &Self::VerificationKey) -> Value;
    fn hvk_from_json(tree: &Value) -> Self::VerificationKey;
    fn pre_to_json(pre: &Self::PreCredential) -> Value;
    fn pre_from_json(tree: &Value) -> Self::PreCredential;
}

macro_rules! json_base {
    ($($base:ty),+) => {$(
        impl JsonBase for $base {
            fn hvk_to_json(hvk: &Self::VerificationKey) -> Value {
                serde_json::to_value(hvk).expect("verification key to JSON")
            }
            fn hvk_from_json(tree: &Value) -> Self::VerificationKey {
                serde_json::from_value(tree.clone()).expect("verification key from JSON")
            }
            fn pre_to_json(pre: &Self::PreCredential) -> Value {
                serde_json::to_value(pre).expect("pre-credential to JSON")
            }
            fn pre_from_json(tree: &Value) -> Self::PreCredential {
                serde_json::from_value(tree.clone()).expect("pre-credential from JSON")
            }
        }
    )+};
}
json_base!(PS, BBS, SPSEQ);

#[test]
fn json_round_trips_ps_ddh() {
    flow::<PS, DDH>(b"serde/ps+ddh", 0x5e7d_0001);
}

#[test]
fn json_round_trips_ps_dy() {
    flow::<PS, DY>(b"serde/ps+dy", 0x5e7d_0002);
}

#[test]
fn json_round_trips_bbs_ddh() {
    flow::<BBS, DDH>(b"serde/bbs+ddh", 0x5e7d_0003);
}

#[test]
fn json_round_trips_bbs_dy() {
    flow::<BBS, DY>(b"serde/bbs+dy", 0x5e7d_0004);
}

#[test]
fn json_round_trips_eq_ddh() {
    flow::<SPSEQ, DDH>(b"serde/eq+ddh", 0x5e7d_0005);
}

#[test]
fn decoding_is_strict() {
    let mut d = Deployment::<PS, DDH>::open(b"serde/strict", 0x5e7d_0010);
    let founders = d.root_members(1);
    let (id, _usk) = d.pcs.user_keygen(&mut d.rng).expect("user key");
    let att = d.attest(&founders[0], &id);
    let tree = serde_json::to_value(&att).expect("attestation");
    let parse = |tree: &Value| serde_json::from_value::<Attestation<E, PS>>(tree.clone());
    assert!(parse(&tree).is_ok());

    // an unknown member
    let mut extra = tree.clone();
    extra["issuer"] = json!("did:example:attester");
    assert!(parse(&extra).is_err());
    // a missing member
    let mut missing = tree.clone();
    missing.as_object_mut().unwrap().remove("phi");
    assert!(parse(&missing).is_err());
    // the same bytes under another multibase base
    let bytes = serialization::from_multibase(tree["tag"].as_str().unwrap()).unwrap();
    let mut other_base = tree.clone();
    other_base["tag"] = json!(multibase_base64url(&bytes));
    assert!(parse(&other_base).is_err());
    // trailing bytes, a truncated value, bytes that are no group element
    for bad in [
        [bytes.clone(), vec![0]].concat(),
        bytes[..bytes.len() - 1].to_vec(),
        vec![0xff; bytes.len()],
    ] {
        let mut t = tree.clone();
        t["tag"] = json!(serialization::to_multibase(&bad));
        assert!(parse(&t).is_err());
    }
    // a scalar that is not reduced modulo r
    let mut t = tree.clone();
    t["phi"] = json!(serialization::to_multibase(&[0xff; 32]));
    assert!(parse(&t).is_err());
    // not a string at all
    let mut t = tree.clone();
    t["proof"] = json!({ "challenge": 1 });
    assert!(parse(&t).is_err());

    // a tampered but well-formed attestation decodes, and the VERIFIER rejects it
    let mut tampered = att.clone();
    tampered.phi += ark_bls12_381::Fr::from(1u64);
    let tampered: Attestation<E, PS> =
        serde_json::from_value(serde_json::to_value(&tampered).unwrap()).unwrap();
    assert!(!d.pcs.verify_attestation(&d.hvk, &id, &tampered));
}

/// `multibase` is not a dependency of the tests: base64url by hand, prefix `u`, no padding.
fn multibase_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::from("u");
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

#[test]
fn a_label_that_is_not_utf8_has_no_json_form() {
    let f = Predicate::new(1, vec![0xff, 0xfe]);
    assert!(serde_json::to_string(&f).is_err());
    // its canonical encoding is unaffected
    assert_eq!(
        predicate_credential_system::serialization::from_bytes::<Predicate>(
            &predicate_credential_system::serialization::to_bytes(&f).unwrap()
        )
        .unwrap(),
        f
    );
    // unknown members are refused here as well
    assert!(
        serde_json::from_value::<Predicate>(json!({ "threshold": 1, "label": "a", "k": 1 }))
            .is_err()
    );
}

#[test]
fn fs_proofs_and_the_designated_verifier_base_have_json_forms() {
    type MAC = cred::MAC<G1, G1Hasher>;
    let mut rng = StdRng::seed_from_u64(0x5e7d_0020);
    let pp = MAC::setup(b"serde/mac").expect("pp");
    let dvk = MAC::keygen(&pp, &mut rng);
    assert_opaque(&round_trip(&pp));
    // the key is a secret: it has a JSON form and no `Debug` output worth reading
    let text = serde_json::to_string(&dvk).expect("dvk");
    let _: <MAC as DVCredentialBase>::DVKey = serde_json::from_str(&text).expect("dvk");
    assert!(!format!("{dvk:?}").contains(text.trim_matches('"')));

    let proof = FSProof::<ark_bls12_381::Fr> {
        challenge: 7u64.into(),
        responses: vec![1u64.into(), 2u64.into()],
    };
    assert_opaque(&round_trip(&proof));
}
