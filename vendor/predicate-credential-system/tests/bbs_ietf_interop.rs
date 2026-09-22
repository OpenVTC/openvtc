//! Interoperability of `Σ-BBS` under IETF parameters (`cred::bbs::ietf`) with `affinidi-bbs`
//! 0.3.3, the BBS crate of the Affinidi / OpenVTC stack (IETF BBS, ciphersuite
//! BLS12-381-SHA-256, curve backend `bls12_381_plus`). The two stacks share no type: everything
//! crosses as bytes, through the `to_ietf_bytes` / `from_ietf_bytes` bridges.
//!
//! What is shown: a credential `(A, e)` of this crate and an IETF BBS signature are the SAME
//! object, in both directions, for the core, the blind and the pseudonym interface; the show of
//! this crate works on credentials THEY signed; and the construction runs under IETF parameters
//! with a helper key THEY generated. What is NOT shown, because it does not hold: wire
//! compatibility of the proofs (see `docs/encodings.md`).
//!
//! All runs are seeded on our side; their `commit` draws its own randomness.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs

use affinidi_bbs::{self as abbs, Ciphersuite};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{UniformRand, Zero};
use predicate_credential_system::{
    Error, PCS, PredicateCredentialSystem,
    cred::{
        self, CredentialBase, SigmaFriendlyCredentialBase,
        bbs::{
            BBSCredential, BBSMessage, BBSPreCredential, BBSPublicParams, BBSSigningKey,
            BBSVerificationKey,
            ietf::{self, Interface},
        },
        possess, verify_possess,
    },
    hash::bls12_381::G1Hasher,
    kiprf,
    pcs::{AcceptAll, HelperSecretKey, Predicate},
};
use rand::{SeedableRng, rngs::StdRng};

type E = Bls12_381;
type BBS = cred::BBS<E, G1Hasher>;
type DDH = kiprf::DDH<G1Projective, G1Hasher>;

const CS: Ciphersuite = Ciphersuite::Bls12381Sha256;
const HEADER: &[u8] = b"did:webvh:example:community";
const PHI_BYTES: &[u8] = b"predicate: threshold 2, members";
const USK_BYTES: &[u8] = b"a committed message that stands for usk";

// ----- the bridge: bytes only ------------------------------------------------------------------

/// A key pair made by THEIR `keygen`, and the same pair as OUR types.
struct Keys {
    sk: abbs::SecretKey,
    pk: abbs::PublicKey,
    our_sk: BBSSigningKey<E>,
    vk: BBSVerificationKey<E>,
}

fn keys(material: &[u8]) -> Keys {
    let sk = abbs::keygen(material, b"interop").expect("their keygen");
    let pk = abbs::sk_to_pk(&sk);
    let our_sk = BBSSigningKey::from_ietf_bytes(&sk.to_bytes()).expect("their SK as ours");
    let vk = BBSVerificationKey::from_ietf_bytes(&pk.to_bytes()).expect("their PK as ours");
    assert_eq!(
        our_sk.verification_key(),
        vk,
        "both stacks derive the same PK"
    );
    Keys { sk, pk, our_sk, vk }
}

fn ours(signature: &abbs::Signature) -> BBSCredential<E> {
    BBSCredential::from_ietf_bytes(&signature.to_bytes()).expect("their signature as ours")
}

fn theirs(cred: &BBSCredential<E>) -> abbs::Signature {
    abbs::Signature::from_bytes(&cred.to_ietf_bytes().expect("encode")).expect("ours as theirs")
}

fn their_scalar(x: &Fr) -> abbs::Scalar {
    abbs::hash::scalar_from_bytes(&ietf::scalar_to_be_bytes(x)).expect("canonical scalar")
}

fn our_scalar(x: &abbs::Scalar) -> Fr {
    ietf::scalar_from_be_bytes(&abbs::hash::scalar_to_bytes(x)).expect("canonical scalar")
}

// ----- the three interfaces ----------------------------------------------------------------------

#[test]
fn core_signatures_are_credentials_and_back() {
    let mut rng = StdRng::seed_from_u64(0x1e7f_1001);
    let k = keys(b"core interface: key material of at least 32 bytes");
    let pp = BBSPublicParams::ietf(Interface::Core, &k.vk, HEADER).expect("IETF parameters");
    let messages: [&[u8]; 3] = [USK_BYTES, PHI_BYTES, b"a third message that stands for rho"];
    let scalar = |m: &[u8]| ietf::message_to_scalar(Interface::Core, m).expect("scalar");
    let m = BBSMessage::<E>::new(
        scalar(messages[0]),
        scalar(messages[1]),
        scalar(messages[2]),
    );

    // THEY sign, WE verify
    let signature = abbs::sign(&k.sk, &k.pk, HEADER, &messages).expect("their sign");
    assert!(BBS::verify(&pp, &k.vk, &m, &ours(&signature)));
    // … only under the parameters of THIS key and THIS header, and only for these messages
    let other_header = BBSPublicParams::ietf(Interface::Core, &k.vk, b"another header").unwrap();
    assert!(!BBS::verify(&other_header, &k.vk, &m, &ours(&signature)));
    assert!(!BBS::verify(
        &BBS::setup(HEADER).unwrap(),
        &k.vk,
        &m,
        &ours(&signature)
    ));
    let tampered = BBSMessage::<E>::new(
        scalar(messages[0]),
        scalar(b"another predicate"),
        scalar(messages[2]),
    );
    assert!(!BBS::verify(&pp, &k.vk, &tampered, &ours(&signature)));

    // WE sign, THEY verify
    let cred = BBS::sign(&pp, &k.our_sk, &m, &mut rng).expect("our sign");
    assert!(abbs::verify(&k.pk, &theirs(&cred), HEADER, &messages).expect("their verify"));
    let wrong: [&[u8]; 3] = [messages[0], b"another predicate", messages[2]];
    assert!(!abbs::verify(&k.pk, &theirs(&cred), HEADER, &wrong).expect("their verify"));
}

#[test]
fn blind_issuance_crosses_both_ways() {
    let mut rng = StdRng::seed_from_u64(0x1e7f_1002);
    let k = keys(b"blind interface: key material of at least 32 bytes");
    let pp = BBSPublicParams::ietf(Interface::Blind, &k.vk, HEADER).expect("IETF parameters");
    let phi = ietf::message_to_scalar(Interface::Blind, PHI_BYTES).unwrap();
    let usk = ietf::message_to_scalar(Interface::Blind, USK_BYTES).unwrap();

    // THEIR user commits, THEIR signer signs blindly; the result is OUR credential on
    // (usk, φ, ρ) with ρ = secret_prover_blind
    let (commitment_with_proof, secret_prover_blind) =
        abbs::commit(&[USK_BYTES], CS).expect("commit");
    let signature = abbs::blind_sign(
        &k.sk,
        &k.pk,
        &commitment_with_proof,
        HEADER,
        &[PHI_BYTES],
        CS,
    )
    .expect("their blind_sign");
    let rho = our_scalar(&secret_prover_blind);
    assert!(BBS::verify(
        &pp,
        &k.vk,
        &BBSMessage::new(usk, phi, rho),
        &ours(&signature)
    ));
    // and as OUR pre-credential it goes through OUR Unblind
    let pre = BBSPreCredential::<E> {
        a: ours(&signature).a,
        e: ours(&signature).e,
    };
    let m = BBSMessage::new(usk, phi, rho);
    let cred = BBS::unblind(&pp, &k.vk, &m, &pre, &rho).expect("unblind");
    assert!(BBS::verify(&pp, &k.vk, &m, &cred));

    // OUR encoded issuance (C = Com(m_hid, φ; ρ), BlindIssue, Unblind); THEY verify
    let (aux, rho) = BBS::sample_issuance(&pp, &mut rng);
    let m_hid = BBS::hidden_message(&usk, &aux);
    let m = BBS::encode_message(&pp, &m_hid, &phi).expect("Enc");
    let c = BBS::issuance_encoding(&pp, &k.vk, &m_hid, &phi, &rho).expect("Com");
    let pre = BBS::blind_issue(&pp, &k.our_sk, &c, &phi, &mut rng).expect("BlindIssue");
    let cred = BBS::unblind(&pp, &k.vk, &m, &pre, &rho).expect("Unblind");
    assert!(BBS::verify(&pp, &k.vk, &m, &cred));
    let their_verdict = |rho: &Fr| {
        abbs::blind_verify(
            &k.pk,
            &theirs(&cred),
            HEADER,
            &[PHI_BYTES],
            &[USK_BYTES],
            their_scalar(rho),
            CS,
        )
        .expect("their blind_verify")
    };
    assert!(their_verdict(&rho));
    assert!(!their_verdict(&(rho + Fr::from(1u64))));
    // a blind signature is not a core signature: other api_id, other generators and domain
    let core = BBSPublicParams::ietf(Interface::Core, &k.vk, HEADER).unwrap();
    assert!(!BBS::verify(&core, &k.vk, &m, &cred));
}

#[test]
fn the_pseudonym_interface_certifies_usk_for_zero_entropy() {
    let mut rng = StdRng::seed_from_u64(0x1e7f_1003);
    let k = keys(b"pseudonym interface: key material, 32+ bytes....");
    let pp =
        BBSPublicParams::ietf(Interface::BlindPseudonym, &k.vk, HEADER).expect("IETF parameters");
    let phi = ietf::message_to_scalar(Interface::BlindPseudonym, PHI_BYTES).unwrap();
    // here usk is a RAW scalar on both sides: their `prover_nym`
    let usk = Fr::rand(&mut rng);
    let (commitment_with_proof, secret_prover_blind) =
        abbs::nym_commit(their_scalar(&usk), &[], CS).expect("their nym_commit");
    let rho = our_scalar(&secret_prover_blind);
    let sign = |entropy: &Fr| {
        let signature = abbs::blind_sign_with_nym(
            &k.sk,
            &k.pk,
            &commitment_with_proof,
            their_scalar(entropy),
            HEADER,
            &[PHI_BYTES],
            CS,
        )
        .expect("their blind_sign_with_nym");
        ours(&signature)
    };
    // the signer's entropy MOVES the certified key: the credential is on usk + entropy
    let entropy = Fr::rand(&mut rng);
    let moved = sign(&entropy);
    assert!(BBS::verify(
        &pp,
        &k.vk,
        &BBSMessage::new(usk + entropy, phi, rho),
        &moved
    ));
    assert!(!BBS::verify(
        &pp,
        &k.vk,
        &BBSMessage::new(usk, phi, rho),
        &moved
    ));
    // with entropy 0 it is on the user's own key, the usk behind its identifier
    let m = BBSMessage::new(usk, phi, rho);
    assert!(BBS::verify(&pp, &k.vk, &m, &sign(&Fr::zero())));

    // OUR issuance, THEIR nym verifier
    let m_hid = BBS::hidden_message(&usk, &rho);
    let c = BBS::issuance_encoding(&pp, &k.vk, &m_hid, &phi, &rho).expect("Com");
    let pre = BBS::blind_issue(&pp, &k.our_sk, &c, &phi, &mut rng).expect("BlindIssue");
    let cred = BBS::unblind(&pp, &k.vk, &m, &pre, &rho).expect("Unblind");
    assert!(
        abbs::blind_verify_with_nym(
            &k.pk,
            &theirs(&cred),
            HEADER,
            &[PHI_BYTES],
            &[],
            their_scalar(&usk),
            their_scalar(&Fr::zero()),
            their_scalar(&rho),
            CS,
        )
        .expect("their blind_verify_with_nym")
    );
}

#[test]
fn our_show_works_on_a_credential_they_signed() {
    let mut rng = StdRng::seed_from_u64(0x1e7f_1004);
    let k = keys(b"show: key material of at least thirty-two bytes");
    let pp = BBSPublicParams::ietf(Interface::Blind, &k.vk, HEADER).unwrap();
    let phi = ietf::message_to_scalar(Interface::Blind, PHI_BYTES).unwrap();
    let usk = ietf::message_to_scalar(Interface::Blind, USK_BYTES).unwrap();
    let (commitment_with_proof, spb) = abbs::commit(&[USK_BYTES], CS).unwrap();
    let signature = abbs::blind_sign(
        &k.sk,
        &k.pk,
        &commitment_with_proof,
        HEADER,
        &[PHI_BYTES],
        CS,
    )
    .unwrap();
    let rho = our_scalar(&spb);
    let (m, m_hid) = (
        BBSMessage::new(usk, phi, rho),
        BBS::hidden_message(&usk, &rho),
    );

    // ReRand, the public checks of VerifyPossess, the possession proof: all of THIS crate
    let (shown, state) = BBS::rerand(&pp, &k.vk, &m, &ours(&signature), &mut rng).expect("ReRand");
    assert!(BBS::verify_possess_public(&pp, &k.vk, &shown, &phi));
    let proof = possess::<E, BBS, _>(&pp, &k.vk, &shown, &phi, &m_hid, &state, b"ctx", &mut rng)
        .expect("Possess");
    assert!(verify_possess::<E, BBS>(
        &pp, &k.vk, &shown, &phi, b"ctx", &proof
    ));
    assert!(!verify_possess::<E, BBS>(
        &pp,
        &k.vk,
        &shown,
        &(phi + Fr::from(1u64)),
        b"ctx",
        &proof
    ));
    assert!(!verify_possess::<E, BBS>(
        &pp,
        &k.vk,
        &shown,
        &phi,
        b"another ctx",
        &proof
    ));
}

// ----- the construction under IETF parameters ----------------------------------------------------

#[test]
fn the_construction_runs_under_ietf_parameters_with_their_key() {
    type System = PCS<E, BBS, DDH>;
    let mut rng = StdRng::seed_from_u64(0x1e7f_1005);
    // the helper's key exists FIRST (here: made by THEIR keygen); pp_Σ depends on it
    let k = keys(b"construction: helper key material, 32+ bytes...");
    let pp_sigma = BBSPublicParams::ietf(Interface::BlindPseudonym, &k.vk, HEADER).unwrap();
    let pcs =
        System::setup_with_base_parameters(HEADER, pp_sigma.clone(), AcceptAll).expect("setup");
    let hsk = HelperSecretKey::<BBS>::new(
        BBSSigningKey::from_ietf_bytes(&k.sk.to_bytes()).unwrap(),
        k.vk.clone(),
        *pcs.parameters_digest(),
    );
    let (hvk, f_root, f) = (
        &k.vk,
        Predicate::root(b"invited".to_vec()),
        Predicate::new(2, b"members".to_vec()),
    );

    // a user who receives pp recomputes pp_Σ from (hvk, header) and compares
    let received = pcs.public_parameters().clone();
    let user_side =
        System::from_public_parameters_with_base(received.clone(), &pp_sigma, AcceptAll)
            .expect("expected base parameters");
    let other = BBSPublicParams::ietf(Interface::BlindPseudonym, &k.vk, b"another header").unwrap();
    assert_eq!(
        System::from_public_parameters_with_base(received.clone(), &other, AcceptAll).err(),
        Some(Error::InvalidPublicParameters(
            "pp_Σ is not the expected base parameters"
        ))
    );
    // the label-derived check refuses them, as it must
    assert!(System::from_public_parameters(received, AcceptAll).is_err());

    // root credentials for two founders, two attestations, the join
    let mut founders = Vec::new();
    for _ in 0..2 {
        let (id_j, usk_j) = user_side.user_keygen(&mut rng).expect("user key");
        let (request, state) = user_side
            .root_request(hvk, &f_root, &id_j, &usk_j, &mut rng)
            .unwrap();
        let pre = pcs
            .issue_root(hvk, &hsk, &f_root, &id_j, &request, &mut rng)
            .expect("issue_root");
        let cred_j = user_side
            .unblind(hvk, &usk_j, &f_root, &pre, &state)
            .expect("unblind");
        founders.push((usk_j, cred_j));
    }
    let (id, usk) = user_side.user_keygen(&mut rng).expect("user key");
    let attestations: Vec<_> = founders
        .iter()
        .map(|(usk_j, cred_j)| {
            user_side
                .attest(hvk, usk_j, &f_root, cred_j, &id, &mut rng)
                .expect("attest")
        })
        .collect();
    let (proof, state) = user_side
        .prove(hvk, &f, &id, &usk, &attestations, &mut rng)
        .expect("prove");
    let pre = pcs
        .issue(hvk, &hsk, &f, &id, &proof, &mut rng)
        .expect("issue");
    let cred = user_side
        .unblind(hvk, &usk, &f, &pre, &state)
        .expect("unblind");
    assert!(user_side.verify_cred(hvk, &usk, &f, &cred));

    // the issued (A, e) is an IETF BBS signature of THEIR key: it round-trips through their
    // signature type, and it satisfies the IETF equation for (usk, φ = EncPred(f), ρ).
    // (Their `blind_verify_with_nym` takes the signer's message as BYTES and maps it with
    // `messages_to_scalars`; the construction's φ is `EncPred(f)`, another map. See
    // docs/encodings.md.)
    let signature = theirs(&cred.cred);
    assert_eq!(ours(&signature), cred.cred);
    let phi = user_side.enc_pred(&f).expect("EncPred");
    let m = BBSMessage::<E>::new(*usk.expose_scalar(), phi, cred.aux);
    assert!(BBS::verify(&pp_sigma, hvk, &m, &cred.cred));
}
