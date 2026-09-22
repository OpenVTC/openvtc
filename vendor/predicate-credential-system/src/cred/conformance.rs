//! Conformance flows, generic over the credential base and the tag. **Test helpers.**
//!
//! Compiled for the crate's own tests and behind the non-default cargo feature `test-utils`
//! (which the crate's dev-dependency on itself enables for `cargo test`, so that integration
//! tests can call the flows as well). The functions panic on the first violated expectation,
//! like any test.
//!
//! Each flow walks through the way the construction of §5.1 (protocol box) consumes a base and
//! a tag, using nothing but the trait interfaces: root signing, `Attest` / `VerifyAtt` on
//! `R_att`, `Prove` / `VerifyProof` on `R_issue`, `Issue`, `Unblind`, `VerifyCred`, and chaining.
//! They serve two purposes:
//!
//! * they are type-checked against the traits for EVERY base and tag, so a trait signature that
//!   does not fit the generic construction fails to compile here, and
//! * every instantiation calls them from its own unit tests (one line plus its
//!   [`Forgery`] list), which gives all bases the same end-to-end coverage.
//!
//! # What the negatives depend on
//!
//! A flow that only mutates public values of an honest attestation is caught by Fiat-Shamir
//! alone and would also pass for a base whose possession clause is vacuous or whose public
//! checks are missing. The flows therefore contain negatives that each hinge on ONE mechanism:
//!
//! | mechanism | negative |
//! |---|---|
//! | the possession clauses bind `usk` (shared variable) | a tag under ANOTHER key next to the honest `cred*`: neither candidate witness satisfies `R_att` and the honest prover refuses; a holder claiming another key for its credential all the way through `Attest` is refused or rejected |
//! | `verify_possess_public` | the caller's credential-free [`Forgery`] list: the clauses ARE satisfiable, the bare Fiat-Shamir proof DOES verify, the attestation is rejected |
//! | `ValidTag` | `T = 1` is rejected; where the base can certify `usk = 0`, a complete attestation with `T = 1` is forged and only `ValidTag` rejects it |
//! | the context covers `pp` | the attestation does not verify under other base parameters, nor in another deployment |
//! | the opening clause binds `usk` | an encoding `C` of ANOTHER key next to the honest `id`, `T_0` has no witness |
//!
//! The flows also check the constants of the sigma-friendly traits (`POSSESSION_VARIABLES`,
//! `ISSUANCE_VARIABLES`) against what the clause functions allocate, round-trip both proofs
//! through the compact fixed-format encoding those constants enable, and run the key and
//! base/tag compatibility checks.
//!
//! The Fiat-Shamir contexts are stand-ins for `ctx_j` and `ctx_0` of the box; the real ones
//! belong to the `pcs` module.
//!
//! # Termination
//!
//! The flows contain the two loops of this crate that restart on an undefined tag evaluation:
//! `UKeyGen` of the box, and the search for a second key. Both are guarded by
//! [`PCSTag::is_well_formed`] (under degenerate tag parameters every evaluation is `⊥`) and
//! bounded by a fixed number of attempts, each of which fails with probability about `2/p`
//! under a well-formed instance. A flow therefore panics instead of hanging, whatever tag it
//! is given; the unit tests of this module run both loops under a degenerate `Tag_DY` instance
//! and under a tag that wrongly claims to be well formed.

use core::fmt::Debug;

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{SeedableRng, rngs::StdRng};

use super::{
    SigmaFriendlyCredentialBase, SigmaFriendlyDVCredentialBase, issuance_witness_vector,
    possession_relation, possession_witness_vector,
};
use crate::{
    error::Error,
    hash::{Transcript, h0_id, h0_identity_point, h0_predicate},
    kiprf::PCSTag,
    pcs::{check_compatibility, check_dv_compatibility},
    serialization::WireFormat,
    sigma::{FSProof, GroupRelation, LinearRelation, PairingRelation, Witness, fiat_shamir},
};

/// What a flow observed; the caller asserts the numbers the paper's size table implies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowReport {
    /// Number of responses of an attestation proof (`Σ-PS`: 1, `Σ-BBS`: 5, `Σ-EQ`: 1, `Σ-MAC`: 1).
    pub attestation_responses: usize,
    /// Number of responses of `π_0` (`Σ-PS`, `Σ-BBS`, `Σ-MAC`: 2, `Σ-EQ`: 1).
    pub issuance_responses: usize,
}

/// A credential-free forgery against the possession CLAUSES of a base: a degenerate shown
/// credential `cred*` for which the clauses hold under a key of the forger's choice, together
/// with the values of the variables the clauses allocate beyond `usk` (the forger's witness is
/// the forged key followed by `extra_witness`). Attacks A1 / A2 of the reference
/// implementations: only the public checks of `VerifyPossess` stand in its way.
///
/// Examples: `σ' = (1, 1)` for `Σ-PS`; `(Ā, B̄, D) = (1, 1, h_0 h_1^K h_2^φ)` with
/// `(e, ρ, r_1, r_3) = (0, 0, 0, 1)` for `Σ-BBS`; `M' = (1, 1, 1)`, `Z' = 1` for `Σ-EQ`;
/// `(U', V') = (1, 1)` for `Σ-MAC`.
#[derive(Clone, Debug)]
pub struct Forgery<S, F> {
    /// The degenerate shown credential.
    pub shown: S,
    /// The forger's values for the variables allocated by the possession clauses.
    pub extra_witness: Vec<F>,
}

fn round_trip<T: CanonicalSerialize + CanonicalDeserialize + PartialEq + Debug>(value: &T) {
    let bytes = value.to_bytes().unwrap();
    assert_eq!(&T::from_bytes(&bytes).unwrap(), value);
}

/// The compact fixed-format encoding `c ‖ z` is decodable from the statically known number of
/// responses, and is 8 bytes shorter than the derived (self-describing) one.
fn compact_round_trip<F: PrimeField>(proof: &FSProof<F>, responses: usize) {
    assert_eq!(proof.responses.len(), responses);
    let mut compact = Vec::new();
    proof.serialize_compact(&mut compact).unwrap();
    assert_eq!(compact.len(), proof.compact_size());
    assert_eq!(compact.len() + 8, proof.to_bytes().unwrap().len());
    let mut reader = &compact[..];
    let back = FSProof::<F>::deserialize_compact(&mut reader, responses).unwrap();
    assert!(reader.is_empty());
    assert_eq!(&back, proof);
}

fn context(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut t = Transcript::new(b"/TEST-CONFORMANCE");
    t.append_bytes(b"label", label);
    for part in parts {
        t.append_bytes(b"part", part);
    }
    t.digest().to_vec()
}

fn bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    crate::serialization::to_bytes(value).unwrap()
}

/// Upper bound on the attempts of the two restart loops below. Under a well-formed tag instance
/// an attempt fails with probability about `2/p` (the contract of [`PCSTag::is_well_formed`]),
/// so running into the bound means a broken tag, and the flow panics as on any other violated
/// expectation.
const MAX_KEYGEN_ATTEMPTS: usize = 64;

/// The guard of the restart loops: under degenerate tag parameters every evaluation is `⊥`, and
/// a loop that restarts on `⊥` would never terminate.
fn assert_usable<G: PrimeGroup, T: PCSTag<G>>(tag: &T) {
    assert!(
        tag.is_well_formed(),
        "degenerate tag parameters: every evaluation is undefined, a restart loop cannot terminate"
    );
}

/// A user key whose identifier and self-exclusion tag are defined (`UKeyGen` of the box).
///
/// Guarded and bounded, unlike the loop of the box ("if `id = ⊥`, restart"), which does not
/// terminate under a degenerate `pp_Tag`.
fn user_keygen<G: PrimeGroup, T: PCSTag<G>>(
    tag: &T,
    domain: &[u8],
    c0: &G::ScalarField,
    rng: &mut StdRng,
) -> (G, G::ScalarField) {
    assert_usable(tag);
    for _ in 0..MAX_KEYGEN_ATTEMPTS {
        let usk = tag.keygen(rng);
        let Some(id) = tag.eval(&usk, c0) else {
            continue;
        };
        let s: G::ScalarField = h0_id(domain, &id).unwrap();
        if tag.eval(&usk, &s).is_some() {
            return (id, usk);
        }
    }
    panic!("UKeyGen: no usable key in {MAX_KEYGEN_ATTEMPTS} attempts");
}

/// A key other than `not` whose tag at `s` is defined. Guarded and bounded like [`user_keygen`].
fn other_key<G: PrimeGroup, T: PCSTag<G>>(
    tag: &T,
    s: &G::ScalarField,
    not: &[G::ScalarField],
    rng: &mut StdRng,
) -> (G::ScalarField, G) {
    assert_usable(tag);
    for _ in 0..MAX_KEYGEN_ATTEMPTS {
        let key = tag.keygen(rng);
        if not.contains(&key) {
            continue;
        }
        if let Some(t) = tag.eval(&key, s) {
            return (key, t);
        }
    }
    panic!("no other key with a defined tag in {MAX_KEYGEN_ATTEMPTS} attempts");
}

/// The witness vector `(key, rest)`.
fn key_then<F: PrimeField>(key: F, rest: &[F]) -> Witness<F> {
    let mut witness = Witness::with_capacity(1 + rest.len());
    witness.push(key);
    witness.extend_from_slice(rest);
    witness
}

/// `witness` with its first coordinate (the shared `usk`) replaced by `key`.
fn with_key<F: PrimeField>(witness: &[F], key: F) -> Witness<F> {
    key_then(key, witness.get(1..).unwrap_or(&[]))
}

// ---------------------------------------------------------------------------------------------
// Publicly verifiable bases
// ---------------------------------------------------------------------------------------------

struct Attestation<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    t: E::G1,
    shown: B::ShownCredential,
    phi: E::ScalarField,
    pi: FSProof<E::ScalarField>,
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> Attestation<E, B> {
    fn with(&self, t: E::G1, phi: E::ScalarField) -> Self {
        Self {
            t,
            shown: self.shown.clone(),
            phi,
            pi: self.pi.clone(),
        }
    }
}

struct Deployment<E: Pairing, B: SigmaFriendlyCredentialBase<E>, T: PCSTag<E::G1>> {
    domain: Vec<u8>,
    pp: B::PublicParams,
    tag: T,
    c0: E::ScalarField,
    vk: B::VerificationKey,
}

impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>, T: PCSTag<E::G1>> Deployment<E, B, T> {
    /// `Setup` of the box for the deployment label `domain`, with the helper key `vk`.
    fn setup(domain: &[u8], vk: B::VerificationKey) -> Self {
        let c0: E::ScalarField = h0_identity_point(domain);
        Self {
            domain: domain.to_vec(),
            pp: B::setup(domain).unwrap(),
            tag: T::setup(domain, c0).unwrap(),
            c0,
            vk,
        }
    }

    /// `R_att`: the clauses of `R_Possess` and of `R_Tag` over one shared variable `usk`.
    fn att_relation(
        &self,
        shown: &B::ShownCredential,
        phi: &E::ScalarField,
        t: &E::G1,
        s: &E::ScalarField,
    ) -> PairingRelation<E> {
        let (mut rel, usk) = possession_relation::<E, B>(&self.pp, &self.vk, shown, phi).unwrap();
        for eq in self.tag.tag_equations(usk, t, s) {
            rel.add_g1(eq).unwrap();
        }
        assert_eq!(rel.num_scalars(), 1 + B::POSSESSION_VARIABLES);
        rel
    }

    fn att_context(
        &self,
        id: &E::G1,
        phi: &E::ScalarField,
        t: &E::G1,
        shown: &B::ShownCredential,
    ) -> Vec<u8> {
        context(
            b"att",
            &[
                &bytes(&self.pp),
                &bytes(&self.tag),
                &bytes(&self.vk),
                &bytes(id),
                &bytes(phi),
                &bytes(t),
                &bytes(shown),
            ],
        )
    }

    /// `Attest(hvk, usk_j, f_j, cred_j, id)`, steps 2-12; also returns the witness it used.
    fn attest(
        &self,
        usk: &E::ScalarField,
        phi: &E::ScalarField,
        (cred, aux): (&B::Credential, &B::Aux),
        id: &E::G1,
        rng: &mut StdRng,
    ) -> (Attestation<E, B>, Witness<E::ScalarField>) {
        let s: E::ScalarField = h0_id(&self.domain, id).unwrap();
        let t = self.tag.eval(usk, &s).unwrap();
        let m_hid = B::hidden_message(usk, aux);
        let m = B::encode_message(&self.pp, &m_hid, phi).unwrap();
        let (shown, omega) = B::rerand(&self.pp, &self.vk, &m, cred, rng).unwrap();
        let rel = self.att_relation(&shown, phi, &t, &s);
        let witness = possession_witness_vector::<E, B>(&m_hid, &omega);
        assert_eq!(witness.first(), Some(usk));
        let ctx = self.att_context(id, phi, &t, &shown);
        let pi = fiat_shamir::prove(&rel, &witness, &ctx, rng).unwrap();
        let att = Attestation {
            t,
            shown,
            phi: *phi,
            pi,
        };
        (att, witness)
    }

    /// `VerifyAtt(hvk, id, att)`: `ValidTag`, the public checks of `VerifyPossess`, Fiat-Shamir.
    fn verify_att(&self, id: &E::G1, att: &Attestation<E, B>) -> bool {
        let s: E::ScalarField = h0_id(&self.domain, id).unwrap();
        self.tag.valid_tag(&att.t, &s)
            && B::verify_possess_public(&self.pp, &self.vk, &att.shown, &att.phi)
            && fiat_shamir::verify(
                &self.att_relation(&att.shown, &att.phi, &att.t, &s),
                &self.att_context(id, &att.phi, &att.t, &att.shown),
                &att.pi,
            )
    }

    /// `R_issue`: the opening clause of `C` and the tag clauses of `id` and `T_0`, shared `usk`.
    fn issue_relation(
        &self,
        c: &B::IssuanceEncoding,
        phi: &E::ScalarField,
        id: &E::G1,
        t0: &E::G1,
    ) -> PairingRelation<E> {
        let mut rel = PairingRelation::new();
        let usk = rel.alloc_scalar();
        let allocated = B::issuance_clauses(&self.pp, &self.vk, c, phi, &mut rel, usk).unwrap();
        assert_eq!(allocated.len(), B::ISSUANCE_VARIABLES);
        let s: E::ScalarField = h0_id(&self.domain, id).unwrap();
        for eq in self
            .tag
            .tag_equations(usk, id, &self.c0)
            .into_iter()
            .chain(self.tag.tag_equations(usk, t0, &s))
        {
            rel.add_g1(eq).unwrap();
        }
        assert_eq!(rel.num_scalars(), 1 + B::ISSUANCE_VARIABLES);
        rel
    }
}

/// The flow of the protocol box for a publicly verifiable base `B` and a tag `T` over `E::G1`.
///
/// `forgeries(pp, vk, φ, K)` lists the credential-free forgeries of the base for the public
/// label `φ` and the forged key `K` (see [`Forgery`]). It must not be empty, and at least one
/// entry must satisfy the clauses: that is what shows that the public checks of the base are
/// load-bearing, and that they are there.
///
/// # Panics
/// On the first violated expectation.
pub fn public_base_flow<E, B, T>(
    domain: &[u8],
    seed: u64,
    forgeries: impl Fn(
        &B::PublicParams,
        &B::VerificationKey,
        &E::ScalarField,
        &E::ScalarField,
    ) -> Vec<Forgery<B::ShownCredential, E::ScalarField>>,
) -> FlowReport
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    let mut rng = StdRng::seed_from_u64(seed);

    // Setup (compatibility is a property of the tag INSTANCE), HKeyGen
    let (vk, sk) = B::keygen(&B::setup(domain).unwrap(), &mut rng);
    let dep = Deployment::<E, B, T>::setup(domain, vk);
    let c0 = dep.c0;
    assert_eq!(
        check_compatibility::<E, B, T>(&dep.tag, &c0),
        Ok(()),
        "Setup must refuse this base/tag pair"
    );
    assert!(B::is_well_formed_key(&dep.pp, &dep.vk));
    round_trip(&dep.pp);
    round_trip(&dep.tag);
    round_trip(&dep.vk);

    // A root credential for the attester: a direct signature on Enc(m_hid, φ_j).
    let phi_j: E::ScalarField = h0_predicate(domain, b"attester predicate");
    let (_, usk_j) = user_keygen(&dep.tag, domain, &c0, &mut rng);
    let (aux_j, _) = B::sample_issuance(&dep.pp, &mut rng);
    let m_hid_j = B::hidden_message(&usk_j, &aux_j);
    let m_j = B::encode_message(&dep.pp, &m_hid_j, &phi_j).unwrap();
    let cred_j = B::sign(&dep.pp, &sk, &m_j, &mut rng).unwrap();
    assert!(B::verify(&dep.pp, &dep.vk, &m_j, &cred_j));
    round_trip(&cred_j);

    // The subject.
    let (id, usk) = user_keygen(&dep.tag, domain, &c0, &mut rng);
    if dep.tag.identity_is_dlog(&c0) {
        assert_eq!(id, E::G1::generator() * usk);
    }
    let s: E::ScalarField = h0_id(domain, &id).unwrap();
    let t0 = dep.tag.eval(&usk, &s).unwrap();

    // Attest, VerifyAtt
    let (att, w_j) = dep.attest(&usk_j, &phi_j, (&cred_j, &aux_j), &id, &mut rng);
    assert!(dep.verify_att(&id, &att));
    round_trip(&att.shown);
    compact_round_trip(&att.pi, 1 + B::POSSESSION_VARIABLES);
    assert_ne!(att.t, t0);
    // ... not for another identifier, another predicate label, or another attester's tag
    assert!(!dep.verify_att(&(id + E::G1::generator()), &att));
    assert!(!dep.verify_att(&id, &att.with(att.t, att.phi + E::ScalarField::ONE)));
    assert!(!dep.verify_att(&id, &att.with(t0, att.phi)));

    // The possession clauses bind usk: next to the honest cred*, a tag under ANOTHER key has no
    // witness. `w_j` fails the tag clause; the other key fails the possession clauses, which is
    // what a base with a vacuous possession clause gets wrong.
    let (key_x, t_x) = other_key(&dep.tag, &s, &[usk_j, usk], &mut rng);
    let rel = dep.att_relation(&att.shown, &att.phi, &att.t, &s);
    let rel_x = dep.att_relation(&att.shown, &att.phi, &t_x, &s);
    let w_x = with_key(&w_j, key_x);
    assert!(rel.is_satisfied_by(&w_j));
    assert!(!rel.is_satisfied_by(&w_x));
    assert!(!rel_x.is_satisfied_by(&w_j));
    assert!(!rel_x.is_satisfied_by(&w_x));
    let ctx_x = dep.att_context(&id, &att.phi, &t_x, &att.shown);
    for w in [&w_j, &w_x] {
        assert_eq!(
            fiat_shamir::prove(&rel_x, w, &ctx_x, &mut rng),
            Err(Error::WitnessDoesNotSatisfyRelation)
        );
    }
    // A holder that claims the other key for its credential all the way through `Attest` gets
    // nowhere: `ReRand` refuses (bases that verify first), or the prover refuses (the clauses
    // have no witness), or the result is rejected (a weak base such as Σ-BBS re-randomizes
    // under the claimed message, and its public pairing check then fails).
    let m_hid_x = B::hidden_message(&key_x, &aux_j);
    let claimed = B::encode_message(&dep.pp, &m_hid_x, &phi_j)
        .and_then(|m_x| B::rerand(&dep.pp, &dep.vk, &m_x, &cred_j, &mut rng))
        .and_then(|(shown, omega_x)| {
            let rel = dep.att_relation(&shown, &phi_j, &t_x, &s);
            let w = possession_witness_vector::<E, B>(&m_hid_x, &omega_x);
            let ctx = dep.att_context(&id, &phi_j, &t_x, &shown);
            let pi = fiat_shamir::prove(&rel, &w, &ctx, &mut rng)?;
            Ok(Attestation::<E, B> {
                t: t_x,
                shown,
                phi: phi_j,
                pi,
            })
        });
    if let Ok(att_x) = claimed {
        assert!(
            !dep.verify_att(&id, &att_x),
            "a credential attested under another key"
        );
    }

    // The public checks of VerifyPossess: credential-free forgeries whose clauses ARE
    // satisfiable and whose bare Fiat-Shamir proofs DO verify.
    let forgeries = forgeries(&dep.pp, &dep.vk, &phi_j, &key_x);
    assert!(!forgeries.is_empty(), "the base must list its forgeries");
    let mut satisfiable = 0;
    for forgery in &forgeries {
        assert!(!B::verify_possess_public(
            &dep.pp,
            &dep.vk,
            &forgery.shown,
            &phi_j
        ));
        let rel = dep.att_relation(&forgery.shown, &phi_j, &t_x, &s);
        let w = key_then(key_x, &forgery.extra_witness);
        if !rel.is_satisfied_by(&w) {
            continue;
        }
        satisfiable += 1;
        let ctx = dep.att_context(&id, &phi_j, &t_x, &forgery.shown);
        let pi = fiat_shamir::prove(&rel, &w, &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &pi));
        assert!(dep.tag.valid_tag(&t_x, &s));
        let forged = Attestation::<E, B> {
            t: t_x,
            shown: forgery.shown.clone(),
            phi: phi_j,
            pi,
        };
        assert!(!dep.verify_att(&id, &forged), "credential-free attestation");
    }
    assert!(satisfiable > 0, "no forgery satisfies the clauses");

    // ValidTag: T = 1 is inadmissible. Where the base can certify usk = 0 and the tag clause
    // accepts (T, K) = (1, 0), everything else about such an attestation verifies.
    assert!(!dep.tag.valid_tag(&E::G1::zero(), &s));
    assert!(!dep.verify_att(&id, &att.with(E::G1::zero(), att.phi)));
    let zero = E::ScalarField::zero();
    let m_hid_0 = B::hidden_message(&zero, &aux_j);
    if let Ok(m_0) = B::encode_message(&dep.pp, &m_hid_0, &phi_j) {
        let cred_0 = B::sign(&dep.pp, &sk, &m_0, &mut rng).unwrap();
        let (shown_0, omega_0) = B::rerand(&dep.pp, &dep.vk, &m_0, &cred_0, &mut rng).unwrap();
        let rel = dep.att_relation(&shown_0, &phi_j, &E::G1::zero(), &s);
        let w = possession_witness_vector::<E, B>(&m_hid_0, &omega_0);
        if rel.is_satisfied_by(&w) {
            let ctx = dep.att_context(&id, &phi_j, &E::G1::zero(), &shown_0);
            let pi = fiat_shamir::prove(&rel, &w, &ctx, &mut rng).unwrap();
            assert!(fiat_shamir::verify(&rel, &ctx, &pi));
            assert!(B::verify_possess_public(&dep.pp, &dep.vk, &shown_0, &phi_j));
            let forged = Attestation::<E, B> {
                t: E::G1::zero(),
                shown: shown_0,
                phi: phi_j,
                pi,
            };
            assert!(!dep.verify_att(&id, &forged), "identity tag");
        }
    }

    // The context covers pp: other base parameters (where the base has any) and another
    // deployment reject the attestation, under the same helper key.
    let other_domain = [domain, b"/other"].concat();
    let other_pp = Deployment::<E, B, T> {
        domain: dep.domain.clone(),
        pp: B::setup(&other_domain).unwrap(),
        tag: dep.tag.clone(),
        c0,
        vk: dep.vk.clone(),
    };
    if other_pp.pp != dep.pp {
        assert!(!other_pp.verify_att(&id, &att));
    }
    let other_dep = Deployment::<E, B, T>::setup(&other_domain, dep.vk.clone());
    assert!(!other_dep.verify_att(&id, &att));

    // Prove: C, T_0, π_0
    let phi: E::ScalarField = h0_predicate(domain, b"subject predicate");
    let (aux, rho) = B::sample_issuance(&dep.pp, &mut rng);
    let m_hid = B::hidden_message(&usk, &aux);
    let c = B::issuance_encoding(&dep.pp, &dep.vk, &m_hid, &phi, &rho).unwrap();
    let rel = dep.issue_relation(&c, &phi, &id, &t0);
    let w_0 = issuance_witness_vector::<E, B>(&m_hid, &rho);
    assert_eq!(w_0.first(), Some(&usk));
    let wire = B::encoding_to_wire(&c);
    round_trip(&wire);
    let ctx0 = context(
        b"issue",
        &[
            &bytes(&dep.pp),
            &bytes(&dep.tag),
            &bytes(&dep.vk),
            &bytes(&id),
            &bytes(&wire),
            &bytes(&t0),
        ],
    );
    let pi0 = fiat_shamir::prove(&rel, &w_0, &ctx0, &mut rng).unwrap();
    compact_round_trip(&pi0, 1 + B::ISSUANCE_VARIABLES);

    // VerifyProof (the part concerning π_0), Issue: the helper sees (id, wire, T_0, π_0) only
    let c_helper = B::encoding_from_wire(&dep.pp, &wire, &id).unwrap();
    assert_eq!(c_helper, c);
    assert!(dep.tag.valid_tag(&id, &c0) && dep.tag.valid_tag(&t0, &s));
    let rel_helper = dep.issue_relation(&c_helper, &phi, &id, &t0);
    assert!(fiat_shamir::verify(&rel_helper, &ctx0, &pi0));
    let rel_other_id = dep.issue_relation(&c_helper, &phi, &(id + id), &t0);
    assert!(!fiat_shamir::verify(&rel_other_id, &ctx0, &pi0));
    let rel_other_t0 = dep.issue_relation(&c_helper, &phi, &id, &att.t);
    assert!(!fiat_shamir::verify(&rel_other_t0, &ctx0, &pi0));
    // The opening clause binds usk: an encoding of ANOTHER key next to this id and T_0 has no
    // witness. (Skipped where the helper derives C from id and nothing travels, as for Σ-EQ.)
    let m_hid_x = B::hidden_message(&key_x, &aux);
    let c_x = B::issuance_encoding(&dep.pp, &dep.vk, &m_hid_x, &phi, &rho).unwrap();
    let c_x_helper = B::encoding_from_wire(&dep.pp, &B::encoding_to_wire(&c_x), &id).unwrap();
    if c_x_helper != c_helper {
        let rel_x = dep.issue_relation(&c_x_helper, &phi, &id, &t0);
        assert!(!rel_x.is_satisfied_by(&w_0));
        assert!(!rel_x.is_satisfied_by(&with_key(&w_0, key_x)));
        assert!(!fiat_shamir::verify(&rel_x, &ctx0, &pi0));
    }
    let pre = B::blind_issue(&dep.pp, &sk, &c_helper, &phi, &mut rng).unwrap();
    round_trip(&pre);

    // Unblind, VerifyCred
    let m = B::encode_message(&dep.pp, &m_hid, &phi).unwrap();
    let cred = B::unblind(&dep.pp, &dep.vk, &m, &pre, &rho).unwrap();
    assert!(B::verify(&dep.pp, &dep.vk, &m, &cred));
    let (usk_back, aux_back) = B::split_hidden_message(&m_hid);
    assert!(usk_back == usk && aux_back == aux);
    round_trip(&aux);
    // the credential certifies (usk, φ) and nothing else: φ entered exactly once
    let m_other_phi = B::encode_message(&dep.pp, &m_hid, &phi_j).unwrap();
    assert!(!B::verify(&dep.pp, &dep.vk, &m_other_phi, &cred));
    let m_other_usk = B::encode_message(&dep.pp, &B::hidden_message(&usk_j, &aux), &phi).unwrap();
    assert!(!B::verify(&dep.pp, &dep.vk, &m_other_usk, &cred));

    // Chaining: the issued credential attests for a third identifier.
    let (id3, _) = user_keygen(&dep.tag, domain, &c0, &mut rng);
    let (att3, _) = dep.attest(&usk, &phi, (&cred, &aux), &id3, &mut rng);
    assert!(dep.verify_att(&id3, &att3));
    assert!(!dep.verify_att(&id, &att3));

    FlowReport {
        attestation_responses: att.pi.responses.len(),
        issuance_responses: pi0.responses.len(),
    }
}

// ---------------------------------------------------------------------------------------------
// Designated-verifier bases
// ---------------------------------------------------------------------------------------------

/// The same flow for a designated-verifier base `B` and a tag `T` over the group `G`: provers
/// never see `dvk`, the verifier derives its statement from it.
///
/// `forgeries(pp, φ, K)` is as for [`public_base_flow`]. The forger of the flow states its
/// clauses with the verifier's relation; that is no shortcut for a degenerate `cred*`, whose
/// key-dependent target is predictable without `dvk` (`X = 1` for `(U', V') = (1, 1)`).
///
/// # Panics
/// On the first violated expectation.
pub fn dv_base_flow<G, B, T>(
    domain: &[u8],
    seed: u64,
    forgeries: impl Fn(
        &B::PublicParams,
        &G::ScalarField,
        &G::ScalarField,
    ) -> Vec<Forgery<B::ShownCredential, G::ScalarField>>,
) -> FlowReport
where
    G: PrimeGroup,
    B: SigmaFriendlyDVCredentialBase<G>,
    T: PCSTag<G>,
{
    let mut rng = StdRng::seed_from_u64(seed);

    // Setup, HKeyGen (the helper keeps dvk)
    let pp = B::setup(domain).unwrap();
    let c0: G::ScalarField = h0_identity_point(domain);
    let tag = T::setup(domain, c0).unwrap();
    assert_eq!(
        check_dv_compatibility::<G, B, T>(&tag, &c0),
        Ok(()),
        "Setup must refuse this base/tag pair"
    );
    let dvk = B::keygen(&pp, &mut rng);
    assert!(B::is_well_formed_key(&pp, &dvk));
    round_trip(&pp);
    round_trip(&tag);

    let tag_clauses = |rel: &mut GroupRelation<G>, usk, t: &G, s: &G::ScalarField| {
        for eq in tag.tag_equations(usk, t, s) {
            rel.add_equation(eq).unwrap();
        }
    };
    let att_context = |pp: &B::PublicParams,
                       tag: &T,
                       id: &G,
                       phi: &G::ScalarField,
                       t: &G,
                       shown: &B::ShownCredential| {
        context(
            b"att",
            &[
                &bytes(pp),
                &bytes(tag),
                &bytes(id),
                &bytes(phi),
                &bytes(t),
                &bytes(shown),
            ],
        )
    };
    // The verifier's R_att for (cred*, φ, T, s), from dvk.
    let verifier_relation =
        |shown: &B::ShownCredential, phi: &G::ScalarField, t: &G, s: &G::ScalarField| {
            let mut rel = GroupRelation::new();
            let var = rel.alloc_scalar();
            let allocated = B::possession_clauses_verifier(&pp, &dvk, shown, phi, &mut rel, var)?;
            assert_eq!(allocated.len(), B::POSSESSION_VARIABLES);
            tag_clauses(&mut rel, var, t, s);
            Ok::<_, Error>(rel)
        };
    // VerifyAtt (keyed): ValidTag, the keyless public checks, Fiat-Shamir on the verifier's
    // statement.
    let verify_att = |shown: &B::ShownCredential,
                      phi: &G::ScalarField,
                      t: &G,
                      s: &G::ScalarField,
                      ctx: &[u8],
                      pi: &FSProof<G::ScalarField>| {
        tag.valid_tag(t, s)
            && B::verify_possess_public(&pp, shown, phi)
            && verifier_relation(shown, phi, t, s)
                .is_ok_and(|rel| fiat_shamir::verify(&rel, ctx, pi))
    };

    // A root credential for the attester: a direct MAC on Enc(m_hid, φ_j).
    let phi_j: G::ScalarField = h0_predicate(domain, b"attester predicate");
    let (_, usk_j) = user_keygen(&tag, domain, &c0, &mut rng);
    let (aux_j, _) = B::sample_issuance(&pp, &mut rng);
    let m_hid_j = B::hidden_message(&usk_j, &aux_j);
    let m_j = B::encode_message(&pp, &m_hid_j, &phi_j).unwrap();
    let cred_j = B::sign(&pp, &dvk, &m_j, &mut rng).unwrap();
    assert!(B::verify(&pp, &dvk, &m_j, &cred_j));
    round_trip(&cred_j);

    // The subject.
    let (id, usk) = user_keygen(&tag, domain, &c0, &mut rng);
    let s: G::ScalarField = h0_id(domain, &id).unwrap();
    let t0 = tag.eval(&usk, &s).unwrap();

    // Attest (keyless)
    let t_j = tag.eval(&usk_j, &s).unwrap();
    let (shown, omega) = B::rerand(&pp, &m_j, &cred_j, &mut rng).unwrap();
    round_trip(&shown);
    let mut rel = GroupRelation::new();
    let var = rel.alloc_scalar();
    let allocated =
        B::possession_clauses_prover(&pp, &shown, &phi_j, &m_hid_j, &omega, &mut rel, var).unwrap();
    assert_eq!(allocated.len(), B::POSSESSION_VARIABLES);
    tag_clauses(&mut rel, var, &t_j, &s);
    let w_j = key_then(usk_j, &B::possession_witness(&m_hid_j, &omega));
    let ctx = att_context(&pp, &tag, &id, &phi_j, &t_j, &shown);
    let pi = fiat_shamir::prove(&rel, &w_j, &ctx, &mut rng).unwrap();
    compact_round_trip(&pi, 1 + B::POSSESSION_VARIABLES);

    // VerifyAtt (keyed): prover and verifier state the same relation
    assert_eq!(verifier_relation(&shown, &phi_j, &t_j, &s).unwrap(), rel);
    assert!(verify_att(&shown, &phi_j, &t_j, &s, &ctx, &pi));
    let one = G::ScalarField::ONE;
    assert!(!verify_att(&shown, &(phi_j + one), &t_j, &s, &ctx, &pi));
    assert!(!verify_att(&shown, &phi_j, &t0, &s, &ctx, &pi));
    assert!(!verify_att(&shown, &phi_j, &t_j, &(s + one), &ctx, &pi));
    // a verifier with ANOTHER key rejects
    let other_dvk = B::keygen(&pp, &mut rng);
    let mut rel_other = GroupRelation::new();
    let var = rel_other.alloc_scalar();
    B::possession_clauses_verifier(&pp, &other_dvk, &shown, &phi_j, &mut rel_other, var).unwrap();
    tag_clauses(&mut rel_other, var, &t_j, &s);
    assert!(!fiat_shamir::verify(&rel_other, &ctx, &pi));

    // The possession clause binds usk: a tag under ANOTHER key next to the honest cred* has no
    // witness in the verifier's relation, and the honest prover's own relation is not
    // satisfied by the other key either.
    let (key_x, t_x) = other_key(&tag, &s, &[usk_j, usk], &mut rng);
    let rel_x = verifier_relation(&shown, &phi_j, &t_x, &s).unwrap();
    let w_x = with_key(&w_j, key_x);
    assert!(rel.is_satisfied_by(&w_j));
    assert!(!rel.is_satisfied_by(&w_x));
    assert!(!rel_x.is_satisfied_by(&w_j));
    assert!(!rel_x.is_satisfied_by(&w_x));
    let ctx_x = att_context(&pp, &tag, &id, &phi_j, &t_x, &shown);
    for w in [&w_j, &w_x] {
        assert_eq!(
            fiat_shamir::prove(&rel_x, w, &ctx_x, &mut rng),
            Err(Error::WitnessDoesNotSatisfyRelation)
        );
    }
    // A holder that claims the other key for its MAC states X = (U')^{other key}, which is not
    // the verifier's X: its proof is rejected.
    let m_hid_x = B::hidden_message(&key_x, &aux_j);
    let mut rel_claim = GroupRelation::new();
    let var = rel_claim.alloc_scalar();
    B::possession_clauses_prover(&pp, &shown, &phi_j, &m_hid_x, &omega, &mut rel_claim, var)
        .unwrap();
    tag_clauses(&mut rel_claim, var, &t_x, &s);
    let w_claim = key_then(key_x, &B::possession_witness(&m_hid_x, &omega));
    if let Ok(pi_claim) = fiat_shamir::prove(&rel_claim, &w_claim, &ctx_x, &mut rng) {
        assert!(!verify_att(&shown, &phi_j, &t_x, &s, &ctx_x, &pi_claim));
    }

    // The keyless public checks: credential-free forgeries.
    let forgeries = forgeries(&pp, &phi_j, &key_x);
    assert!(!forgeries.is_empty(), "the base must list its forgeries");
    let mut satisfiable = 0;
    for forgery in &forgeries {
        assert!(!B::verify_possess_public(&pp, &forgery.shown, &phi_j));
        let Ok(rel) = verifier_relation(&forgery.shown, &phi_j, &t_x, &s) else {
            continue;
        };
        let w = key_then(key_x, &forgery.extra_witness);
        if !rel.is_satisfied_by(&w) {
            continue;
        }
        satisfiable += 1;
        let ctx = att_context(&pp, &tag, &id, &phi_j, &t_x, &forgery.shown);
        let pi = fiat_shamir::prove(&rel, &w, &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &pi));
        assert!(
            !verify_att(&forgery.shown, &phi_j, &t_x, &s, &ctx, &pi),
            "credential-free attestation"
        );
    }
    assert!(satisfiable > 0, "no forgery satisfies the clauses");

    // ValidTag
    assert!(!tag.valid_tag(&G::zero(), &s));
    assert!(!verify_att(&shown, &phi_j, &G::zero(), &s, &ctx, &pi));

    // The context covers pp: another deployment rejects the attestation under the same dvk.
    let other_domain = [domain, b"/other"].concat();
    let other_pp = B::setup(&other_domain).unwrap();
    let other_tag = T::setup(&other_domain, h0_identity_point(&other_domain)).unwrap();
    let other_s: G::ScalarField = h0_id(&other_domain, &id).unwrap();
    let other_ctx = att_context(&other_pp, &other_tag, &id, &phi_j, &t_j, &shown);
    let mut rel_dep = GroupRelation::new();
    let var = rel_dep.alloc_scalar();
    B::possession_clauses_verifier(&other_pp, &dvk, &shown, &phi_j, &mut rel_dep, var).unwrap();
    for eq in other_tag.tag_equations(var, &t_j, &other_s) {
        rel_dep.add_equation(eq).unwrap();
    }
    assert!(!fiat_shamir::verify(&rel_dep, &other_ctx, &pi));

    // Prove: C, T_0, π_0 (keyless), verified and answered by the helper
    let phi: G::ScalarField = h0_predicate(domain, b"subject predicate");
    let (aux, rho) = B::sample_issuance(&pp, &mut rng);
    let m_hid = B::hidden_message(&usk, &aux);
    let c = B::issuance_encoding(&pp, &m_hid, &phi, &rho).unwrap();
    let issue_relation = |c: &B::IssuanceEncoding, id: &G, t0: &G| {
        let mut rel = GroupRelation::new();
        let var = rel.alloc_scalar();
        let allocated = B::issuance_clauses(&pp, c, &phi, &mut rel, var).unwrap();
        assert_eq!(allocated.len(), B::ISSUANCE_VARIABLES);
        tag_clauses(&mut rel, var, id, &c0);
        tag_clauses(&mut rel, var, t0, &s);
        rel
    };
    let rel = issue_relation(&c, &id, &t0);
    let w_0 = key_then(usk, &B::issuance_witness(&m_hid, &rho));
    let wire = B::encoding_to_wire(&c);
    round_trip(&wire);
    let ctx0 = context(
        b"issue",
        &[
            &bytes(&pp),
            &bytes(&tag),
            &bytes(&id),
            &bytes(&wire),
            &bytes(&t0),
        ],
    );
    let pi0 = fiat_shamir::prove(&rel, &w_0, &ctx0, &mut rng).unwrap();
    compact_round_trip(&pi0, 1 + B::ISSUANCE_VARIABLES);

    let c_helper = B::encoding_from_wire(&pp, &wire, &id).unwrap();
    assert_eq!(c_helper, c);
    assert!(fiat_shamir::verify(
        &issue_relation(&c_helper, &id, &t0),
        &ctx0,
        &pi0
    ));
    assert!(!fiat_shamir::verify(
        &issue_relation(&c_helper, &(id + id), &t0),
        &ctx0,
        &pi0
    ));
    // The opening clause binds usk.
    let m_hid_x = B::hidden_message(&key_x, &aux);
    let c_x = B::issuance_encoding(&pp, &m_hid_x, &phi, &rho).unwrap();
    let c_x_helper = B::encoding_from_wire(&pp, &B::encoding_to_wire(&c_x), &id).unwrap();
    if c_x_helper != c_helper {
        let rel_x = issue_relation(&c_x_helper, &id, &t0);
        assert!(!rel_x.is_satisfied_by(&w_0));
        assert!(!rel_x.is_satisfied_by(&with_key(&w_0, key_x)));
    }
    let pre = B::blind_issue(&pp, &dvk, &c_helper, &phi, &mut rng).unwrap();
    round_trip(&pre);

    // Unblind; only the helper can run VerifyCred
    let m = B::encode_message(&pp, &m_hid, &phi).unwrap();
    let cred = B::unblind(&pp, &m, &pre, &rho).unwrap();
    assert!(B::verify(&pp, &dvk, &m, &cred));
    let (usk_back, aux_back) = B::split_hidden_message(&m_hid);
    assert!(usk_back == usk && aux_back == aux);
    let m_other_phi = B::encode_message(&pp, &m_hid, &phi_j).unwrap();
    assert!(!B::verify(&pp, &dvk, &m_other_phi, &cred));
    assert!(!B::verify(&pp, &other_dvk, &m, &cred));

    FlowReport {
        attestation_responses: pi.responses.len(),
        issuance_responses: pi0.responses.len(),
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use ark_bls12_381::{Fr, G1Projective as G1};
    use ark_ff::UniformRand;
    use ark_std::rand::{CryptoRng, RngCore};

    use super::*;
    use crate::{
        hash::bls12_381::G1Hasher,
        kiprf::{DDH, DY, KIPRF, SigmaFriendlyKIPRF},
        sigma::{LinearEquation, ScalarVar},
    };

    const DOMAIN: &[u8] = b"conformance-unit-tests";

    /// `Tag_DY` with the identity in the place of `g_1`: `TagEval` is `⊥` everywhere. Only
    /// decoding WITHOUT validation produces it.
    fn degenerate_dy() -> DY<G1> {
        let bytes = crate::serialization::to_bytes(&G1::zero()).unwrap();
        let tag = DY::<G1>::deserialize_compressed_unchecked(&bytes[..]).unwrap();
        assert!(!PCSTag::<G1>::is_well_formed(&tag));
        tag
    }

    thread_local! {
        /// Calls of `LyingTag::keygen` on this thread (every test runs on its own thread).
        static LYING_KEYGEN_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// A broken tag: it CLAIMS to be well formed and is undefined everywhere. The guard of the
    /// restart loops cannot catch it; their bound has to. Its `keygen` panics with a message of
    /// its own once it is called more often than the bound allows, so that a loop without a
    /// bound makes the tests below FAIL instead of hang.
    #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
    struct LyingTag {
        marker: u8,
    }

    impl KIPRF for LyingTag {
        type Key = Fr;
        type Input = Fr;
        type Output = G1;

        fn keygen<R: RngCore + CryptoRng + ?Sized>(&self, rng: &mut R) -> Fr {
            let calls = LYING_KEYGEN_CALLS.with(|c| {
                c.set(c.get() + 1);
                c.get()
            });
            assert!(
                calls <= MAX_KEYGEN_ATTEMPTS,
                "the restart loop is not bounded"
            );
            Fr::rand(rng)
        }

        fn eval(&self, _key: &Fr, _input: &Fr) -> Option<G1> {
            None
        }
    }

    impl SigmaFriendlyKIPRF for LyingTag {
        type Group = G1;

        fn valid_tag(&self, _tag: &G1, _input: &Fr) -> bool {
            false
        }

        fn tag_equations(
            &self,
            _key: ScalarVar,
            _tag: &G1,
            _input: &Fr,
        ) -> Vec<LinearEquation<G1>> {
            Vec::new()
        }
    }

    impl PCSTag<G1> for LyingTag {
        const IDENTITY_IS_DLOG: bool = false;

        fn setup(_domain: &[u8], _c0: Fr) -> Result<Self, Error> {
            Ok(Self { marker: 0 })
        }

        fn identity_is_dlog(&self, _c0: &Fr) -> bool {
            false
        }

        fn is_well_formed(&self) -> bool {
            true
        }
    }

    /// Under well-formed instances of both tags of the paper the loops return a usable key.
    #[test]
    fn restart_loops_return_usable_keys_under_well_formed_tags() {
        fn check<T: PCSTag<G1>>(seed: u64) {
            let mut rng = StdRng::seed_from_u64(seed);
            let c0: Fr = h0_identity_point(DOMAIN);
            let tag = T::setup(DOMAIN, c0).unwrap();
            assert!(tag.is_well_formed());
            let (id, usk) = user_keygen(&tag, DOMAIN, &c0, &mut rng);
            assert_eq!(tag.eval(&usk, &c0), Some(id));
            let s: Fr = h0_id(DOMAIN, &id).unwrap();
            let t0 = tag.eval(&usk, &s).expect("UKeyGen step 5");
            assert!(tag.valid_tag(&id, &c0) && tag.valid_tag(&t0, &s));
            let (key, t) = other_key(&tag, &s, &[usk], &mut rng);
            assert_ne!(key, usk);
            assert_eq!(tag.eval(&key, &s), Some(t));
        }
        check::<DDH<G1, G1Hasher>>(0xc0f0_0001);
        check::<DY<G1>>(0xc0f0_0002);
    }

    /// The guard: a degenerate `pp_Tag` is refused before the first attempt (the loop of the
    /// box would spin forever, every evaluation being `⊥`).
    #[test]
    #[should_panic(expected = "degenerate tag parameters")]
    fn user_keygen_refuses_degenerate_tag_parameters() {
        let mut rng = StdRng::seed_from_u64(0xc0f0_0003);
        let c0: Fr = h0_identity_point(DOMAIN);
        let _ = user_keygen(&degenerate_dy(), DOMAIN, &c0, &mut rng);
    }

    #[test]
    #[should_panic(expected = "degenerate tag parameters")]
    fn other_key_refuses_degenerate_tag_parameters() {
        let mut rng = StdRng::seed_from_u64(0xc0f0_0004);
        let _ = other_key(&degenerate_dy(), &Fr::from(5u64), &[], &mut rng);
    }

    /// The bound: a tag that passes the guard and is undefined everywhere costs
    /// `MAX_KEYGEN_ATTEMPTS` attempts, not forever. (Without the bound `LyingTag::keygen` panics
    /// with another message and the test fails.)
    #[test]
    #[should_panic(expected = "UKeyGen: no usable key in 64 attempts")]
    fn user_keygen_is_bounded() {
        let mut rng = StdRng::seed_from_u64(0xc0f0_0005);
        let c0: Fr = h0_identity_point(DOMAIN);
        let _ = user_keygen(&LyingTag { marker: 0 }, DOMAIN, &c0, &mut rng);
    }

    #[test]
    #[should_panic(expected = "no other key with a defined tag in 64 attempts")]
    fn other_key_is_bounded() {
        let mut rng = StdRng::seed_from_u64(0xc0f0_0006);
        let _ = other_key(&LyingTag { marker: 0 }, &Fr::from(5u64), &[], &mut rng);
    }

    /// The flows run the compatibility check of `Setup` before anything else, and that check
    /// refuses degenerate tag parameters for every base.
    #[test]
    fn compatibility_checks_refuse_degenerate_tag_parameters() {
        type E = ark_bls12_381::Bls12_381;
        let c0: Fr = h0_identity_point(DOMAIN);
        let refused: Result<(), Error> = Err(Error::DegenerateInput("pp_Tag"));
        assert_eq!(
            check_compatibility::<E, crate::cred::PS<E>, _>(&degenerate_dy(), &c0),
            refused
        );
        assert_eq!(
            check_dv_compatibility::<G1, crate::cred::MAC<G1, G1Hasher>, DY<G1>>(
                &degenerate_dy(),
                &c0
            ),
            refused
        );
    }
}
