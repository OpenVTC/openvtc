//! Correctness of the modular threshold construction (`predicate_credential_system::pcs::PCS`, paper §5.1) through the
//! PUBLIC API only, plus the basic negatives (DESIGN §6). An exhaustive adversarial suite is a
//! separate file; what is here is what has to hold for the construction to be usable at all.
//!
//! * Def. "Correctness", for EVERY compatible pair of a base and a tag (`Σ-PS`, `Σ-BBS` with
//!   `Tag_DDH` and `Tag_DY`; `Σ-EQ` with `Tag_DDH`) and `k ∈ {1, 2, 5}`: root issuance for
//!   `k + 1` users, `Attest × k`, `VerifyAtt`, `Prove`, `VerifyProof`, `Issue`, `Unblind`,
//!   `VerifyCred`; then CHAINING (Remark "Chaining and the base case"): the freshly issued
//!   credential attests for a third user, whose proof is accepted.
//! * The byte sizes of the paper's comparison table (§5.3) over BLS12-381. They are sizes of
//!   the FIXED-FORMAT compact encoding (`to_compact_bytes`); the derived canonical encoding is
//!   self-describing and longer, and the tests pin the difference.
//! * Def. "Proof-gated issuance": `Issue` outputs `⊥` on every proof `VerifyProof` rejects.
//! * Negatives that each hinge on ONE verifier-side check. Where the honest `prove` refuses to
//!   produce the offending proof, a CHEATING prover (`cheat`) builds it from the public relation
//!   and context builders, so that everything about the proof verifies except the one check.
//!
//! All runs are seeded (`StdRng::seed_from_u64`, the seed is an argument of every flow). The
//! BN254 run puts the INSECURE test oracle behind `H_2`; it shows that the code is generic over
//! the pairing, not that BN254 is a supported deployment.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_bn254::Bn254;
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use predicate_credential_system::{
    Error,
    cred::{
        self, CredentialBase, EQ, SigmaFriendlyCredentialBase, bbs::BBSPreCredential,
        eq::EQPreCredential, ps::PSPreCredential,
    },
    hash::{bls12_381::G1Hasher, testing::InsecureExponentHasher},
    kiprf::{self, KIPRF, PCSTag},
    pcs::{
        AcceptAll, AllowList, Attestation, AttributePolicy, Credential, HelperSecretKey,
        IssuanceProof, IssuanceState, PCS, Predicate, PredicateCredentialSystem, PublicParameters,
        RootRequest, SetupParams, UserSecretKey,
    },
    serialization::WireFormat,
    sigma::fiat_shamir,
};
use rand::{SeedableRng, rngs::StdRng};

type E = Bls12_381;
type G1 = G1Projective;
type PS = cred::PS<E>;
type BBS = cred::BBS<E, G1Hasher>;
type SPSEQ = EQ<E>;
type DDH = kiprf::DDH<G1, G1Hasher>;
type DY = kiprf::DY<G1>;

// ---------------------------------------------------------------------------------------------
// A deployment and its members
// ---------------------------------------------------------------------------------------------

struct Deployment<E, B, T, P = AcceptAll>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    pcs: PCS<E, B, T, P>,
    hvk: B::VerificationKey,
    hsk: HelperSecretKey<B>,
    f_root: Predicate,
}

/// A user holding a credential under the predicate `f`.
struct Member<E: Pairing, B: SigmaFriendlyCredentialBase<E>> {
    id: E::G1,
    usk: UserSecretKey<E>,
    f: Predicate,
    cred: Credential<E, B>,
}

impl<E, B, T, P> Deployment<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
    P: AttributePolicy<E::ScalarField>,
{
    fn new(label: &[u8], policy: P, rng: &mut StdRng) -> Self {
        let pcs = PCS::setup(SetupParams::with_policy(label.to_vec(), policy)).unwrap();
        let (hvk, hsk) = pcs.helper_keygen(rng);
        assert_eq!(hsk.verification_key(), &hvk);
        Self {
            pcs,
            hvk,
            hsk,
            f_root: Predicate::root(b"founding members".to_vec()),
        }
    }

    /// Root issuance (Remark "Chaining and the base case") for the key pair `(id, usk)`.
    fn admit(&self, id: E::G1, usk: UserSecretKey<E>, rng: &mut StdRng) -> Member<E, B> {
        let (pcs, hvk, f_root) = (&self.pcs, &self.hvk, &self.f_root);
        let (request, state) = pcs.root_request(hvk, f_root, &id, &usk, rng).unwrap();
        assert_eq!(pcs.check_root_request(hvk, f_root, &id, &request), Ok(()));
        assert!(pcs.verify_root_request(hvk, f_root, &id, &request));
        let pre = pcs
            .issue_root(hvk, &self.hsk, f_root, &id, &request, rng)
            .unwrap();
        let cred = pcs.unblind(hvk, &usk, f_root, &pre, &state).unwrap();
        assert!(pcs.verify_cred(hvk, &usk, f_root, &cred));
        Member {
            id,
            usk,
            f: f_root.clone(),
            cred,
        }
    }

    fn root_member(&self, rng: &mut StdRng) -> Member<E, B> {
        let (id, usk) = self.pcs.user_keygen(rng).unwrap();
        self.admit(id, usk, rng)
    }

    fn attest(&self, member: &Member<E, B>, id: &E::G1, rng: &mut StdRng) -> Attestation<E, B> {
        self.pcs
            .attest(&self.hvk, &member.usk, &member.f, &member.cred, id, rng)
            .unwrap()
    }

    fn attestations<'a>(
        &self,
        members: impl IntoIterator<Item = &'a Member<E, B>>,
        id: &E::G1,
        rng: &mut StdRng,
    ) -> Vec<Attestation<E, B>>
    where
        E: 'a,
        B: 'a,
    {
        members
            .into_iter()
            .map(|member| {
                let att = self.attest(member, id, rng);
                assert_eq!(self.pcs.check_attestation(&self.hvk, id, &att), Ok(()));
                assert!(self.pcs.verify_attestation(&self.hvk, id, &att));
                att
            })
            .collect()
    }

    /// `Prove → VerifyProof → Issue → Unblind → VerifyCred` (Def. "Correctness").
    fn join(
        &self,
        f: &Predicate,
        id: E::G1,
        usk: UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
        rng: &mut StdRng,
    ) -> (Member<E, B>, IssuanceProof<E, B>) {
        let (pcs, hvk) = (&self.pcs, &self.hvk);
        let (proof, state) = pcs.prove(hvk, f, &id, &usk, attestations, rng).unwrap();
        assert_eq!(pcs.check_proof(hvk, f, &id, &proof), Ok(()));
        assert!(pcs.verify_proof(hvk, f, &id, &proof));
        let pre = pcs.issue(hvk, &self.hsk, f, &id, &proof, rng).unwrap();
        let cred = pcs.unblind(hvk, &usk, f, &pre, &state).unwrap();
        assert!(pcs.verify_cred(hvk, &usk, f, &cred));
        let member = Member {
            id,
            usk,
            f: f.clone(),
            cred,
        };
        (member, proof)
    }

    /// A CHEATING prover for the statement `(hvk, f, id)`: steps 3-5 and 7-13 of `Prove` WITHOUT
    /// step 6 (`CheckAtts_P`) and without the count of step 2. `π_0` is an honest proof for
    /// `R_issue` under the context `ctx_0` of exactly the given attestation list, so whatever
    /// rejects the result is a check of the verifier on the attestations.
    fn cheat(
        &self,
        f: &Predicate,
        id: &E::G1,
        usk: &UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
        rng: &mut StdRng,
    ) -> IssuanceProof<E, B> {
        self.try_cheat(f, id, usk, attestations, rng).unwrap()
    }

    /// [`Self::cheat`]; `Err` if `R_issue` has no witness under `usk` (the cheating prover still
    /// needs ONE key behind `C`, `id` and `T_0`).
    fn try_cheat(
        &self,
        f: &Predicate,
        id: &E::G1,
        usk: &UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
        rng: &mut StdRng,
    ) -> Result<IssuanceProof<E, B>, Error> {
        let (pcs, hvk) = (&self.pcs, &self.hvk);
        let pp = pcs.base_parameters();
        let phi = pcs.enc_pred(f).unwrap();
        let s = pcs.tag_point(id).unwrap();
        let t0 = pcs.tag().eval(usk.expose_scalar(), &s).unwrap();
        let (aux, rho) = B::sample_issuance(pp, rng);
        let m_hid = B::hidden_message(usk.expose_scalar(), &aux);
        let c = B::issuance_encoding(pp, hvk, &m_hid, &phi, &rho).unwrap();
        let relation = pcs.issuance_relation(hvk, &c, &phi, id, &t0, &s).unwrap();
        let ctx = pcs
            .issuance_context(hvk, f, id, &c, &t0, attestations)
            .unwrap();
        let witness = PCS::<E, B, T, P>::issuance_witness(&m_hid, &rho);
        let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng)?;
        // the bare Fiat-Shamir proof is fine
        assert!(fiat_shamir::verify(&relation, &ctx, &proof));
        Ok(IssuanceProof {
            attestations: attestations.to_vec(),
            encoding: B::encoding_to_wire(&c),
            t0,
            proof,
        })
    }

    /// `VerifyProof` rejects for the given reason, and `Issue` outputs `⊥` (Def. "Proof-gated
    /// issuance").
    fn assert_rejected(
        &self,
        f: &Predicate,
        id: &E::G1,
        proof: &IssuanceProof<E, B>,
        reason: Error,
        rng: &mut StdRng,
    ) {
        let (pcs, hvk) = (&self.pcs, &self.hvk);
        assert_eq!(pcs.check_proof(hvk, f, id, proof), Err(reason.clone()));
        assert!(!pcs.verify_proof(hvk, f, id, proof), "{reason:?}");
        let gate = if f.is_root() {
            Error::ZeroThreshold
        } else {
            Error::InvalidProof
        };
        assert_eq!(
            pcs.issue(hvk, &self.hsk, f, id, proof, rng).err(),
            Some(gate)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Def. "Correctness", chaining, serialization
// ---------------------------------------------------------------------------------------------

/// Byte sizes observed by a flow, all of the COMPACT fixed-format encoding except `credential`,
/// `base_credential` and `pre_credential` (derived canonical encoding, which has no length
/// prefixes for these types).
#[derive(Debug, PartialEq, Eq)]
struct Sizes {
    attestation: usize,
    proof: usize,
    root_request: usize,
    /// `cred = (cred_Σ, m_aux)`.
    credential: usize,
    /// `cred_Σ` alone.
    base_credential: usize,
    pre_credential: usize,
}

fn correctness_flow<E, B, T>(label: &[u8], seed: u64, k: u32) -> Sizes
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let rng = &mut rng;
    let dep = Deployment::<E, B, T>::new(label, AcceptAll, rng);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);
    let threshold = k as usize;

    // pp travels, and the receiver re-derives it
    let pp_bytes = pcs.public_parameters().to_bytes().unwrap();
    let received = PublicParameters::<E, B, T>::from_bytes(&pp_bytes).unwrap();
    let rebuilt = PCS::from_public_parameters(received, AcceptAll).unwrap();
    assert_eq!(rebuilt.parameters_digest(), pcs.parameters_digest());

    // Root issuance for k + 1 users.
    let roots: Vec<Member<E, B>> = (0..=k).map(|_| dep.root_member(rng)).collect();

    // The subject collects k attestations and joins under f_k.
    let (id, usk) = pcs.user_keygen(rng).unwrap();
    assert_eq!(pcs.identity(&usk), Ok(id));
    let attestations = dep.attestations(&roots[..threshold], &id, rng);
    let f = Predicate::new(k, b"members".to_vec());
    let (subject, proof) = dep.join(&f, id, usk, &attestations, rng);
    assert_eq!(proof.attestations, attestations);
    // the credential is bound to (usk, f): not to the root predicate, not to another key
    assert!(!pcs.verify_cred(hvk, &subject.usk, &dep.f_root, &subject.cred));
    assert!(!pcs.verify_cred(hvk, &roots[0].usk, &f, &subject.cred));

    // Serialization: both encodings round-trip, and the decoded objects verify.
    let att = &attestations[0];
    let att_bytes = att.to_compact_bytes().unwrap();
    assert_eq!(att_bytes.len(), att.compact_size());
    let decoded = Attestation::<E, B>::from_compact_bytes(&att_bytes).unwrap();
    assert_eq!(&decoded, att);
    assert!(pcs.verify_attestation(hvk, &id, &decoded));
    assert_eq!(
        &Attestation::<E, B>::from_bytes(&att.to_bytes().unwrap()).unwrap(),
        att
    );
    // the derived encoding length-prefixes the responses: 8 bytes more
    assert_eq!(att.to_bytes().unwrap().len(), att_bytes.len() + 8);

    let proof_bytes = proof.to_compact_bytes().unwrap();
    assert_eq!(proof_bytes.len(), proof.compact_size());
    let decoded = IssuanceProof::<E, B>::from_compact_bytes(&proof_bytes, &f).unwrap();
    assert_eq!(decoded, proof);
    assert!(pcs.verify_proof(hvk, &f, &id, &decoded));
    assert_eq!(
        IssuanceProof::<E, B>::from_bytes(&proof.to_bytes().unwrap()).unwrap(),
        proof
    );
    // ... and the attestations, and the responses of each of the k + 1 proofs
    assert_eq!(
        proof.to_bytes().unwrap().len(),
        proof_bytes.len() + 8 * (threshold + 1) + 8
    );
    // the number of attestations is NEVER read from the wire: for f_{k-1} and f_{k+1} the same
    // bytes are not a proof
    assert_eq!(
        IssuanceProof::<E, B>::from_compact_bytes(
            &proof_bytes,
            &Predicate::new(k + 1, b"m".to_vec())
        )
        .err()
        .map(|e| matches!(e, Error::Serialization(_))),
        Some(true)
    );
    if k > 1 {
        assert!(
            IssuanceProof::<E, B>::from_compact_bytes(
                &proof_bytes,
                &Predicate::new(k - 1, b"m".to_vec())
            )
            .is_err()
        );
    }
    // T_0 is mandatory: with its bytes stripped, what remains is not a proof ("fail closed when
    // T_0 is absent", §5.5; attack A5 of the reference implementations)
    let t0_at = proof_bytes.len() - proof.proof.compact_size() - proof.t0.compressed_size();
    let mut stripped = proof_bytes[..t0_at].to_vec();
    stripped.extend_from_slice(&proof_bytes[t0_at + proof.t0.compressed_size()..]);
    assert!(IssuanceProof::<E, B>::from_compact_bytes(&stripped, &f).is_err());
    assert_eq!(
        Credential::<E, B>::from_bytes(&subject.cred.to_bytes().unwrap()).unwrap(),
        subject.cred
    );

    // CHAINING: the fresh credential (under f_k) and k − 1 root credentials, the one of the
    // (k + 1)-th root user among them, endorse a third user, whose proof is accepted; its
    // credential is as good as any.
    let (id_3, usk_3) = pcs.user_keygen(rng).unwrap();
    let endorsers = core::iter::once(&subject).chain(&roots[2..]);
    let attestations_3 = dep.attestations(endorsers, &id_3, rng);
    assert_eq!(attestations_3.len(), threshold);
    assert_eq!(attestations_3[0].phi, pcs.enc_pred(&f).unwrap());
    let f_3 = Predicate::new(k, b"second community".to_vec());
    let (third, _) = dep.join(&f_3, id_3, usk_3, &attestations_3, rng);
    let (id_4, _) = pcs.user_keygen(rng).unwrap();
    let att = dep.attest(&third, &id_4, rng);
    assert!(pcs.verify_attestation(hvk, &id_4, &att));

    // sizes
    let (request, _) = pcs
        .root_request(hvk, &dep.f_root, &subject.id, &subject.usk, rng)
        .unwrap();
    let request_bytes = request.to_compact_bytes().unwrap();
    assert_eq!(
        RootRequest::<E, B>::from_compact_bytes(&request_bytes).unwrap(),
        request
    );
    let (proof_again, _) = pcs
        .prove(hvk, &f, &subject.id, &subject.usk, &attestations, rng)
        .unwrap();
    let pre = pcs
        .issue(hvk, &dep.hsk, &f, &subject.id, &proof_again, rng)
        .unwrap();
    Sizes {
        attestation: att_bytes.len(),
        proof: proof_bytes.len(),
        root_request: request_bytes.len(),
        credential: subject.cred.to_bytes().unwrap().len(),
        base_credential: subject.cred.cred.to_bytes().unwrap().len(),
        pre_credential: pre.to_bytes().unwrap().len(),
    }
}

/// `|π| = k·|att| + |C| + |T_0| + |π_0|` over BLS12-381 (`G_1`: 48 B, `Z_p`: 32 B).
fn expected_sizes(
    att: usize,
    c: usize,
    pi_0_scalars: usize,
    cred: (usize, usize),
    k: u32,
) -> Sizes {
    Sizes {
        attestation: att,
        proof: k as usize * att + c + 48 + pi_0_scalars * 32,
        root_request: c + 48 + pi_0_scalars * 32,
        credential: cred.0,
        base_credential: cred.1,
        pre_credential: cred.1,
    }
}

/// `Σ-PS`: `att = (T, σ'_1, σ'_2; φ, c, z)`, `π_0 = (c, z_usk, z_ρ)`, `cred = (σ_1, σ_2)`.
fn ps_sizes(k: u32) -> Sizes {
    expected_sizes(3 * 48 + 3 * 32, 48, 3, (96, 96), k)
}

/// `Σ-BBS`: `att = (T, Ā, B̄, D; φ, c, z_usk, z_e, z_ρ, z_{r_1}, z_{r_3})`, `π_0 = (c, z_usk, z_ρ)`,
/// `cred_Σ = (A, e)` and `cred = (cred_Σ, m_aux = ρ)`.
fn bbs_sizes(k: u32) -> Sizes {
    expected_sizes(4 * 48 + 7 * 32, 48, 3, (48 + 32 + 32, 48 + 32), k)
}

/// `Σ-EQ`: `att = (T, M'_1, M'_2, M'_3, Z', Y', Ỹ'; φ, c, z)`, no `C`, `π_0 = (c, z_usk)`,
/// `cred = (Z, Y, Ỹ)`.
fn eq_sizes(k: u32) -> Sizes {
    expected_sizes(6 * 48 + 96 + 3 * 32, 0, 2, (192, 192), k)
}

#[test]
fn ps_with_tag_ddh_is_correct() {
    for (seed, k) in [(0xa11c_0001, 1), (0xa11c_0002, 2), (0xa11c_0005, 5)] {
        assert_eq!(
            correctness_flow::<E, PS, DDH>(b"pcs/ps+ddh", seed, k),
            ps_sizes(k)
        );
    }
}

#[test]
fn ps_with_tag_dy_is_correct() {
    for (seed, k) in [(0xa12c_0001, 1), (0xa12c_0002, 2), (0xa12c_0005, 5)] {
        assert_eq!(
            correctness_flow::<E, PS, DY>(b"pcs/ps+dy", seed, k),
            ps_sizes(k)
        );
    }
}

#[test]
fn bbs_with_tag_ddh_is_correct() {
    for (seed, k) in [(0xa13c_0001, 1), (0xa13c_0002, 2), (0xa13c_0005, 5)] {
        assert_eq!(
            correctness_flow::<E, BBS, DDH>(b"pcs/bbs+ddh", seed, k),
            bbs_sizes(k)
        );
    }
}

#[test]
fn bbs_with_tag_dy_is_correct() {
    for (seed, k) in [(0xa14c_0001, 1), (0xa14c_0002, 2), (0xa14c_0005, 5)] {
        assert_eq!(
            correctness_flow::<E, BBS, DY>(b"pcs/bbs+dy", seed, k),
            bbs_sizes(k)
        );
    }
}

#[test]
fn eq_with_tag_ddh_is_correct() {
    for (seed, k) in [(0xa15c_0001, 1), (0xa15c_0002, 2), (0xa15c_0005, 5)] {
        assert_eq!(
            correctness_flow::<E, SPSEQ, DDH>(b"pcs/eq+ddh", seed, k),
            eq_sizes(k)
        );
    }
}

/// The sizes of the paper's comparison table (§5.3): `|att|` and `|π|` at `k = 5`, in the
/// fixed-format compact encoding. For `Σ-PS` in general `|π| = (3k+2) G_1 + (3k+3) Z_p`.
///
/// `|cred|`: the table lists 96 / 80 / 336 B. `Σ-PS` agrees. For `Σ-BBS` the table counts
/// `cred_Σ = (A, e)`; the PCS credential of the box is `(cred_Σ, m_aux)` with `m_aux = ρ`, 32 B
/// more. For `Σ-EQ` the box's `cred = (Z, Y, Ỹ)` has 192 B; 336 B is `|cred*|`.
#[test]
fn sizes_are_those_of_the_comparison_table() {
    assert_eq!((ps_sizes(5).attestation, ps_sizes(5).proof), (240, 1392));
    assert_eq!((bbs_sizes(5).attestation, bbs_sizes(5).proof), (416, 2272));
    assert_eq!((eq_sizes(5).attestation, eq_sizes(5).proof), (480, 2512));
    for k in [1u32, 2, 5, 17] {
        let k_usize = k as usize;
        assert_eq!(
            ps_sizes(k).proof,
            (3 * k_usize + 2) * 48 + (3 * k_usize + 3) * 32
        );
    }
    assert_eq!(
        (
            ps_sizes(5).credential,
            bbs_sizes(5).base_credential,
            bbs_sizes(5).credential
        ),
        (96, 80, 112)
    );
    assert_eq!(eq_sizes(5).credential, 192);
    // π_0 with T_0 and C: 144 B for Σ-PS and Σ-BBS, 112 B for Σ-EQ (T_0 and π_0 only)
    assert_eq!(
        (
            ps_sizes(5).root_request,
            bbs_sizes(5).root_request,
            eq_sizes(5).root_request
        ),
        (192, 192, 112)
    );
}

/// The code is generic over the pairing: a full round trip, with chaining, over BN254 (the
/// INSECURE test oracle behind `H_2` and behind the generators of `Σ-BBS`).
#[test]
fn round_trips_over_a_second_pairing_engine() {
    type Bn254G1 = <Bn254 as Pairing>::G1;
    type BnDDH = kiprf::DDH<Bn254G1, InsecureExponentHasher>;
    // BN254: G_1 has 32 B, G_2 has 64 B, Z_p has 32 B
    let ps = correctness_flow::<Bn254, cred::PS<Bn254>, BnDDH>(b"pcs/bn254/ps+ddh", 0xb254_0001, 2);
    assert_eq!(
        (ps.attestation, ps.proof),
        (6 * 32, 2 * 6 * 32 + 2 * 32 + 3 * 32)
    );
    let eq = correctness_flow::<Bn254, EQ<Bn254>, BnDDH>(b"pcs/bn254/eq+ddh", 0xb254_0002, 2);
    assert_eq!(eq.attestation, 6 * 32 + 64 + 3 * 32);
    let bbs = correctness_flow::<Bn254, cred::BBS<Bn254, InsecureExponentHasher>, kiprf::DY<Bn254G1>>(
        b"pcs/bn254/bbs+dy",
        0xb254_0003,
        1,
    );
    assert_eq!(bbs.attestation, 4 * 32 + 7 * 32);
}

// ---------------------------------------------------------------------------------------------
// Negatives
// ---------------------------------------------------------------------------------------------

/// The basic negatives, for one pair of a base and a tag, at threshold `k = 2`.
fn negative_flow<E, B, T>(label: &[u8], seed: u64)
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let rng = &mut rng;
    let dep = Deployment::<E, B, T>::new(label, AcceptAll, rng);
    let (pcs, hvk, hsk) = (&dep.pcs, &dep.hvk, &dep.hsk);
    let roots: Vec<Member<E, B>> = (0..3).map(|_| dep.root_member(rng)).collect();
    let f = Predicate::new(2, b"members".to_vec());
    let (id, usk) = pcs.user_keygen(rng).unwrap();
    let atts = dep.attestations(&roots, &id, rng);

    // ----- control: the cheating prover's proof IS accepted when nothing is wrong ------------
    let honest_shape = dep.cheat(&f, &id, &usk, &atts[..2], rng);
    assert_eq!(pcs.check_proof(hvk, &f, &id, &honest_shape), Ok(()));
    assert!(pcs.issue(hvk, hsk, &f, &id, &honest_shape, rng).is_ok());

    // ----- wrong number of attestations: k − 1, k + 1, 0 -------------------------------------
    for wrong in [&atts[..1], &atts[..3], &atts[..0]] {
        let count = Error::WrongAttestationCount {
            expected: 2,
            actual: wrong.len(),
        };
        assert_eq!(
            pcs.prove(hvk, &f, &id, &usk, wrong, rng).err(),
            Some(count.clone())
        );
        // everything else about this proof verifies: π_0 is bound to f_2 and to this list
        let proof = dep.cheat(&f, &id, &usk, wrong, rng);
        dep.assert_rejected(&f, &id, &proof, count, rng);
    }
    // an honest proof for f_1 / f_3 (same label) is not a proof for f_2, and vice versa
    let f_1 = Predicate::new(1, b"members".to_vec());
    let f_3 = Predicate::new(3, b"members".to_vec());
    let (proof_1, _) = pcs.prove(hvk, &f_1, &id, &usk, &atts[..1], rng).unwrap();
    let (proof_2, state_2) = pcs.prove(hvk, &f, &id, &usk, &atts[..2], rng).unwrap();
    let (proof_3, _) = pcs.prove(hvk, &f_3, &id, &usk, &atts, rng).unwrap();
    for (g, proof, actual) in [(&f, &proof_1, 1), (&f, &proof_3, 3), (&f_1, &proof_2, 2)] {
        let count = Error::WrongAttestationCount {
            expected: g.threshold as usize,
            actual,
        };
        dep.assert_rejected(g, &id, proof, count, rng);
    }

    // ----- proof for f rejected for f' (another label, same threshold) -----------------------
    let f_other = Predicate::new(2, b"another community".to_vec());
    dep.assert_rejected(&f_other, &id, &proof_2, Error::InvalidProof, rng);
    assert_eq!(pcs.check_proof(hvk, &f, &id, &proof_2), Ok(()));

    // ----- duplicate attester ----------------------------------------------------------------
    // a second attestation of roots[0] for the same id: another cred*, the SAME tag
    let again = dep.attest(&roots[0], &id, rng);
    assert_eq!(again.tag, atts[0].tag);
    assert_ne!(again.shown, atts[0].shown);
    for duplicate in [
        vec![atts[0].clone(), again.clone()],
        vec![atts[0].clone(), atts[0].clone()],
    ] {
        assert_eq!(
            pcs.prove(hvk, &f, &id, &usk, &duplicate, rng).err(),
            Some(Error::DuplicateAttester)
        );
        let proof = dep.cheat(&f, &id, &usk, &duplicate, rng);
        dep.assert_rejected(&f, &id, &proof, Error::DuplicateAttester, rng);
    }

    // ----- self-attestation: T_0 ∈ {T_j} -----------------------------------------------------
    // roots[0] wants a second credential and endorses itself
    let (id_0, usk_0) = (&roots[0].id, &roots[0].usk);
    let own = dep.attest(&roots[0], id_0, rng);
    assert!(pcs.verify_attestation(hvk, id_0, &own));
    let other = dep.attest(&roots[1], id_0, rng);
    for list in [
        vec![own.clone(), other.clone()],
        vec![other.clone(), own.clone()],
    ] {
        assert_eq!(
            pcs.prove(hvk, &f, id_0, usk_0, &list, rng).err(),
            Some(Error::SelfAttestation)
        );
        let proof = dep.cheat(&f, id_0, usk_0, &list, rng);
        assert_eq!(proof.t0, own.tag);
        dep.assert_rejected(&f, id_0, &proof, Error::SelfAttestation, rng);
    }
    // control: with two OTHER endorsers the same user is served
    let others = dep.attestations(&roots[1..], id_0, rng);
    let (proof, _) = pcs.prove(hvk, &f, id_0, usk_0, &others, rng).unwrap();
    assert!(pcs.verify_proof(hvk, &f, id_0, &proof));

    // ----- an attestation made for id' is rejected for id -------------------------------------
    let (id_prime, _) = pcs.user_keygen(rng).unwrap();
    let for_prime = dep.attest(&roots[2], &id_prime, rng);
    assert!(pcs.verify_attestation(hvk, &id_prime, &for_prime));
    assert!(!pcs.verify_attestation(hvk, &id, &for_prime));
    assert_eq!(
        pcs.check_attestation(hvk, &id, &for_prime),
        Err(Error::InvalidProof)
    );
    let grafted = vec![atts[0].clone(), for_prime];
    assert_eq!(
        pcs.prove(hvk, &f, &id, &usk, &grafted, rng).err(),
        Some(Error::InvalidAttestation)
    );
    let proof = dep.cheat(&f, &id, &usk, &grafted, rng);
    dep.assert_rejected(&f, &id, &proof, Error::InvalidAttestation, rng);
    // ... and a whole proof for id is not a proof for id'
    dep.assert_rejected(&f, &id_prime, &proof_2, Error::InvalidAttestation, rng);
    // ... nor can another user redeem it: π_0 is bound to the key behind id
    let (_, usk_thief) = pcs.user_keygen(rng).unwrap();
    assert_eq!(
        pcs.prove(hvk, &f, &id, &usk_thief, &atts[..2], rng).err(),
        Some(Error::IdentifierMismatch)
    );
    // (not a courtesy of the honest prover: R_issue has no witness under another key, because
    // the clause of `id` shares its variable with the clauses of C and T_0)
    assert_eq!(
        dep.try_cheat(&f, &id, &usk_thief, &atts[..2], rng).err(),
        Some(Error::WitnessDoesNotSatisfyRelation)
    );

    // ----- π_0 over a context of the prover's choosing (attack A6) ----------------------------
    // The verifier REBUILDS ctx_0; a π_0 that is a perfectly good proof for R_issue under any
    // other context is worth nothing.
    {
        let mut bogus = proof_2.clone();
        let c = B::encoding_from_wire(pcs.base_parameters(), &bogus.encoding, &id).unwrap();
        let s = pcs.tag_point(&id).unwrap();
        let phi = pcs.enc_pred(&f).unwrap();
        let relation = pcs
            .issuance_relation(hvk, &c, &phi, &id, &bogus.t0, &s)
            .unwrap();
        bogus.proof =
            fiat_shamir::prove(&relation, &state_2.witness(), b"a context of my own", rng).unwrap();
        assert!(fiat_shamir::verify(
            &relation,
            b"a context of my own",
            &bogus.proof
        ));
        dep.assert_rejected(&f, &id, &bogus, Error::InvalidProof, rng);
    }

    // ----- tampering with the public parts of a valid proof ----------------------------------
    let g = E::G1::generator();
    // a tag that is moved after the fact: π_j is bound to T_j (hazard F1 / W1)
    let mut bad = proof_2.clone();
    bad.attestations[0].tag += g;
    dep.assert_rejected(&f, &id, &bad, Error::InvalidAttestation, rng);
    assert_eq!(
        pcs.check_attestation(hvk, &id, &bad.attestations[0]),
        Err(Error::InvalidProof)
    );
    let mut bad = proof_2.clone();
    bad.t0 += g;
    dep.assert_rejected(&f, &id, &bad, Error::InvalidProof, rng);
    let mut bad = proof_2.clone();
    bad.t0 = E::G1::zero();
    dep.assert_rejected(&f, &id, &bad, Error::InvalidTag, rng);
    let mut bad = proof_2.clone();
    bad.proof.responses[0] += E::ScalarField::from(1u64);
    dep.assert_rejected(&f, &id, &bad, Error::InvalidProof, rng);
    let mut bad = proof_2.clone();
    bad.proof.responses.push(E::ScalarField::from(1u64));
    dep.assert_rejected(&f, &id, &bad, Error::InvalidProof, rng);
    let mut bad = proof_2.clone();
    bad.attestations.swap(0, 1);
    dep.assert_rejected(&f, &id, &bad, Error::InvalidProof, rng);
    let mut bad = proof_2.clone();
    bad.attestations[1].phi += E::ScalarField::from(1u64);
    dep.assert_rejected(&f, &id, &bad, Error::InvalidAttestation, rng);
    let mut bad = proof_2.clone();
    bad.attestations[1].tag = E::G1::zero();
    dep.assert_rejected(&f, &id, &bad, Error::InvalidAttestation, rng);
    // the identity is not an identifier
    dep.assert_rejected(&f, &E::G1::zero(), &proof_2, Error::InvalidTag, rng);
    assert_eq!(
        pcs.check_attestation(hvk, &E::G1::zero(), &atts[0]),
        Err(Error::InvalidTag)
    );
    assert_eq!(
        pcs.attest(
            hvk,
            &roots[0].usk,
            &roots[0].f,
            &roots[0].cred,
            &E::G1::zero(),
            rng
        )
        .err(),
        Some(Error::InvalidTag)
    );

    // ----- wrong hvk ---------------------------------------------------------------------------
    let (hvk_2, hsk_2) = pcs.helper_keygen(rng);
    assert_ne!(&hvk_2, hvk);
    assert!(!pcs.verify_attestation(&hvk_2, &id, &atts[0]));
    assert!(!pcs.verify_proof(&hvk_2, &f, &id, &proof_2));
    assert!(!pcs.verify_cred(&hvk_2, &roots[0].usk, &roots[0].f, &roots[0].cred));
    // the other helper does not issue on it, and the two copies of hvk have to agree
    assert_eq!(
        pcs.issue(&hvk_2, &hsk_2, &f, &id, &proof_2, rng).err(),
        Some(Error::InvalidProof)
    );
    for (vk, sk) in [(&hvk_2, hsk), (hvk, &hsk_2)] {
        assert_eq!(
            pcs.issue(vk, sk, &f, &id, &proof_2, rng).err(),
            Some(Error::InvalidKey)
        );
    }

    // ----- threshold 0 -------------------------------------------------------------------------
    let f_0 = Predicate::new(0, b"members".to_vec());
    assert_eq!(
        pcs.prove(hvk, &f_0, &id, &usk, &[], rng).err(),
        Some(Error::ZeroThreshold)
    );
    assert_eq!(
        pcs.prove(hvk, &dep.f_root, &id, &usk, &[], rng).err(),
        Some(Error::ZeroThreshold)
    );
    // everything else about this proof verifies: no attestations, π_0 bound to f_0
    let free = dep.cheat(&f_0, &id, &usk, &[], rng);
    dep.assert_rejected(&f_0, &id, &free, Error::ZeroThreshold, rng);
    assert!(
        IssuanceProof::<E, B>::from_compact_bytes(&free.to_compact_bytes().unwrap(), &f_0).is_err()
    );

    // ----- the root path and the ordinary path do not mix -----------------------------------
    let (request, root_state) = pcs.root_request(hvk, &dep.f_root, &id, &usk, rng).unwrap();
    let as_proof = IssuanceProof {
        attestations: Vec::new(),
        encoding: request.encoding.clone(),
        t0: request.t0,
        proof: request.proof.clone(),
    };
    dep.assert_rejected(&dep.f_root, &id, &as_proof, Error::ZeroThreshold, rng);
    let count = Error::WrongAttestationCount {
        expected: 2,
        actual: 0,
    };
    dep.assert_rejected(&f, &id, &as_proof, count, rng);
    // a threshold proof is not a root request (not even one made for f_0: the contexts differ)
    for proof in [&proof_2, &free] {
        let as_request = RootRequest {
            encoding: proof.encoding.clone(),
            t0: proof.t0,
            proof: proof.proof.clone(),
        };
        for f_root in [&dep.f_root, &f_0] {
            assert_eq!(
                pcs.check_root_request(hvk, f_root, &id, &as_request),
                Err(Error::InvalidProof)
            );
            assert!(!pcs.verify_root_request(hvk, f_root, &id, &as_request));
            assert_eq!(
                pcs.issue_root(hvk, hsk, f_root, &id, &as_request, rng)
                    .err(),
                Some(Error::InvalidProof)
            );
        }
    }
    // the root path takes root predicates only, and a request is bound to (f_root, id, hvk)
    assert_eq!(
        pcs.root_request(hvk, &f, &id, &usk, rng).err(),
        Some(Error::NotARootPredicate)
    );
    assert_eq!(
        pcs.check_root_request(hvk, &f, &id, &request),
        Err(Error::NotARootPredicate)
    );
    assert_eq!(
        pcs.issue_root(hvk, hsk, &f, &id, &request, rng).err(),
        Some(Error::NotARootPredicate)
    );
    let other_root = Predicate::root(b"another root".to_vec());
    assert!(!pcs.verify_root_request(hvk, &other_root, &id, &request));
    assert!(!pcs.verify_root_request(hvk, &dep.f_root, &id_prime, &request));
    assert!(!pcs.verify_root_request(&hvk_2, &dep.f_root, &id, &request));
    assert_eq!(
        pcs.issue_root(&hvk_2, hsk, &dep.f_root, &id, &request, rng)
            .err(),
        Some(Error::InvalidKey)
    );
    assert_eq!(
        pcs.root_request(hvk, &dep.f_root, &id, &usk_thief, rng)
            .err(),
        Some(Error::IdentifierMismatch)
    );

    // ----- Unblind -----------------------------------------------------------------------------
    let pre = pcs.issue(hvk, hsk, &f, &id, &proof_2, rng).unwrap();
    // st_iss does not belong to (usk, f): another key, another predicate (step 2)
    assert_eq!(
        pcs.unblind(hvk, &usk_thief, &f, &pre, &state_2).err(),
        Some(Error::IssuanceStateMismatch)
    );
    for g in [&f_other, &f_1, &dep.f_root] {
        assert_eq!(
            pcs.unblind(hvk, &usk, g, &pre, &state_2).err(),
            Some(Error::IssuanceStateMismatch)
        );
    }
    // fail closed: a pre-credential that was issued for someone else, under another predicate,
    // or by another helper does not unblind to a credential
    let (id_b, usk_b) = pcs.user_keygen(rng).unwrap();
    let atts_b = dep.attestations(&roots[..2], &id_b, rng);
    let (proof_b, _) = pcs.prove(hvk, &f, &id_b, &usk_b, &atts_b, rng).unwrap();
    let pre_b = pcs.issue(hvk, hsk, &f, &id_b, &proof_b, rng).unwrap();
    let pre_root = pcs
        .issue_root(hvk, hsk, &dep.f_root, &id, &request, rng)
        .unwrap();
    // (the attestations do not verify under hvk_2, so the other helper's pre-credential comes
    // from its root path)
    let (request_2, _) = pcs
        .root_request(&hvk_2, &dep.f_root, &id, &usk, rng)
        .unwrap();
    let pre_other_helper = pcs
        .issue_root(&hvk_2, &hsk_2, &dep.f_root, &id, &request_2, rng)
        .unwrap();
    for wrong in [&pre_b, &pre_root] {
        assert_eq!(
            pcs.unblind(hvk, &usk, &f, wrong, &state_2).err(),
            Some(Error::InvalidPreCredential)
        );
    }
    assert_eq!(
        pcs.unblind(hvk, &usk, &dep.f_root, &pre_other_helper, &root_state)
            .err(),
        Some(Error::InvalidPreCredential)
    );
    // control: the right pre-credentials unblind, for the ordinary and for the root path
    let cred = pcs.unblind(hvk, &usk, &f, &pre, &state_2).unwrap();
    let root_cred = pcs
        .unblind(hvk, &usk, &dep.f_root, &pre_root, &root_state)
        .unwrap();

    // ----- VerifyCred ----------------------------------------------------------------------------
    assert!(pcs.verify_cred(hvk, &usk, &f, &cred));
    assert!(pcs.verify_cred(hvk, &usk, &dep.f_root, &root_cred));
    assert!(!pcs.verify_cred(hvk, &usk_thief, &f, &cred));
    assert!(!pcs.verify_cred(hvk, &usk_b, &f, &cred));
    for g in [&f_other, &f_1, &f_3, &f_0, &dep.f_root] {
        assert!(!pcs.verify_cred(hvk, &usk, g, &cred), "{g:?}");
    }
    assert!(!pcs.verify_cred(hvk, &usk, &f, &root_cred));
    // ... and a credential cannot be attested with under another key or another predicate:
    // `ReRand` refuses (Σ-EQ verifies first), or the prover refuses (Σ-PS: R_att has no
    // witness), or the attestation is rejected (the weak base Σ-BBS re-randomizes under the
    // CLAIMED message, and the public pairing check of `VerifyPossess` then fails).
    let (id_c, _) = pcs.user_keygen(rng).unwrap();
    for (key, g) in [(&usk_thief, &f), (&usk, &f_other)] {
        match pcs.attest(hvk, key, g, &cred, &id_c, rng) {
            Ok(att) => assert_eq!(
                pcs.check_attestation(hvk, &id_c, &att),
                Err(Error::InvalidCredential)
            ),
            Err(error) => assert!(
                matches!(
                    error,
                    Error::WitnessDoesNotSatisfyRelation | Error::InvalidCredential
                ),
                "{error:?}"
            ),
        }
    }
    // control
    let att = pcs.attest(hvk, &usk, &f, &cred, &id_c, rng).unwrap();
    assert!(pcs.verify_attestation(hvk, &id_c, &att));
}

#[test]
fn negatives_for_ps_with_tag_ddh() {
    negative_flow::<E, PS, DDH>(b"pcs/neg/ps+ddh", 0xbad0_0001);
}

#[test]
fn negatives_for_ps_with_tag_dy() {
    negative_flow::<E, PS, DY>(b"pcs/neg/ps+dy", 0xbad0_0002);
}

#[test]
fn negatives_for_bbs_with_tag_ddh() {
    negative_flow::<E, BBS, DDH>(b"pcs/neg/bbs+ddh", 0xbad0_0003);
}

#[test]
fn negatives_for_bbs_with_tag_dy() {
    negative_flow::<E, BBS, DY>(b"pcs/neg/bbs+dy", 0xbad0_0004);
}

#[test]
fn negatives_for_eq_with_tag_ddh() {
    negative_flow::<E, SPSEQ, DDH>(b"pcs/neg/eq+ddh", 0xbad0_0005);
}

/// Fail-closed `Unblind` on GARBAGE pre-credentials (random group elements and scalars), per
/// base: the base's own `Unblind` accepts them (they are not malformed on their face), the
/// construction's does not.
#[test]
fn unblind_rejects_garbage_pre_credentials() {
    fn check<B, T>(label: &[u8], seed: u64, garbage: impl Fn(&mut StdRng) -> B::PreCredential)
    where
        B: SigmaFriendlyCredentialBase<E>,
        T: PCSTag<G1>,
    {
        let mut rng = StdRng::seed_from_u64(seed);
        let rng = &mut rng;
        let dep = Deployment::<E, B, T>::new(label, AcceptAll, rng);
        let (pcs, hvk) = (&dep.pcs, &dep.hvk);
        let (id, usk) = pcs.user_keygen(rng).unwrap();
        let (request, state) = pcs.root_request(hvk, &dep.f_root, &id, &usk, rng).unwrap();
        for _ in 0..3 {
            assert_eq!(
                pcs.unblind(hvk, &usk, &dep.f_root, &garbage(rng), &state)
                    .err(),
                Some(Error::InvalidPreCredential)
            );
        }
        // control
        let pre = pcs
            .issue_root(hvk, &dep.hsk, &dep.f_root, &id, &request, rng)
            .unwrap();
        assert!(pcs.unblind(hvk, &usk, &dep.f_root, &pre, &state).is_ok());
    }
    check::<PS, DDH>(b"pcs/garbage/ps", 0x6a2b_0001, |rng| PSPreCredential {
        sigma_1: G1::rand(rng),
        sigma_2: G1::rand(rng),
    });
    check::<BBS, DY>(b"pcs/garbage/bbs", 0x6a2b_0002, |rng| BBSPreCredential {
        a: G1::rand(rng),
        e: Fr::rand(rng),
    });
    check::<SPSEQ, DDH>(b"pcs/garbage/eq", 0x6a2b_0003, |rng| EQPreCredential {
        z: G1::rand(rng),
        y: G1::rand(rng),
        y_tilde: <E as Pairing>::G2::rand(rng),
    });
}

/// `Σ-EQ` issues from `id = g_1^usk`, which `Tag_DY` does not provide: `Setup` refuses the pair
/// (proof sketch of the Lemma on `Σ-EQ`: compatible "with `Tag_DDH` under `H_2(c_0) = g_1`, not
/// with `Tag_DY`").
#[test]
fn setup_refuses_eq_with_tag_dy() {
    let refused = PCS::<E, SPSEQ, DY>::setup(SetupParams::new(b"pcs/eq+dy".to_vec()));
    assert_eq!(refused.err(), Some(Error::IncompatibleBaseAndTag));
    let bn = PCS::<Bn254, EQ<Bn254>, kiprf::DY<<Bn254 as Pairing>::G1>>::setup(SetupParams::new(
        b"pcs/eq+dy".to_vec(),
    ));
    assert_eq!(bn.err(), Some(Error::IncompatibleBaseAndTag));
    // control
    assert!(PCS::<E, SPSEQ, DDH>::setup(SetupParams::new(b"pcs/eq+dy".to_vec())).is_ok());
    assert!(PCS::<E, PS, DY>::setup(SetupParams::new(b"pcs/eq+dy".to_vec())).is_ok());
}

/// `Tag_DY`: "`Attest` returns `⊥` on a later undefined evaluation" (§5.1). The attester whose
/// key is `usk_j = −H_0(id)` is constructed deterministically; it is an ordinary member for
/// every other identifier.
#[test]
fn tag_dy_attester_at_its_undefined_point() {
    fn check<B: SigmaFriendlyCredentialBase<E>>(label: &[u8], seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let rng = &mut rng;
        let dep = Deployment::<E, B, DY>::new(label, AcceptAll, rng);
        let (pcs, hvk) = (&dep.pcs, &dep.hvk);
        let (id, _usk) = pcs.user_keygen(rng).unwrap();

        // usk_j := −H_0(id); its own identifier and self-exclusion tag are defined
        let s = pcs.tag_point(&id).unwrap();
        let usk_j = UserSecretKey::<E>::from_scalar(-s);
        assert_eq!(pcs.tag().eval(usk_j.expose_scalar(), &s), None);
        let id_j = pcs.identity(&usk_j).unwrap();
        let unlucky = dep.admit(id_j, usk_j, rng);

        assert_eq!(
            pcs.attest(hvk, &unlucky.usk, &unlucky.f, &unlucky.cred, &id, rng)
                .err(),
            Some(Error::UndefinedTag)
        );
        // for any other identifier it attests like everybody else
        let (id_2, _) = pcs.user_keygen(rng).unwrap();
        let att = dep.attest(&unlucky, &id_2, rng);
        assert!(pcs.verify_attestation(hvk, &id_2, &att));
    }
    check::<PS>(b"pcs/dy/ps", 0xd1d1_0001);
    check::<BBS>(b"pcs/dy/bbs", 0xd1d1_0002);

    // Prove: T_0 = ⊥ cannot happen for a key of UKeyGen, and a key for which it would is refused
    let mut rng = StdRng::seed_from_u64(0xd1d1_0003);
    let pcs = PCS::<E, PS, DY>::setup(SetupParams::new(b"pcs/dy/keys".to_vec())).unwrap();
    let minus_c0 = UserSecretKey::<E>::from_scalar(-*pcs.identity_point());
    assert_eq!(pcs.identity(&minus_c0), Err(Error::UndefinedTag));
    for _ in 0..8 {
        let (id, usk) = pcs.user_keygen(&mut rng).unwrap();
        assert_eq!(pcs.identity(&usk), Ok(id));
        assert_eq!(
            id * (*usk.expose_scalar() + pcs.identity_point()),
            G1::generator()
        );
    }
}

/// The public attribute policy `P` of `CheckAtts_P` (Def. "Threshold authorization relation"):
/// "whether credentials carrying the root tag `φ_root` count toward a threshold" is its call.
#[test]
fn the_attribute_policy_is_enforced() {
    let label = b"pcs/policy";
    let mut rng = StdRng::seed_from_u64(0x9011_c401);
    let rng = &mut rng;
    let f = Predicate::new(2, b"members".to_vec());
    let f_root = Predicate::root(b"founding members".to_vec());

    // the open deployment: P ≡ 1
    let open = Deployment::<E, PS, DDH>::new(label, AcceptAll, rng);
    let roots: Vec<_> = (0..3).map(|_| open.root_member(rng)).collect();
    let (id, usk) = open.pcs.user_keygen(rng).unwrap();
    let root_atts = open.attestations(&roots[..2], &id, rng);
    let (member_a, by_roots) = open.join(&f, id, usk, &root_atts, rng);
    let (id_b, usk_b) = open.pcs.user_keygen(rng).unwrap();
    let root_atts_b = open.attestations(&roots[1..], &id_b, rng);
    let (member_b, _) = open.join(&f, id_b, usk_b, &root_atts_b, rng);

    // the same deployment (same pp, same helper key) with a verifier that only counts members
    let members_only = AllowList::<Fr>::from_predicates(label, [&f]).unwrap();
    assert!(!members_only.accepts(&[open.pcs.enc_pred(&f_root).unwrap()]));
    let strict = PCS::<E, PS, DDH, _>::from_public_parameters(
        open.pcs.public_parameters().clone(),
        members_only,
    )
    .unwrap();
    assert_eq!(strict.parameters_digest(), open.pcs.parameters_digest());
    let hvk = &open.hvk;

    // a proof backed by root credentials: fine for P ≡ 1, rejected by the strict verifier, whose
    // helper does not issue on it
    let id_a = member_a.id;
    assert_eq!(open.pcs.check_proof(hvk, &f, &id_a, &by_roots), Ok(()));
    assert_eq!(
        strict.check_proof(hvk, &f, &id_a, &by_roots),
        Err(Error::PolicyRejected)
    );
    assert!(!strict.verify_proof(hvk, &f, &id_a, &by_roots));
    assert_eq!(
        strict
            .issue(hvk, &open.hsk, &f, &id_a, &by_roots, rng)
            .err(),
        Some(Error::InvalidProof)
    );
    // the strict prover refuses as well; ONE root credential among the endorsers is enough
    let (id_c, usk_c) = open.pcs.user_keygen(rng).unwrap();
    let mixed = open.attestations([&member_a, &roots[0]], &id_c, rng);
    assert_eq!(
        strict.prove(hvk, &f, &id_c, &usk_c, &mixed, rng).err(),
        Some(Error::PolicyRejected)
    );
    // endorsed by two members, the same user passes the strict policy
    let by_members = open.attestations([&member_a, &member_b], &id_c, rng);
    let (proof, state) = strict
        .prove(hvk, &f, &id_c, &usk_c, &by_members, rng)
        .unwrap();
    assert!(strict.verify_proof(hvk, &f, &id_c, &proof));
    let pre = strict
        .issue(hvk, &open.hsk, &f, &id_c, &proof, rng)
        .unwrap();
    assert!(strict.unblind(hvk, &usk_c, &f, &pre, &state).is_ok());

    // a closure is a policy: "at most one root credential"
    let phi_root = open.pcs.enc_pred(&f_root).unwrap();
    let at_most_one_root =
        move |phis: &[Fr]| phis.iter().filter(|phi| **phi == phi_root).count() <= 1;
    let lenient = PCS::<E, PS, DDH, _>::from_public_parameters(
        open.pcs.public_parameters().clone(),
        at_most_one_root,
    )
    .unwrap();
    assert_eq!(
        lenient.check_proof(hvk, &f, &id_a, &by_roots),
        Err(Error::PolicyRejected)
    );
    let (proof, _) = lenient.prove(hvk, &f, &id_c, &usk_c, &mixed, rng).unwrap();
    assert!(lenient.verify_proof(hvk, &f, &id_c, &proof));
    assert!(!strict.verify_proof(hvk, &f, &id_c, &proof));
}

/// A proof, attestation or credential MADE FOR one deployment does not verify in another, even
/// under the same helper key: every context and every tag point `s = H_0(id)` is bound to the
/// deployment label. `Σ-PS` with `Tag_DY` is the pair whose ALGEBRAIC parameters are the same
/// everywhere, so nothing but the label separates the two.
///
/// This is NOT key-level isolation: see `an_object_rebuilt_for_another_deployment_is_accepted`
/// below for what one helper key across two labels does allow, and why a helper uses one key per
/// label and an `AllowList` (`docs/operating-a-helper.md`).
#[test]
fn objects_made_for_one_deployment_do_not_verify_in_another() {
    let mut rng = StdRng::seed_from_u64(0xc205_5001);
    let rng = &mut rng;
    let here = Deployment::<E, PS, DY>::new(b"pcs/deployment/here", AcceptAll, rng);
    let there = Deployment::<E, PS, DY>::new(b"pcs/deployment/there", AcceptAll, rng);
    assert_eq!(here.pcs.base_parameters(), there.pcs.base_parameters());
    assert_eq!(here.pcs.tag(), there.pcs.tag());
    assert_ne!(here.pcs.parameters_digest(), there.pcs.parameters_digest());

    let root = here.root_member(rng);
    let (id, usk) = here.pcs.user_keygen(rng).unwrap();
    let atts = here.attestations([&root], &id, rng);
    let f = Predicate::new(1, b"members".to_vec());
    let (_, proof) = here.join(&f, id, usk, &atts, rng);
    // objects made for `here`, verified under `there` with the SAME helper key: all rejected,
    // because their context (and, for the attestation, the tag point s = H_0(id)) is here's
    assert!(!there.pcs.verify_attestation(&here.hvk, &id, &atts[0]));
    assert!(!there.pcs.verify_proof(&here.hvk, &f, &id, &proof));
    assert!(
        !there
            .pcs
            .verify_cred(&here.hvk, &root.usk, &root.f, &root.cred)
    );
}

/// Documented behaviour (review finding F2b): a credential the helper issued under `hvk` is a
/// `Σ-PS` signature on `(usk, φ)` and nothing else — `pp_Σ` is empty. So a member of one
/// deployment can REBUILD a valid attestation for the OTHER deployment (a fresh tag at the
/// other's `s`, the credential re-randomized, `R_att` proved under the other's context) using the
/// same helper key. Under the default policy `P ≡ 1` the other deployment's verifier accepts it,
/// because `φ` is just a scalar it does not recognize but does not reject. An `AllowList` over the
/// other deployment's own predicates rejects it. This is why a helper uses one key per label AND
/// a non-default policy (`docs/operating-a-helper.md`; the key binding of `Issue` stops the
/// issuance side, this is the attestation side).
#[test]
fn an_object_rebuilt_for_another_deployment_is_accepted_under_accept_all_only() {
    let mut rng = StdRng::seed_from_u64(0xc205_5002);
    let rng = &mut rng;
    // ONE helper key, generated for `here`, reused as the verification key of `there`
    let here = Deployment::<E, PS, DY>::new(b"pcs/xdep/here", AcceptAll, rng);
    let there = Deployment::<E, PS, DY>::new(b"pcs/xdep/there", AcceptAll, rng);
    let hvk = &here.hvk;

    // a member of `here`
    let member = here.root_member(rng);
    let phi_here = here.pcs.enc_pred(&member.f).unwrap();

    // the newcomer of `there`, and a REBUILT attestation for it under the key of `here`
    let (id, _usk) = there.pcs.user_keygen(rng).unwrap();
    let s = there.pcs.tag_point(&id).unwrap();
    let tag = there
        .pcs
        .tag()
        .eval(member.usk.expose_scalar(), &s)
        .unwrap();
    let pp = there.pcs.base_parameters();
    let m = PS::encode_message(pp, member.usk.expose_scalar(), &phi_here).unwrap();
    let (shown, omega) = PS::rerand(pp, hvk, &m, &member.cred.cred, rng).unwrap();
    let relation = there
        .pcs
        .attestation_relation(hvk, &shown, &phi_here, &tag, &s)
        .unwrap();
    let witness = PCS::<E, PS, DY>::attestation_witness(member.usk.expose_scalar(), &omega);
    let ctx = there
        .pcs
        .attestation_context(hvk, &id, &phi_here, &tag, &shown)
        .unwrap();
    let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng).unwrap();
    let att = Attestation::<E, PS> {
        tag,
        shown,
        phi: phi_here,
        proof,
    };

    // under P ≡ 1 the verifier of `there` accepts the rebuilt attestation ...
    assert_eq!(there.pcs.check_attestation(hvk, &id, &att), Ok(()));
    // ... and under an AllowList over there's OWN predicates it does not
    let f_there = Predicate::new(1, b"members of there".to_vec());
    let strict = PCS::<E, PS, DY, _>::from_public_parameters(
        there.pcs.public_parameters().clone(),
        there.pcs.allow_list([&f_there]).unwrap(),
    )
    .unwrap();
    // (the attestation still verifies as an attestation; the policy is enforced by CheckAtts_P,
    // i.e. in a proof) so we check it through a proof of `there`
    let (id_sub, usk_sub) = there.pcs.user_keygen(rng).unwrap();
    let att_sub = {
        // a genuine `there` attestation, to complete an otherwise-valid k = 1 proof shape
        let s = there.pcs.tag_point(&id_sub).unwrap();
        let tag = there
            .pcs
            .tag()
            .eval(member.usk.expose_scalar(), &s)
            .unwrap();
        let (shown, omega) = PS::rerand(pp, hvk, &m, &member.cred.cred, rng).unwrap();
        let relation = there
            .pcs
            .attestation_relation(hvk, &shown, &phi_here, &tag, &s)
            .unwrap();
        let witness = PCS::<E, PS, DY>::attestation_witness(member.usk.expose_scalar(), &omega);
        let ctx = there
            .pcs
            .attestation_context(hvk, &id_sub, &phi_here, &tag, &shown)
            .unwrap();
        let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng).unwrap();
        Attestation::<E, PS> {
            tag,
            shown,
            phi: phi_here,
            proof,
        }
    };
    // A cheating prover of `there` builds π_0 over exactly this one foreign-φ attestation. The
    // proof is policy-independent (π_0 is over the statement, not over P); the same bytes are
    // checked against both verifiers, so the only difference is the policy of CheckAtts_P.
    let open = &there.pcs;
    let f = Predicate::new(1, b"members of there".to_vec());
    let phi = open.enc_pred(&f).unwrap();
    let s = open.tag_point(&id_sub).unwrap();
    let t0 = open.tag().eval(usk_sub.expose_scalar(), &s).unwrap();
    let rho = Fr::rand(rng);
    let c = PS::issuance_encoding(pp, hvk, usk_sub.expose_scalar(), &phi, &rho).unwrap();
    let relation = open
        .issuance_relation(hvk, &c, &phi, &id_sub, &t0, &s)
        .unwrap();
    let ctx = open
        .issuance_context(hvk, &f, &id_sub, &c, &t0, std::slice::from_ref(&att_sub))
        .unwrap();
    let witness = PCS::<E, PS, DY>::issuance_witness(usk_sub.expose_scalar(), &rho);
    let proof = fiat_shamir::prove(&relation, &witness, &ctx, rng).unwrap();
    let cheat = IssuanceProof::<E, PS> {
        attestations: vec![att_sub],
        encoding: c,
        t0,
        proof,
    };
    // accepted under P ≡ 1, rejected under the AllowList of `there`
    assert_eq!(open.check_proof(hvk, &f, &id_sub, &cheat), Ok(()));
    assert_eq!(
        strict.check_proof(hvk, &f, &id_sub, &cheat),
        Err(Error::PolicyRejected)
    );
}

/// The issuance state is the witness of `R_issue`, and a fresh state is made per proof.
#[test]
fn issuance_states_are_per_proof() {
    let mut rng = StdRng::seed_from_u64(0x57a7_e001);
    let rng = &mut rng;
    let dep = Deployment::<E, BBS, DDH>::new(b"pcs/state", AcceptAll, rng);
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);
    let root = dep.root_member(rng);
    let (id, usk) = pcs.user_keygen(rng).unwrap();
    let atts = dep.attestations([&root], &id, rng);
    let f = Predicate::new(1, b"members".to_vec());
    let (proof_1, state_1): (_, IssuanceState<E, BBS>) =
        pcs.prove(hvk, &f, &id, &usk, &atts, rng).unwrap();
    let (proof_2, state_2) = pcs.prove(hvk, &f, &id, &usk, &atts, rng).unwrap();
    assert_ne!(proof_1.encoding, proof_2.encoding);
    assert_eq!(proof_1.t0, proof_2.t0);
    assert_eq!(state_1.witness()[0], *usk.expose_scalar());
    assert_eq!(format!("{state_1:?}"), "IssuanceState(<redacted>)");

    // the pre-credential of one proof does not unblind with the state of the other
    let pre_1 = pcs.issue(hvk, &dep.hsk, &f, &id, &proof_1, rng).unwrap();
    assert_eq!(
        pcs.unblind(hvk, &usk, &f, &pre_1, &state_2)
            .err()
            .map(|e| matches!(e, Error::InvalidPreCredential | Error::InvalidMessage)),
        Some(true)
    );
    assert!(pcs.unblind(hvk, &usk, &f, &pre_1, &state_1).is_ok());
}
