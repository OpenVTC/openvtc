//! Shared fixtures for the independent soundness / adversarial / serialization suites.
//!
//! This module is compiled into each of `pcs_soundness.rs`, `pcs_adversarial.rs` and
//! `serialization.rs`; every item is used by at least one of them (hence the blanket
//! `allow(dead_code)`, which stops the other binaries from warning about the items they do not
//! use). Everything here drives the crate through its PUBLIC API only.
//!
//! All randomness is seeded (`StdRng::seed_from_u64`, the seed recorded at every call site) and
//! reproducible.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
#![allow(dead_code)]

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ff::{UniformRand, Zero};
use predicate_credential_system::{
    Error,
    cred::{
        self, EQ, SigmaFriendlyCredentialBase,
        bbs::BBSShownCredential,
        eq::{EQCredential, EQMessage, EQShownCredential},
        ps::PSShownCredential,
    },
    hash::bls12_381::G1Hasher,
    kiprf::{self, PCSTag},
    pcs::{
        Attestation, AttributePolicy, Credential, HelperSecretKey, IssuanceProof, IssuanceState,
        PCS, Predicate, PredicateCredentialSystem, RootRequest, SetupParams, UserSecretKey,
    },
    sigma::{FSProof, fiat_shamir},
};
use rand::{SeedableRng, rngs::StdRng};

pub type E = Bls12_381;
pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type PS = cred::PS<E>;
pub type BBS = cred::BBS<E, G1Hasher>;
pub type SPSEQ = EQ<E>;
pub type DDH = kiprf::DDH<G1, G1Hasher>;
pub type DY = kiprf::DY<G1>;

/// Per-base test hooks that the generic harness needs but the trait interface does not expose:
/// random and degenerate shown credentials, the group-element decomposition of a shown
/// credential (for exhaustive mutation), and how an extracted `R_issue` witness splits into
/// `(m_aux, ρ)`.
pub trait BaseTest: SigmaFriendlyCredentialBase<E, PublicMessage = Fr> {
    /// Number of group elements in a shown credential (`Σ-PS`: 2, `Σ-BBS`: 3, `Σ-EQ`: 6).
    const NUM_SHOWN_ELEMENTS: usize;
    /// Number of responses of an attestation proof, `1 + POSSESSION_VARIABLES`.
    const ATT_RESPONSES: usize = 1 + Self::POSSESSION_VARIABLES;
    /// Number of responses of `π_0`, `1 + ISSUANCE_VARIABLES`.
    const ISSUE_RESPONSES: usize = 1 + Self::ISSUANCE_VARIABLES;

    fn random_shown(rng: &mut StdRng) -> Self::ShownCredential;
    fn random_wire(rng: &mut StdRng) -> Self::WireEncoding;
    /// A shown credential with every group element the identity.
    fn zero_shown() -> Self::ShownCredential;
    /// The wire encoding `C` with every group element the identity (`()` for `Σ-EQ`).
    fn zero_wire() -> Self::WireEncoding;
    /// One copy of `shown` per group element, each with exactly that element perturbed (by `dg1`
    /// for a `G_1` element, by `dg2` for the one `G_2` element of `Σ-EQ`). Length is
    /// [`Self::NUM_SHOWN_ELEMENTS`].
    fn shown_variants(
        shown: &Self::ShownCredential,
        dg1: G1,
        dg2: G2,
    ) -> Vec<Self::ShownCredential>;
    /// `C + dg1` for the bases that transmit `C` (`Σ-PS`, `Σ-BBS`); `None` for `Σ-EQ`.
    fn bump_wire(wire: &Self::WireEncoding, dg1: G1) -> Option<Self::WireEncoding>;
    /// `(m_aux, ρ)` from an `R_issue` witness `usk ‖ (opening variables)`.
    fn issuance_aux_rho(witness: &[Fr]) -> (Self::Aux, Self::IssuanceState);
}

impl BaseTest for PS {
    const NUM_SHOWN_ELEMENTS: usize = 2;

    fn random_shown(rng: &mut StdRng) -> Self::ShownCredential {
        PSShownCredential {
            sigma_1: G1::rand(rng),
            sigma_2: G1::rand(rng),
        }
    }
    fn random_wire(rng: &mut StdRng) -> Self::WireEncoding {
        G1::rand(rng)
    }
    fn zero_shown() -> Self::ShownCredential {
        PSShownCredential {
            sigma_1: G1::zero(),
            sigma_2: G1::zero(),
        }
    }
    fn zero_wire() -> Self::WireEncoding {
        G1::zero()
    }
    fn shown_variants(
        shown: &Self::ShownCredential,
        dg1: G1,
        _dg2: G2,
    ) -> Vec<Self::ShownCredential> {
        vec![
            PSShownCredential {
                sigma_1: shown.sigma_1 + dg1,
                sigma_2: shown.sigma_2,
            },
            PSShownCredential {
                sigma_1: shown.sigma_1,
                sigma_2: shown.sigma_2 + dg1,
            },
        ]
    }
    fn bump_wire(wire: &Self::WireEncoding, dg1: G1) -> Option<Self::WireEncoding> {
        Some(*wire + dg1)
    }
    fn issuance_aux_rho(witness: &[Fr]) -> (Self::Aux, Self::IssuanceState) {
        ((), witness[1])
    }
}

impl BaseTest for BBS {
    const NUM_SHOWN_ELEMENTS: usize = 3;

    fn random_shown(rng: &mut StdRng) -> Self::ShownCredential {
        BBSShownCredential {
            a_bar: G1::rand(rng),
            b_bar: G1::rand(rng),
            d: G1::rand(rng),
        }
    }
    fn random_wire(rng: &mut StdRng) -> Self::WireEncoding {
        G1::rand(rng)
    }
    fn zero_shown() -> Self::ShownCredential {
        BBSShownCredential {
            a_bar: G1::zero(),
            b_bar: G1::zero(),
            d: G1::zero(),
        }
    }
    fn zero_wire() -> Self::WireEncoding {
        G1::zero()
    }
    fn shown_variants(
        shown: &Self::ShownCredential,
        dg1: G1,
        _dg2: G2,
    ) -> Vec<Self::ShownCredential> {
        vec![
            BBSShownCredential {
                a_bar: shown.a_bar + dg1,
                b_bar: shown.b_bar,
                d: shown.d,
            },
            BBSShownCredential {
                a_bar: shown.a_bar,
                b_bar: shown.b_bar + dg1,
                d: shown.d,
            },
            BBSShownCredential {
                a_bar: shown.a_bar,
                b_bar: shown.b_bar,
                d: shown.d + dg1,
            },
        ]
    }
    fn bump_wire(wire: &Self::WireEncoding, dg1: G1) -> Option<Self::WireEncoding> {
        Some(*wire + dg1)
    }
    fn issuance_aux_rho(witness: &[Fr]) -> (Self::Aux, Self::IssuanceState) {
        // Σ-BBS: m_aux = ρ = the same certified randomizer, R_issue variable 1.
        (witness[1], witness[1])
    }
}

impl BaseTest for SPSEQ {
    const NUM_SHOWN_ELEMENTS: usize = 6;

    fn random_shown(rng: &mut StdRng) -> Self::ShownCredential {
        EQShownCredential {
            message: EQMessage {
                m1: G1::rand(rng),
                m2: G1::rand(rng),
                m3: G1::rand(rng),
            },
            credential: EQCredential {
                z: G1::rand(rng),
                y: G1::rand(rng),
                y_tilde: G2::rand(rng),
            },
        }
    }
    fn random_wire(_rng: &mut StdRng) -> Self::WireEncoding {}
    fn zero_shown() -> Self::ShownCredential {
        EQShownCredential {
            message: EQMessage {
                m1: G1::zero(),
                m2: G1::zero(),
                m3: G1::zero(),
            },
            credential: EQCredential {
                z: G1::zero(),
                y: G1::zero(),
                y_tilde: G2::zero(),
            },
        }
    }
    fn zero_wire() -> Self::WireEncoding {}
    fn shown_variants(
        shown: &Self::ShownCredential,
        dg1: G1,
        dg2: G2,
    ) -> Vec<Self::ShownCredential> {
        let base = shown.clone();
        let mut out = Vec::new();
        for i in 0..6 {
            let mut m = base.clone();
            match i {
                0 => m.message.m1 += dg1,
                1 => m.message.m2 += dg1,
                2 => m.message.m3 += dg1,
                3 => m.credential.z += dg1,
                4 => m.credential.y += dg1,
                _ => m.credential.y_tilde += dg2,
            }
            out.push(m);
        }
        out
    }
    fn bump_wire(_wire: &Self::WireEncoding, _dg1: G1) -> Option<Self::WireEncoding> {
        None
    }
    fn issuance_aux_rho(_witness: &[Fr]) -> (Self::Aux, Self::IssuanceState) {
        ((), ())
    }
}

/// A user holding a credential under the predicate `f`.
pub struct Member<B: SigmaFriendlyCredentialBase<E>> {
    pub id: G1,
    pub usk: UserSecretKey<E>,
    pub f: Predicate,
    pub cred: Credential<E, B>,
}

/// A deployment (public parameters, a helper key pair, a root predicate) with an owned,
/// seeded RNG. Mirrors the flow used by `tests/pcs_correctness.rs`, through the public API only.
pub struct Deployment<B, T, P = predicate_credential_system::pcs::AcceptAll>
where
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<G1>,
{
    pub pcs: PCS<E, B, T, P>,
    pub hvk: B::VerificationKey,
    pub hsk: HelperSecretKey<B>,
    pub f_root: Predicate,
    pub rng: StdRng,
}

impl<B, T> Deployment<B, T, predicate_credential_system::pcs::AcceptAll>
where
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<G1>,
{
    /// A deployment with the open policy `P ≡ 1`.
    pub fn open(label: &[u8], seed: u64) -> Self {
        Self::with_policy(label, seed, predicate_credential_system::pcs::AcceptAll)
    }
}

impl<B, T, P> Deployment<B, T, P>
where
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<G1>,
    P: AttributePolicy<Fr>,
{
    pub fn with_policy(label: &[u8], seed: u64, policy: P) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let pcs = PCS::setup(SetupParams::with_policy(label.to_vec(), policy)).unwrap();
        let (hvk, hsk) = pcs.helper_keygen(&mut rng);
        Self {
            pcs,
            hvk,
            hsk,
            f_root: Predicate::root(b"root".to_vec()),
            rng,
        }
    }

    /// Root issuance (Remark "Chaining and the base case") for a key pair `(id, usk)`.
    pub fn admit(&mut self, id: G1, usk: UserSecretKey<E>) -> Member<B> {
        let (pcs, hvk, f_root, rng) = (&self.pcs, &self.hvk, &self.f_root, &mut self.rng);
        let (request, state) = pcs.root_request(hvk, f_root, &id, &usk, rng).unwrap();
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

    /// A fresh root member.
    pub fn root_member(&mut self) -> Member<B> {
        let (id, usk) = self.pcs.user_keygen(&mut self.rng).unwrap();
        self.admit(id, usk)
    }

    /// `n` fresh root members.
    pub fn root_members(&mut self, n: usize) -> Vec<Member<B>> {
        (0..n).map(|_| self.root_member()).collect()
    }

    /// An attestation of `member` for `id` (the honest `Attest`).
    pub fn attest(&mut self, member: &Member<B>, id: &G1) -> Attestation<E, B> {
        let (pcs, hvk, rng) = (&self.pcs, &self.hvk, &mut self.rng);
        pcs.attest(hvk, &member.usk, &member.f, &member.cred, id, rng)
            .unwrap()
    }

    /// One attestation per member for `id`, each asserted to verify.
    pub fn attestations(&mut self, members: &[Member<B>], id: &G1) -> Vec<Attestation<E, B>> {
        members
            .iter()
            .map(|m| {
                let att = self.attest(m, id);
                assert!(self.pcs.verify_attestation(&self.hvk, id, &att));
                att
            })
            .collect()
    }

    /// `Prove` for a subject that holds `attestations` for `id`; asserts the proof verifies.
    pub fn prove_ok(
        &mut self,
        f: &Predicate,
        id: &G1,
        usk: &UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
    ) -> (IssuanceProof<E, B>, IssuanceState<E, B>) {
        let (proof, state) = self
            .pcs
            .prove(&self.hvk, f, id, usk, attestations, &mut self.rng)
            .unwrap();
        assert!(self.pcs.verify_proof(&self.hvk, f, id, &proof));
        (proof, state)
    }

    /// A CHEATING prover for `(hvk, f, id)`: it builds `C`, `T_0` and an honest `π_0` for
    /// `R_issue` under `ctx_0` of EXACTLY the given attestation list, but WITHOUT `CheckAtts_P`
    /// and without the count check that `Prove` runs. Whatever rejects the result is therefore a
    /// verifier-side check on the attestations or the statement, not a courtesy of the honest
    /// prover. `usk` must be the key behind `id` (`π_0` still needs one key behind `C`, `id`,
    /// `T_0`); panics otherwise.
    pub fn cheat_proof(
        &mut self,
        f: &Predicate,
        id: &G1,
        usk: &UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
    ) -> IssuanceProof<E, B> {
        self.try_cheat_proof(f, id, usk, attestations)
            .expect("R_issue has a witness under usk")
    }

    /// [`Self::cheat_proof`], `Err` if `R_issue` has no witness under `usk`.
    pub fn try_cheat_proof(
        &mut self,
        f: &Predicate,
        id: &G1,
        usk: &UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
    ) -> Result<IssuanceProof<E, B>, Error> {
        let pcs = &self.pcs;
        let pp = pcs.base_parameters();
        let phi = pcs.enc_pred(f).unwrap();
        let s = pcs.tag_point(id).unwrap();
        let t0 = pcs.tag().eval(usk.expose_scalar(), &s).unwrap();
        let (aux, rho) = B::sample_issuance(pp, &mut self.rng);
        let m_hid = B::hidden_message(usk.expose_scalar(), &aux);
        let c = B::issuance_encoding(pp, &self.hvk, &m_hid, &phi, &rho).unwrap();
        let relation = pcs
            .issuance_relation(&self.hvk, &c, &phi, id, &t0, &s)
            .unwrap();
        let ctx = pcs
            .issuance_context(&self.hvk, f, id, &c, &t0, attestations)
            .unwrap();
        let witness = PCS::<E, B, T, P>::issuance_witness(&m_hid, &rho);
        let proof = fiat_shamir::prove(&relation, &witness, &ctx, &mut self.rng)?;
        Ok(IssuanceProof {
            attestations: attestations.to_vec(),
            encoding: B::encoding_to_wire(&c),
            t0,
            proof,
        })
    }

    /// Full `Prove → VerifyProof → Issue → Unblind → VerifyCred`, returning the new member and
    /// the proof it presented.
    pub fn join(
        &mut self,
        f: &Predicate,
        id: G1,
        usk: UserSecretKey<E>,
        attestations: &[Attestation<E, B>],
    ) -> (Member<B>, IssuanceProof<E, B>) {
        let (proof, state) = self.prove_ok(f, &id, &usk, attestations);
        let (pcs, hvk, rng) = (&self.pcs, &self.hvk, &mut self.rng);
        let pre = pcs.issue(hvk, &self.hsk, f, &id, &proof, rng).unwrap();
        let cred = pcs.unblind(hvk, &usk, f, &pre, &state).unwrap();
        assert!(pcs.verify_cred(hvk, &usk, f, &cred));
        (
            Member {
                id,
                usk,
                f: f.clone(),
                cred,
            },
            proof,
        )
    }
}

/// The pieces of an honest `Attest` show, exposed so that a harness can rebuild `R_att` and run
/// the interactive sigma protocol on it (which `attest` hides inside a Fiat-Shamir proof). This
/// replays steps 3-9 of `Attest` (construction box) with the public trait interface.
pub struct AttShow<B: SigmaFriendlyCredentialBase<E>> {
    pub s: Fr,
    pub phi: Fr,
    pub tag: G1,
    pub shown: B::ShownCredential,
    pub show_state: B::ShowState,
    pub m_hid: B::HiddenMessage,
}

impl<B, T, P> Deployment<B, T, P>
where
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<G1>,
    P: AttributePolicy<Fr>,
{
    /// The show `member` would produce when attesting for `id`, with the show state `ω` and the
    /// hidden message `m_hid` that the honest prover keeps secret (needed to run the extractor).
    pub fn att_show(&mut self, member: &Member<B>, id: &G1) -> AttShow<B> {
        let pcs = &self.pcs;
        let pp = pcs.base_parameters();
        let s = pcs.tag_point(id).unwrap();
        let phi = pcs.enc_pred(&member.f).unwrap();
        let tag = pcs.tag().eval(member.usk.expose_scalar(), &s).unwrap();
        let m_hid = B::hidden_message(member.usk.expose_scalar(), &member.cred.aux);
        let m = B::encode_message(pp, &m_hid, &phi).unwrap();
        let (shown, show_state) =
            B::rerand(pp, &self.hvk, &m, &member.cred.cred, &mut self.rng).unwrap();
        AttShow {
            s,
            phi,
            tag,
            shown,
            show_state,
            m_hid,
        }
    }
}

/// A random attestation in the right FORMAT (it does not verify).
pub fn random_attestation<B: BaseTest>(rng: &mut StdRng) -> Attestation<E, B> {
    Attestation {
        tag: G1::rand(rng),
        shown: B::random_shown(rng),
        phi: Fr::rand(rng),
        proof: random_fs_proof(B::ATT_RESPONSES, rng),
    }
}

/// A random issuance proof in the right FORMAT, with `k` attestations.
pub fn random_proof<B: BaseTest>(k: usize, rng: &mut StdRng) -> IssuanceProof<E, B> {
    IssuanceProof {
        attestations: (0..k).map(|_| random_attestation::<B>(rng)).collect(),
        encoding: B::random_wire(rng),
        t0: G1::rand(rng),
        proof: random_fs_proof(B::ISSUE_RESPONSES, rng),
    }
}

/// A random root request in the right FORMAT.
pub fn random_root_request<B: BaseTest>(rng: &mut StdRng) -> RootRequest<E, B> {
    RootRequest {
        encoding: B::random_wire(rng),
        t0: G1::rand(rng),
        proof: random_fs_proof(B::ISSUE_RESPONSES, rng),
    }
}

fn random_fs_proof(responses: usize, rng: &mut StdRng) -> FSProof<Fr> {
    FSProof {
        challenge: Fr::rand(rng),
        responses: (0..responses).map(|_| Fr::rand(rng)).collect(),
    }
}

/// `Err(reason)` iff `check_proof` returned it, and `Issue` output `⊥` (Def. "Proof-gated
/// issuance"). The gate error of `Issue` is `InvalidProof` for a threshold predicate.
pub fn assert_proof_rejected<B, T, P>(
    dep: &mut Deployment<B, T, P>,
    f: &Predicate,
    id: &G1,
    proof: &IssuanceProof<E, B>,
    reason: &Error,
) where
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<G1>,
    P: AttributePolicy<Fr>,
{
    let (pcs, hvk) = (&dep.pcs, &dep.hvk);
    assert_eq!(
        pcs.check_proof(hvk, f, id, proof).as_ref().err(),
        Some(reason)
    );
    assert!(!pcs.verify_proof(hvk, f, id, proof));
    let gate = pcs.issue(hvk, &dep.hsk, f, id, proof, &mut dep.rng);
    assert_eq!(gate.err(), Some(Error::InvalidProof), "{reason:?}");
}
