//! Fixtures shared by the unit tests of [`crate::pcs`]. All runs are seeded.

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use rand::{SeedableRng, rngs::StdRng};

use super::{
    Attestation, Credential, HelperSecretKey, IssuanceProof, PCS, Predicate,
    PredicateCredentialSystem, RootRequest, SetupParams, UserSecretKey,
};
use crate::{
    cred::{
        self, EQ, SigmaFriendlyCredentialBase,
        bbs::BBSShownCredential,
        eq::{EQCredential, EQMessage, EQShownCredential},
        ps::PSShownCredential,
    },
    hash::bls12_381::G1Hasher,
    kiprf::{self, PCSTag},
    sigma::FSProof,
};

pub(crate) type E = Bls12_381;
pub(crate) type G1 = G1Projective;
pub(crate) type G2 = G2Projective;
pub(crate) type PS = cred::PS<E>;
pub(crate) type BBS = cred::BBS<E, G1Hasher>;
pub(crate) type SPSEQ = EQ<E>;
pub(crate) type DDH = kiprf::DDH<G1, G1Hasher>;
pub(crate) type DY = kiprf::DY<G1>;

/// A deployment with a helper.
pub(crate) struct Fixture<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>> {
    pub(crate) pcs: PCS<E, B, T>,
    pub(crate) hvk: B::VerificationKey,
    pub(crate) hsk: HelperSecretKey<B>,
    pub(crate) f_root: Predicate,
    pub(crate) rng: StdRng,
}

/// A user with a root credential.
pub(crate) struct Holder<B: SigmaFriendlyCredentialBase<E>> {
    pub(crate) id: G1,
    pub(crate) usk: UserSecretKey<E>,
    pub(crate) cred: Credential<E, B>,
}

impl<B: SigmaFriendlyCredentialBase<E>, T: PCSTag<G1>> Fixture<B, T> {
    pub(crate) fn new(label: &[u8], seed: u64) -> Self {
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

    /// Root issuance for a fresh user.
    pub(crate) fn holder(&mut self) -> Holder<B> {
        let (pcs, hvk, f_root, rng) = (&self.pcs, &self.hvk, &self.f_root, &mut self.rng);
        let (id, usk) = pcs.user_keygen(rng).unwrap();
        let (request, state) = pcs.root_request(hvk, f_root, &id, &usk, rng).unwrap();
        let pre = pcs
            .issue_root(hvk, &self.hsk, f_root, &id, &request, rng)
            .unwrap();
        let cred = pcs.unblind(hvk, &usk, f_root, &pre, &state).unwrap();
        Holder { id, usk, cred }
    }

    /// `k` attestations for `id` by `k` fresh root members.
    pub(crate) fn attestations(&mut self, k: usize, id: &G1) -> Vec<Attestation<E, B>> {
        (0..k)
            .map(|_| {
                let holder = self.holder();
                self.pcs
                    .attest(
                        &self.hvk,
                        &holder.usk,
                        &self.f_root,
                        &holder.cred,
                        id,
                        &mut self.rng,
                    )
                    .unwrap()
            })
            .collect()
    }
}

/// A proof `(c, z)` of random scalars with `responses` responses: it does not verify, it has the
/// right FORMAT.
pub(crate) fn random_fs_proof(responses: usize, rng: &mut StdRng) -> FSProof<Fr> {
    FSProof {
        challenge: Fr::rand(rng),
        responses: (0..responses).map(|_| Fr::rand(rng)).collect(),
    }
}

/// A shown credential of random group elements, per base (format only).
pub(crate) trait RandomShown: SigmaFriendlyCredentialBase<E> {
    fn random_shown(rng: &mut StdRng) -> Self::ShownCredential;
    fn random_wire(rng: &mut StdRng) -> Self::WireEncoding;
}

impl RandomShown for PS {
    fn random_shown(rng: &mut StdRng) -> Self::ShownCredential {
        PSShownCredential {
            sigma_1: G1::rand(rng),
            sigma_2: G1::rand(rng),
        }
    }

    fn random_wire(rng: &mut StdRng) -> Self::WireEncoding {
        G1::rand(rng)
    }
}

impl RandomShown for BBS {
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
}

impl RandomShown for SPSEQ {
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
                y_tilde: <E as Pairing>::G2::rand(rng),
            },
        }
    }

    fn random_wire(_rng: &mut StdRng) -> Self::WireEncoding {}
}

/// An attestation of random elements in the right FORMAT.
pub(crate) fn random_attestation<B: RandomShown>(rng: &mut StdRng) -> Attestation<E, B> {
    Attestation {
        tag: G1::rand(rng),
        shown: B::random_shown(rng),
        phi: Fr::rand(rng),
        proof: random_fs_proof(Attestation::<E, B>::RESPONSES, rng),
    }
}

/// An issuance proof of random elements in the right FORMAT, with `k` attestations.
pub(crate) fn random_proof<B: RandomShown>(k: usize, rng: &mut StdRng) -> IssuanceProof<E, B> {
    IssuanceProof {
        attestations: (0..k).map(|_| random_attestation::<B>(rng)).collect(),
        encoding: B::random_wire(rng),
        t0: G1::rand(rng),
        proof: random_fs_proof(IssuanceProof::<E, B>::RESPONSES, rng),
    }
}

/// A root request of random elements in the right FORMAT.
pub(crate) fn random_root_request<B: RandomShown>(rng: &mut StdRng) -> RootRequest<E, B> {
    RootRequest {
        encoding: B::random_wire(rng),
        t0: G1::rand(rng),
        proof: random_fs_proof(RootRequest::<E, B>::RESPONSES, rng),
    }
}
