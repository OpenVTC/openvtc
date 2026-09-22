//! Criterion benchmarks of the modular threshold construction (§5.1) for every compatible
//! public base/tag pair over BLS12-381, at the threshold `k = 5` of the paper's comparison
//! table (§5.3).
//!
//! ```text
//! cargo bench --bench pcs
//! cargo bench --bench pcs -- ps-ddh          # one pair (the filter is a regex)
//! cargo bench --bench pcs --features parallel
//! ```
//!
//! For every pair the run first prints the OBJECT SIZES (`att`, `π`, the root request in their
//! compact fixed format, everything else in the compressed canonical encoding): `att` and `π`
//! are the figures of the comparison table. The component benchmarks are `--bench cred` and
//! `--bench kiprf`.
//!
//! What each measurement covers (all inputs are prepared outside the timed closure):
//!
//! | id | algorithm | includes |
//! |---|---|---|
//! | `attest` | `Attest` | `ReRand`, the tag, one proof for `R_att` |
//! | `verify_att` | `VerifyAtt` | key check, `ValidTag`, public checks of `VerifyPossess`, `Verify_FS` |
//! | `prove` | `Prove` | `CheckAtts_P` (i.e. `k` times `VerifyAtt`), `Com`, one proof for `R_issue` |
//! | `verify_proof` | `VerifyProof` | `CheckAtts_P`, `Verify_FS` of `π_0` |
//! | `issue` | `Issue` | `VerifyProof` (proof gating) and `BlindIssue` |
//! | `unblind` | `Unblind` | the base's `Unblind` and the fail-closed credential verification |
//! | `verify_cred` | `VerifyCred` | one signature verification |
//!
//! The paper's "prove" column counts the `k` attestations together with the subject's proof;
//! that figure is `k · attest + prove` here. Numbers depend on the machine, the compiler and the
//! enabled features; record them together with `rustc --version` and the commit.
//!
//! The RNG is seeded, so the benchmarked inputs are the same in every run.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs
use std::hint::black_box;

use ark_bls12_381::{Bls12_381, G1Projective};
use ark_serialize::CanonicalSerialize;
use criterion::{BatchSize, Criterion};
use predicate_credential_system::{
    cred::{BBS, EQ, PS, SigmaFriendlyCredentialBase},
    hash::bls12_381::G1Hasher,
    kiprf::{self, PCSTag},
    pcs::{PCS, Predicate, PredicateCredentialSystem, SetupParams},
};
use rand::{SeedableRng, rngs::StdRng};

type E = Bls12_381;
type G1 = G1Projective;
type DDH = kiprf::DDH<G1, G1Hasher>;
type DY = kiprf::DY<G1>;

/// The threshold of the paper's comparison table.
const K: u32 = 5;

fn bench_pair<B, T>(c: &mut Criterion, name: &str, seed: u64)
where
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<G1>,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let label = format!("bench/{name}").into_bytes();
    let pcs = PCS::<E, B, T>::setup(SetupParams::new(label)).expect("compatible pair");
    let (hvk, hsk) = pcs.helper_keygen(&mut rng);
    let f_root = Predicate::root(b"founders".to_vec());
    let f = Predicate::new(K, b"members".to_vec());

    // K founders with root credentials, and the subject.
    let mut root_request_size = 0;
    let founders: Vec<_> = (0..K)
        .map(|_| {
            let (id_j, usk_j) = pcs.user_keygen(&mut rng).expect("user key");
            let (request, state) = pcs
                .root_request(&hvk, &f_root, &id_j, &usk_j, &mut rng)
                .expect("root request");
            root_request_size = request.compact_size();
            let pre = pcs
                .issue_root(&hvk, &hsk, &f_root, &id_j, &request, &mut rng)
                .expect("root issuance");
            let cred_j = pcs
                .unblind(&hvk, &usk_j, &f_root, &pre, &state)
                .expect("unblind");
            (usk_j, cred_j)
        })
        .collect();
    let (id, usk) = pcs.user_keygen(&mut rng).expect("user key");
    let attestations: Vec<_> = founders
        .iter()
        .map(|(usk_j, cred_j)| {
            pcs.attest(&hvk, usk_j, &f_root, cred_j, &id, &mut rng)
                .expect("attestation")
        })
        .collect();
    let (proof, state) = pcs
        .prove(&hvk, &f, &id, &usk, &attestations, &mut rng)
        .expect("issuance proof");
    let pre = pcs
        .issue(&hvk, &hsk, &f, &id, &proof, &mut rng)
        .expect("issuance");
    let cred = pcs.unblind(&hvk, &usk, &f, &pre, &state).expect("unblind");
    assert!(pcs.verify_cred(&hvk, &usk, &f, &cred));

    println!("{name}: object sizes over BLS12-381 at k = {K}");
    for (object, bytes) in [
        (
            "public parameters pp",
            pcs.public_parameters().compressed_size(),
        ),
        ("helper verification key hvk", hvk.compressed_size()),
        ("root request (C, T_0, π_0), compact", root_request_size),
        ("pre-credential ĉred", pre.compressed_size()),
        ("credential cred = (cred_Σ, m_aux)", cred.compressed_size()),
        ("attestation att_j, compact", attestations[0].compact_size()),
        ("issuance proof π, compact", proof.compact_size()),
    ] {
        println!("  {object:<40} {bytes:>5} B");
    }

    let mut group = c.benchmark_group(name);
    group.sample_size(20);

    let (usk_0, cred_0) = &founders[0];
    group.bench_function("attest", |b| {
        b.iter(|| {
            pcs.attest(&hvk, usk_0, &f_root, cred_0, &id, &mut rng)
                .expect("attestation")
        });
    });
    group.bench_function("verify_att", |b| {
        b.iter(|| assert!(pcs.verify_attestation(&hvk, &id, black_box(&attestations[0]))));
    });
    group.bench_function("prove", |b| {
        b.iter(|| {
            pcs.prove(&hvk, &f, &id, &usk, black_box(&attestations), &mut rng)
                .expect("issuance proof")
        });
    });
    group.bench_function("verify_proof", |b| {
        b.iter(|| assert!(pcs.verify_proof(&hvk, &f, &id, black_box(&proof))));
    });
    group.bench_function("issue", |b| {
        b.iter(|| {
            pcs.issue(&hvk, &hsk, &f, &id, black_box(&proof), &mut rng)
                .expect("issuance")
        });
    });
    group.bench_function("unblind", |b| {
        // Unblind consumes nothing, but the state is a secret without `Clone`: every iteration
        // gets its own (proof, state, pre-credential) triple, prepared outside the timing.
        b.iter_batched(
            || {
                let (proof, state) = pcs
                    .prove(&hvk, &f, &id, &usk, &attestations, &mut rng)
                    .expect("issuance proof");
                let pre = pcs
                    .issue(&hvk, &hsk, &f, &id, &proof, &mut rng)
                    .expect("issuance");
                (pre, state)
            },
            |(pre, state)| pcs.unblind(&hvk, &usk, &f, &pre, &state).expect("unblind"),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("verify_cred", |b| {
        b.iter(|| assert!(pcs.verify_cred(&hvk, &usk, &f, black_box(&cred))));
    });
    group.finish();
}

fn benches(c: &mut Criterion) {
    bench_pair::<PS<E>, DDH>(c, "ps-ddh", 0x5053_0001);
    bench_pair::<PS<E>, DY>(c, "ps-dy", 0x5053_0002);
    bench_pair::<BBS<E, G1Hasher>, DDH>(c, "bbs-ddh", 0x4242_0001);
    bench_pair::<BBS<E, G1Hasher>, DY>(c, "bbs-dy", 0x4242_0002);
    bench_pair::<EQ<E>, DDH>(c, "eq-ddh", 0x4551_0001);
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    benches(&mut criterion);
    criterion.final_summary();
}
