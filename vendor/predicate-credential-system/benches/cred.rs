//! Criterion benchmarks and object sizes of the credential-base instantiations (§3.2): `Σ-PS`
//! (§3.2.1), `Σ-BBS` (§3.2.2), `Σ-EQ` (§3.2.3) over BLS12-381, and the designated-verifier
//! `Σ-MAC` (§3.2.4) over `G_1` of BLS12-381 (a prime-order group; the paper's measurements of
//! `Σ-MAC` use ristretto255, so its figures are not comparable with these).
//!
//! ```text
//! cargo bench --bench cred
//! cargo bench --bench cred -- sigma-bbs        # one base (the filter is a regex)
//! ```
//!
//! The run starts with a table of OBJECT SIZES (compressed canonical encoding; the possession
//! proof in its compact `(c, z)` form), then measures every algorithm of Def. "Credential base"
//! and of its sigma-friendly add-on:
//!
//! | id | algorithm |
//! |---|---|
//! | `setup` | the transparent public parameters `pp_Σ` (`Σ-BBS`, `Σ-MAC`: generators hashed to the curve) |
//! | `keygen` | `KeyGen` |
//! | `is_well_formed_key` | the range check of `vk` that every PCS verifier runs once per call |
//! | `sign`, `verify` | `Sign`, `Verify` on `m = Enc_Σ(m_hid, φ)` |
//! | `issuance_encoding` | `C = Com(m_hid, φ; ρ)` |
//! | `blind_issue`, `unblind` | `BlindIssue(sk, C, φ)`, `Unblind(vk, m, ĉred, ρ)` |
//! | `rerand` | `ReRand`: the shown credential `cred*` and its state `ω` |
//! | `verify_possess_public` | the witness-independent checks of `VerifyPossess` |
//! | `possess`, `verify_possess` | the stand-alone Fiat-Shamir proof for `R_Possess` and its verifier (public checks included) |
//!
//! For `Σ-MAC` the prover works without the key and `verify_possess` is the KEYED verifier.
//! Inputs are seeded, so every run benchmarks the same values. Timings depend on the machine,
//! the compiler and the enabled features: record them with `rustc --version` and the commit.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs

use std::hint::black_box;

use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use criterion::Criterion;
use predicate_credential_system::{
    cred::{
        self, DVCredentialBase, SigmaFriendlyCredentialBase, SigmaFriendlyDVCredentialBase,
        possess, verify_possess,
    },
    hash::bls12_381::G1Hasher,
    sigma::FSProof,
};
use rand::{SeedableRng, rngs::StdRng};

type E = Bls12_381;
type G1 = G1Projective;
type PS = cred::PS<E>;
type BBS = cred::BBS<E, G1Hasher>;
type EQ = cred::EQ<E>;
type MAC = cred::MAC<G1, G1Hasher>;

const CTX: &[u8] = b"bench/cred/ctx";

fn domain(name: &str) -> Vec<u8> {
    format!("bench/cred/{name}").into_bytes()
}

fn print_rows(name: &str, rows: &[(&str, usize)]) {
    println!("{name}");
    for (object, bytes) in rows {
        println!("  {object:<42} {bytes:>5} B");
    }
}

// ---------------------------------------------------------------------------------------------
// Publicly verifiable bases: Σ-PS, Σ-BBS, Σ-EQ
// ---------------------------------------------------------------------------------------------

/// Everything one run of the encoded-issuance and show flow produces.
struct Fixture<B: SigmaFriendlyCredentialBase<E>> {
    pp: B::PublicParams,
    vk: B::VerificationKey,
    sk: B::SigningKey,
    phi: Fr,
    aux: B::Aux,
    rho: B::IssuanceState,
    m_hid: B::HiddenMessage,
    m: B::Message,
    cred: B::Credential,
    encoding: B::IssuanceEncoding,
    pre: B::PreCredential,
    shown: B::ShownCredential,
    show_state: B::ShowState,
    proof: FSProof<Fr>,
}

fn fixture<B: SigmaFriendlyCredentialBase<E>>(name: &str, rng: &mut StdRng) -> Fixture<B> {
    let pp = B::setup(&domain(name)).expect("pp_Σ");
    let (vk, sk) = B::keygen(&pp, rng);
    let (usk, phi) = (Fr::rand(rng), Fr::rand(rng));
    // (m_aux, ρ) as `Prove` generates them; m_hid = (usk, m_aux); m = Enc_Σ(m_hid, φ)
    let (aux, rho) = B::sample_issuance(&pp, rng);
    let m_hid = B::hidden_message(&usk, &aux);
    let m = B::encode_message(&pp, &m_hid, &phi).expect("Enc_Σ");
    // encoded issuance: C = Com(m_hid, φ; ρ), BlindIssue, Unblind
    let encoding = B::issuance_encoding(&pp, &vk, &m_hid, &phi, &rho).expect("Com");
    let pre = B::blind_issue(&pp, &sk, &encoding, &phi, rng).expect("BlindIssue");
    let cred = B::unblind(&pp, &vk, &m, &pre, &rho).expect("Unblind");
    assert!(B::verify(&pp, &vk, &m, &cred));
    // show: ReRand and the possession proof
    let (shown, show_state) = B::rerand(&pp, &vk, &m, &cred, rng).expect("ReRand");
    let proof =
        possess::<E, B, _>(&pp, &vk, &shown, &phi, &m_hid, &show_state, CTX, rng).expect("Possess");
    assert!(verify_possess::<E, B>(&pp, &vk, &shown, &phi, CTX, &proof));
    Fixture {
        pp,
        vk,
        sk,
        phi,
        aux,
        rho,
        m_hid,
        m,
        cred,
        encoding,
        pre,
        shown,
        show_state,
        proof,
    }
}

fn print_sizes<B: SigmaFriendlyCredentialBase<E>>(name: &str, seed: u64) {
    let f = fixture::<B>(name, &mut StdRng::seed_from_u64(seed));
    print_rows(
        name,
        &[
            ("public parameters pp_Σ", f.pp.compressed_size()),
            ("verification key vk", f.vk.compressed_size()),
            ("signing key sk", f.sk.compressed_size()),
            ("credential cred_Σ", f.cred.compressed_size()),
            (
                "hidden component m_aux kept with cred_Σ",
                f.aux.compressed_size(),
            ),
            ("issuance encoding C", f.encoding.compressed_size()),
            ("issuance state ρ", f.rho.compressed_size()),
            ("pre-credential ĉred", f.pre.compressed_size()),
            ("shown credential cred*", f.shown.compressed_size()),
            ("possession proof (c, z), compact", f.proof.compact_size()),
        ],
    );
    println!(
        "  {:<42} {:>5}",
        "responses in the possession proof",
        f.proof.responses.len()
    );
}

fn bench_base<B: SigmaFriendlyCredentialBase<E>>(c: &mut Criterion, name: &str, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let f = fixture::<B>(name, &mut rng);
    let label = domain(name);

    let mut group = c.benchmark_group(name);
    group.bench_function("setup", |b| {
        b.iter(|| B::setup(black_box(&label)).expect("pp_Σ"))
    });
    group.bench_function("keygen", |b| b.iter(|| B::keygen(&f.pp, &mut rng)));
    group.bench_function("is_well_formed_key", |b| {
        b.iter(|| assert!(B::is_well_formed_key(&f.pp, black_box(&f.vk))));
    });
    group.bench_function("sign", |b| {
        b.iter(|| B::sign(&f.pp, &f.sk, &f.m, &mut rng).expect("Sign"));
    });
    group.bench_function("verify", |b| {
        b.iter(|| assert!(B::verify(&f.pp, &f.vk, &f.m, black_box(&f.cred))));
    });
    group.bench_function("issuance_encoding", |b| {
        b.iter(|| B::issuance_encoding(&f.pp, &f.vk, &f.m_hid, &f.phi, &f.rho).expect("Com"));
    });
    group.bench_function("blind_issue", |b| {
        b.iter(|| B::blind_issue(&f.pp, &f.sk, &f.encoding, &f.phi, &mut rng).expect("BlindIssue"));
    });
    group.bench_function("unblind", |b| {
        b.iter(|| B::unblind(&f.pp, &f.vk, &f.m, black_box(&f.pre), &f.rho).expect("Unblind"));
    });
    group.bench_function("rerand", |b| {
        b.iter(|| B::rerand(&f.pp, &f.vk, &f.m, &f.cred, &mut rng).expect("ReRand"));
    });
    group.bench_function("verify_possess_public", |b| {
        b.iter(|| {
            assert!(B::verify_possess_public(
                &f.pp,
                &f.vk,
                black_box(&f.shown),
                &f.phi
            ))
        });
    });
    group.bench_function("possess", |b| {
        b.iter(|| {
            possess::<E, B, _>(
                &f.pp,
                &f.vk,
                &f.shown,
                &f.phi,
                &f.m_hid,
                &f.show_state,
                CTX,
                &mut rng,
            )
            .expect("Possess")
        });
    });
    group.bench_function("verify_possess", |b| {
        b.iter(|| {
            assert!(verify_possess::<E, B>(
                &f.pp,
                &f.vk,
                &f.shown,
                &f.phi,
                CTX,
                black_box(&f.proof)
            ));
        });
    });
    group.finish();
}

// ---------------------------------------------------------------------------------------------
// The designated-verifier base Σ-MAC
// ---------------------------------------------------------------------------------------------

struct MacFixture {
    pp: <MAC as DVCredentialBase>::PublicParams,
    dvk: <MAC as DVCredentialBase>::DVKey,
    usk: Fr,
    phi: Fr,
    rho: Fr,
    m: <MAC as DVCredentialBase>::Message,
    cred: <MAC as DVCredentialBase>::Credential,
    encoding: G1,
    pre: <MAC as DVCredentialBase>::PreCredential,
    shown: <MAC as DVCredentialBase>::ShownCredential,
    proof: FSProof<Fr>,
}

fn mac_fixture(name: &str, rng: &mut StdRng) -> MacFixture {
    let pp = MAC::setup(&domain(name)).expect("pp");
    let dvk = MAC::keygen(&pp, rng);
    let (usk, phi) = (Fr::rand(rng), Fr::rand(rng));
    let ((), rho) = MAC::sample_issuance(&pp, rng);
    let m_hid = MAC::hidden_message(&usk, &());
    let m = MAC::encode_message(&pp, &m_hid, &phi).expect("Enc_Σ");
    let encoding = MAC::issuance_encoding(&pp, &m_hid, &phi, &rho).expect("Com");
    let pre = MAC::blind_issue(&pp, &dvk, &encoding, &phi, rng).expect("BlindIssue");
    let cred = MAC::unblind(&pp, &m, &pre, &rho).expect("Unblind");
    assert!(MAC::verify(&pp, &dvk, &m, &cred));
    let (shown, ()) = MAC::rerand(&pp, &m, &cred, rng).expect("ReRand");
    let proof = MAC::possess(&pp, &shown, &phi, &usk, &(), CTX, rng).expect("Possess");
    assert!(MAC::verify_possess(&pp, &dvk, &shown, &phi, CTX, &proof));
    MacFixture {
        pp,
        dvk,
        usk,
        phi,
        rho,
        m,
        cred,
        encoding,
        pre,
        shown,
        proof,
    }
}

fn print_mac_sizes(name: &str, seed: u64) {
    let f = mac_fixture(name, &mut StdRng::seed_from_u64(seed));
    print_rows(
        name,
        &[
            ("public parameters pp", f.pp.compressed_size()),
            (
                "key dvk (secret, signs AND verifies)",
                f.dvk.compressed_size(),
            ),
            ("credential cred", f.cred.compressed_size()),
            ("issuance encoding C", f.encoding.compressed_size()),
            ("issuance state ρ", f.rho.compressed_size()),
            ("pre-credential ĉred", f.pre.compressed_size()),
            ("shown credential cred*", f.shown.compressed_size()),
            ("possession proof (c, z), compact", f.proof.compact_size()),
        ],
    );
    println!(
        "  {:<42} {:>5}",
        "responses in the possession proof",
        f.proof.responses.len()
    );
}

fn bench_mac(c: &mut Criterion, name: &str, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let f = mac_fixture(name, &mut rng);
    let label = domain(name);
    let m_hid = MAC::hidden_message(&f.usk, &());

    let mut group = c.benchmark_group(name);
    group.bench_function("setup", |b| {
        b.iter(|| MAC::setup(black_box(&label)).expect("pp"))
    });
    group.bench_function("keygen", |b| b.iter(|| MAC::keygen(&f.pp, &mut rng)));
    group.bench_function("is_well_formed_key", |b| {
        b.iter(|| assert!(MAC::is_well_formed_key(&f.pp, black_box(&f.dvk))));
    });
    group.bench_function("sign", |b| {
        b.iter(|| MAC::sign(&f.pp, &f.dvk, &f.m, &mut rng).expect("Sign"));
    });
    group.bench_function("verify", |b| {
        b.iter(|| assert!(MAC::verify(&f.pp, &f.dvk, &f.m, black_box(&f.cred))));
    });
    group.bench_function("issuance_encoding", |b| {
        b.iter(|| MAC::issuance_encoding(&f.pp, &m_hid, &f.phi, &f.rho).expect("Com"));
    });
    group.bench_function("blind_issue", |b| {
        b.iter(|| {
            MAC::blind_issue(&f.pp, &f.dvk, &f.encoding, &f.phi, &mut rng).expect("BlindIssue")
        });
    });
    group.bench_function("unblind", |b| {
        b.iter(|| MAC::unblind(&f.pp, &f.m, black_box(&f.pre), &f.rho).expect("Unblind"));
    });
    group.bench_function("rerand", |b| {
        b.iter(|| MAC::rerand(&f.pp, &f.m, &f.cred, &mut rng).expect("ReRand"));
    });
    group.bench_function("verify_possess_public", |b| {
        b.iter(|| {
            assert!(MAC::verify_possess_public(
                &f.pp,
                black_box(&f.shown),
                &f.phi
            ))
        });
    });
    group.bench_function("possess", |b| {
        b.iter(|| {
            MAC::possess(&f.pp, &f.shown, &f.phi, &f.usk, &(), CTX, &mut rng).expect("Possess")
        });
    });
    group.bench_function("verify_possess", |b| {
        b.iter(|| {
            assert!(MAC::verify_possess(
                &f.pp,
                &f.dvk,
                &f.shown,
                &f.phi,
                CTX,
                black_box(&f.proof)
            ));
        });
    });
    group.finish();
}

fn main() {
    println!("object sizes over BLS12-381, compressed canonical encoding");
    print_sizes::<PS>("sigma-ps", 0x5053_0001);
    print_sizes::<BBS>("sigma-bbs", 0x4242_0001);
    print_sizes::<EQ>("sigma-eq", 0x4551_0001);
    print_mac_sizes("sigma-mac", 0x4d41_0001);
    println!();

    let mut criterion = Criterion::default().configure_from_args();
    bench_base::<PS>(&mut criterion, "sigma-ps", 0x5053_0001);
    bench_base::<BBS>(&mut criterion, "sigma-bbs", 0x4242_0001);
    bench_base::<EQ>(&mut criterion, "sigma-eq", 0x4551_0001);
    bench_mac(&mut criterion, "sigma-mac", 0x4d41_0001);
    criterion.final_summary();
}
