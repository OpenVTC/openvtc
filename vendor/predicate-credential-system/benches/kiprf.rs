//! Criterion benchmarks and object sizes of the key-injective PRF instantiations (§3.1):
//! `Tag_DDH` (§3.1.1) and `Tag_DY` (§3.1.2) over `G_1` of BLS12-381.
//!
//! ```text
//! cargo bench --bench kiprf
//! cargo bench --bench kiprf -- tag-dy          # one instantiation (the filter is a regex)
//! ```
//!
//! The run starts with a table of OBJECT SIZES (compressed canonical encoding), then measures:
//!
//! | id | algorithm | includes |
//! |---|---|---|
//! | `keygen` | `TagKeyGen` | one scalar (`Tag_DDH`: non-zero) |
//! | `eval` | `TagEval(K, s)` at an ordinary point | `Tag_DDH`: `H_2(s)` (hash to the curve) and one scalar multiplication; `Tag_DY`: one field inversion and one scalar multiplication |
//! | `eval_identity_point` | `TagEval(K, c_0)`, the identifier `id` of the construction | `Tag_DDH`: `H_2(c_0) = g_1` is programmed, so no hashing |
//! | `valid_tag` | `ValidTag(T, s)` | a non-identity test |
//! | `prove_tag` | stand-alone Fiat-Shamir proof for `R_Tag` | building the clause (`Tag_DDH`: `H_2(s)` again), one commitment, one response |
//! | `verify_tag` | its verifier | `ValidTag`, the clause, recomputing the commitment |
//! | `h2` (`Tag_DDH` only) | `H_2(s)` alone | the hash-to-curve suite of RFC 9380 |
//!
//! Inputs are seeded, so every run benchmarks the same values. Timings depend on the machine,
//! the compiler and the enabled features: record them with `rustc --version` and the commit.

#![allow(clippy::upper_case_acronyms)] // naming policy: see src/lib.rs

use std::hint::black_box;

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use criterion::Criterion;
use predicate_credential_system::{
    hash::{bls12_381::G1Hasher, h0_identity_point},
    kiprf::{self, PCSTag, prove_tag, verify_tag},
};
use rand::{SeedableRng, rngs::StdRng};

type G1 = G1Projective;
type DDH = kiprf::DDH<G1, G1Hasher>;
type DY = kiprf::DY<G1>;

const DOMAIN: &[u8] = b"bench/kiprf";
const CTX: &[u8] = b"bench/kiprf/ctx";

/// One instantiation: its key, an ordinary evaluation point with its tag, and a tag proof.
struct Instance<T> {
    tag: T,
    c0: Fr,
    key: Fr,
    s: Fr,
    t: G1,
}

fn instance<T: PCSTag<G1>>(seed: u64) -> Instance<T> {
    let mut rng = StdRng::seed_from_u64(seed);
    let c0: Fr = h0_identity_point(DOMAIN);
    let tag = T::setup(DOMAIN, c0).expect("tag parameters");
    let key = tag.keygen(&mut rng);
    let s = Fr::rand(&mut rng);
    let t = tag.eval(&key, &s).expect("defined evaluation");
    Instance { tag, c0, key, s, t }
}

fn print_sizes<T: PCSTag<G1>>(name: &str, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xffff);
    let i = instance::<T>(seed);
    let proof = prove_tag(&i.tag, &i.key, &i.t, &i.s, CTX, &mut rng).expect("tag proof");
    assert!(verify_tag(&i.tag, &i.t, &i.s, CTX, &proof));
    println!("{name}");
    for (object, bytes) in [
        ("public parameters pp_Tag", i.tag.compressed_size()),
        ("key K", i.key.compressed_size()),
        ("evaluation point s", i.s.compressed_size()),
        ("tag T", i.t.compressed_size()),
        ("tag proof (c, z), compact", proof.compact_size()),
    ] {
        println!("  {object:<34} {bytes:>5} B");
    }
}

fn bench_tag<T: PCSTag<G1>>(c: &mut Criterion, name: &str, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xffff);
    let i = instance::<T>(seed);
    let proof = prove_tag(&i.tag, &i.key, &i.t, &i.s, CTX, &mut rng).expect("tag proof");

    let mut group = c.benchmark_group(name);
    group.bench_function("keygen", |b| b.iter(|| i.tag.keygen(&mut rng)));
    group.bench_function("eval", |b| {
        b.iter(|| i.tag.eval(black_box(&i.key), black_box(&i.s)));
    });
    group.bench_function("eval_identity_point", |b| {
        b.iter(|| i.tag.eval(black_box(&i.key), black_box(&i.c0)));
    });
    group.bench_function("valid_tag", |b| {
        b.iter(|| i.tag.valid_tag(black_box(&i.t), black_box(&i.s)));
    });
    group.bench_function("prove_tag", |b| {
        b.iter(|| prove_tag(&i.tag, &i.key, &i.t, &i.s, CTX, &mut rng).expect("tag proof"));
    });
    group.bench_function("verify_tag", |b| {
        b.iter(|| assert!(verify_tag(&i.tag, &i.t, &i.s, CTX, black_box(&proof))));
    });
    group.finish();
}

/// `H_2(s)` alone: what `Tag_DDH` pays per evaluation point on top of `Tag_DY`.
fn bench_h2(c: &mut Criterion) {
    let i = instance::<DDH>(0x4444_0001);
    c.bench_function("tag-ddh/h2", |b| b.iter(|| i.tag.htag(black_box(&i.s))));
}

fn main() {
    println!("object sizes over BLS12-381, compressed canonical encoding");
    print_sizes::<DDH>("tag-ddh", 0x4444_0001);
    print_sizes::<DY>("tag-dy", 0x4459_0001);
    println!();

    let mut criterion = Criterion::default().configure_from_args();
    bench_tag::<DDH>(&mut criterion, "tag-ddh", 0x4444_0001);
    bench_h2(&mut criterion);
    bench_tag::<DY>(&mut criterion, "tag-dy", 0x4459_0001);
    criterion.final_summary();
}
