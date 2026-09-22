//! Random oracles and the hashing transcript (paper §2.1, "Notation and algebraic setting").
//!
//! The paper uses random oracles `H_0, H_1 : {0,1}* → Z_p` and a hash-to-group oracle
//! `H_2 = htag : Z_p → G_1 \ {1}`: `H_0` derives public tag points and instantiates the predicate
//! encoding, `H_1` supplies Fiat-Shamir challenges, `htag` is the base of `Tag_DDH`.
//!
//! Everything below the oracle *names* is an implementation choice of this crate, not something
//! the paper specifies:
//!
//! * **Framing.** A [`Transcript`] absorbs a sequence of `(label, data)` items, each encoded as
//!   `len(label) ‖ label ‖ len(data) ‖ data` with 8-byte little-endian lengths. The encoding of
//!   a sequence is uniquely decodable, hence injective: `("ab", "c")` and `("a", "bc")` hash
//!   differently.
//! * **Domain separation.** Every oracle has the domain-separation tag
//!   [`DOMAIN_PREFIX`]` ‖ suffix` (`PCS-V1/H0`, `PCS-V1/H1`, `PCS-V1/H2`,
//!   `PCS-V1/BBS-GENERATORS`, ...), which is never empty. For `H_0`, `H_2` and the generator
//!   derivations, the *deployment label* stored in the public parameters is bound as a framed
//!   item of the oracle input (not by concatenating it to the tag), so that no
//!   `(suffix, label)` pair can collide with another one.
//! * **`H_1` is deployment-bound only through `ctx`.** [`h1_transcript`] absorbs the tag
//!   `PCS-V1/H1` and the caller's context, nothing else: the paper's `c = H_1(ctx, A)` has no
//!   further input, and its `ctx_j`, `ctx_0` begin with `pp`. Binding a proof to a deployment is
//!   therefore the job of whoever builds `ctx`, which must contain (a digest of) the public
//!   parameters. The stand-alone proofs of this crate do so
//!   ([`crate::kiprf::prove_tag`] absorbs `pp_Tag`, [`crate::cred::possess`] absorbs
//!   `pp_Σ` and `vk`); a statement whose bases are the same in every deployment (`id = g_1^usk`)
//!   would otherwise replay across deployments.
//! * **`H_0` is typed.** Its three uses `c_0 = H_0("identity")`, `EncPred(f) =
//!   H_0("predicate" ‖ ⟨f⟩)` and `s = H_0(id)` are separate functions whose inputs carry a type
//!   item, so the three uses cannot collide.
//! * **Hash to field.** Scalars are derived with arkworks' `DefaultFieldHasher<Sha256, 128>`:
//!   `expand_message_xmd` to `L = ⌈(⌈log p⌉ + 128)/8⌉` bytes, read as an integer and reduced mod
//!   `p`. If the `L` bytes are uniform the result is within statistical distance
//!   `p / 2^(8L+2) < 2^-128` of uniform (a uniform integer below `N` reduced mod `p` is at
//!   distance at most `p/4N`; this is the design rationale of RFC 9380 §5). Known caveat:
//!   arkworks pads the expander with `L` instead of 64 zero bytes when hashing to the scalar
//!   field, so the output is **not** RFC 9380 `hash_to_field` and does not interoperate with RFC
//!   hashers. It is used here only as a random oracle into `Z_p`.

pub mod bls12_381;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

use core::fmt::Debug;

use ark_ec::PrimeGroup;
use ark_ff::{
    BigInteger, PrimeField,
    field_hashers::{DefaultFieldHasher, HashToField},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

use crate::{error::Error, serialization};

/// Crate-wide prefix of every domain-separation tag.
pub const DOMAIN_PREFIX: &[u8] = b"PCS-V1";
/// Oracle suffix of `H_0` (tag points and predicate encoding).
pub const H0_SUFFIX: &[u8] = b"/H0";
/// Oracle suffix of `H_1` (Fiat-Shamir challenges).
pub const H1_SUFFIX: &[u8] = b"/H1";
/// Oracle suffix of `H_2 = htag` (hash to group).
pub const H2_SUFFIX: &[u8] = b"/H2";

/// Security parameter of the hash-to-field expansion, in bits.
const SEC_PARAM: usize = 128;

/// The domain-separation tag `PCS-V1 ‖ suffix` of an oracle. Never empty.
#[must_use]
pub fn domain_separation_tag(oracle_suffix: &[u8]) -> Vec<u8> {
    [DOMAIN_PREFIX, oracle_suffix].concat()
}

/// `len(label) ‖ label ‖ len(data) ‖ data`, lengths as 8-byte little-endian integers.
fn frame(sink: &mut impl FnMut(&[u8]), label: &[u8], data: &[u8]) {
    // `usize` is at most 64 bits wide on every supported target, so the casts are lossless.
    sink(&(label.len() as u64).to_le_bytes());
    sink(label);
    sink(&(data.len() as u64).to_le_bytes());
    sink(data);
}

/// SHA-256-backed absorber with injective framing; the common core of `H_0`, `H_1` and of the
/// Fiat-Shamir contexts `ctx_j`, `ctx_0` of the construction box.
///
/// Cloning a transcript forks it: both copies continue from the same absorbed prefix.
#[derive(Clone, Debug)]
pub struct Transcript {
    dst: Vec<u8>,
    hasher: Sha256,
}

impl Transcript {
    /// A fresh transcript of the oracle `PCS-V1 ‖ oracle_suffix`. The tag is absorbed as the
    /// first item, so transcripts of different oracles never produce the same digest.
    #[must_use]
    pub fn new(oracle_suffix: &[u8]) -> Self {
        let dst = domain_separation_tag(oracle_suffix);
        let mut transcript = Self {
            dst: dst.clone(),
            hasher: Sha256::new(),
        };
        transcript.append_bytes(b"dst", &dst);
        transcript
    }

    /// Absorbs the item `(label, data)`.
    pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
        let hasher = &mut self.hasher;
        frame(&mut |bytes| hasher.update(bytes), label, data);
    }

    /// Absorbs the item `(label, value)` with `value` as an 8-byte little-endian integer.
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append_bytes(label, &value.to_le_bytes());
    }

    /// Absorbs the item `(label, value)` with `value` in its **compressed** canonical encoding
    /// (the same bytes as [`serialization::to_bytes`]), which covers `G_1`, `G_2`, `G_T` and `Z_p`
    /// elements, and every public protocol object, uniformly.
    ///
    /// # Errors
    /// [`Error::Serialization`] if the serializer of `value` fails; nothing is absorbed then.
    pub fn append_serializable<T: CanonicalSerialize + ?Sized>(
        &mut self,
        label: &[u8],
        value: &T,
    ) -> Result<(), Error> {
        let bytes = serialization::to_bytes(value)?;
        self.append_bytes(label, &bytes);
        Ok(())
    }

    /// SHA-256 digest of everything absorbed so far. The transcript can be extended afterwards.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }

    /// The oracle output in `F`: `hash_to_field(DST, digest)` with the transcript's
    /// domain-separation tag (see the module docs for the exact hash-to-field variant).
    #[must_use]
    pub fn challenge_scalar<F: PrimeField>(&self) -> F {
        let hasher = <DefaultFieldHasher<Sha256, SEC_PARAM> as HashToField<F>>::new(&self.dst);
        let [scalar] = hasher.hash_to_field::<1>(&self.digest());
        scalar
    }
}

// ---------------------------------------------------------------------------------------------
// H_0 and H_1
// ---------------------------------------------------------------------------------------------

fn h0_transcript(domain: &[u8], input_type: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(H0_SUFFIX);
    transcript.append_bytes(b"deployment", domain);
    transcript.append_bytes(b"input-type", input_type);
    transcript
}

/// `c_0 := H_0("identity")`, the fixed public point at which the identifier
/// `id = Tag(usk, c_0)` is evaluated (construction box, `Setup` step 3).
#[must_use]
pub fn h0_identity_point<F: PrimeField>(domain: &[u8]) -> F {
    h0_transcript(domain, b"identity").challenge_scalar()
}

/// `EncPred(f) := H_0("predicate" ‖ ⟨f⟩)` for the canonical serialization
/// `encoded_predicate = ⟨f⟩` (§5.1, "Scheme description"). Public and not hiding.
#[must_use]
pub fn h0_predicate<F: PrimeField>(domain: &[u8], encoded_predicate: &[u8]) -> F {
    let mut transcript = h0_transcript(domain, b"predicate");
    transcript.append_bytes(b"predicate", encoded_predicate);
    transcript.challenge_scalar()
}

/// `s := H_0(id)`, the tag point of the identifier `id` (construction box, `Attest` step 4,
/// `Prove` step 4). `id` is absorbed in its compressed canonical encoding.
///
/// # Errors
/// [`Error::Serialization`] if `id` cannot be serialized.
pub fn h0_id<F: PrimeField, I: CanonicalSerialize + ?Sized>(
    domain: &[u8],
    id: &I,
) -> Result<F, Error> {
    let mut transcript = h0_transcript(domain, b"id");
    transcript.append_serializable(b"id", id)?;
    Ok(transcript.challenge_scalar())
}

/// The `H_1` transcript of a Fiat-Shamir challenge `c = H_1(ctx, statement, A)` with `ctx`
/// already absorbed. Used only by [`crate::sigma::fiat_shamir`], which appends the statement and
/// the commitment.
///
/// Unlike `H_0` and `H_2` this oracle takes no deployment label: `ctx` is its only
/// deployment-specific input and has to carry the public parameters (module docs).
#[must_use]
pub fn h1_transcript(ctx: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(H1_SUFFIX);
    transcript.append_bytes(b"ctx", ctx);
    transcript
}

// ---------------------------------------------------------------------------------------------
// H_2: hash to group
// ---------------------------------------------------------------------------------------------

/// The canonical fixed-length little-endian encoding of a scalar (identical to its compressed
/// canonical serialization, but infallible).
#[must_use]
pub fn scalar_bytes<F: PrimeField>(scalar: &F) -> Vec<u8> {
    scalar.into_bigint().to_bytes_le()
}

/// The injectively framed input `(deployment, counter, msg)` of a hash-to-group oracle.
/// `counter` is `0` except in the negligible case that an output had to be re-hashed.
#[must_use]
pub fn oracle_input(domain: &[u8], counter: u64, msg: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + msg.len() + 64);
    let mut sink = |bytes: &[u8]| input.extend_from_slice(bytes);
    frame(&mut sink, b"deployment", domain);
    frame(&mut sink, b"counter", &counter.to_le_bytes());
    frame(&mut sink, b"msg", msg);
    input
}

/// A random oracle into a prime-order group `G` that **never outputs the identity**; models
/// `htag : Z_p → G_1 \ {1}` (§3.1.1) and derives independent generators for the credential
/// bases.
///
/// An instance is bound to a deployment label and is part of the public parameters, hence the
/// serialization bounds. The oracle with suffix `dst_suffix` has the domain-separation tag
/// `PCS-V1 ‖ dst_suffix`; oracles with different suffixes, or different deployment labels, are
/// independent. Generic code takes `H: HashToGroup<E::G1>` as a type parameter because
/// arkworks ships hash-to-curve suites only for BLS12-381 and BLS12-377.
pub trait HashToGroup<G: PrimeGroup>:
    Clone + Debug + PartialEq + Eq + CanonicalSerialize + CanonicalDeserialize
{
    /// The oracle family of the deployment `domain`.
    ///
    /// # Errors
    /// [`Error::HashToCurve`] if the underlying hash-to-curve suite cannot be instantiated.
    fn new(domain: &[u8]) -> Result<Self, Error>;

    /// The deployment label this instance is bound to.
    fn domain(&self) -> &[u8];

    /// `H_{dst_suffix}(msg) ∈ G \ {1}`. Deterministic. An identity output is re-hashed with an
    /// incremented counter, so the identity is never returned.
    fn hash(&self, dst_suffix: &[u8], msg: &[u8]) -> G;

    /// `htag(s)` for a scalar `s`, hashed in its canonical encoding ([`scalar_bytes`]).
    fn hash_scalar(&self, dst_suffix: &[u8], scalar: &G::ScalarField) -> G {
        self.hash(dst_suffix, &scalar_bytes(scalar))
    }

    /// `n` generators `H_{dst_suffix}(0), …, H_{dst_suffix}(n-1)` with mutually unknown discrete
    /// logarithms (in the random-oracle model), e.g. `h_0, …, h_3` of `Σ-BBS` or `g, h` of
    /// `Σ-MAC`.
    fn generators(&self, dst_suffix: &[u8], n: usize) -> Vec<G> {
        (0..n as u64)
            .map(|i| self.hash(dst_suffix, &i.to_le_bytes()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::Zero;

    use super::*;
    use crate::serialization::WireFormat;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn framing_is_injective() {
        // ("ab", "c") vs ("a", "bc"): the concatenations coincide, the framed items do not.
        let mut t1 = Transcript::new(b"/TEST");
        t1.append_bytes(b"ab", b"c");
        let mut t2 = Transcript::new(b"/TEST");
        t2.append_bytes(b"a", b"bc");
        assert_ne!(t1.digest(), t2.digest());

        // one item vs the same bytes split over two items
        let mut t3 = Transcript::new(b"/TEST");
        t3.append_bytes(b"x", b"abcd");
        let mut t4 = Transcript::new(b"/TEST");
        t4.append_bytes(b"x", b"ab");
        t4.append_bytes(b"x", b"cd");
        assert_ne!(t3.digest(), t4.digest());

        // an empty item is not a no-op
        let mut t5 = Transcript::new(b"/TEST");
        t5.append_bytes(b"", b"");
        assert_ne!(t5.digest(), Transcript::new(b"/TEST").digest());

        // data moved into the label
        let mut t6 = Transcript::new(b"/TEST");
        t6.append_bytes(b"xabcd", b"");
        assert_ne!(t3.digest(), t6.digest());
    }

    #[test]
    fn framing_bytes_are_as_documented() {
        let mut out = Vec::new();
        frame(&mut |b| out.extend_from_slice(b), b"ab", b"c");
        let mut expected = Vec::new();
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(b"c");
        assert_eq!(out, expected);
    }

    #[test]
    fn transcript_is_deterministic_and_forkable() {
        let build = || {
            let mut t = Transcript::new(H1_SUFFIX);
            t.append_bytes(b"a", b"1");
            t.append_u64(b"n", 7);
            t.append_serializable(b"p", &G1Projective::generator())
                .unwrap();
            t
        };
        assert_eq!(build().digest(), build().digest());
        assert_eq!(
            build().challenge_scalar::<Fr>(),
            build().challenge_scalar::<Fr>()
        );

        let base = build();
        let mut fork = base.clone();
        fork.append_bytes(b"more", b"data");
        assert_ne!(base.digest(), fork.digest());
        assert_eq!(base.digest(), build().digest());
    }

    #[test]
    fn append_serializable_uses_the_compressed_encoding() {
        let p = G1Projective::generator();
        let mut t1 = Transcript::new(b"/TEST");
        t1.append_serializable(b"p", &p).unwrap();
        let mut t2 = Transcript::new(b"/TEST");
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes.len(), 48);
        t2.append_bytes(b"p", &bytes);
        assert_eq!(t1.digest(), t2.digest());
    }

    #[test]
    fn oracles_are_domain_separated() {
        // same items, different oracle
        let mut t0 = Transcript::new(H0_SUFFIX);
        let mut t1 = Transcript::new(H1_SUFFIX);
        t0.append_bytes(b"x", b"y");
        t1.append_bytes(b"x", b"y");
        assert_ne!(t0.digest(), t1.digest());
        assert_ne!(t0.challenge_scalar::<Fr>(), t1.challenge_scalar::<Fr>());

        // H_1 on a context vs H_0 on anything we can form from the same bytes
        let ctx = b"identity";
        let h1: Fr = h1_transcript(ctx).challenge_scalar();
        assert_ne!(h1, h0_identity_point::<Fr>(ctx));
        assert_ne!(h1, h0_predicate::<Fr>(b"", ctx));
        assert_ne!(h1, h0_id::<Fr, _>(b"", &ctx.to_vec()).unwrap());
    }

    #[test]
    fn h0_uses_are_typed_and_deployment_bound() {
        let d = b"deployment-a";
        let c0: Fr = h0_identity_point(d);
        // the three uses never collide, even on "matching" inputs
        assert_ne!(c0, h0_predicate::<Fr>(d, b"identity"));
        assert_ne!(c0, h0_predicate::<Fr>(d, b""));
        assert_ne!(c0, h0_id::<Fr, _>(d, &b"identity".to_vec()).unwrap());
        assert_ne!(
            h0_predicate::<Fr>(d, b"abc"),
            h0_id::<Fr, [u8]>(d, b"abc").unwrap()
        );
        // deployments are separated
        assert_ne!(c0, h0_identity_point::<Fr>(b"deployment-b"));
        assert_ne!(
            h0_predicate::<Fr>(d, b"f"),
            h0_predicate::<Fr>(b"deployment-b", b"f")
        );
        // (deployment, predicate) framing is injective
        assert_ne!(
            h0_predicate::<Fr>(b"ab", b"c"),
            h0_predicate::<Fr>(b"a", b"bc")
        );
        // deterministic, input sensitive, non-zero on these inputs
        assert_eq!(c0, h0_identity_point::<Fr>(d));
        assert_ne!(h0_predicate::<Fr>(d, b"f1"), h0_predicate::<Fr>(d, b"f2"));
        assert!(!c0.is_zero());
    }

    #[test]
    fn h0_id_hashes_the_compressed_point() {
        let d = b"dep";
        let id = G1Projective::generator() * Fr::from(42u64);
        let s: Fr = h0_id(d, &id).unwrap();
        assert_eq!(s, h0_id::<Fr, _>(d, &id).unwrap());
        assert_ne!(
            s,
            h0_id::<Fr, _>(d, &(id + G1Projective::generator())).unwrap()
        );
        // a different in-memory representation of the same point gives the same hash
        let doubled_repr = (id + id) - id;
        assert_eq!(s, h0_id::<Fr, _>(d, &doubled_repr).unwrap());
    }

    #[test]
    fn scalar_bytes_equal_the_canonical_serialization() {
        for s in [
            Fr::zero(),
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(u64::MAX),
        ] {
            assert_eq!(scalar_bytes(&s), s.to_bytes().unwrap());
        }
    }

    #[test]
    fn oracle_input_is_injective_in_its_parts() {
        assert_ne!(oracle_input(b"ab", 0, b"c"), oracle_input(b"a", 0, b"bc"));
        assert_ne!(oracle_input(b"d", 0, b"m"), oracle_input(b"d", 1, b"m"));
    }

    /// Known-answer regression vectors: any change of the framing, the domain-separation tags or
    /// the hash-to-field variant shows up here. The expected values were computed by an
    /// independent Python re-implementation of the documented framing and of arkworks'
    /// `expand_message_xmd` variant (SHA-256, `Z_pad` of `L = 48` bytes, big-endian reduction
    /// mod `p`), so they also cross-check this module. They are NOT vectors of an external
    /// specification.
    #[test]
    fn known_answers() {
        let mut t = Transcript::new(H1_SUFFIX);
        t.append_bytes(b"label", b"data");
        t.append_u64(b"n", 5);
        assert_eq!(
            hex(&t.digest()),
            "cbdf0ce8df056c28618f0c1171a1f238817cb5c0506813b71194b5c8057a052a"
        );
        assert_eq!(
            hex(&t.challenge_scalar::<Fr>().to_bytes().unwrap()),
            "667dd8b9896694540758017abb3e76ec1fa260468ce051d64d9182013dbf5a1c"
        );
        assert_eq!(
            hex(&h0_identity_point::<Fr>(b"kat").to_bytes().unwrap()),
            "ba4e10eb4b6498e0ae6d31de1a5e9de0eec2dbc4b8dab326b06fc7040f34ab0b"
        );
        assert_eq!(
            hex(&h0_predicate::<Fr>(b"kat", b"threshold-3")
                .to_bytes()
                .unwrap()),
            "e0d7d98bdaaa9eea091ddf0e2fcbf36d37893aea6471a7d54525b28509825f27"
        );
        let id = G1Projective::generator();
        assert_eq!(
            hex(&h0_id::<Fr, _>(b"kat", &id).unwrap().to_bytes().unwrap()),
            "eae3736e0cf2d4c19d05913d343e2f81536e0a79f928489271dffb2cfff60022"
        );
    }
}
