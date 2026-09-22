//! `Tag_DDH`, the default tag of the construction (paper §3.1.1, "The DDH instantiation").
//!
//! | paper (box `Tag_DDH`) | here |
//! |---|---|
//! | key space `Z_p \ {0}`, domain `Z_p`, range `G_1 \ {1}` | [`KIPRF::Key`], [`KIPRF::Input`] `= Z_p`, [`KIPRF::Output`] `= G` |
//! | `TagKeyGen`: `K ← Z_p \ {0}` | [`KIPRF::keygen`] |
//! | `TagEval(K, s)`: `P ← htag(s)`; return `P^K` | [`KIPRF::eval`], [`DDH::htag`] |
//! | `ValidTag(T, s) = [T ≠ 1]` | [`SigmaFriendlyKIPRF::valid_tag`] |
//! | `R_Tag`: the Schnorr relation with base `htag(s)`, target `T`, witness `K` | [`SigmaFriendlyKIPRF::tag_equations`] |
//! | Remark "Identity point": `htag(c_0) = g_1`, hence `id = Tag(usk, c_0) = g_1^usk` | [`DDH::with_identity_point`], [`PCSTag::setup`] |
//!
//! The paper states the instantiation over `G_1`; the code is generic over a prime-order group
//! `G` so that the designated-verifier variant can reuse it over its own group. `htag` is a
//! [`HashToGroup`] oracle with range `G \ {1}`.
//!
//! Security (Lemma on `Tag_DDH`, §3.1.1): in the random-oracle model for `htag` and under DDH
//! in `G_1` the function is a sigma-friendly non-adaptive KI-PRF. Key injectivity is
//! unconditional: `htag(s) ≠ 1` has order `p`, so `htag(s)^K = htag(s)^{K'}` forces `K = K'`.
//!
//! # In formulas
//!
//! With $`H_2 = \mathsf{htag}`$ a random oracle onto $`\mathbb{G} \setminus \{1\}`$:
//!
//! ```math
//! \mathsf{Tag}_{\mathsf{DDH}}(K, s) = H_2(s)^{K}, \qquad K \in \mathbb{Z}_p \setminus \{0\},\quad s \in \mathbb{Z}_p
//! ```
//!
//! ```math
//! R_{\mathsf{Tag}} = \bigl\{\, \bigl((T, s),\ K\bigr) \;:\; T = H_2(s)^{K} \,\bigr\}, \qquad \mathsf{ValidTag}(T, s) = [\, T \neq 1 \,]
//! ```
//!
//! Under the programmed point $`H_2(c_0) = g_1`$ the identifier is $`id = \mathsf{Tag}_{\mathsf{DDH}}(usk, c_0) = g_1^{usk}`$.
//!
//! # Example
//!
//! ```
//! use ark_bls12_381::{Fr, G1Projective as G1};
//! use ark_ec::PrimeGroup;
//! use predicate_credential_system::{
//!     hash::{bls12_381::G1Hasher, h0_id, h0_identity_point},
//!     kiprf::{prove_tag, verify_tag, KIPRF, PCSTag, DDH},
//! };
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! let mut rng = StdRng::seed_from_u64(1);
//! let domain = b"example deployment";
//! let c0: Fr = h0_identity_point(domain);
//! let tag = DDH::<G1, G1Hasher>::setup(domain, c0)?;
//!
//! // a user: usk, and the identifier id = Tag(usk, c_0) = g_1^usk
//! let usk = tag.keygen(&mut rng);
//! let id = tag.eval(&usk, &c0).expect("the domain of Tag_DDH is total");
//! assert_eq!(id, G1::generator() * usk);
//!
//! // its tag at the point s = H_0(id'), with a proof of knowledge of the key behind it
//! let s: Fr = h0_id(domain, &(G1::generator() * Fr::from(7u64)))?;
//! let t = tag.eval(&usk, &s).expect("the domain of Tag_DDH is total");
//! let proof = prove_tag(&tag, &usk, &t, &s, b"context", &mut rng)?;
//! assert!(verify_tag(&tag, &t, &s, b"context", &proof));
//! assert!(!verify_tag(&tag, &t, &c0, b"context", &proof));
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

use ark_ec::PrimeGroup;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};

use super::{KIPRF, PCSTag, SigmaFriendlyKIPRF};
use crate::{
    error::Error,
    hash::{H2_SUFFIX, HashToGroup},
    sample::nonzero_scalar,
    sigma::{LinearEquation, ScalarVar},
};

/// The public parameters `pp_Tag` of `Tag_DDH` over the group `G`: the hash-to-group oracle
/// `htag` and, optionally, the programmed identity point `c_0` of Remark "Identity point".
///
/// An instance is part of the public parameters of the credential system, hence the
/// serialization derives. Two instances are equal iff they define the same function.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DDH<G: PrimeGroup, H: HashToGroup<G>> {
    /// The random oracle behind `htag`, bound to a deployment label.
    hasher: H,
    /// `Some(c_0)` iff `htag(c_0)` is programmed to the generator of `G`.
    identity_point: Option<G::ScalarField>,
}

impl<G: PrimeGroup, H: HashToGroup<G>> DDH<G, H> {
    /// Plain `Tag_DDH` (box `Tag_DDH`): `htag` is the oracle `hasher` at every point.
    #[must_use]
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            identity_point: None,
        }
    }

    /// `Tag_DDH` with the convention of Remark "Identity point": `htag(c_0) := g`, the standard
    /// generator of `G`, so that the identifier is the plain discrete logarithm
    /// `id = Tag(usk, c_0) = g^usk`.
    ///
    /// Implementation note: the generator is `PrimeGroup::generator()`, the same `g_1` the
    /// pairing-based credential bases use; this is what lets the helper of `Σ-EQ` build its
    /// signed vector `(g_1, id, g_1^φ)` from the public `id`.
    #[must_use]
    pub fn with_identity_point(hasher: H, c0: G::ScalarField) -> Self {
        Self {
            hasher,
            identity_point: Some(c0),
        }
    }

    /// The programmed identity point `c_0`, if any.
    #[must_use]
    pub fn identity_point(&self) -> Option<&G::ScalarField> {
        self.identity_point.as_ref()
    }

    /// The oracle behind `htag`.
    #[must_use]
    pub fn hasher(&self) -> &H {
        &self.hasher
    }

    /// `htag(s) ∈ G \ {1}` (box `Tag_DDH`, `TagEval` step 1): the generator of `G` at the
    /// programmed point `c_0`, the random oracle `H_2` on the canonical encoding of `s`
    /// everywhere else. Deterministic; never the identity.
    #[must_use]
    pub fn htag(&self, input: &G::ScalarField) -> G {
        match &self.identity_point {
            Some(c0) if c0 == input => G::generator(),
            _ => self.hasher.hash_scalar(H2_SUFFIX, input),
        }
    }

    /// Always `true`: `Tag_DDH` has no degenerate parameters.
    ///
    /// Implementation note, not an algorithm of the paper
    /// ([`PCSTag::is_well_formed`] explains what the check is for). An instance consists of a
    /// deployment label and an optional programmed point, and whatever these are (assembled or
    /// decoded, with or without validation) `htag` has range `G \ {1}`: the programmed value is
    /// the generator, and every other value comes from a [`HashToGroup`] oracle, whose contract
    /// excludes the identity. `TagEval` is therefore defined for every key of the key space
    /// `Z_p \ {0}` at every point, and a `UKeyGen` loop runs once. What a decoded instance CAN
    /// get wrong is the programmed point; that is [`PCSTag::identity_is_dlog`].
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        true
    }
}

impl<G: PrimeGroup, H: HashToGroup<G>> KIPRF for DDH<G, H> {
    type Key = G::ScalarField;
    type Input = G::ScalarField;
    type Output = G;

    /// `TagKeyGen` (box `Tag_DDH`): step 1, `K ← Z_p \ {0}`; step 2, return `K`.
    fn keygen<R: RngCore + CryptoRng + ?Sized>(&self, rng: &mut R) -> Self::Key {
        nonzero_scalar(rng)
    }

    /// `TagEval(K, s)` (box `Tag_DDH`): step 1, `P ← htag(s)`; step 2, return `P^K`.
    ///
    /// The domain is total: for a key of the key space the result is never `⊥` and, because
    /// `P ≠ 1` and `K ≠ 0`, never the identity. `K = 0` lies outside the key space and
    /// evaluates to `None` (its "tag" would be the identity at every point).
    fn eval(&self, key: &Self::Key, input: &Self::Input) -> Option<Self::Output> {
        if key.is_zero() {
            return None;
        }
        let p = self.htag(input);
        Some(p * *key)
    }
}

impl<G: PrimeGroup, H: HashToGroup<G>> SigmaFriendlyKIPRF for DDH<G, H> {
    type Group = G;

    /// `ValidTag(T, s) = [T ≠ 1]` (§3.1.1). With `T = 1` the clause `T = htag(s)^K` would only
    /// be satisfied by `K = 0`, which is not a key.
    fn valid_tag(&self, tag: &G, _input: &G::ScalarField) -> bool {
        !tag.is_zero()
    }

    /// `R_Tag_DDH` as ONE linear equation (Lemma on `Tag_DDH`, "Sigma-friendliness"): after
    /// computing `P = htag(s)`, the Schnorr relation `T = P^K` with base `P`, target `T` and
    /// witness `K`.
    fn tag_equations(
        &self,
        key: ScalarVar,
        tag: &G,
        input: &G::ScalarField,
    ) -> Vec<LinearEquation<G>> {
        vec![LinearEquation::dlog(key, self.htag(input), *tag)]
    }
}

impl<G: PrimeGroup, H: HashToGroup<G>> PCSTag<G> for DDH<G, H> {
    /// Holds for every instance built by [`PCSTag::setup`], which programs `htag(c_0) := g`. It
    /// does NOT hold for [`DDH::new`], for [`DDH::with_identity_point`] at another point,
    /// or for whatever a decoded `pp` contains: [`PCSTag::identity_is_dlog`] tells.
    const IDENTITY_IS_DLOG: bool = true;

    /// `pp_Tag` of the construction (box, `Setup` steps 1 and 4): the oracle `htag` of the
    /// deployment `domain` with `htag(c_0) := g` programmed.
    ///
    /// Implementation note: step 4 of the box asks for the programming only "for `Σ-EQ` with
    /// `Tag_DDH`", while Remark "Identity point" fixes it as a general convention. This
    /// implementation follows the Remark and programs the point for every base, so that
    /// `id = g^usk` has one definition per deployment, whatever the base.
    fn setup(domain: &[u8], c0: G::ScalarField) -> Result<Self, Error> {
        Ok(Self::with_identity_point(H::new(domain)?, c0))
    }

    /// `htag(c_0) = g`, which is equivalent to `Tag(K, c_0) = htag(c_0)^K = g^K` for every `K`
    /// (take `K = 1` for the converse). True iff `c_0` is the programmed point, except in the
    /// event that the oracle itself outputs `g` at `c_0` (probability about `1/p` in the
    /// random-oracle model).
    fn identity_is_dlog(&self, c0: &G::ScalarField) -> bool {
        self.htag(c0) == G::generator()
    }

    /// [`DDH::is_well_formed`]: always `true`, `TagEval` is total on the key space.
    fn is_well_formed(&self) -> bool {
        // The inherent method (inherent associated functions take precedence in a path).
        DDH::is_well_formed(self)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ff::{Field, One, PrimeField, UniformRand};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        cred::{EQ, PS},
        hash::{bls12_381::G1Hasher, h0_id, h0_identity_point, testing::InsecureExponentHasher},
        kiprf::{prove_tag, tag_proof_context, tag_relation, verify_tag},
        pcs::check_compatibility,
        serialization::WireFormat,
        sigma::{FSProof, LinearRelation, fiat_shamir},
    };

    type G1 = G1Projective;
    type Tag = DDH<G1, G1Hasher>;

    const DOMAIN: &[u8] = b"tag-ddh-unit-tests";

    fn setup() -> (Tag, Fr) {
        let c0: Fr = h0_identity_point(DOMAIN);
        (Tag::setup(DOMAIN, c0).unwrap(), c0)
    }

    #[test]
    fn evaluation_is_deterministic() {
        let mut rng = StdRng::seed_from_u64(0xdd01);
        let (tag, _) = setup();
        let (key, s) = (tag.keygen(&mut rng), Fr::rand(&mut rng));
        let t = tag.eval(&key, &s).unwrap();
        assert_eq!(tag.eval(&key, &s).unwrap(), t);
        // an independently constructed instance of the same deployment is the same function
        let (again, _) = setup();
        assert_eq!(again, tag);
        assert_eq!(again.eval(&key, &s).unwrap(), t);
        // and it is `htag(s)^K`
        assert_eq!(t, tag.htag(&s) * key);
        // another point, another deployment: another tag
        assert_ne!(tag.eval(&key, &(s + Fr::one())).unwrap(), t);
        let other = Tag::setup(b"another deployment", h0_identity_point(DOMAIN)).unwrap();
        assert_ne!(other.eval(&key, &s).unwrap(), t);
    }

    #[test]
    fn keys_are_nonzero_and_the_zero_key_has_no_tag() {
        let mut rng = StdRng::seed_from_u64(0xdd02);
        let (tag, c0) = setup();
        for _ in 0..64 {
            assert!(!tag.keygen(&mut rng).is_zero());
        }
        let s = Fr::rand(&mut rng);
        assert_eq!(tag.eval(&Fr::zero(), &s), None);
        assert_eq!(tag.eval(&Fr::zero(), &c0), None);
    }

    /// Key injectivity (Def. "Non-adaptive key-injective pseudorandom function", (i)) on
    /// samples: pairwise distinct keys give pairwise distinct tags at a common point, at an
    /// ordinary point as well as at the programmed one. Evidence on samples, not a proof; the
    /// proof is the one-line argument of the Lemma on `Tag_DDH`.
    #[test]
    fn key_injectivity_on_samples() {
        let mut rng = StdRng::seed_from_u64(0xdd03);
        let (tag, c0) = setup();
        let s = Fr::rand(&mut rng);
        let mut keys: Vec<Fr> = (0..24).map(|_| tag.keygen(&mut rng)).collect();
        // edge keys of the key space, and a pair of neighbours
        keys.extend([Fr::one(), -Fr::one(), Fr::from(2u64), keys[0] + Fr::one()]);
        for point in [s, c0] {
            let tags: Vec<G1> = keys.iter().map(|k| tag.eval(k, &point).unwrap()).collect();
            for i in 0..keys.len() {
                for j in i + 1..keys.len() {
                    assert_ne!(keys[i], keys[j]);
                    assert_ne!(tags[i], tags[j], "keys {i} and {j} collide");
                }
            }
        }
    }

    /// Remark "Identity point": `htag(c_0) = g_1`, hence `id = Tag(usk, c_0) = g_1^usk`.
    #[test]
    fn programmed_point_gives_the_dlog_identifier() {
        let mut rng = StdRng::seed_from_u64(0xdd04);
        let (tag, c0) = setup();
        assert_eq!(tag.identity_point(), Some(&c0));
        assert_eq!(tag.htag(&c0), G1::generator());
        let usk = tag.keygen(&mut rng);
        assert_eq!(tag.eval(&usk, &c0).unwrap(), G1::generator() * usk);
        // ... which is what the associated constant promises (checked at compile time).
        const { assert!(Tag::IDENTITY_IS_DLOG) };

        // Only c_0 is programmed: everywhere else htag is the oracle, which never returns the
        // identity (nor, on these samples, the generator).
        for i in 0u64..16 {
            let s = Fr::from(i);
            let p = tag.htag(&s);
            assert_eq!(p, tag.hasher().hash_scalar(H2_SUFFIX, &s));
            assert!(!p.is_zero());
            assert_ne!(p, G1::generator());
            assert!(p.mul_bigint(Fr::MODULUS).is_zero());
        }

        // The plain instantiation does not program anything.
        let plain = Tag::new(G1Hasher::new(DOMAIN).unwrap());
        assert_eq!(plain.identity_point(), None);
        assert_ne!(plain.htag(&c0), G1::generator());
        assert_ne!(plain, tag);
        // Off c_0 the two instances coincide.
        let s = Fr::rand(&mut rng);
        assert_eq!(plain.eval(&usk, &s), tag.eval(&usk, &s));
    }

    /// `IDENTITY_IS_DLOG` is a promise about the type and about `PCSTag::setup`; whether an
    /// INSTANCE satisfies `Tag(K, c_0) = g^K` is a value-level question. The instances below
    /// all have the type-level constant `true`, and only the first one is compatible with a
    /// base that needs `id = g_1^usk` (`Σ-EQ`).
    #[test]
    fn identity_is_dlog_is_decided_per_instance() {
        type E = ark_bls12_381::Bls12_381;
        let mut rng = StdRng::seed_from_u64(0xdd0e);
        let (programmed, c0) = setup();
        const { assert!(Tag::IDENTITY_IS_DLOG) };
        let usk = programmed.keygen(&mut rng);

        let plain = Tag::new(G1Hasher::new(DOMAIN).unwrap());
        let elsewhere = Tag::with_identity_point(G1Hasher::new(DOMAIN).unwrap(), c0 + Fr::one());
        // what a decoded `pp` may contain: the sender controls the programmed point
        let decoded = Tag::from_bytes(&elsewhere.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded, elsewhere);

        assert!(programmed.identity_is_dlog(&c0));
        assert_eq!(
            check_compatibility::<E, EQ<E>, Tag>(&programmed, &c0),
            Ok(())
        );
        // the check is relative to the identity point in use
        assert!(!programmed.identity_is_dlog(&(c0 + Fr::one())));
        assert!(elsewhere.identity_is_dlog(&(c0 + Fr::one())));

        for (i, tag) in [&plain, &elsewhere, &decoded].into_iter().enumerate() {
            assert_ne!(
                tag.eval(&usk, &c0).unwrap(),
                G1::generator() * usk,
                "case {i}"
            );
            assert!(!tag.identity_is_dlog(&c0), "case {i}");
            assert_eq!(
                check_compatibility::<E, EQ<E>, Tag>(tag, &c0),
                Err(Error::IncompatibleBaseAndTag),
                "case {i}"
            );
            // a base that does not need the discrete-logarithm identifier takes any instance
            assert_eq!(
                check_compatibility::<E, PS<E>, Tag>(tag, &c0),
                Ok(()),
                "case {i}"
            );
        }
    }

    /// `PCSTag::is_well_formed` is the liveness hook of generic code: under a well-formed
    /// instance a `UKeyGen` loop terminates. `Tag_DDH` has no degenerate parameters: whatever
    /// the label and the programmed point are, and however the instance was decoded, every key
    /// of the key space has a defined, admissible tag at every point.
    #[test]
    fn every_instance_is_well_formed_and_total() {
        fn through_the_trait<T: PCSTag<G1>>(tag: &T) -> bool {
            tag.is_well_formed()
        }
        let mut rng = StdRng::seed_from_u64(0xdd0f);
        let (programmed, c0) = setup();
        let plain = Tag::new(G1Hasher::new(DOMAIN).unwrap());
        let elsewhere = Tag::with_identity_point(G1Hasher::new(b"").unwrap(), Fr::zero());
        // decoded without any validation: the contract of the `*_unchecked` decoders
        let mut bytes = Vec::new();
        elsewhere.serialize_compressed(&mut bytes).unwrap();
        let unchecked = Tag::deserialize_compressed_unchecked(&bytes[..]).unwrap();
        assert_eq!(unchecked, elsewhere);

        for (i, tag) in [&programmed, &plain, &elsewhere, &unchecked]
            .into_iter()
            .enumerate()
        {
            assert!(tag.is_well_formed(), "case {i}");
            assert!(through_the_trait(tag), "case {i}");
            // what the hook promises: no key of the key space is undefined anywhere
            for s in [c0, Fr::zero(), Fr::one(), -Fr::one(), Fr::rand(&mut rng)] {
                for key in [Fr::one(), -Fr::one(), -s, tag.keygen(&mut rng)] {
                    if key.is_zero() {
                        continue; // −s = 0 is not a key
                    }
                    let t = tag.eval(&key, &s).expect("Tag_DDH is total");
                    assert!(tag.valid_tag(&t, &s), "case {i}");
                }
            }
        }
    }

    #[test]
    fn valid_tag_rejects_exactly_the_identity() {
        let mut rng = StdRng::seed_from_u64(0xdd05);
        let (tag, c0) = setup();
        let s = Fr::rand(&mut rng);
        assert!(!tag.valid_tag(&G1::zero(), &s));
        assert!(!tag.valid_tag(&G1::zero(), &c0));
        // every honestly generated tag is admissible ...
        for _ in 0..16 {
            let key = tag.keygen(&mut rng);
            assert!(tag.valid_tag(&tag.eval(&key, &s).unwrap(), &s));
        }
        // ... and so is any other non-identity element (it is a tag under SOME key)
        assert!(tag.valid_tag(&G1::rand(&mut rng), &s));
    }

    #[test]
    fn tag_equation_is_satisfied_by_the_key_only() {
        let mut rng = StdRng::seed_from_u64(0xdd06);
        let (tag, c0) = setup();
        for s in [Fr::rand(&mut rng), c0] {
            let key = tag.keygen(&mut rng);
            let t = tag.eval(&key, &s).unwrap();
            let (rel, var) = tag_relation(&tag, &t, &s).unwrap();
            assert_eq!(var.index(), 0);
            assert_eq!(rel.num_scalars(), 1);
            // ONE linear equation: base htag(s), target T
            assert_eq!(
                rel.equations(),
                [LinearEquation::dlog(var, tag.htag(&s), t)]
            );
            assert!(rel.is_satisfied_by(&[key]));
            let other = tag.keygen(&mut rng);
            assert!(!rel.is_satisfied_by(&[other]));
            assert!(!rel.is_satisfied_by(&[key + Fr::one()]));
            assert!(!rel.is_satisfied_by(&[-key]));
            assert!(!rel.is_satisfied_by(&[Fr::zero()]));
            assert!(!rel.is_satisfied_by(&[]));
        }
    }

    /// Why `ValidTag` is a separate public check: the linear clause alone accepts `T = 1` with
    /// the non-key `K = 0`.
    #[test]
    fn identity_tag_satisfies_the_clause_but_not_the_relation() {
        let mut rng = StdRng::seed_from_u64(0xdd07);
        let (tag, _) = setup();
        let s = Fr::rand(&mut rng);
        let (rel, _) = tag_relation(&tag, &G1::zero(), &s).unwrap();
        assert!(rel.is_satisfied_by(&[Fr::zero()]));
        // A cheating prover builds a Fiat-Shamir proof for the bare clause, under exactly the
        // context the tag verifier derives ...
        let ctx = tag_proof_context(&tag, &G1::zero(), &s, b"ctx").unwrap();
        let bare = fiat_shamir::prove(&rel, &[Fr::zero()], &ctx, &mut rng).unwrap();
        assert!(fiat_shamir::verify(&rel, &ctx, &bare));
        // ... so ONLY the public pre-check ValidTag stands between it and acceptance.
        assert!(!verify_tag(&tag, &G1::zero(), &s, b"ctx", &bare));
        // The honest prover refuses the statement as well.
        assert_eq!(
            prove_tag(&tag, &Fr::zero(), &G1::zero(), &s, b"ctx", &mut rng),
            Err(Error::InvalidTag)
        );
    }

    #[test]
    fn standalone_proof_verifies_and_is_bound_to_tag_point_and_context() {
        let mut rng = StdRng::seed_from_u64(0xdd08);
        let (tag, c0) = setup();
        let id = G1::generator() * Fr::rand(&mut rng);
        let s: Fr = h0_id(DOMAIN, &id).unwrap();
        let key = tag.keygen(&mut rng);
        let t = tag.eval(&key, &s).unwrap();

        let proof = prove_tag(&tag, &key, &t, &s, b"ctx", &mut rng).unwrap();
        assert!(verify_tag(&tag, &t, &s, b"ctx", &proof));
        // compact: the challenge and ONE response
        assert_eq!(proof.responses.len(), 1);

        // bound to T ...
        let t_other = tag.eval(&(key + Fr::one()), &s).unwrap();
        assert!(!verify_tag(&tag, &t_other, &s, b"ctx", &proof));
        assert!(!verify_tag(&tag, &(t + t), &s, b"ctx", &proof));
        assert!(!verify_tag(&tag, &G1::zero(), &s, b"ctx", &proof));
        // ... to s (also when the tag is re-evaluated at the new point) ...
        let s_other = s + Fr::one();
        assert!(!verify_tag(&tag, &t, &s_other, b"ctx", &proof));
        let t_at_other = tag.eval(&key, &s_other).unwrap();
        assert!(!verify_tag(&tag, &t_at_other, &s_other, b"ctx", &proof));
        assert!(!verify_tag(&tag, &t, &c0, b"ctx", &proof));
        // ... to the context ...
        assert!(!verify_tag(&tag, &t, &s, b"ctx2", &proof));
        assert!(!verify_tag(&tag, &t, &s, b"", &proof));
        // ... and to the deployment (another oracle htag).
        let other = Tag::setup(b"another deployment", c0).unwrap();
        assert!(!verify_tag(&other, &t, &s, b"ctx", &proof));

        // mauled and malformed proofs
        let mut bad = proof.clone();
        bad.responses[0] += Fr::one();
        assert!(!verify_tag(&tag, &t, &s, b"ctx", &bad));
        let mut bad = proof.clone();
        bad.challenge += Fr::one();
        assert!(!verify_tag(&tag, &t, &s, b"ctx", &bad));
        let mut bad = proof.clone();
        bad.responses.push(Fr::zero());
        assert!(!verify_tag(&tag, &t, &s, b"ctx", &bad));
        let empty = FSProof {
            challenge: proof.challenge,
            responses: vec![],
        };
        assert!(!verify_tag(&tag, &t, &s, b"ctx", &empty));
    }

    /// `H_1` has no deployment input; a stand-alone proof is bound to its deployment through
    /// `pp_Tag` in the context. At the programmed point the statement `id = g^usk` has the SAME
    /// base and target in every deployment, so without that binding the proof would replay.
    #[test]
    fn identifier_proof_does_not_replay_in_another_deployment() {
        let mut rng = StdRng::seed_from_u64(0xdd0f);
        // two deployments that (deliberately) share c_0, which `PCSTag::setup` permits
        let c0: Fr = h0_identity_point(b"shared identity point");
        let a = Tag::setup(b"deployment-A", c0).unwrap();
        let b = Tag::setup(b"deployment-B", c0).unwrap();
        let usk = a.keygen(&mut rng);
        let id = a.eval(&usk, &c0).unwrap();
        assert_eq!(b.eval(&usk, &c0).unwrap(), id);
        // the linear statement is literally the same ...
        assert_eq!(
            tag_relation(&a, &id, &c0).unwrap().0,
            tag_relation(&b, &id, &c0).unwrap().0
        );
        // ... and the proof is still not transferable
        let proof = prove_tag(&a, &usk, &id, &c0, b"ctx", &mut rng).unwrap();
        assert!(verify_tag(&a, &id, &c0, b"ctx", &proof));
        assert!(!verify_tag(&b, &id, &c0, b"ctx", &proof));
        // nor to an instance of the same deployment with other parameters
        let plain = Tag::new(G1Hasher::new(b"deployment-A").unwrap());
        assert!(!verify_tag(&plain, &id, &c0, b"ctx", &proof));
    }

    #[test]
    fn standalone_prover_refuses_a_wrong_key() {
        let mut rng = StdRng::seed_from_u64(0xdd09);
        let (tag, _) = setup();
        let s = Fr::rand(&mut rng);
        let key = tag.keygen(&mut rng);
        let t = tag.eval(&key, &s).unwrap();
        let wrong = tag.keygen(&mut rng);
        assert_eq!(
            prove_tag(&tag, &wrong, &t, &s, b"ctx", &mut rng),
            Err(Error::WitnessDoesNotSatisfyRelation)
        );
    }

    /// A proof at the programmed point is a plain Schnorr proof of `id = g_1^usk`.
    #[test]
    fn identifier_proof_is_a_schnorr_proof_to_the_generator() {
        let mut rng = StdRng::seed_from_u64(0xdd0a);
        let (tag, c0) = setup();
        let usk = tag.keygen(&mut rng);
        let id = tag.eval(&usk, &c0).unwrap();
        let (rel, var) = tag_relation(&tag, &id, &c0).unwrap();
        assert_eq!(
            rel.equations(),
            [LinearEquation::dlog(var, G1::generator(), id)]
        );
        let proof = prove_tag(&tag, &usk, &id, &c0, b"", &mut rng).unwrap();
        assert!(verify_tag(&tag, &id, &c0, b"", &proof));
    }

    #[test]
    fn public_parameters_round_trip() {
        let (tag, c0) = setup();
        let bytes = tag.to_bytes().unwrap();
        let back = Tag::from_bytes(&bytes).unwrap();
        assert_eq!(back, tag);
        assert_eq!(back.htag(&c0), G1::generator());
        assert_eq!(back.htag(&Fr::from(9u64)), tag.htag(&Fr::from(9u64)));

        let plain = Tag::new(G1Hasher::new(DOMAIN).unwrap());
        let back = Tag::from_bytes(&plain.to_bytes().unwrap()).unwrap();
        assert_eq!(back, plain);
        assert_ne!(plain.to_bytes().unwrap(), bytes);
    }

    // -----------------------------------------------------------------------------------------
    // Genericity: the same code over another group
    // -----------------------------------------------------------------------------------------

    fn generic_round_trip<G: PrimeGroup>(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let c0: G::ScalarField = h0_identity_point(DOMAIN);
        let tag = DDH::<G, InsecureExponentHasher>::setup(DOMAIN, c0).unwrap();
        let usk = tag.keygen(&mut rng);
        assert_eq!(tag.eval(&usk, &c0).unwrap(), G::generator() * usk);
        let s = G::ScalarField::rand(&mut rng);
        let t = tag.eval(&usk, &s).unwrap();
        assert!(tag.valid_tag(&t, &s));
        assert_ne!(tag.eval(&(usk + G::ScalarField::ONE), &s).unwrap(), t);
        let proof = prove_tag(&tag, &usk, &t, &s, b"ctx", &mut rng).unwrap();
        assert!(verify_tag(&tag, &t, &s, b"ctx", &proof));
        assert!(!verify_tag(&tag, &t, &c0, b"ctx", &proof));
        assert!(!verify_tag(&tag, &G::zero(), &s, b"ctx", &proof));
    }

    #[test]
    fn generic_over_the_group() {
        generic_round_trip::<ark_bn254::G1Projective>(0xdd0b);
        generic_round_trip::<ark_bn254::G2Projective>(0xdd0c);
        generic_round_trip::<ark_bls12_381::G2Projective>(0xdd0d);
    }
}
