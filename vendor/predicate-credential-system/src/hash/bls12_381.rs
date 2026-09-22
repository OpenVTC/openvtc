//! Hash-to-group oracles for BLS12-381 (`H_2 = htag`, §2.1 and §3.1.1).
//!
//! This is the only module of the library that names a concrete curve: arkworks 0.6.0 ships
//! hash-to-curve configurations for BLS12-381 (and BLS12-377) only.
//!
//! Implementation notes:
//!
//! * [`G1Hasher`] and [`G2Hasher`] wrap the RFC 9380 suites `BLS12381G1_XMD:SHA-256_SSWU_RO_`
//!   and `BLS12381G2_XMD:SHA-256_SSWU_RO_` as implemented by arkworks
//!   (`MapToCurveBasedHasher<_, DefaultFieldHasher<Sha256, 128>, WBMap<_>>`: hash to two field
//!   elements, map both to the curve, add, clear the cofactor).
//! * The suite is applied to the framed input [`oracle_input`]`(deployment, counter, msg)` under
//!   the tag `PCS-V1 ‖ dst_suffix`, so an output is *not* the RFC hash of the bare `msg`.
//! * Outputs lie in the prime-order subgroup. The identity is a possible output of the RFC map
//!   (with negligible probability); since the range of `htag` is `G_1 \ {1}`, such an output is
//!   re-hashed with the next counter value.

use ark_bls12_381::{G1Projective, G2Projective, g1, g2};
use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

use super::{H2_SUFFIX, HashToGroup, domain_separation_tag, oracle_input};
use crate::error::Error;

/// RFC 9380 suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` (the domain-separation tag is a parameter).
type G1Suite =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;
/// RFC 9380 suite `BLS12381G2_XMD:SHA-256_SSWU_RO_` (the domain-separation tag is a parameter).
type G2Suite =
    MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>;

/// One attempt: `Ok(None)` if the suite returned the identity.
fn try_hash<C: CurveGroup, S: HashToCurve<C>>(
    domain: &[u8],
    dst_suffix: &[u8],
    counter: u64,
    msg: &[u8],
) -> Result<Option<C>, Error> {
    let suite = S::new(&domain_separation_tag(dst_suffix))?;
    let point = suite.hash(&oracle_input(domain, counter, msg))?;
    Ok((!point.is_zero()).then(|| point.into_group()))
}

/// Hashes with increasing counters until the output is not the identity.
///
/// Every iteration fails with negligible probability only: an identity output has probability
/// about `1/p`, and the `Err` branch of the arkworks suite is unreachable for the BLS12-381
/// Wahby-Boneh maps (in arkworks 0.6.0 neither `new` nor `map_to_curve` of these suites
/// constructs an error; [`HashToGroup::new`] additionally exercises the suite once). The loop
/// therefore terminates after one iteration in practice and never panics.
fn hash_to_group<C: CurveGroup, S: HashToCurve<C>>(
    domain: &[u8],
    dst_suffix: &[u8],
    msg: &[u8],
) -> C {
    let mut counter = 0u64;
    loop {
        if let Ok(Some(point)) = try_hash::<C, S>(domain, dst_suffix, counter, msg) {
            return point;
        }
        counter = counter.wrapping_add(1);
    }
}

macro_rules! bls12_381_hasher {
    ($(#[$doc:meta])* $name:ident, $group:ty, $suite:ty) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
        pub struct $name {
            domain: Vec<u8>,
        }

        impl HashToGroup<$group> for $name {
            fn new(domain: &[u8]) -> Result<Self, Error> {
                // Surface a broken suite at construction time instead of inside `hash`.
                try_hash::<$group, $suite>(domain, H2_SUFFIX, 0, b"self-test")?;
                Ok(Self {
                    domain: domain.to_vec(),
                })
            }

            fn domain(&self) -> &[u8] {
                &self.domain
            }

            fn hash(&self, dst_suffix: &[u8], msg: &[u8]) -> $group {
                hash_to_group::<$group, $suite>(&self.domain, dst_suffix, msg)
            }
        }
    };
}

bls12_381_hasher!(
    /// Random oracle into `G_1 \ {1}` of BLS12-381; instantiates `htag` for `Tag_DDH`.
    G1Hasher,
    G1Projective,
    G1Suite
);
bls12_381_hasher!(
    /// Random oracle into `G_2 \ {1}` of BLS12-381.
    G2Hasher,
    G2Projective,
    G2Suite
);

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::PrimeGroup;
    use ark_ff::{PrimeField, Zero};

    use super::*;
    use crate::serialization::WireFormat;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn outputs_are_valid_non_identity_subgroup_points() {
        let h1 = G1Hasher::new(b"test").unwrap();
        let h2 = G2Hasher::new(b"test").unwrap();
        for i in 0u64..32 {
            let msg = i.to_le_bytes();
            let p = h1.hash(H2_SUFFIX, &msg);
            assert!(!p.is_zero());
            assert!(p.mul_bigint(Fr::MODULUS).is_zero());
            // validated decoding re-checks curve and subgroup membership
            assert_eq!(
                G1Affine::from_bytes(&p.to_bytes().unwrap()).unwrap(),
                p.into_affine()
            );

            let q = h2.hash(H2_SUFFIX, &msg);
            assert!(!q.is_zero());
            assert!(q.mul_bigint(Fr::MODULUS).is_zero());
            assert_eq!(
                G2Affine::from_bytes(&q.to_bytes().unwrap()).unwrap(),
                q.into_affine()
            );
        }
    }

    #[test]
    fn deterministic_and_input_sensitive() {
        let h = G1Hasher::new(b"test").unwrap();
        assert_eq!(h.hash(H2_SUFFIX, b"abc"), h.hash(H2_SUFFIX, b"abc"));
        assert_ne!(h.hash(H2_SUFFIX, b"abc"), h.hash(H2_SUFFIX, b"abd"));
        assert_ne!(h.hash(H2_SUFFIX, b""), h.hash(H2_SUFFIX, b"\0"));
        assert_eq!(h, G1Hasher::new(b"test").unwrap());
        assert_eq!(h.domain(), b"test");
    }

    #[test]
    fn oracles_and_deployments_are_separated() {
        let h = G1Hasher::new(b"test").unwrap();
        // different oracle suffix
        assert_ne!(
            h.hash(H2_SUFFIX, b"abc"),
            h.hash(b"/BBS-GENERATORS", b"abc")
        );
        // different deployment label
        let other = G1Hasher::new(b"test2").unwrap();
        assert_ne!(h.hash(H2_SUFFIX, b"abc"), other.hash(H2_SUFFIX, b"abc"));
        // (deployment, msg) framing: moving bytes across the boundary changes the output
        let ab = G1Hasher::new(b"ab").unwrap();
        let a = G1Hasher::new(b"a").unwrap();
        assert_ne!(ab.hash(H2_SUFFIX, b"c"), a.hash(H2_SUFFIX, b"bc"));
        // the empty deployment label is fine: the domain-separation tag is never empty
        assert!(!G1Hasher::new(b"").unwrap().hash(H2_SUFFIX, b"").is_zero());
    }

    #[test]
    fn hash_scalar_hashes_the_canonical_encoding() {
        let h = G1Hasher::new(b"test").unwrap();
        let s = Fr::from(77u64);
        assert_eq!(
            h.hash_scalar(H2_SUFFIX, &s),
            h.hash(H2_SUFFIX, &s.to_bytes().unwrap())
        );
        assert_ne!(
            h.hash_scalar(H2_SUFFIX, &s),
            h.hash_scalar(H2_SUFFIX, &(s + Fr::from(1u64)))
        );
    }

    #[test]
    fn generators_are_distinct_and_reproducible() {
        let h = G1Hasher::new(b"test").unwrap();
        let gens = h.generators(b"/BBS-GENERATORS", 4);
        assert_eq!(gens.len(), 4);
        for (i, g) in gens.iter().enumerate() {
            assert!(!g.is_zero());
            assert_ne!(*g, G1Projective::generator());
            for other in &gens[i + 1..] {
                assert_ne!(g, other);
            }
        }
        // prefix-stable: asking for fewer generators returns a prefix
        assert_eq!(h.generators(b"/BBS-GENERATORS", 2), gens[..2]);
        assert_ne!(h.generators(b"/MAC-GENERATORS", 1)[0], gens[0]);
        assert!(h.generators(b"/BBS-GENERATORS", 0).is_empty());
    }

    #[test]
    fn hasher_serialization_round_trips() {
        let h = G1Hasher::new(b"some deployment").unwrap();
        let back = G1Hasher::from_bytes(&h.to_bytes().unwrap()).unwrap();
        assert_eq!(h, back);
        assert_eq!(h.hash(H2_SUFFIX, b"x"), back.hash(H2_SUFFIX, b"x"));
    }

    /// The type alias really is the RFC 9380 suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`: test
    /// vector for `msg = ""` as shipped with ark-bls12-381 0.6.0
    /// (`src/curves/tests/BLS12381G1_XMD-SHA-256_SSWU_RO_.json`).
    #[test]
    fn underlying_suite_matches_the_rfc_9380_vector() {
        use ark_bls12_381::Fq;
        let fq = |hex: &str| {
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            Fq::from_be_bytes_mod_order(&bytes)
        };
        let suite = G1Suite::new(b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_").unwrap();
        assert_eq!(
            suite.hash(b"").unwrap(),
            G1Affine::new(
                fq(
                    "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"
                ),
                fq(
                    "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"
                ),
            )
        );
    }

    /// The wrapper is the RFC suite under the tag `PCS-V1 ‖ suffix`, applied to the framed
    /// input with counter 0.
    #[test]
    fn wrapper_is_the_suite_on_the_framed_input() {
        let h = G1Hasher::new(b"kat").unwrap();
        let suite = G1Suite::new(b"PCS-V1/H2").unwrap();
        let expected = suite.hash(&oracle_input(b"kat", 0, b"abc")).unwrap();
        assert_eq!(h.hash(H2_SUFFIX, b"abc").into_affine(), expected);
        // documented framing of the oracle input
        let mut framed = Vec::new();
        for (label, data) in [
            (&b"deployment"[..], &b"kat"[..]),
            (b"counter", &0u64.to_le_bytes()),
            (b"msg", b"abc"),
        ] {
            framed.extend_from_slice(&(label.len() as u64).to_le_bytes());
            framed.extend_from_slice(label);
            framed.extend_from_slice(&(data.len() as u64).to_le_bytes());
            framed.extend_from_slice(data);
        }
        assert_eq!(oracle_input(b"kat", 0, b"abc"), framed);
    }

    /// Known-answer regression vectors, computed once with this implementation and pinned (the
    /// two tests above tie them to the RFC suite). They are NOT vectors of an external
    /// specification.
    #[test]
    fn known_answers() {
        let h1 = G1Hasher::new(b"kat").unwrap();
        assert_eq!(
            hex(&h1.hash(H2_SUFFIX, b"abc").to_bytes().unwrap()),
            "93e4d29ca70c01951ebbe6f9ed5da64549df24b4ad6ef6c75759271c6d392f0d\
             96e96b58df526358f497454ceb032da7"
        );
        assert_eq!(
            hex(&h1
                .hash_scalar(H2_SUFFIX, &Fr::from(1u64))
                .to_bytes()
                .unwrap()),
            "b08e3a408e7a86ba1b60a07bd688b6303a8d29a702f22a7e43e47b4128adff59\
             aece9b7c6448c38733b88646dededbd1"
        );
        let h2 = G2Hasher::new(b"kat").unwrap();
        assert_eq!(
            hex(&h2.hash(H2_SUFFIX, b"abc").to_bytes().unwrap()),
            "89e60ec861d892acb0c8dcdb3ea414d476f6444cecc27942fad52a27544e9c00\
             2f60ced33d0b1024df48b0192525683f02dfdd657e5b4e1f55381b5aed626fa6\
             de8a13e7a0aa18aebc02a7439e7c306c50cccc65ba0fb1217c0bd193539674b7"
        );
    }
}
