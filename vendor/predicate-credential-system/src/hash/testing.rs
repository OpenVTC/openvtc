//! TEST-ONLY, INSECURE hash-to-group oracle for groups without a hash-to-curve suite.
//!
//! Compiled for the crate's own tests and behind the non-default cargo feature `test-utils`
//! (which the crate's dev-dependency on itself enables for `cargo test`, so that integration
//! tests can run the library over BN254 or over `G_2`). Never enable that feature in a
//! deployment.

use ark_ec::PrimeGroup;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::{HashToGroup, Transcript};
use crate::error::Error;

/// TEST-ONLY oracle into an arbitrary prime-order group: `H(m) = g^{H'(m)}` for a hash `H'` into
/// the scalar field. The discrete logarithm of every output is known, so this is NOT a secure
/// instantiation of `htag` or of "independent generators" (DDH tags under it are linkable,
/// Pedersen commitments under it are not binding). It only lets the algebra run over groups for
/// which arkworks ships no hash-to-curve suite (BN254, `G_2`, ...), to show that the library
/// code is generic.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct InsecureExponentHasher {
    domain: Vec<u8>,
}

impl<G: PrimeGroup> HashToGroup<G> for InsecureExponentHasher {
    fn new(domain: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            domain: domain.to_vec(),
        })
    }

    fn domain(&self) -> &[u8] {
        &self.domain
    }

    fn hash(&self, dst_suffix: &[u8], msg: &[u8]) -> G {
        let mut counter = 0u64;
        loop {
            let mut t = Transcript::new(dst_suffix);
            t.append_bytes(b"deployment", &self.domain);
            t.append_u64(b"counter", counter);
            t.append_bytes(b"msg", msg);
            let exponent: G::ScalarField = t.challenge_scalar();
            if !exponent.is_zero() {
                return G::generator() * exponent;
            }
            counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;

    use super::*;

    #[test]
    fn behaves_like_an_oracle_into_the_group() {
        let h = <InsecureExponentHasher as HashToGroup<G1Projective>>::new(b"d").unwrap();
        let hash = |suffix: &[u8], msg: &[u8]| -> G1Projective { h.hash(suffix, msg) };
        assert_eq!(hash(b"/A", b"m"), hash(b"/A", b"m"));
        assert_ne!(hash(b"/A", b"m"), hash(b"/A", b"n"));
        assert_ne!(hash(b"/A", b"m"), hash(b"/B", b"m"));
        assert!(!hash(b"/A", b"m").is_zero());
        let gens: Vec<G1Projective> = h.generators(b"/G", 3);
        assert!(gens[0] != gens[1] && gens[1] != gens[2] && gens[0] != gens[2]);
    }
}
