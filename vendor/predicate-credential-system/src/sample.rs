//! Sampling helpers shared by the instantiations.
//!
//! The paper samples several values from `Z_p^* = Z_p \ {0}` (the `Tag_DDH` key, the `Σ-PS`
//! re-randomizer `r` and blinding exponent `u`, ...). arkworks has no such sampler, so it is
//! written once here.

use ark_ff::Field;
use ark_std::rand::{CryptoRng, RngCore};

/// `x ← Z_p^*`: a uniform non-zero field element.
///
/// Implementation note: rejection sampling on top of `F::rand`, which for prime fields is
/// itself exact rejection sampling (random limbs, unused top bits masked, retry while the value
/// is `≥ p`). The output is therefore exactly uniform on `F \ {0}` for a uniform `rng`, and the
/// loop repeats with probability `1/p` per iteration.
pub(crate) fn nonzero_scalar<F, R>(rng: &mut R) -> F
where
    F: Field,
    R: RngCore + CryptoRng + ?Sized,
{
    loop {
        let x = F::rand(rng);
        if !x.is_zero() {
            return x;
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_std::rand::{CryptoRng, Error, RngCore};

    use super::*;

    /// Yields all-zero output for the first `zeros` bytes-requests, then counts upwards.
    struct ZeroThenCounter {
        zero_calls: usize,
        counter: u64,
    }

    impl RngCore for ZeroThenCounter {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            if self.zero_calls > 0 {
                self.zero_calls -= 1;
                0
            } else {
                self.counter += 1;
                self.counter
            }
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // Test-only marker: the sampler's bound asks for a `CryptoRng`.
    impl CryptoRng for ZeroThenCounter {}

    /// The zero element is really skipped: an RNG whose first outputs encode `0 ∈ F` must not
    /// make the sampler return zero.
    #[test]
    fn zero_is_rejected() {
        // Control: with this RNG, plain `Fr::rand` returns zero.
        let mut rng = ZeroThenCounter {
            zero_calls: 4,
            counter: 0,
        };
        assert!(<Fr as ark_ff::UniformRand>::rand(&mut rng).is_zero());

        let mut rng = ZeroThenCounter {
            zero_calls: 4,
            counter: 0,
        };
        let x: Fr = nonzero_scalar(&mut rng);
        assert!(!x.is_zero());
    }
}
