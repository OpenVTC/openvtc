//! Sigma protocols: generalized Schnorr proofs with witness-preserving AND composition and
//! their Fiat-Shamir transform (paper §2.3, "Sigma protocols and Schnorr proofs").
//!
//! * [`relation`]: statements. A statement is a conjunction of linear representation equations
//!   over prime-order groups sharing one scalar field, built with [`GroupRelation`] (one group)
//!   or [`PairingRelation`] (`G_1`, `G_2` and lazily evaluated `G_T` equations). Both implement
//!   [`LinearRelation`], the only interface the protocol layers use.
//! * [`protocol`]: the interactive three-move protocol, its special-HVZK simulator and its
//!   special-soundness extractor (Defs. "Sigma protocol", "Schnorr sigma protocol").
//! * [`fiat_shamir`]: the non-interactive `zkPoK_ctx{…}` of §5.1 with compact `(c, z)` proofs.
//!
//! # In formulas
//!
//! A statement is a system of representation equations with bases $`G_{ij}`$, targets $`Y_i`$ and
//! the witness $`(x_j)_j`$; a coordinate $`x_j`$ that occurs in several equations is ONE variable:
//!
//! ```math
//! R = \Bigl\{\, \bigl((G_{ij}, Y_i)_{i,j},\ (x_j)_j\bigr) \;:\; Y_i = \prod_{j} G_{ij}^{\,x_j} \ \text{ for all } i \,\Bigr\}
//! ```
//!
//! The three moves, with one mask $`r_j`$ and one response $`z_j`$ per variable:
//!
//! ```math
//! A_i = \prod_{j} G_{ij}^{\,r_j}, \qquad c \leftarrow \mathbb{Z}_p, \qquad z_j = r_j + c\, x_j, \qquad \text{accept iff } \prod_{j} G_{ij}^{\,z_j} = A_i\, Y_i^{\,c} \ \text{ for all } i
//! ```
//!
//! # Witness-preserving AND composition
//!
//! A witness coordinate is a [`ScalarVar`]; every equation that mentions the same variable
//! shares its mask and its response. This is precisely the composition rule the paper states
//! for generalized Schnorr protocols ("the prover uses the same mask `r` and hence the same
//! response `z = r + cx` in each such equation"), and it makes the extractor return a *single*
//! value for a shared coordinate such as `usk`.
//!
//! # Example
//!
//! ```
//! use ark_bls12_381::{Fr, G1Projective as G1};
//! use ark_ec::PrimeGroup;
//! use predicate_credential_system::sigma::{fiat_shamir, GroupRelation, LinearEquation};
//! use rand::{rngs::StdRng, SeedableRng};
//!
//! let mut rng = StdRng::seed_from_u64(7);
//! let (g, h) = (G1::generator(), G1::generator() * Fr::from(5u64));
//! let usk = Fr::from(1234u64);
//!
//! // Two equations sharing ONE witness coordinate:  T1 = usk·g  and  T2 = usk·h.
//! let mut rel = GroupRelation::<G1>::new();
//! let x = rel.alloc_scalar();
//! rel.add_equation(LinearEquation::dlog(x, g, g * usk))?;
//! rel.add_equation(LinearEquation::dlog(x, h, h * usk))?;
//!
//! let proof = fiat_shamir::prove(&rel, &[usk], b"context", &mut rng)?;
//! assert!(fiat_shamir::verify(&rel, b"context", &proof));
//! assert!(!fiat_shamir::verify(&rel, b"another context", &proof));
//! # Ok::<(), predicate_credential_system::Error>(())
//! ```

pub mod fiat_shamir;
pub mod protocol;
pub mod relation;

pub use fiat_shamir::FSProof;
pub use protocol::{ProverState, Witness, commit, extract, respond, simulate, verify};
pub use relation::{
    GroupRelation, GtEquation, LinearEquation, LinearRelation, PairingImage, PairingProduct,
    PairingRelation, ScalarVar, pairing_product,
};
