//! # Predicate credential system
//!
//! A Rust rendering of the *predicate credential system* (PCS) of the accompanying paper: a
//! helper issues a credential to a user who proves, in zero knowledge, that it holds
//! attestations from `k` pairwise-distinct credentialed users, none of whom is the user itself.
//! The crate follows the paper's modular construction: generalized Schnorr proofs, a
//! key-injective PRF ("tag") and a credential base are combined by a generic protocol.
//!
//! ## Paper-to-module map
//!
//! | Paper | Module |
//! |---|---|
//! | §2.1 random oracles `H_0`, `H_1`, `H_2 = htag` (hash to group) | [`hash`] |
//! | §2.3 sigma protocols, generalized Schnorr, Fiat-Shamir | [`sigma`] |
//! | §3.1 non-adaptive key-injective PRFs (`Tag_DDH`, `Tag_DY`) | [`kiprf`] |
//! | §3.2 credential bases (`Σ-PS`, `Σ-BBS`, `Σ-EQ`, designated-verifier `Σ-MAC`) | [`cred`] |
//! | §4 syntax of a predicate credential system | [`pcs::PredicateCredentialSystem`] |
//! | §5.1 modular threshold construction (protocol box) | [`pcs::PCS`], generic over the pairing, the credential base, the tag and the attribute policy |
//! | §5.1 predicates `f_k`, `EncPred`, the attribute policy `P` | [`pcs::Predicate`], [`pcs::enc_pred`], [`pcs::AttributePolicy`] |
//! | §5.1 `R_att`, `R_issue`, `ctx_j`, `ctx_0` | [`pcs::PCS::attestation_relation`], [`pcs::PCS::issuance_relation`], [`pcs::context`] |
//! | Remark "Chaining and the base case": root credentials | [`pcs::PCS::root_request`], [`pcs::PCS::issue_root`] |
//! | §5.3 sizes of attestations and proofs | [`pcs::codec`] (fixed-format encoding) |
//!
//! Supporting modules: [`error`] (every `⊥` of the paper is an [`Error`]) and
//! [`serialization`] (the byte encoding of protocol objects).
//!
//! ## Getting started
//!
//! [`PCS`] is the credential system; its ten algorithms are the methods of the trait
//! [`PredicateCredentialSystem`] (both live in the module [`pcs`] and are re-exported here, next
//! to [`Error`]). The module docs of [`pcs::construction`] contain a complete
//! flow (root credentials, `Attest`, `Prove`, `Issue`, `Unblind`, `VerifyCred`) for the paper's
//! main instantiation `Σ-PS + Tag_DDH` over BLS12-381; `tests/pcs_correctness.rs` runs it with
//! chaining for every pair, and the benchmarks print the sizes of all objects. The publicly
//! verifiable bases `Σ-PS`, `Σ-BBS` and `Σ-EQ` are supported, each with `Tag_DDH` or `Tag_DY`
//! (`Σ-EQ`: `Tag_DDH` only). The designated-verifier variant of the construction for `Σ-MAC` is
//! not implemented yet; the base itself is.
//!
//! ## Conventions
//!
//! * The paper writes groups multiplicatively (`g^x`); the code is additive (`g * x`). Doc
//!   comments quote the paper's multiplicative formulas.
//! * Pairing-based code is generic over `E: ark_ec::pairing::Pairing`; only
//!   [`hash::bls12_381`] names a concrete curve.
//! * Randomized algorithms take an explicit `rng: &mut R` with
//!   `R: RngCore + CryptoRng + ?Sized` (the traits of `ark_std::rand`, i.e. rand 0.8), so a
//!   trait object works as well as a concrete generator. There is no hidden system RNG.
//! * `⊥` is `Err(`[`Error`]`)` (or `None` for a tag evaluation). Verifiers return `bool` and do
//!   not panic on adversarial input.
//! * Decoding accepts the identity point and the zero scalar, so every non-degeneracy
//!   requirement of the paper (`T ≠ 1`, `σ'_1 ≠ 1`, ...) is an explicit check of the verifier of
//!   the corresponding relation. That covers verification keys too
//!   ([`cred::CredentialBase::is_well_formed_key`]).
//! * The cargo feature `test-utils` (off by default, switched on for `cargo test` by the crate's
//!   dev-dependency on itself) exposes test helpers: the generic conformance flows of
//!   `cred::conformance` and the INSECURE oracle of `hash::testing`.
//!
//! ## Formulas
//!
//! Doc comments quote the paper's formulas as plain text (`g_1^usk`, `e(σ_1, X̃) = …`), which
//! reads in an editor and in every build of the documentation. In addition, the central
//! equations of a module are typeset under the heading "In formulas", e.g. in [`cred::ps`],
//! [`kiprf::ddh`], [`sigma`] and [`pcs::construction`]. Math is written inside code, inline as
//! `` $`…`$ `` and displayed as a code block with the language tag `math`, so that Markdown
//! leaves the LaTeX source alone. `cargo docs` (an alias defined in `.cargo/config.toml`) and
//! docs.rs render it with KaTeX through `docs/katex-header.html`; a plain `cargo doc` shows the
//! LaTeX source instead. A sample: $`T_j = H_2(H_0(id))^{usk_j}`$.
//!
//! ## Limitations
//!
//! * **Research artifact.** Not audited; see the README, "Security". Secret scalars are wiped
//!   on drop where this crate owns them, but field elements are `Copy` and temporaries may stay
//!   on the stack.
//! * **Plain Fiat-Shamir.** Proofs are Fiat-Shamir-compiled sigma protocols in the random-oracle
//!   model; knowledge extraction is by rewinding. Straight-line extractable compilers, the
//!   post-quantum instantiation and the SNARK-based variant of the paper are out of scope.

// docs.rs builds with `--cfg docsrs` on nightly: feature-gated items get an "Available on crate
// feature …" badge. Stable builds never see the attribute.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms, missing_debug_implementations)]
// Naming policy: in struct, trait and type-alias names the acronyms of schemes, primitives and
// assumptions keep the paper's capitalisation (PCS, PS, BBS, EQ, MAC, DY, DDH, KIPRF, FS for
// Fiat-Shamir, DV for designated verifier): `PCS`, `BBS`, `DDH`, `KIPRF`, `FSProof`. The
// instantiations carry the bare acronym, without the paper's `Σ-` / `Tag_` prefix: the credential
// bases are `cred::{PS, BBS, EQ, MAC}`, the tags are `kiprf::{DDH, DY}`, so that a scheme reads
// `PCS<Bls12_381, PS<Bls12_381>, DDH<G1Projective, G1Hasher>>`. Function, module and file names
// stay snake_case / lowercase. clippy would prefer `Bbs`-style names, hence this allowance.
#![allow(clippy::upper_case_acronyms)]

pub mod cred;
pub mod error;
pub mod hash;
pub mod kiprf;
pub mod pcs;
mod sample;
pub mod serialization;
pub mod sigma;

pub use crate::{
    error::Error,
    pcs::{PCS, PredicateCredentialSystem},
};

/// Compiles and runs the Rust code blocks of `README.md` under `cargo test --doc`, so that the
/// examples shown there cannot drift away from the API. Not part of the library.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// The same for the guide `docs/operating-a-helper.md`.
#[cfg(doctest)]
#[doc = include_str!("../docs/operating-a-helper.md")]
pub struct HelperGuideDoctests;
