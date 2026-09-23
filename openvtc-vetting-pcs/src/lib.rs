//! Throwaway prototype of hidden-vetter admission for OpenVTC, built on the Predicate
//! Credential System (PCS). Design: `design-docs/vetting-hidden-vetters-pcs.md`, with the
//! corrections of its §13 applied.
//!
//! What it proves end to end, in memory, with no transport:
//!
//! - the VTC (the PCS *helper*) issues vetter credentials under class labels that carry the
//!   epoch (`vetter/<period>`), from one long-lived `hvk` (§13 C1);
//! - a vetter's `usk` and `id` are stable for life and bound to their member record (C2);
//! - tokens on a constant drip are PS blind signatures on secret serials, under a key separate
//!   from `hvk`, spent once per label (§5.1);
//! - the applicant proves `k` distinct vetters under application contexts, and the VTC turns
//!   the proof into VTI's own `StatementFacts`, counted by VTI's own
//!   `vta_sdk::vetting::requirements::evaluate`, unchanged;
//! - withdrawal by tag, from a sender that need not be named (§4.4).
//!
//! The engines stand in for the VTA (`vetter`, `applicant`: the PCS engine of §13 C7) and the
//! VTC (`vtc`). Nothing here is production code.

pub mod applicant;
pub mod community;
pub mod error;
pub mod issuer;
pub mod meta;
pub mod scheme;
pub mod snapshot;
pub mod token;
pub mod verifier;
pub mod vetter;
pub mod vtc;
pub mod wire;

pub use error::ProtoError;

/// The `rand` the PCS algorithms take — 0.8, because `ark_std::rand` re-exports it and its
/// traits are what the randomized algorithms are written against.
///
/// Re-exported so a consumer on a newer `rand` (`vtc-service` is on 0.9) can still drive the
/// member-side calls that need an RNG, without a second `rand` in its own manifest pinned for
/// reasons that live here.
pub use rand;
