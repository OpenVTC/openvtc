//! Peer identity vetting — the client half of `docs/design/vetting-process.md`.
//!
//! Someone who wants to join a community is vetted by members the community
//! trusts to do it. The applicant shows each vetter a signed card of who they
//! say they are; the vetter checks it against the person and their documents
//! and signs a statement; the applicant presents the statements with their join
//! request, and the community's policy decides.
//!
//! This is the Linux kernel's web of trust with the keyring taken out: no
//! public graph of who vouched for whom, no signing parties, and a community
//! policy — not a path length through strangers' keys — deciding what is enough.
//!
//! - [`book`] — everything persisted, in `ProtectedConfig::vetting`.
//! - [`tickets`] — how a vetter lets someone ask them, and how everyone else is
//!   ignored (design §8).
//! - [`applicant`] — one application per community and persona: requests out,
//!   sessions and statements in, and the advisory checklist.
//! - [`vetter`] — the vetter desk: requests in, sessions out, the card check,
//!   the statement, declines and withdrawals.
//! - [`wire`] — the Trust Task documents and DIDComm messages on the peer path.
//! - [`inbound`] — routing an inbound message to the right side.
//! - [`queries`] — questions put to a community (manifest, directory, profile,
//!   resend), matched to their answers.
//! - [`registry`] — the vetter directory and a vetter's published profile.
//! - [`guide`] — a community's requirements in plain words.
//! - [`status`] — whether the community has revoked a vetter's grant.
//!
//! Every artifact's shape, signature and verification is vta-sdk's
//! (`protocols::vetting`, and `vetting` behind the feature of that name). This
//! module owns state and sequencing only; it never re-implements a check the
//! SDK makes.

/// Carry a generated vocabulary value into another specification's copy of it.
///
/// `trust-tasks-codegen` generates the vetting vocabulary **per specification**:
/// `VettingMethod` exists in `join-requests/manifest/0.2`, `vetting/request/0.1`,
/// `vetting/session/0.1`, `vetters/profile/0.1` and `vetters/list/0.1` as five
/// distinct Rust types with the same variants and the same wire tokens, and
/// `VettingDocumentation`, `ClaimType`, `CountryCode`, `PlaceName`,
/// `LanguageTag` and `CalendarDate` are duplicated the same way. They do not
/// unify, so a method chosen on the Vetting page cannot be handed straight to a
/// session payload.
///
/// This carries a value across by the token both spell — the only thing the two
/// copies agree on, and the thing that actually travels. It converts between
/// two generated types; it does not restate either of them.
///
/// This repo keeps one of each in its own state (the manifest's, which is the
/// vocabulary a community publishes) and converts at each task boundary.
pub(crate) fn same_token<A, B>(value: &A) -> Result<B, B::Err>
where
    A: std::fmt::Display,
    B: std::str::FromStr,
{
    value.to_string().parse()
}

pub mod applicant;
pub mod book;
pub mod guide;
pub mod inbound;
pub mod queries;
pub mod registry;
pub mod status;
pub mod tickets;
pub mod vetter;
pub mod wire;

#[cfg(test)]
mod tests;

pub use book::VettingBook;
