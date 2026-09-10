//! The holder's own identity — the personas, the attributes behind them, and what each
//! persona presents where.
//!
//! # Two meanings of "persona", and they compose
//!
//! [`config::account::PersonaRecord`](crate::config::account::PersonaRecord) is
//! a persona as an *identity*: a `did:webvh`, its keys, its mediator. That record
//! is local, and the TUI has always been able to mint one.
//!
//! The agent's `persona/*` Trust Tasks use the same word one layer up: a pool
//! of identity attributes, named projections over that pool ([`profile`]), and
//! the assignment of a projection to a persona DID within one trust context
//! ([`binding`]). Those live in the VTA, not in `Config`, and every function
//! here is a round-trip to it.
//!
//! [`claim_types`] is the table the other three resolve against — how a value
//! is shown, and what it takes to let it leave. It is **read from the agent**
//! like everything else here (`persona/claim-types/list`, VTI #1315); the
//! compiled copy it used to be survives only as the answer for an agent too old
//! to serve one. Its header says what that is worth and what it is not.
//!
//! This crate holds the persona; the agent holds what the persona says. They join on
//! the `(context_id, persona_did)` pair every community membership already
//! carries.
//!
//! # The boundary this module sits astride
//!
//! [`pool`], [`profile`] and [`disclosure`] are **holder-scoped**: they read
//! across every trust context and the VTA gates them on *unrestricted*
//! authority. [`binding`] is **context-scoped**. That asymmetry is the design, not an accident of the
//! API — the holder pushes a materialised projection down into a context, and a
//! context never pulls from the pool. Everything in [`binding`] therefore names
//! a context; nothing in [`pool`] or [`profile`] can.
//!
//! An OpenVTC operator holds the account's admin credential, which is
//! unrestricted, so all three work from the TUI. A caller holding anything
//! narrower will see `e.p.msg.forbidden` from the holder-scoped half, and that
//! is the boundary working rather than a misconfiguration.
//!
//! # Reads are best-effort; writes are not
//!
//! A read failure must never stop OpenVTC starting or a panel drawing — a
//! membership works whether or not we can say what it presents, and
//! [`binding::BindingSummary::unknown`] is the honest thing to draw while we
//! cannot. A *write* is a decision the operator just made about their own
//! identity, so it returns its error and the panel says so.

pub mod binding;
pub mod claim_types;
pub mod disclosure;
pub mod facet;
pub mod family;
pub mod pool;
pub mod profile;
