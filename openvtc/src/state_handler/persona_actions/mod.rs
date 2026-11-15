//! Identity-pane business logic: what each key does to the pane's state, and
//! which of them need the agent.
//!
//! Split the way the architecture asks for it. [`apply`] is pure — it takes
//! `&mut State` and an action, mutates the pane, and *names* any network work
//! as a [`PersonaEffect`] rather than doing it. The loop spawns that off-thread
//! and folds the result back in through [`PersonaOutcome::apply`], on the loop
//! thread, so the single-mutator invariant holds and every decision this module
//! makes is testable without a `VtaClient`.
//!
//! # One domain for the whole pane
//!
//! Reads and writes share one dispatch domain
//! ([`DispatchDomain::PersonaManage`](crate::state_handler::background_dispatch::DispatchDomain::PersonaManage)),
//! so a listing cannot overtake the write that invalidated it. A write asks for a re-read by
//! setting `refresh_queued` rather than starting one, because its own outcome
//! is still holding the domain — the same shape the VIC manager uses.
//!
//! # The words, and where they change
//!
//! This module is engineering-side: it keeps the spec's nouns
//! (`attribute`, `profile`, `binding`), because those are what it addresses on
//! the wire. The strings it *hands to the panel* — status lines, refusals — use
//! the vocabulary a person reads (`design-docs/persona-vocabulary.md`): an attribute,
//! a face, wearing one.
//!
//! # Questions are asked once, and correctly
//!
//! Deleting an attribute a profile references is refused by the VTA unless the
//! caller cascades; deleting a profile a persona presents is refused unless the
//! caller unbinds. Neither refusal is *discovered* here. The profile listing
//! already says which attributes are referenced and the binding map already
//! says which profiles are presented, so the prompt names the real consequence
//! the first time it is put. Asking "delete this?", being refused, and then
//! asking "delete it and edit three profiles?" trains a holder to answer the
//! second question with the first one's reasoning.

mod form;
mod jobs;
mod outcome;
mod reducer;
#[cfg(test)]
mod test_support;

pub(crate) use form::release_form;
pub(crate) use reducer::{PersonaEffect, apply};
// Only a doc link outside the module names it (`main_page::content`).
#[cfg(doc)]
pub(crate) use jobs::DISCLOSURE_PAGE;
pub(crate) use jobs::{PersonaJobRun, PersonaReadJob};
pub(crate) use outcome::PersonaOutcome;
