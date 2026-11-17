//! The Vetting page: applying to be vetted, and vetting others
//! (`docs/design/vetting-process.md` §12).
//!
//! State and sequencing live in `openvtc_core::vetting`. This module maps the
//! page's actions onto the book, signs what has to be sent on the loop (the
//! keys are local, so signing is quick), and hands the send itself to a
//! background job. A send that fails puts the book back the way it was, so the
//! step can simply be tried again.
//!
//! # Reducer and effect
//!
//! [`dispatch()`] offers each action to `dispatch::reduce` (view-only: it
//! changes the page and at most reads the book), then to `dispatch::plan`,
//! which is pure — no `.await`, no spawning, no saving. A plan:
//!
//! 1. reads `busy` (whether a vetting job holds [`DispatchDomain::Vetting`](crate::state_handler::background_dispatch::DispatchDomain::Vetting),
//!    sampled once by the loop) and refuses with `send::claimable` before it
//!    prepares anything, in the place the handler's busy check stands;
//! 2. makes, on `&mut State` and `&mut Config`, exactly the changes the
//!    handler makes before its first save or key lookup — the book entries
//!    recorded, the questions filed, the mode and status set — and gives up
//!    on a build failure with `send::give_up` (log, re-sync, error status);
//! 3. returns an `effect::VettingEffect`: the ordered `effect::Step`s left.
//!
//! The book changes are made in the plan rather than returned as steps
//! because what they return (a request body, the record a profile replaces)
//! is what the document is built from, and because they stand where the
//! handler made them: after the busy check, before any save or signing.
//!
//! `effect::run` does the steps in order: `Persist` (save and sync, showing
//! and logging the message), `MarkDirty`, `Status`, `Sign` (the persona's key
//! lookup and the signing, holding the signed document), `Send` (the signed
//! document to a `SendJob`, filing a manifest question first, claimed through
//! `background_dispatch::dispatch` for `Claim::Held` or `spawn_unclaimed` for
//! `Claim::Unheld`), and `Then` (a `Followup` planned on the state the steps
//! before left, with `busy` sampled again). A `Sign` or `Send` that fails
//! applies its `Abort` — each `Undo` in order, then `give_up` with its
//! `what` — and the run stops there.
//!
//! Hidden vetting's steps are the client's own: `SendOrSay` (signed and sent
//! unheld; a failure is said and the run goes on), `SendMessage` (an unsigned
//! message), `StartPcs` (a job at the VTA, its `PcsCommit` applied once it
//! started), `RefreshVetterSide` (the vetter pass, awaited), and `PcsAnswer`
//! (one of a PCS job's answers, planned when it is reached, like `Then`).
//!
//! # Planning a handler still on the loop
//!
//! What stays on the loop is handled by `dispatch::on_loop`
//! with the `send` helpers (`begin`, `abandon`, `sign_and_send`, `spawn`),
//! which do the same things the plan and the runner do. To plan one:
//!
//! - Pin it first, in `runtime/tests/vetting.rs` under its own heading: the
//!   busy refusal, the key-lookup failure (a persona whose `key_info` is
//!   cleared), and the claimed send, settled through `dispatch_rx`.
//! - Write `plan_<handler>(state, config, busy, ..) -> VettingEffect`:
//!   `ctx.config` becomes `config`, `page(ctx)` / `status(ctx, ..)` become
//!   `panel(state)` / `show(state, ..)`, `begin(ctx)` becomes
//!   `claimable(state, busy)`, `abandon(ctx, ..)` becomes `give_up(state,
//!   config, ..)` followed by `return VettingEffect::none()`.
//! - `persist(ctx, m)` becomes `Step::Persist(m)`, `ctx.save.mark_dirty()`
//!   `Step::MarkDirty`, a status set after either `Step::Status`, and a
//!   `sign_and_send` with its error branch
//!   `VettingEffect::sign_and_send(before, persona, document, sent, claim,
//!   Abort::undoing(what, undo))`, where `before` holds the steps that precede
//!   it and `undo` replays the error branch's book changes as `Undo` variants
//!   (add one where none fits).
//! - A handler that keeps the document it signed — `desk::open_session`
//!   records it into the book before saving — is `Step::Sign`, then a new
//!   step that records the held document (its failure an `Abort` like the
//!   signing's), then `Step::Then` with a `Followup` that reads what was
//!   recorded and returns `[Step::Persist(..), Step::Send { .. }]`. The held
//!   document is kept by the runner from `Sign` to `Send`.
//! - Work that is not a signed document send (a face job, a PCS job) is a new
//!   step that spawns it with the same `Claim`, as `Step::Face` does for the
//!   face and card jobs. A loop-side helper still awaited after a plan
//!   (`refresh_vetter_side`) is run by the `on_loop` arm after `effect::run`,
//!   as `RefreshRequirements` does, or as a `Step::RefreshVetterSide` among
//!   the plan's steps.
//! - Route the action (or the view's Enter, in `plan_submit`) to the plan, and
//!   move its arm in `on_loop` / `submit` to the "planned" list.
//!
//! A step is added only when a handler needs it.

mod answers;
mod applicant;
mod desk;
mod dispatch;
mod effect;
mod faces;
mod hidden;
mod jobs;
mod outcome;
mod pcs;
mod send;
#[cfg(test)]
mod test_support;
mod tickets;
mod vetter;
mod view_sync;
mod words;

pub(crate) use answers::{
    GrantChecked, apply_answers, expire_queries, focus_application, focus_vetting_target,
    spawn_grant_check,
};
pub(crate) use desk::{desk_open, refresh_stale_modes};
pub(crate) use dispatch::dispatch;
#[cfg(test)]
pub(crate) use jobs::Sent;
pub(crate) use outcome::VettingOutcome;
pub(crate) use pcs::{apply_pcs_outcome, pcs_work_due, start_pcs_work};
pub(crate) use tickets::settle_pending_tickets;
pub(crate) use view_sync::sync;
pub(crate) use words::{community_display, joining_standing, next_step_words, progress_line};
