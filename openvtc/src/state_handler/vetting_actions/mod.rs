//! The Vetting page: applying to be vetted, and vetting others
//! (`docs/design/vetting-process.md` §12).
//!
//! State and sequencing live in `openvtc_core::vetting`. This module maps the
//! page's actions onto the book, signs what has to be sent on the loop (the
//! keys are local, so signing is quick), and hands the send itself to a
//! background job. A send that fails puts the book back the way it was, so the
//! step can simply be tried again.

mod answers;
mod applicant;
mod desk;
mod dispatch;
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
