//! What a planned vetting action still owes the loop, and the runner that
//! does it.
//!
//! A plan ([`super::dispatch::plan`]) decides and makes every state and book
//! change a handler makes before its first save or key lookup. What is left —
//! saving, signing with the persona's keys, handing the send to a background
//! job that claims the vetting domain, and anything planned on the state those
//! leave behind — is a [`VettingEffect`]: steps [`run`] does in order.
//!
//! A step that fails ([`Step::Sign`], [`Step::Send`]) applies its [`Abort`] —
//! the book changes it undoes, then the failure said through
//! [`give_up`] — and the steps after it are not run.

use std::collections::VecDeque;

use crate::state_handler::main_page::status::Status;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::registry::VetterProfileRecord;
use openvtc_core::vetting::wire::Document;

use super::dispatch::{panel, persist, plan_followup, show};
use super::jobs::Sent;
use super::send::{Claim, give_up, send_signed, sign};
use crate::state_handler::background_dispatch::DispatchDomain;
use crate::state_handler::main_page::content::VettingMode;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

/// The steps a planned action still owes, in the order they run.
#[derive(Default)]
pub(super) struct VettingEffect(pub(super) Vec<Step>);

impl VettingEffect {
    /// Nothing more: the plan changed the view, refused, or did nothing.
    pub(super) fn none() -> Self {
        Self::default()
    }

    /// Sign `document` as `persona`, then send it (`sent`, held as `claim`),
    /// after `before`. Either failing applies `abort`.
    pub(super) fn sign_and_send(
        before: impl IntoIterator<Item = Step>,
        persona: PersonaId,
        document: Document,
        sent: Sent,
        claim: Claim,
        abort: Abort,
    ) -> Self {
        let mut steps: Vec<Step> = before.into_iter().collect();
        steps.push(Step::Sign {
            persona,
            document: Box::new(document),
            abort: abort.clone(),
        });
        steps.push(Step::Send {
            sent: Box::new(sent),
            claim,
            abort,
        });
        Self(steps)
    }
}

/// One thing the loop does for a planned action.
pub(super) enum Step {
    /// Save the book, show `message` as done, and log it
    /// ([`persist`]).
    Persist(String),
    /// Mark the config dirty for the coalesced save.
    MarkDirty,
    /// Show a status line.
    Status(Status),
    /// Look up `persona`'s keys and sign `document` with its authentication
    /// key. The runner holds the signed document for the [`Step::Send`] that
    /// follows.
    Sign {
        persona: PersonaId,
        document: Box<Document>,
        abort: Abort,
    },
    /// Hand the document [`Step::Sign`] signed to a background job, held as
    /// `claim` says; a manifest question is filed first
    /// ([`send_signed`]).
    Send {
        sent: Box<Sent>,
        claim: Claim,
        abort: Abort,
    },
    /// Plan the rest on the state and book as the steps before left them.
    Then(Followup),
}

/// A plan made only once the steps before it have run, because it reads what
/// they changed — the page a save re-synced, or the domain a send claimed.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Followup {
    /// An application was started and saved: select its row, then ask its
    /// community what it requires.
    Started { application_id: String },
}

/// How a send that fails before it went out is given up: the book changes
/// undone, in order, then the failure said as `"{what}: {error}"`.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Abort {
    pub(super) what: &'static str,
    pub(super) undo: Vec<Undo>,
}

impl Abort {
    /// Give up saying `what`, with nothing to undo.
    pub(super) fn say(what: &'static str) -> Self {
        Self {
            what,
            undo: Vec::new(),
        }
    }

    /// Give up saying `what`, after undoing `undo` in order.
    pub(super) fn undoing(what: &'static str, undo: Vec<Undo>) -> Self {
        Self { what, undo }
    }

    fn apply(self, state: &mut State, config: &mut Config, error: String) {
        for undo in self.undo {
            undo.apply(state, config);
        }
        give_up(state, config, self.what, error);
    }
}

/// A change a plan made that a send failing before it went out takes back.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Undo {
    /// The request `document_id` of `application_id` was never sent.
    ForgetUnsent {
        application_id: String,
        document_id: String,
    },
    /// The question `document_id` was never asked.
    ForgetQuery(String),
    /// The open directory is not waiting on an answer.
    DirectoryNotPending,
    /// The profile record `previous` stands again for `community` and
    /// `persona`.
    RestoreProfile {
        community: String,
        persona: PersonaId,
        previous: Option<Box<VetterProfileRecord>>,
    },
}

impl Undo {
    fn apply(self, state: &mut State, config: &mut Config) {
        let book = &mut config.private.vetting;
        match self {
            Undo::ForgetUnsent {
                application_id,
                document_id,
            } => {
                if let Some(app) = book.application_by_id_mut(&application_id) {
                    app.forget_unsent(&document_id);
                }
            }
            Undo::ForgetQuery(document_id) => {
                book.forget_query(&document_id);
            }
            Undo::DirectoryNotPending => {
                if let VettingMode::Directory(view) = &mut panel(state).mode {
                    view.pending = None;
                    view.pending_cursors = None;
                }
            }
            Undo::RestoreProfile {
                community,
                persona,
                previous,
            } => book.restore_profile(&community, persona, previous.map(|p| *p)),
        }
    }
}

/// Run `effect`'s steps in order, stopping at the first that gives up.
pub(super) async fn run(ctx: &mut ActionCtx<'_>, effect: VettingEffect) {
    let mut steps: VecDeque<Step> = effect.0.into();
    let mut signed: Option<(PersonaId, Document)> = None;
    while let Some(step) = steps.pop_front() {
        match step {
            Step::Persist(message) => persist(ctx, message),
            Step::MarkDirty => ctx.save.mark_dirty(),
            Step::Status(message) => show(ctx.state, message),
            Step::Sign {
                persona,
                mut document,
                abort,
            } => match sign(ctx, persona, &mut document).await {
                Ok(()) => signed = Some((persona, *document)),
                Err(e) => return abort.apply(ctx.state, ctx.config, e),
            },
            Step::Send { sent, claim, abort } => {
                // A plan builds a send only after its signing
                // ([`VettingEffect::sign_and_send`]), and a failed signing
                // stops the run, so a document is always held here.
                let Some((persona, document)) = signed.take() else {
                    debug_assert!(false, "a vetting send planned without a signing");
                    return;
                };
                if let Err(e) = send_signed(ctx, persona, document, *sent, claim) {
                    return abort.apply(ctx.state, ctx.config, e);
                }
            }
            Step::Then(followup) => {
                let busy = ctx.in_flight.is_busy(DispatchDomain::Vetting);
                let VettingEffect(next) = plan_followup(ctx.state, ctx.config, busy, followup);
                for step in next.into_iter().rev() {
                    steps.push_front(step);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::DirectoryView;
    use crate::state_handler::main_page::status::Severity;
    use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};

    /// Giving up undoes the plan's changes in order, then says why — in the
    /// status line and the activity log.
    #[test]
    fn an_abort_undoes_then_says_why() {
        let mut config = test_config();
        let mut state = State::default();
        config.private.vetting.ask(CommunityQuery {
            document_id: "q1".into(),
            community: "did:web:vtc".into(),
            persona: PersonaId::new(),
            kind: QueryKind::VetterList,
            sent_at: chrono::Utc::now(),
        });
        panel(&mut state).mode = VettingMode::Directory(Box::new(DirectoryView {
            pending: Some("q1".into()),
            pending_cursors: Some(vec![None]),
            ..DirectoryView::default()
        }));

        Abort::undoing(
            "Could not search the directory",
            vec![Undo::ForgetQuery("q1".into()), Undo::DirectoryNotPending],
        )
        .apply(&mut state, &mut config, "no keys".into());

        assert!(config.private.vetting.queries.is_empty());
        let VettingMode::Directory(view) = &panel(&mut state).mode else {
            panic!("the directory stays open");
        };
        assert_eq!(view.pending, None);
        assert_eq!(view.pending_cursors, None);
        let said = panel(&mut state).status_message.clone().unwrap();
        assert_eq!(said.severity, Severity::Error);
        assert_eq!(said.text, "Could not search the directory: no keys");
        assert!(state.main_page.activity_log.iter().any(|e| {
            e.summary
                .contains("Could not search the directory: no keys")
        }));
    }
}
