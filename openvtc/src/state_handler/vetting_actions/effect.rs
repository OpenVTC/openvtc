//! What a planned vetting action still owes the loop, and the runner that
//! does it.
//!
//! A plan ([`super::dispatch::plan`]) decides and makes every state and book
//! change a handler makes before its first save or key lookup. What is left —
//! saving, signing with the persona's keys, handing the send to a background
//! job that claims the vetting domain, and anything planned on the state those
//! leave behind — is a [`VettingEffect`]: steps [`run`] does in order.
//!
//! A step that fails ([`Step::Sign`], [`Step::Send`], [`Step::CardKeys`])
//! applies its [`Abort`] — the book changes it undoes, then the failure said
//! through [`give_up`] — and the steps after it are not run, except those
//! marked [`Step::Always`], which follow an action whatever became of it.

use std::collections::VecDeque;

use crate::state_handler::main_page::status::{Severity, Status};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::registry::VetterProfileRecord;
use openvtc_core::vetting::wire::Document;

use super::dispatch::{panel, persist, plan_followup, show};
use super::faces::{CardKeys, FaceWork, card_keys, spawn_face};
use super::jobs::Sent;
use super::send::{Claim, give_up, send_signed, sign};
use crate::state_handler::background_dispatch::DispatchDomain;
use crate::state_handler::main_page::content::VettingMode;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;
// desk and tickets
use super::desk::{
    Asked, BookChange, DeskSnapshot, NamedStatement, deliver_statement, keep_session,
};
use chrono::{DateTime, Utc};
// Hidden vetting
use super::desk::refresh_vetter_side;
use super::pcs::{self, PcsAnswer, PcsStart};
use super::send::{sign_and_send, spawn_send};
use affinidi_tdk::didcomm::Message;

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

    // Faces and the card

    /// Spawn the face job `work`, holding the vetting domain.
    pub(super) fn face(work: FaceWork) -> Self {
        Self(vec![Step::Face {
            work: Box::new(work),
            claim: Claim::Held,
        }])
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
    /// Show a summary of what the steps before it did — unless one of them
    /// left a warning or an error on the status line, which is the real
    /// news and stays.
    Summary(Status),
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
    // Faces and the card
    /// Look up `persona`'s keys for a card ([`card_keys`]). The runner holds
    /// them for the [`Step::Face`] that follows.
    CardKeys { persona: PersonaId, abort: Abort },
    /// Hand a face or card job to the background, against the loop's VTA
    /// session, held as `claim` says ([`spawn_face`]).
    Face { work: Box<FaceWork>, claim: Claim },
    // desk and tickets
    /// Keep the document the [`Step::Sign`] before signed as `request_id`'s
    /// session document, so the saved desk holds it exactly as it goes out
    /// ([`keep_session`]). The runner still holds it for the [`Step::Send`]
    /// that follows.
    KeepSession { request_id: String, abort: Abort },
    /// Sign, record and send a named Vetting Statement
    /// ([`deliver_statement`]): the persona's key lookup, the signing with its
    /// assertion key, the statement's verification, its delivery, the save,
    /// and the send, claiming the domain.
    Statement(Box<NamedStatement>),
    /// Change the book here, in order with the sends around it.
    Book(BookChange),
    /// Sign `document` as `persona` and send it, held as `claim` says, then
    /// apply `then` with how that went. The run goes on either way.
    Ask {
        persona: PersonaId,
        document: Box<Document>,
        sent: Box<Sent>,
        claim: Claim,
        then: Asked,
    },
    // Hidden vetting
    /// Sign `document` as `persona` and send it as the client's own step
    /// ([`Claim::Unheld`]). A failure applies `undo` in order, is said as
    /// `"{failed}: {error}"` in the status line and the activity log, and the
    /// steps after it still run.
    SendOrSay {
        persona: PersonaId,
        document: Box<Document>,
        sent: Box<Sent>,
        failed: &'static str,
        undo: Vec<Undo>,
    },
    /// Hand an unsigned `message` from `from` to `to` to a background job,
    /// held as `claim` says ([`spawn_send`]).
    SendMessage {
        message: Box<Message>,
        from: String,
        to: String,
        sent: Box<Sent>,
        claim: Claim,
    },
    /// Start the job at the VTA [`plan_pcs_work`](super::pcs::plan_pcs_work)
    /// planned, claiming the hidden-vetting domain ([`pcs::start`]). `commit`
    /// is applied once it started; `refused` is said when it did not.
    StartPcs {
        start: PcsStart,
        commit: Option<PcsCommit>,
        refused: Option<Status>,
    },
    /// Run the vetter side's pass: each community's requirements read again,
    /// and what its hidden-vetting schedule owes
    /// ([`refresh_vetter_side`], awaited).
    RefreshVetterSide,
    /// Plan one of a PCS job's answers on the state and book as the steps
    /// before left them ([`pcs::plan_pcs_answer`]), and run its steps next.
    PcsAnswer(Box<PcsAnswer>),
    /// Run the step inside even when a step before it gave up. The steps a
    /// plan makes of it ([`Step::Then`]) are ordinary: one of them giving up
    /// skips the rest of them, but not the `Always` steps after.
    Always(Box<Step>),
}

impl Step {
    /// `step`, run even when a step before it gave up.
    pub(super) fn always(step: Step) -> Self {
        Self::Always(Box::new(step))
    }

    fn runs_always(&self) -> bool {
        matches!(self, Self::Always(_))
    }
}

/// What a started job at the VTA changes on the page.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum PcsCommit {
    /// The VTA is making a hidden attestation: back to the list, saying so.
    Attesting,
}

impl PcsCommit {
    fn apply(self, state: &mut State) {
        match self {
            PcsCommit::Attesting => {
                panel(state).mode = VettingMode::List;
                show(
                    state,
                    Status::progress("Your VTA is making the attestation — it names nobody…"),
                );
            }
        }
    }
}

/// A plan made only once the steps before it have run, because it reads what
/// they changed — the page a save re-synced, or the domain a send claimed.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Followup {
    /// An application was started and saved, saying `started`: select its
    /// row, then ask its community what it requires.
    Started {
        application_id: String,
        started: String,
    },
    // desk and tickets
    /// A session's signed document is kept: close the form, save saying the
    /// match code, and send it — a send that cannot start puts the request
    /// back to `previous`.
    SessionKept {
        request_id: String,
        known: bool,
        previous: DeskSnapshot,
    },
    /// Ask `community` for its manifest as `persona`, unless the questions
    /// before this one just did.
    AskManifest {
        community: String,
        persona: PersonaId,
    },
    /// Ask `community` which key it bound `persona` to, as of `now`.
    AskBinding {
        community: String,
        persona: PersonaId,
        now: DateTime<Utc>,
    },
    // Hidden vetting
    /// Ask the community of hidden-vetting application `application_id` for a
    /// submission challenge; quietly when the status line changed since
    /// `said_before` to a warning or an error, which stays.
    AskChallenge {
        application_id: String,
        said_before: Option<Status>,
    },
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

    /// Undo, then say why. A plan whose own build fails after it changed the
    /// book gives up through this too, so a failure takes back exactly what
    /// was changed for the attempt, whichever step it fails at.
    pub(super) fn apply(
        self,
        state: &mut State,
        config: &mut Config,
        error: impl std::fmt::Display,
    ) {
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
    // desk and tickets
    /// The desk request `request_id` stands where it stood again.
    RestoreDesk {
        request_id: String,
        previous: DeskSnapshot,
    },
    /// The withdrawal of statement `0` was never sent.
    NotWithdrawn(String),
    /// The draw `0` was never sent, so it is not in flight.
    NotDrawing(String),
    /// Application `0` keeps no VTA context: the one derived for a job that
    /// never started is not kept.
    NoContext(String),
    /// The page has not asked community `0` what it requires: the question
    /// never went, so the next session asks again.
    NotRequested(String),
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
            // desk and tickets
            Undo::RestoreDesk {
                request_id,
                previous,
            } => {
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = *previous.0;
                }
            }
            Undo::NotWithdrawn(statement_id) => {
                if let Some(s) = book.issued.iter_mut().find(|s| s.id == statement_id) {
                    s.withdrawal = None;
                }
            }
            Undo::NotDrawing(document_id) => {
                book.draws_in_flight.remove(&document_id);
            }
            Undo::NoContext(application_id) => {
                if let Some(app) = book.application_by_id_mut(&application_id) {
                    app.context_id = None;
                }
            }
            Undo::NotRequested(community) => {
                panel(state)
                    .requirements_requested
                    .retain(|c| *c != community);
            }
        }
    }
}

/// Run `effect`'s steps in order. A step that gives up skips every step after
/// it but the [`Step::Always`] ones.
pub(super) async fn run(ctx: &mut ActionCtx<'_>, effect: VettingEffect) {
    let mut steps: VecDeque<Step> = effect.0.into();
    // What is left once a step gave up: only the steps that run regardless.
    let gave_up = |steps: &mut VecDeque<Step>| steps.retain(Step::runs_always);
    let mut signed: Option<(PersonaId, Document)> = None;
    let mut keys: Option<CardKeys> = None;
    let said_before = panel(ctx.state).status_message.clone();
    while let Some(step) = steps.pop_front() {
        match step {
            Step::Persist(message) => persist(ctx, message),
            Step::MarkDirty => ctx.save.mark_dirty(),
            Step::Status(message) => show(ctx.state, message),
            Step::Summary(message) => summarise(ctx.state, said_before.as_ref(), message),
            Step::Sign {
                persona,
                mut document,
                abort,
            } => match sign(ctx, persona, &mut document).await {
                Ok(()) => signed = Some((persona, *document)),
                Err(e) => {
                    abort.apply(ctx.state, ctx.config, e);
                    gave_up(&mut steps);
                }
            },
            Step::Send { sent, claim, abort } => {
                // A plan builds a send only after its signing
                // ([`VettingEffect::sign_and_send`]), and a failed signing
                // stops the run, so a document is always held here.
                let Some((persona, document)) = signed.take() else {
                    debug_assert!(false, "a vetting send planned without a signing");
                    gave_up(&mut steps);
                    continue;
                };
                if let Err(e) = send_signed(ctx, persona, document, *sent, claim) {
                    abort.apply(ctx.state, ctx.config, e);
                    gave_up(&mut steps);
                }
            }
            Step::Then(followup) => {
                let busy = ctx.in_flight.is_busy(DispatchDomain::Vetting);
                let VettingEffect(next) = plan_followup(ctx.state, ctx.config, busy, followup);
                for step in next.into_iter().rev() {
                    steps.push_front(step);
                }
            }
            // Faces and the card
            Step::CardKeys { persona, abort } => match card_keys(ctx, persona).await {
                Ok(found) => keys = Some(found),
                Err(e) => {
                    abort.apply(ctx.state, ctx.config, e);
                    gave_up(&mut steps);
                }
            },
            Step::Face { work, claim } => {
                // A plan builds a face job only when the loop held a VTA
                // session, and the session is not dropped within an arm.
                let Some(client) = ctx.admin_vta.cloned() else {
                    debug_assert!(false, "a face job planned without a VTA session");
                    gave_up(&mut steps);
                    continue;
                };
                spawn_face(ctx, client, *work, keys.take(), claim);
            }
            // desk and tickets
            Step::KeepSession { request_id, abort } => {
                // As with `Send`: a plan keeps a session only after its signing.
                let Some((_, document)) = signed.as_ref() else {
                    debug_assert!(false, "a session kept without a signing");
                    gave_up(&mut steps);
                    continue;
                };
                if let Err(e) = keep_session(ctx.config, &request_id, document) {
                    abort.apply(ctx.state, ctx.config, e);
                    gave_up(&mut steps);
                }
            }
            Step::Statement(statement) => deliver_statement(ctx, *statement).await,
            Step::Book(change) => change.apply(ctx.config),
            Step::Ask {
                persona,
                mut document,
                sent,
                claim,
                then,
            } => {
                let result = match sign(ctx, persona, &mut document).await {
                    Ok(()) => send_signed(ctx, persona, *document, *sent, claim),
                    Err(e) => Err(e),
                };
                match result {
                    Ok(()) => then.went(ctx.state, ctx.config),
                    Err(e) => then.failed(ctx.state, ctx.config, e),
                }
            }
            // Hidden vetting
            Step::SendOrSay {
                persona,
                document,
                sent,
                failed,
                undo,
            } => {
                if let Err(e) = sign_and_send(ctx, persona, *document, *sent, Claim::Unheld).await {
                    for undo in undo {
                        undo.apply(ctx.state, ctx.config);
                    }
                    let message = format!("{failed}: {e}");
                    tracing::warn!("{message}");
                    ctx.state.main_page.log(message.clone());
                    show(ctx.state, Status::error(message));
                }
            }
            Step::SendMessage {
                message,
                from,
                to,
                sent,
                claim,
            } => spawn_send(ctx, *message, &from, &to, *sent, claim),
            Step::StartPcs {
                start,
                commit,
                refused,
            } => {
                if pcs::start(ctx, start) {
                    if let Some(commit) = commit {
                        commit.apply(ctx.state);
                    }
                } else if let Some(refused) = refused {
                    show(ctx.state, refused);
                }
            }
            // Boxed: the pass is a long future of its own, and boxing keeps
            // this one small should the pass ever run an effect in turn.
            Step::RefreshVetterSide => Box::pin(refresh_vetter_side(ctx)).await,
            Step::PcsAnswer(answer) => {
                let VettingEffect(next) = pcs::plan_pcs_answer(ctx.state, ctx.config, *answer);
                for step in next.into_iter().rev() {
                    steps.push_front(step);
                }
            }
            Step::Always(step) => steps.push_front(*step),
        }
    }
}

/// Show `summary`, unless the status line changed since `said_before` to a
/// warning or an error ([`Step::Summary`]).
fn summarise(state: &mut State, said_before: Option<&Status>, summary: Status) {
    if !warned_since(state, said_before) {
        show(state, summary);
    }
}

/// Whether the status line changed since `said_before` to a warning or an
/// error: news a later word must not cover.
pub(super) fn warned_since(state: &mut State, said_before: Option<&Status>) -> bool {
    let now = panel(state).status_message.as_ref();
    now != said_before
        && now.is_some_and(|s| matches!(s.severity, Severity::Warning | Severity::Error))
}

/// Run an effect of local steps — [`Step::Persist`], [`Step::MarkDirty`],
/// [`Step::Status`] — without awaiting, for a plan made inside a synchronous
/// pass ([`hidden_vetting_tick`](super::hidden::hidden_vetting_tick)).
pub(super) fn run_local(ctx: &mut ActionCtx<'_>, effect: VettingEffect) {
    for step in effect.0 {
        match step {
            Step::Persist(message) => persist(ctx, message),
            Step::MarkDirty => ctx.save.mark_dirty(),
            Step::Status(message) | Step::Summary(message) => show(ctx.state, message),
            _ => debug_assert!(false, "a step that awaits, run without awaiting"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::DirectoryView;
    use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};

    /// A summary is said over what was there before and over progress, but
    /// not over a warning or an error the steps before it left.
    #[test]
    fn a_summary_does_not_cover_a_warning_said_before_it() {
        let mut state = State::default();
        let summary = Status::info("summary");
        let stale = Status::error("from an earlier action");

        panel(&mut state).status_message = Some(stale.clone());
        summarise(&mut state, Some(&stale), summary.clone());
        assert_eq!(panel(&mut state).status_message, Some(summary.clone()));

        panel(&mut state).status_message = Some(Status::progress("working"));
        summarise(&mut state, None, summary.clone());
        assert_eq!(panel(&mut state).status_message, Some(summary.clone()));

        let failed = Status::error("could not ask");
        panel(&mut state).status_message = Some(failed.clone());
        summarise(&mut state, None, summary);
        assert_eq!(panel(&mut state).status_message, Some(failed));
    }

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
        .apply(&mut state, &mut config, "no keys");

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
