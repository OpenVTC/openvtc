//! The Elections panel: a community's elections, from the member's side.
//!
//! Opened from Communities with `e`. Three parties, three lanes, none of them the loop:
//!
//! - the **community** — `vtc/elections/{list,show,tickets/issue}`, signed with the persona's
//!   key and sent on its channel in [`DispatchDomain::Elections`], exactly as the Rooms panel
//!   sends `vtc/rooms/*`; the answer arrives on the inbound channel and [`apply_replies`]
//!   matches it by thread;
//! - the member's **VTA**, which holds every voter key — register, accept, vote, keep the
//!   receipt — in [`DispatchDomain::ElectionsVta`];
//! - the **ballot box**, over HTTPS from this client's own connection after a random pause, in
//!   [`DispatchDomain::ElectionsCast`]. Nothing about a ballot, a cast or a receipt goes to the
//!   community ([`openvtc_core::elections`]).
//!
//! **Taking a ticket and voting are separate.** The community knows when it issued a member's
//! ticket and the ballot box when a cast arrived, so a vote cast straight after its ticket
//! could be paired with it by the two clocks. Voting with no ticket held takes the ticket and
//! stops, asking the member to come back later; the ballot screen warns when this app took the
//! ticket less than an hour ago.
//!
//! Each step's answer sets the view's [`Next`]; [`advance`], which the loop calls after
//! applying replies and outcomes and on its tick, takes it. Every step answers a repeat with
//! its first answer, so an interrupted ticket or vote is finished by starting it again; a cast
//! whose answer was lost is resent **unchanged** (`r` on the result), never rebuilt.

use std::time::{Duration, Instant};

use affinidi_tdk::TDK;
use openvtc_core::capabilities::{RequestDocument, correlation_thread};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::elections::{
    self, Cast, CastError, Kept, Registered, Reply, Request, ShownElection, VerifiedReceipt, Voter,
};
use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::ElectionsAction as Act;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::elections::{
    BallotForm, ElectionsPhase, ElectionsView, Flow, Intent, Next, Pending, Purpose, Screen,
    Severity, Step, VoteResult,
};
use crate::state_handler::repos_actions::{Sender, sender};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

const SEND: DispatchDomain = DispatchDomain::Elections;
const VTA: DispatchDomain = DispatchDomain::ElectionsVta;
const CAST: DispatchDomain = DispatchDomain::ElectionsCast;

/// How long a request waits for the community's answer (R1.2).
pub(crate) const REPLY_WINDOW: Duration = Duration::from_secs(30);

/// A `vtc/elections/*` answer as it arrived.
pub(crate) struct InboundReply {
    /// The transport-authenticated sender.
    pub(crate) from: String,
    /// The document's `issuer`.
    pub(crate) issuer: Option<String>,
    pub(crate) thid: String,
    pub(crate) reply: Reply,
}

fn did_part(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

fn view_mut(state: &mut State) -> Option<&mut ElectionsView> {
    state.main_page.content_panel.elections.view.as_mut()
}

// ****************************************************************************
// View-only changes
// ****************************************************************************

/// Apply a view-only action. `false` for the actions the runtime loop services.
pub(crate) fn reduce(state: &mut State, action: &Act) -> bool {
    let panel = &mut state.main_page.content_panel.elections;
    let Some(view) = panel.view.as_mut() else {
        return !matches!(action, Act::Open(_));
    };
    match action {
        Act::Open(_)
        | Act::Refresh
        | Act::Show
        | Act::TakeTicket
        | Act::Vote
        | Act::Cast
        | Act::Resend => return false,
        Act::Back => match view.screen {
            Screen::List => panel.view = None,
            Screen::Detail => {
                view.screen = Screen::List;
                view.shown = None;
                view.flow = None;
                view.status = None;
            }
            Screen::Ballot => {
                view.drop_ballot();
                view.screen = Screen::Detail;
            }
            Screen::Confirm => view.screen = Screen::Ballot,
            Screen::Result => {
                view.result = None;
                view.screen = Screen::Detail;
            }
        },
        Act::Select(i) => {
            view.selected = (*i).min(view.elections.len().saturating_sub(1));
        }
        Act::BallotQuestion(d) => {
            if let Some(f) = view.form.as_mut() {
                f.move_question(*d);
            }
        }
        Act::BallotOption(d) => {
            if let (Some(f), Some(s)) = (view.form.as_mut(), view.shown.as_ref()) {
                f.move_option(s.manifest(), *d);
            }
        }
        Act::BallotToggle => {
            if let (Some(f), Some(s)) = (view.form.as_mut(), view.shown.as_ref()) {
                f.toggle(s.manifest());
            }
        }
        Act::BallotAdjust(d) => {
            if let (Some(f), Some(s)) = (view.form.as_mut(), view.shown.as_ref()) {
                f.adjust(s.manifest(), *d);
            }
        }
        Act::BallotChar(c) => {
            if let (Some(f), Some(s)) = (view.form.as_mut(), view.shown.as_ref()) {
                f.type_char(s.manifest(), *c);
            }
        }
        Act::BallotBackspace => {
            if let Some(f) = view.form.as_mut() {
                f.backspace();
            }
        }
        Act::BallotAbstain => {
            if let (Some(f), Some(s)) = (view.form.as_mut(), view.shown.as_ref()) {
                f.toggle_abstain(s.manifest());
            }
        }
        Act::Review => review(view),
    }
    true
}

/// Check the ballot; when it passes, show it for confirmation.
fn review(view: &mut ElectionsView) {
    let (Some(form), Some(shown)) = (view.form.as_mut(), view.shown.as_ref()) else {
        return;
    };
    let ballot = form
        .draft
        .to_ballot(shown.election_id(), shown.manifest_digest());
    match elections::check_ballot(shown.manifest(), shown.manifest_digest(), &ballot) {
        Ok(()) => {
            form.error = None;
            view.screen = Screen::Confirm;
        }
        Err(e) => form.error = Some(capitalise(&e.to_string())),
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

// ****************************************************************************
// The loop's side
// ****************************************************************************

/// What a send or a VTA call needs from the loop.
pub(crate) struct Loop<'a> {
    pub(crate) state: &'a mut State,
    pub(crate) config: &'a Config,
    pub(crate) tdk: &'a TDK,
    pub(crate) vta: Option<&'a VtaClient>,
    pub(crate) dispatch_tx: &'a UnboundedSender<DispatchOutcome>,
    pub(crate) in_flight: &'a mut InFlight,
}

impl Loop<'_> {
    /// Send `request` to the open view's community, armed on `purpose`. Returns whether it was
    /// dispatched; every early return says why in the view.
    async fn send(&mut self, request: Request, purpose: Purpose) -> bool {
        let Some((vtc_did, persona, waiting)) = self
            .state
            .main_page
            .content_panel
            .elections
            .view
            .as_ref()
            .map(|v| (v.vtc_did.clone(), v.persona, v.pending.is_some()))
        else {
            return false;
        };
        if waiting {
            return false;
        }
        let sender = match sender(self.config, self.tdk, persona, &vtc_did).await {
            Ok(s) => s,
            Err(e) => {
                fail(self.state, &purpose, e);
                return true;
            }
        };
        let doc = match elections::build(&request, &sender.persona_did, &vtc_did) {
            Ok(doc) => doc,
            Err(e) => {
                fail(self.state, &purpose, format!("couldn't send: {e}"));
                return true;
            }
        };
        if !self.in_flight.try_begin(SEND) {
            return false;
        }
        let thid = correlation_thread(&doc).to_string();
        if let Some(view) = view_mut(self.state) {
            view.pending = Some(Pending {
                thid,
                sent_at: Instant::now(),
                purpose,
            });
        }
        let job = SendJob {
            sender,
            vtc_did,
            persona,
            doc,
        };
        background_dispatch::spawn_dispatch(self.dispatch_tx.clone(), SEND, async move {
            DispatchOutcome::Elections(job.run().await)
        });
        true
    }

    /// Ask the VTA. Returns whether it was dispatched (or failed in a way the view now shows).
    fn ask_vta(&mut self, ask: VtaAsk) -> bool {
        let Some((vtc_did, persona)) = self
            .state
            .main_page
            .content_panel
            .elections
            .view
            .as_ref()
            .map(|v| (v.vtc_did.clone(), v.persona))
        else {
            return true;
        };
        let Some(vta) = self.vta.cloned() else {
            end_flow(
                self.state,
                Severity::Error,
                "Voting needs your VTA: it holds the voter keys and the ticket. None is \
                 connected.",
            );
            return true;
        };
        let Some(context_id) = persona_context(self.config, persona) else {
            end_flow(
                self.state,
                Severity::Error,
                "This persona has no VTA context to hold its voter keys.",
            );
            return true;
        };
        if !self.in_flight.try_begin(VTA) {
            return false;
        }
        background_dispatch::spawn_dispatch(self.dispatch_tx.clone(), VTA, async move {
            let voter = Voter {
                vta: &vta,
                context_id: &context_id,
                community: &vtc_did,
            };
            let answer = ask.run(&voter).await;
            DispatchOutcome::ElectionsVta(ElectionsVtaOutcome {
                vtc_did,
                persona,
                answer,
            })
        });
        true
    }

    /// Send the cast to the ballot box, after a random pause.
    fn deliver(&mut self, cast: Cast) -> bool {
        let Some((vtc_did, persona, ballot_box)) = self
            .state
            .main_page
            .content_panel
            .elections
            .view
            .as_ref()
            .and_then(|v| {
                v.shown
                    .as_ref()
                    .map(|s| (v.vtc_did.clone(), v.persona, s.ballot_box().to_string()))
            })
        else {
            return true;
        };
        if !self.in_flight.try_begin(CAST) {
            return false;
        }
        let resolver = self.tdk.did_resolver().clone();
        background_dispatch::spawn_dispatch(self.dispatch_tx.clone(), CAST, async move {
            let result =
                elections::deliver_cast(&resolver, &ballot_box, &cast, elections::cast_delay())
                    .await;
            DispatchOutcome::ElectionsCast(Box::new(ElectionsCastOutcome {
                vtc_did,
                persona,
                cast,
                result,
            }))
        });
        true
    }

    /// Read the list again.
    pub(crate) async fn refresh(&mut self) {
        match view_mut(self.state) {
            Some(view) => view.restart_pages(),
            None => return,
        }
        self.send(Request::List { cursor: None }, Purpose::List)
            .await;
    }
}

/// The context the persona's keys — and so its voter keys — are derived in.
fn persona_context(config: &Config, persona: PersonaId) -> Option<String> {
    let top = config.account.top_context_id.as_str();
    config
        .account
        .personas
        .get(&persona)
        .map(|p| openvtc_core::config::community_context::persona_context(p, top).to_string())
}

/// End the ticket or vote in progress, saying why.
fn end_flow(state: &mut State, severity: Severity, why: impl Into<String>) {
    if let Some(view) = view_mut(state) {
        view.flow = None;
        view.next = None;
        view.note(severity, why);
    }
}

/// Say a request never left, where the view shows it.
fn fail(state: &mut State, purpose: &Purpose, why: String) {
    let Some(view) = view_mut(state) else {
        return;
    };
    match purpose {
        Purpose::List if view.elections.is_empty() => view.phase = ElectionsPhase::Failed(why),
        Purpose::List | Purpose::Show { .. } | Purpose::Issue { .. } => {
            view.flow = None;
            view.note(Severity::Error, why);
        }
    }
}

/// Service an action that reads the config or sends.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: Act) {
    if let Act::Open(index) = action {
        open(ctx, index);
    }
    let mut lp = Loop {
        state: &mut *ctx.state,
        config: ctx.config,
        tdk: ctx.tdk,
        vta: ctx.admin_vta,
        dispatch_tx: ctx.dispatch_tx,
        in_flight: &mut *ctx.in_flight,
    };
    match action {
        Act::Open(_) => {
            if let Some(view) = view_mut(lp.state) {
                view.phase = ElectionsPhase::Loading;
            }
            lp.refresh().await;
        }
        Act::Refresh => refresh_screen(&mut lp).await,
        Act::Show => show_selected(&mut lp).await,
        Act::TakeTicket => start_flow(&mut lp, Intent::Ticket).await,
        Act::Vote => start_flow(&mut lp, Intent::Vote).await,
        Act::Cast => cast(&mut lp),
        Act::Resend => resend(&mut lp),
        _ => {}
    }
}

/// `r`: read again what the screen shows.
async fn refresh_screen(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if view.pending.is_some() {
        view.note(
            Severity::Warning,
            "Still waiting for the community's answer.",
        );
        return;
    }
    view.status = None;
    match (
        view.screen,
        view.shown.as_ref().map(|s| s.election_id().to_string()),
    ) {
        (Screen::Detail, Some(election)) => {
            let sent = lp
                .send(
                    Request::Show {
                        election_id: election.clone(),
                    },
                    Purpose::Show {
                        election,
                        intent: Intent::View,
                    },
                )
                .await;
            if !sent && let Some(view) = view_mut(lp.state) {
                view.note(Severity::Warning, InFlight::busy_message(SEND));
            }
        }
        (Screen::List, _) => lp.refresh().await,
        // The first read of this election never arrived: read it again.
        (Screen::Detail, None) => {
            view.screen = Screen::List;
            show_selected(lp).await;
        }
        _ => {}
    }
}

/// `⏎` on the list: open the highlighted election.
async fn show_selected(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if view.screen != Screen::List || view.pending.is_some() {
        return;
    }
    let Some(election) = view.selected_item().map(|e| e.election_id.to_string()) else {
        return;
    };
    view.screen = Screen::Detail;
    view.shown = None;
    view.status = None;
    view.note(Severity::Progress, "Reading the election…");
    let sent = lp
        .send(
            Request::Show {
                election_id: election.clone(),
            },
            Purpose::Show {
                election,
                intent: Intent::View,
            },
        )
        .await;
    if !sent && let Some(view) = view_mut(lp.state) {
        view.screen = Screen::List;
        view.note(Severity::Warning, InFlight::busy_message(SEND));
    }
}

/// `t` / `v` on an election: read it again, then take the ticket or vote.
async fn start_flow(lp: &mut Loop<'_>, intent: Intent) {
    let has_vta = lp.vta.is_some();
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if view.screen != Screen::Detail {
        return;
    }
    if view.flow.is_some() || view.pending.is_some() {
        view.note(Severity::Warning, "Something is already in progress here.");
        return;
    }
    let Some(election) = view.shown.as_ref().map(|s| s.election_id().to_string()) else {
        return;
    };
    if !has_vta {
        view.note(
            Severity::Error,
            "Voting needs your VTA: it holds the voter keys and the ticket. None is connected.",
        );
        return;
    }
    view.flow = Some(Flow {
        election: election.clone(),
        intent,
        step: Step::Reading,
    });
    view.note(Severity::Progress, "Reading the election again…");
    let sent = lp
        .send(
            Request::Show {
                election_id: election.clone(),
            },
            Purpose::Show { election, intent },
        )
        .await;
    if !sent && let Some(view) = view_mut(lp.state) {
        view.flow = None;
        view.note(Severity::Warning, InFlight::busy_message(SEND));
    }
}

/// `y` on the confirmation: have the VTA build the cast.
fn cast(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if view.screen != Screen::Confirm || view.flow.is_some() {
        return;
    }
    let (Some(form), Some(shown)) = (view.form.as_ref(), view.shown.as_ref()) else {
        return;
    };
    let ballot = form
        .draft
        .to_ballot(shown.election_id(), shown.manifest_digest());
    let election = shown.election_id().to_string();
    view.flow = Some(Flow {
        election,
        intent: Intent::Vote,
        step: Step::Building,
    });
    view.note(Severity::Progress, Step::Building.words());
    view.next = Some(Next::Vote { ballot });
}

/// `r` on a lost answer: send the same cast again.
fn resend(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if view.screen != Screen::Result || view.flow.is_some() {
        return;
    }
    let Some(cast) = view.cast.clone() else {
        return;
    };
    let election = view
        .shown
        .as_ref()
        .map(|s| s.election_id().to_string())
        .unwrap_or_default();
    view.result = None;
    view.flow = Some(Flow {
        election,
        intent: Intent::Vote,
        step: Step::Casting,
    });
    view.note(Severity::Progress, Step::Casting.words());
    view.next = Some(Next::Deliver(cast));
}

/// Open the panel for the Active community at a Communities display index.
fn open(ctx: &mut ActionCtx<'_>, index: usize) {
    let target = ctx
        .config
        .account
        .communities_for_display(ctx.state.main_page.content_panel.communities.show_archived)
        .get(index)
        .filter(|c| c.status.is_active())
        .map(|c| {
            (
                c.vtc_did.clone(),
                c.persona_ref,
                crate::state_handler::community_label(
                    ctx.config,
                    &c.vtc_did,
                    c.display_name.as_deref(),
                    256,
                ),
            )
        });
    let Some((vtc, persona, name)) = target else {
        return;
    };
    let me = ctx
        .config
        .identities
        .get(&persona)
        .map(|id| id.persona_did().to_string())
        .unwrap_or_default();
    ctx.state.main_page.content_panel.elections.view =
        Some(ElectionsView::new(vtc, persona, me, name));
}

/// Take the step the view's last answer called for, if its lane is free. The loop calls this
/// after applying replies and dispatch outcomes, and on its tick.
pub(crate) async fn advance(lp: &mut Loop<'_>) {
    let Some(next) = view_mut(lp.state).and_then(|v| v.next.take()) else {
        return;
    };
    let shown = view_mut(lp.state).and_then(|v| v.shown.clone());
    let taken = match next.clone() {
        Next::Refresh => {
            if lp.in_flight.is_busy(SEND) || view_mut(lp.state).is_some_and(|v| v.pending.is_some())
            {
                false
            } else {
                lp.refresh().await;
                true
            }
        }
        Next::ListPage { cursor } => {
            lp.send(
                Request::List {
                    cursor: Some(cursor),
                },
                Purpose::List,
            )
            .await
        }
        Next::Register => match shown {
            Some(shown) => lp.ask_vta(VtaAsk::Register { shown }),
            None => true,
        },
        Next::SendIssue(ticket) => {
            let election = ticket.election_id.clone();
            lp.send(Request::IssueTicket(ticket), Purpose::Issue { election })
                .await
        }
        Next::Accept { issued } => match shown {
            Some(shown) => lp.ask_vta(VtaAsk::Accept { shown, issued }),
            None => true,
        },
        Next::Vote { ballot } => match shown {
            Some(shown) => lp.ask_vta(VtaAsk::Vote { shown, ballot }),
            None => true,
        },
        Next::Deliver(cast) => lp.deliver(cast),
        Next::Keep(receipt) => match shown {
            Some(shown) => lp.ask_vta(VtaAsk::Keep {
                election: shown.election_id().to_string(),
                receipt,
            }),
            None => true,
        },
    };
    // A lane that was busy: keep the step for the next tick.
    if !taken && let Some(view) = view_mut(lp.state) {
        view.next.get_or_insert(next);
    }
}

/// The loop's periodic pass: reply windows, and any step left waiting on a busy lane.
pub(crate) async fn tick(lp: &mut Loop<'_>) {
    let now = Instant::now();
    if let Some(view) = view_mut(lp.state)
        && view
            .pending
            .as_ref()
            .is_some_and(|p| now.duration_since(p.sent_at) > REPLY_WINDOW)
        && let Some(p) = view.pending.take()
    {
        let secs = REPLY_WINDOW.as_secs();
        match p.purpose {
            Purpose::List if view.elections.is_empty() => {
                // A community that does not serve elections still answers, with a refusal
                // shown in words, so silence means the request or its answer was lost (R6.4).
                view.phase = ElectionsPhase::Failed(format!(
                    "no reply within {secs}s. A community that does not serve elections says \
                     so, so this is not that: the request or its answer was lost — the \
                     community's VTC is offline or unreachable, or it answered on a route this \
                     persona does not collect. Press r to try again."
                ));
            }
            Purpose::List | Purpose::Show { .. } => {
                view.flow = None;
                view.note(
                    Severity::Error,
                    format!("No reply from the community within {secs}s. Press r to try again."),
                );
            }
            Purpose::Issue { .. } => {
                view.flow = None;
                view.note(
                    Severity::Error,
                    format!(
                        "No reply to the ticket request within {secs}s. Taking the ticket again \
                         is safe: your VTA repeats the same request, and the community answers \
                         it as before."
                    ),
                );
            }
        }
    }
    advance(lp).await;
}

/// A job ended without an outcome (it panicked): end what it was part of.
pub(crate) fn job_lost(state: &mut State, msg: &str) {
    if let Some(view) = view_mut(state) {
        view.pending = None;
        view.flow = None;
        view.next = None;
        view.note(Severity::Error, msg.to_string());
    }
}

// ****************************************************************************
// Sending to the community
// ****************************************************************************

/// One `vtc/elections/*` send, off the loop.
pub(crate) struct SendJob {
    sender: Sender,
    vtc_did: String,
    persona: PersonaId,
    doc: RequestDocument,
}

impl SendJob {
    async fn run(mut self) -> ElectionsOutcome {
        let thid = correlation_thread(&self.doc).to_string();
        let result = crate::state_handler::repos_actions::sign_and_send(
            &self.sender,
            &self.vtc_did,
            &mut self.doc,
        )
        .await;
        ElectionsOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            thid,
            result,
        }
    }
}

/// What a send did. Applied on the loop.
pub(crate) struct ElectionsOutcome {
    vtc_did: String,
    persona: PersonaId,
    thid: String,
    result: Result<(), String>,
}

impl ElectionsOutcome {
    /// Say the send never left — while the view still waits on this request.
    pub(crate) fn apply(self, state: &mut State) {
        let Err(e) = self.result else {
            return;
        };
        let Some(view) = view_mut(state) else {
            return;
        };
        if view.vtc_did != self.vtc_did
            || view.persona != self.persona
            || view.pending.as_ref().is_none_or(|p| p.thid != self.thid)
        {
            tracing::debug!(thid = %self.thid, "elections send failed for a request no longer awaited: {e}");
            return;
        }
        if let Some(p) = view.pending.take() {
            fail(
                state,
                &p.purpose,
                format!("couldn't reach the community: {e}"),
            );
        }
    }
}

/// Apply the community's answers. Returns whether any was taken, so the loop [`advance`]s.
pub(crate) fn apply_replies(state: &mut State, replies: Vec<InboundReply>) -> bool {
    let mut taken = false;
    for inbound in replies {
        let Some(vtc) = view_mut(state).map(|v| v.vtc_did.clone()) else {
            continue;
        };
        // A thread id is a correlation key, not a credential: an answer is taken only from the
        // community the view is asking — sent by it and issued by it.
        let from_vtc = vta_sdk::did_scid::same_reference(did_part(&inbound.from), &vtc);
        let issued_by_vtc = inbound
            .issuer
            .as_deref()
            .map(did_part)
            .is_some_and(|issuer| vta_sdk::did_scid::same_reference(issuer, &vtc));
        if !(from_vtc && issued_by_vtc) {
            tracing::warn!(from = %inbound.from, thid = %inbound.thid, "elections reply not from the community the view is asking — dropped");
            continue;
        }
        taken |= apply_reply(state, &inbound.thid, inbound.reply);
    }
    taken
}

fn apply_reply(state: &mut State, thid: &str, reply: Reply) -> bool {
    let Some(view) = view_mut(state) else {
        return false;
    };
    if view.pending.as_ref().is_none_or(|p| p.thid != thid) {
        if !matches!(reply, Reply::Refused(_)) {
            tracing::warn!(%thid, "elections reply matches no pending request — dropped");
        }
        return false;
    }
    let Some(pending) = view.pending.take() else {
        return false;
    };
    match (reply, pending.purpose) {
        (Reply::List(page), Purpose::List) => {
            let next = page.next_cursor.as_ref().map(|c| c.as_str().to_string());
            view.take_page(page.elections, next.is_none());
            match next {
                Some(cursor) => view.next = Some(Next::ListPage { cursor }),
                None => view.clear_progress(),
            }
        }
        (Reply::Show(shown), Purpose::Show { election, intent }) => {
            if shown.election_id() != election {
                view.flow = None;
                view.note(
                    Severity::Error,
                    "The community answered about another election.",
                );
                return true;
            }
            view.shown = Some(shown);
            match intent {
                Intent::View => view.clear_progress(),
                Intent::Ticket | Intent::Vote => after_show(view),
            }
        }
        (Reply::TicketIssued { raw, .. }, Purpose::Issue { .. }) => {
            if let Some(flow) = view.flow.as_mut() {
                flow.step = Step::Accepting;
            }
            view.note(Severity::Progress, Step::Accepting.words());
            view.next = Some(Next::Accept { issued: raw });
        }
        (Reply::Refused(r), purpose) => match purpose {
            Purpose::List if view.elections.is_empty() => {
                view.phase = ElectionsPhase::Failed(r.explain());
            }
            _ => {
                view.flow = None;
                view.note(Severity::Error, r.explain());
            }
        },
        (Reply::Unreadable { task, detail }, purpose) => {
            let text = format!(
                "the community's answer to {task} doesn't match what this client expects \
                 ({detail}) — the community or this client may need updating"
            );
            if matches!(purpose, Purpose::List) && view.elections.is_empty() {
                view.phase = ElectionsPhase::Failed(text);
            } else {
                view.flow = None;
                view.note(Severity::Error, text);
            }
        }
        (_, purpose) => {
            tracing::warn!(
                ?purpose,
                "elections reply of the wrong kind for its request"
            );
            view.flow = None;
            view.note(
                Severity::Error,
                "The community answered with something else.",
            );
        }
    }
    true
}

/// The election was read again for a ticket or a vote: go on, or say why not.
fn after_show(view: &mut ElectionsView) {
    let Some(shown) = view.shown.as_ref() else {
        return;
    };
    if !shown.tickets_open() {
        let state = shown.state_label();
        view.flow = None;
        view.note(
            Severity::Warning,
            format!("This election is {state}: there is nothing to take part in now."),
        );
        return;
    }
    if let Some(flow) = view.flow.as_mut() {
        flow.step = Step::Registering;
    }
    view.note(Severity::Progress, Step::Registering.words());
    view.next = Some(Next::Register);
}

// ****************************************************************************
// Asking the VTA
// ****************************************************************************

/// One call to the member's VTA.
enum VtaAsk {
    Register {
        shown: Box<ShownElection>,
    },
    Accept {
        shown: Box<ShownElection>,
        issued: serde_json::Value,
    },
    Vote {
        shown: Box<ShownElection>,
        ballot: serde_json::Value,
    },
    Keep {
        election: String,
        receipt: Box<VerifiedReceipt>,
    },
}

/// What the VTA answered.
pub(crate) enum VtaAnswer {
    Registered(Result<Registered, String>),
    Accepted(Result<(), String>),
    Voted(Result<Cast, String>),
    Kept(Result<Kept, String>),
}

impl VtaAsk {
    async fn run(self, v: &Voter<'_>) -> VtaAnswer {
        match self {
            VtaAsk::Register { shown } => VtaAnswer::Registered(
                elections::register(v, &shown)
                    .await
                    .map_err(|e| e.to_string()),
            ),
            VtaAsk::Accept { shown, issued } => VtaAnswer::Accepted(
                elections::accept(v, &shown, &issued)
                    .await
                    .map_err(|e| e.to_string()),
            ),
            VtaAsk::Vote { shown, ballot } => VtaAnswer::Voted(
                elections::vote(v, &shown, &ballot)
                    .await
                    .map_err(|e| e.to_string()),
            ),
            VtaAsk::Keep { election, receipt } => VtaAnswer::Kept(
                elections::keep_receipt(v, &election, &receipt)
                    .await
                    .map_err(|e| e.to_string()),
            ),
        }
    }
}

/// The VTA's answer. Applied on the loop.
pub(crate) struct ElectionsVtaOutcome {
    vtc_did: String,
    persona: PersonaId,
    answer: VtaAnswer,
}

impl ElectionsVtaOutcome {
    pub(crate) fn apply(self, state: &mut State) {
        let now = Instant::now();
        let panel = &mut state.main_page.content_panel.elections;
        let Some(view) = panel.view.as_mut() else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        let intent = view.flow.as_ref().map(|f| f.intent);
        match self.answer {
            VtaAnswer::Registered(Ok(Registered::Request(ticket))) => {
                if let Some(flow) = view.flow.as_mut() {
                    flow.step = Step::Issuing;
                }
                view.note(Severity::Progress, Step::Issuing.words());
                view.next = Some(Next::SendIssue(ticket));
            }
            VtaAnswer::Registered(Ok(Registered::AlreadyHeld)) => {
                view.flow = None;
                let voting = view.shown.as_ref().is_some_and(|s| s.voting_open());
                match intent {
                    Some(Intent::Vote) if voting => {
                        if let Some(s) = view.shown.as_ref() {
                            view.form = Some(BallotForm::new(s.manifest()));
                        }
                        view.screen = Screen::Ballot;
                        view.status = None;
                    }
                    Some(Intent::Vote) => view.note(
                        Severity::Info,
                        "You hold this election's ticket. Voting has not opened yet: come \
                         back then.",
                    ),
                    _ => view.note(
                        Severity::Info,
                        "Your VTA already holds this election's ticket.",
                    ),
                }
            }
            VtaAnswer::Accepted(Ok(())) => {
                if let Some(flow) = view.flow.take() {
                    panel
                        .tickets_taken
                        .insert((view.vtc_did.clone(), flow.election), now);
                }
                view.note(
                    Severity::Success,
                    "Ticket taken — the community signed it without seeing it. Come back later \
                     to vote: a vote cast straight after its ticket could be paired with it by \
                     when each arrived.",
                );
                view.next = Some(Next::Refresh);
            }
            VtaAnswer::Voted(Ok(cast)) => {
                // Built: the ballot has gone into the cast, and the form goes.
                view.drop_ballot();
                view.cast = Some(cast.clone());
                if let Some(flow) = view.flow.as_mut() {
                    flow.step = Step::Casting;
                }
                view.screen = Screen::Result;
                view.note(Severity::Progress, Step::Casting.words());
                view.next = Some(Next::Deliver(cast));
            }
            VtaAnswer::Kept(result) => {
                view.flow = None;
                view.cast = None;
                if let Some(VoteResult::Counted {
                    kept, keep_error, ..
                }) = view.result.as_mut()
                {
                    match result {
                        Ok(k) => *kept = Some(k),
                        Err(e) => *keep_error = Some(e),
                    }
                }
                view.clear_progress();
            }
            VtaAnswer::Registered(Err(e)) | VtaAnswer::Accepted(Err(e)) => {
                view.flow = None;
                view.note(Severity::Error, e);
            }
            VtaAnswer::Voted(Err(e)) => {
                view.flow = None;
                view.screen = Screen::Ballot;
                view.note(Severity::Error, e);
            }
        }
    }
}

// ****************************************************************************
// The ballot box
// ****************************************************************************

/// How a cast's journey ended. Applied on the loop.
pub(crate) struct ElectionsCastOutcome {
    vtc_did: String,
    persona: PersonaId,
    cast: Cast,
    result: Result<VerifiedReceipt, CastError>,
}

impl ElectionsCastOutcome {
    pub(crate) fn apply(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        view.screen = Screen::Result;
        match self.result {
            Ok(receipt) => {
                if let Some(flow) = view.flow.as_mut() {
                    flow.step = Step::Keeping;
                }
                view.result = Some(VoteResult::Counted {
                    outcome: receipt.outcome,
                    leaf_index: receipt.leaf_index,
                    kept: None,
                    keep_error: None,
                });
                view.note(Severity::Progress, Step::Keeping.words());
                view.next = Some(Next::Keep(Box::new(receipt)));
            }
            Err(e) => {
                view.flow = None;
                let resend = e.resendable();
                // A cast the ballot box answered is spent; only a lost answer is resent.
                view.cast = resend.then_some(self.cast);
                view.clear_progress();
                view.result = Some(VoteResult::Failed {
                    why: e.to_string(),
                    resend,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests;
