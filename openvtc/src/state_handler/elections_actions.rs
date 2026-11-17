//! The Elections panel: a community's elections, from the member's side.
//!
//! Opened from Communities with `e`. Three parties, three lanes, none of them the loop:
//!
//! - the **community** — `vtc/elections/{list,show,tickets/issue}`, signed with the persona's
//!   key and sent on its channel in [`DispatchDomain::Elections`], exactly as the Rooms panel
//!   sends `vtc/rooms/*`; the answer arrives on the inbound channel and [`apply_replies`]
//!   matches it by thread. A read or claim that carries a presentation of the member's
//!   membership credential (a credential roll, VTI-VOT-015, VTI-VOT-025) is signed by the VTA
//!   instead and carried unchanged. A notified election (VTI-NTF-063) is read from the
//!   community holding it, which may be one this persona is not a member of;
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
//!
//! An action that sends is planned by [`plan`], a [`Next`] by [`plan_next`] and the held
//! notifications' read by [`plan_notified`]: all are pure, make the changes due before
//! anything is claimed, and return the steps in order ([`ElectionsEffect`]). [`run`] takes
//! them: a send looks up the persona's key, builds, claims and arms
//! ([`community_request::send`]); a question to the VTA or the ballot box claims its lane;
//! each applies its [`Commit`] once under way. A send that failed in a way the view shows
//! counts as under way: the commit is applied first, so the failure shows where the request
//! would have.

use std::time::Instant;

use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::elections::{
    self, Cast, CastError, Claim, Kept, Registered, Reply, Request, ShownElection, VerifiedReceipt,
    Voter,
};
use openvtc_core::notifications::NotifiedElection;
use openvtc_core::pending_replies::PendingReplies;

use crate::state_handler::actions::ElectionsAction as Act;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
pub(crate) use crate::state_handler::community_request::CommunityLoop as Loop;
use crate::state_handler::community_request::{
    self, CommunityFeature, Doc, SendOutcome, Sender, Sent, UNTHREADED, capitalise, fail,
};
use crate::state_handler::main_page::elections::{
    BallotForm, Disclose, ElectionsPhase, ElectionsView, Flow, Intent, Next, NotifiedPhase,
    Purpose, Row, Screen, Severity, Step as FlowStep, VoteResult,
};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

const SEND: DispatchDomain = DispatchDomain::Elections;
const VTA: DispatchDomain = DispatchDomain::ElectionsVta;
const CAST: DispatchDomain = DispatchDomain::ElectionsCast;

/// A `vtc/elections/*` answer as it arrived, threaded on the request it answers
/// ([`openvtc_core::inbound::ThreadedReply`]).
pub(crate) type InboundReply = openvtc_core::inbound::ThreadedReply<Reply>;

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
        | Act::Present
        | Act::TakeTicket
        | Act::Vote
        | Act::Cast
        | Act::Resend => return false,
        Act::Back => match view.screen {
            Screen::List => panel.view = None,
            Screen::Disclose => {
                view.screen = Screen::List;
                view.reset_target();
                view.status = None;
            }
            Screen::Detail => {
                view.screen = Screen::List;
                view.shown = None;
                view.flow = None;
                view.status = None;
                view.reset_target();
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
            view.selected = (*i).min(view.rows().len().saturating_sub(1));
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
        Act::BallotText(text) => {
            if let (Some(f), Some(s)) = (view.form.as_mut(), view.shown.as_ref()) {
                f.set_text(s.manifest(), text);
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

// ****************************************************************************
// The loop's side
// ****************************************************************************

/// The Elections panel, on the shared request/reply plumbing
/// ([`community_request`]).
pub(crate) struct Elections;

impl CommunityFeature for Elections {
    type View = ElectionsView;
    type Purpose = Purpose;
    type Reply = Reply;
    type Next = Next;
    type Request = Outgoing;
    const NAME: &'static str = "elections";
    const SEND: DispatchDomain = SEND;
    /// A notified election is read from the community holding it, which may be one this
    /// persona is not a member of (VTI-NTF-063): its answer is admitted only on a thread
    /// recorded for it.
    const RECORDS_THREAD: bool = true;

    fn view_mut(state: &mut State) -> Option<&mut ElectionsView> {
        view_mut(state)
    }
    fn pending_mut(view: &mut ElectionsView) -> &mut Option<community_request::Pending<Purpose>> {
        &mut view.pending
    }
    fn next_mut(view: &mut ElectionsView) -> &mut Option<Next> {
        &mut view.next
    }
    fn community(view: &ElectionsView) -> (&str, PersonaId) {
        (&view.vtc_did, view.persona)
    }
    fn note(view: &mut ElectionsView, severity: Severity, text: String) {
        view.note(severity, text);
    }
    fn outcome(outcome: SendOutcome) -> DispatchOutcome {
        DispatchOutcome::Elections(outcome)
    }
    fn build(
        config: &Config,
        sender: &mut Sender,
        to: &str,
        persona: PersonaId,
        outgoing: Outgoing,
    ) -> Result<Doc, String> {
        // A community this persona is not a member of (one holding a notified election) has
        // no membership transport to follow: TSP when the persona speaks it anywhere, so the
        // answer comes back on the socket TSP answers arrive on; DIDComm otherwise.
        if config.account.membership(to, persona).is_none() {
            sender.over_tsp = config
                .account
                .memberships()
                .any(|c| c.persona_ref == persona && c.joined_over_tsp());
        }
        match outgoing {
            Outgoing::Build(request) => elections::build(&request, &sender.persona_did, to)
                .map(|doc| Doc::Unsigned(Box::new(doc)))
                .map_err(|e| format!("couldn't send: {e}")),
            Outgoing::Signed(document) => {
                let addressed = document
                    .get("recipient")
                    .and_then(serde_json::Value::as_str);
                if !addressed.is_some_and(|r| vta_sdk::did_scid::same_reference(r, to)) {
                    return Err(
                        "your VTA signed the request for another community than this one".into(),
                    );
                }
                Ok(Doc::Signed(document))
            }
        }
    }
    fn is_refusal(reply: &Reply) -> bool {
        matches!(reply, Reply::Refused(_))
    }
    fn take_reply(view: &mut ElectionsView, reply: Reply, purpose: Purpose) {
        take_reply(view, reply, purpose);
    }
    fn timed_out(view: &mut ElectionsView, purpose: Purpose, secs: u64) {
        timed_out(view, purpose, secs);
    }
    fn failed(view: &mut ElectionsView, purpose: &Purpose, why: String) {
        failed(view, purpose, why);
    }
    fn end_flow(view: &mut ElectionsView) {
        view.flow = None;
    }
    async fn step(lp: &mut Loop<'_>, next: Next) -> bool {
        step(lp, next).await
    }
    fn before_step(lp: &mut Loop<'_>) {
        ask_notified(lp);
    }
}

// ****************************************************************************
// The loop's side: the reducer
// ****************************************************************************

/// What an action or a [`Next`] asks of the loop once [`plan`] or
/// [`plan_next`] has made its own changes: the steps, in order, and whether a
/// [`Next`] it came from counts as taken.
struct ElectionsEffect {
    steps: Vec<Step>,
    taken: Taken,
}

impl ElectionsEffect {
    /// Nothing to send or ask; a [`Next`] counts as taken.
    fn done() -> Self {
        Self {
            steps: Vec::new(),
            taken: Taken::Yes,
        }
    }

    /// One step, whose own answer says whether a [`Next`] was taken.
    fn one(step: Step) -> Self {
        Self {
            steps: vec![step],
            taken: Taken::ByLastStep,
        }
    }
}

/// Whether a [`Next`] counts as taken; one that is not is kept for the next
/// tick.
#[derive(Debug, PartialEq, Eq)]
enum Taken {
    Yes,
    /// Its lane is busy, or the view still waits.
    No,
    /// As the last step answered.
    ByLastStep,
}

/// One thing the runner does.
enum Step {
    /// Send to a community ([`community_request::send`]).
    Send(Box<Send>),
    /// Ask the VTA ([`ask_vta`]), then apply `commit` once it is asked — or
    /// once it failed in a way the view shows.
    Ask { ask: VtaAsk, commit: Option<Commit> },
    /// Send the cast to the ballot box ([`deliver`]).
    Deliver(Cast),
}

/// A request to a community, planned to everything but the persona's key.
struct Send {
    to: String,
    persona: PersonaId,
    request: Outgoing,
    purpose: Purpose,
    /// Applied once the request is claimed and the view armed — or, before
    /// its reason is shown, when the key lookup or the document failed: a
    /// failure shows where the request would have.
    commit: Option<Commit>,
    /// Shown when the lane was busy.
    refusal: Option<Refusal>,
}

/// A view change made only once its request or question is under way.
#[derive(Debug, PartialEq, Eq)]
enum Commit {
    /// The detail screen, reading the election held by `target` — opened
    /// from `opening` when it came from a notification. The earlier target,
    /// and what was shown, are replaced only now.
    Showing {
        target: String,
        opening: Option<Box<NotifiedElection>>,
    },
    /// A ticket or a vote begins by reading the election again.
    Reading(Flow),
    /// The held notifications were asked for.
    NotifiedAsked,
}

impl Commit {
    fn apply(self, view: &mut ElectionsView) {
        match self {
            Commit::Showing { target, opening } => {
                view.reset_target();
                view.target = target;
                view.opening = opening.map(|n| *n);
                view.shown = None;
                view.screen = Screen::Detail;
                view.note(Severity::Progress, "Reading the election…");
            }
            Commit::Reading(flow) => {
                view.flow = Some(flow);
                view.note(Severity::Progress, "Reading the election again…");
            }
            Commit::NotifiedAsked => view.notified_due = false,
        }
    }
}

/// What the view says when a request was not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The community lane is busy.
    Busy,
    /// The list was not read again: the community lane is busy.
    ListBusy,
}

impl Refusal {
    fn show(self, state: &mut State) {
        if let Some(view) = view_mut(state) {
            match self {
                Refusal::Busy => view.note(Severity::Warning, InFlight::busy_message(SEND)),
                Refusal::ListBusy => view.note(
                    Severity::Warning,
                    format!(
                        "{} The elections were not read again — press r once it finishes.",
                        InFlight::busy_message(SEND)
                    ),
                ),
            }
        }
    }
}

/// A request built here. The list is always the panel's own community's; one
/// election is read from where it is held.
fn request(
    view: &ElectionsView,
    request: Request,
    purpose: Purpose,
    commit: Option<Commit>,
    refusal: Option<Refusal>,
) -> Step {
    let to = if matches!(request, Request::List { .. }) {
        view.vtc_did.clone()
    } else {
        view.target.clone()
    };
    Step::Send(Box::new(Send {
        to,
        persona: view.persona,
        request: Outgoing::Build(request),
        purpose,
        commit,
        refusal,
    }))
}

/// A document the VTA signed, carried to the view's target community unchanged.
fn signed(view: &ElectionsView, document: serde_json::Value, purpose: Purpose) -> Step {
    Step::Send(Box::new(Send {
        to: view.target.clone(),
        persona: view.persona,
        request: Outgoing::Signed(document),
        purpose,
        commit: None,
        refusal: None,
    }))
}

/// Plan an action that reads the config or sends. Pure: it makes the changes
/// the action makes before anything is claimed and returns the steps the loop
/// still owes. `has_vta` is whether a VTA session is connected.
fn plan(state: &mut State, config: &Config, has_vta: bool, action: Act) -> ElectionsEffect {
    match action {
        Act::Open(index) => {
            open(state, config, index);
            if let Some(view) = view_mut(state) {
                view.phase = ElectionsPhase::Loading;
            }
            ElectionsEffect {
                steps: plan_refresh(state),
                taken: Taken::Yes,
            }
        }
        Act::Refresh => plan_refresh_screen(state),
        Act::Show => plan_show(state),
        Act::Present => {
            present(state, has_vta);
            ElectionsEffect::done()
        }
        Act::TakeTicket => plan_flow(state, has_vta, Intent::Ticket),
        Act::Vote => plan_flow(state, has_vta, Intent::Vote),
        Act::Cast => {
            cast(state);
            ElectionsEffect::done()
        }
        Act::Resend => {
            resend(state);
            ElectionsEffect::done()
        }
        _ => ElectionsEffect::done(),
    }
}

/// Read the list again, and the VTA's held election notifications beside it.
/// The notifications are the VTA's, on a lane of their own, so they are read
/// even when the community lane is busy and the list is not; that refusal is
/// said.
/// A busy lane reads nothing and says nothing.
fn plan_refresh(state: &mut State) -> Vec<Step> {
    let Some(view) = view_mut(state) else {
        return Vec::new();
    };
    view.restart_pages();
    view.notified_due = true;
    vec![request(
        view,
        Request::List { cursor: None },
        Purpose::List,
        None,
        Some(Refusal::ListBusy),
    )]
}

/// Read the open election again — presenting the membership the member chose to show for
/// it, and nothing else (VTI-VOT-016): that read is the VTA's to sign, so it is left as the
/// next step and nothing is sent here. `commit` and `refusal` go with a read sent here.
fn plan_read_election(
    view: &mut ElectionsView,
    election: String,
    intent: Intent,
    commit: Option<Commit>,
    refusal: Option<Refusal>,
) -> Vec<Step> {
    match view.presenting.clone() {
        Some(member_of) => {
            // Nothing is sent here, so the change is due now.
            if let Some(commit) = commit {
                commit.apply(view);
            }
            view.next = Some(Next::ReadPresenting {
                election,
                member_of,
                intent,
            });
            Vec::new()
        }
        None => vec![request(
            view,
            Request::Show {
                election_id: election.clone(),
            },
            Purpose::Show { election, intent },
            commit,
            refusal,
        )],
    }
}

/// `r`: read again what the screen shows.
fn plan_refresh_screen(state: &mut State) -> ElectionsEffect {
    let Some(view) = view_mut(state) else {
        return ElectionsEffect::done();
    };
    if view.pending.is_some() {
        view.note(
            Severity::Warning,
            "Still waiting for the community's answer.",
        );
        return ElectionsEffect::done();
    }
    view.status = None;
    let steps = match (
        view.screen,
        view.shown.as_ref().map(|s| s.election_id().to_string()),
    ) {
        (Screen::Detail, Some(election)) => {
            plan_read_election(view, election, Intent::View, None, Some(Refusal::Busy))
        }
        (Screen::List, _) => plan_refresh(state),
        // The first read of this election never arrived: read it again.
        (Screen::Detail, None) => {
            view.screen = Screen::List;
            return plan_show(state);
        }
        _ => Vec::new(),
    };
    ElectionsEffect {
        steps,
        taken: Taken::Yes,
    }
}

/// `⏎` on the list: open the highlighted election.
fn plan_show(state: &mut State) -> ElectionsEffect {
    let Some(view) = view_mut(state) else {
        return ElectionsEffect::done();
    };
    if view.screen != Screen::List || view.pending.is_some() {
        return ElectionsEffect::done();
    }
    // What the read changes is its commit, applied once it is under way: a
    // busy lane leaves the earlier target as it was.
    let (election, target, opening) = match view.selected_row() {
        Some(Row::Listed(e)) => (e.election_id.to_string(), view.vtc_did.clone(), None),
        Some(Row::Notified(n)) => {
            let n = n.clone();
            if !n.opens_with_a_served_version() {
                view.note(
                    Severity::Warning,
                    "The notification names a way to open this election that this app does not \
                     speak (it reads elections with vtc/elections/show/0.6).",
                );
                return ElectionsEffect::done();
            }
            // Read without presenting anything first: an election the member can already see
            // shows the community nothing (VTI-VOT-016).
            (n.election_id.clone(), n.held_by.clone(), Some(Box::new(n)))
        }
        None => return ElectionsEffect::done(),
    };
    view.status = None;
    // Not sent (lane busy): the list stays, saying so.
    ElectionsEffect {
        steps: vec![Step::Send(Box::new(Send {
            to: target.clone(),
            persona: view.persona,
            request: Outgoing::Build(Request::Show {
                election_id: election.clone(),
            }),
            purpose: Purpose::Show {
                election,
                intent: Intent::View,
            },
            commit: Some(Commit::Showing { target, opening }),
            refusal: Some(Refusal::Busy),
        }))],
        taken: Taken::Yes,
    }
}

/// `t` / `v` on an election: read it again, then take the ticket or vote.
fn plan_flow(state: &mut State, has_vta: bool, intent: Intent) -> ElectionsEffect {
    let Some(view) = view_mut(state) else {
        return ElectionsEffect::done();
    };
    if view.screen != Screen::Detail {
        return ElectionsEffect::done();
    }
    if view.flow.is_some() || view.pending.is_some() {
        view.note(Severity::Warning, "Something is already in progress here.");
        return ElectionsEffect::done();
    }
    let Some(election) = view.shown.as_ref().map(|s| s.election_id().to_string()) else {
        return ElectionsEffect::done();
    };
    if !has_vta {
        view.note(
            Severity::Error,
            "Voting needs your VTA: it holds the voter keys and the ticket. None is connected.",
        );
        return ElectionsEffect::done();
    }
    let flow = Flow {
        election: election.clone(),
        intent,
        step: FlowStep::Reading,
    };
    // Not sent (lane busy): no flow begins, and the lane is said to be busy.
    ElectionsEffect {
        steps: plan_read_election(
            view,
            election,
            intent,
            Some(Commit::Reading(flow)),
            Some(Refusal::Busy),
        ),
        taken: Taken::Yes,
    }
}

/// Plan one [`Next`]. Pure, like [`plan`]; `send_busy` is whether the
/// community lane is held.
fn plan_next(state: &mut State, send_busy: bool, next: Next) -> ElectionsEffect {
    // [`advance`] takes a step only from an open view.
    let Some(view) = view_mut(state) else {
        return ElectionsEffect::done();
    };
    let shown = view.shown.clone();
    match next {
        Next::Refresh => {
            if send_busy || view.pending.is_some() {
                ElectionsEffect {
                    steps: Vec::new(),
                    taken: Taken::No,
                }
            } else {
                ElectionsEffect {
                    steps: plan_refresh(state),
                    taken: Taken::Yes,
                }
            }
        }
        Next::ReadPresenting {
            election,
            member_of,
            intent,
        } => ElectionsEffect::one(Step::Ask {
            ask: VtaAsk::ReadPresenting {
                member: view.me.clone(),
                election,
                member_of,
                intent,
            },
            commit: None,
        }),
        Next::SendShowDocument {
            document,
            election,
            intent,
        } => ElectionsEffect::one(signed(view, document, Purpose::Show { election, intent })),
        Next::SendIssueDocument(document) => {
            let election = shown
                .as_ref()
                .map(|s| s.election_id().to_string())
                .unwrap_or_default();
            ElectionsEffect::one(signed(view, document, Purpose::Issue { election }))
        }
        Next::ListPage { cursor } => ElectionsEffect::one(request(
            view,
            Request::List {
                cursor: Some(cursor),
            },
            Purpose::List,
            None,
            None,
        )),
        Next::Register => match shown {
            Some(shown) => ElectionsEffect::one(Step::Ask {
                ask: VtaAsk::Register {
                    shown,
                    member: view.me.clone(),
                },
                commit: None,
            }),
            None => ElectionsEffect::done(),
        },
        Next::SendIssue(ticket) => {
            let election = ticket.election_id.clone();
            ElectionsEffect::one(request(
                view,
                Request::IssueTicket(ticket),
                Purpose::Issue { election },
                None,
                None,
            ))
        }
        Next::Accept { issued } => match shown {
            Some(shown) => ElectionsEffect::one(Step::Ask {
                ask: VtaAsk::Accept { shown, issued },
                commit: None,
            }),
            None => ElectionsEffect::done(),
        },
        Next::Vote { ballot } => match shown {
            Some(shown) => ElectionsEffect::one(Step::Ask {
                ask: VtaAsk::Vote { shown, ballot },
                commit: None,
            }),
            None => ElectionsEffect::done(),
        },
        Next::Deliver(cast) => ElectionsEffect::one(Step::Deliver(cast)),
        Next::Keep(receipt) => match shown {
            Some(shown) => ElectionsEffect::one(Step::Ask {
                ask: VtaAsk::Keep {
                    election: shown.election_id().to_string(),
                    receipt,
                },
                commit: None,
            }),
            None => ElectionsEffect::done(),
        },
    }
}

/// Plan the read of the VTA's held election notifications, when due and its lane is free
/// (VTI-NTF-063). Pure; `vta_busy` is whether the VTA's lane is held.
fn plan_notified(state: &mut State, has_vta: bool, vta_busy: bool) -> Option<Step> {
    let view = view_mut(state)?;
    if !view.notified_due || view.flow.is_some() {
        return None;
    }
    if !has_vta {
        view.notified_due = false;
        view.notified_phase =
            NotifiedPhase::Unavailable("no VTA is connected, and it holds them".into());
        return None;
    }
    if vta_busy {
        return None;
    }
    Some(Step::Ask {
        ask: VtaAsk::Notified,
        commit: Some(Commit::NotifiedAsked),
    })
}

// ****************************************************************************
// The loop's side: the effect runner
// ****************************************************************************

/// Service an action that reads the config or sends: [`plan`] it, then
/// [`run`] what it asks for.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: Act) {
    let effect = plan(ctx.state, ctx.config, ctx.admin_vta.is_some(), action);
    run(&mut Loop::from_ctx(ctx), effect).await;
}

/// Take one step the view's last answer called for: [`plan_next`], then
/// [`run`]. Returns whether it was taken (a busy lane keeps it).
async fn step(lp: &mut Loop<'_>, next: Next) -> bool {
    let effect = plan_next(lp.state, lp.in_flight.is_busy(SEND), next);
    run(lp, effect).await
}

/// Read the VTA's held election notifications, when due and its lane is free:
/// [`plan_notified`], then the question it asks.
fn ask_notified(lp: &mut Loop<'_>) {
    let has_vta = lp.vta.is_some();
    let vta_busy = lp.in_flight.is_busy(VTA);
    if let Some(Step::Ask { ask, commit }) = plan_notified(lp.state, has_vta, vta_busy) {
        run_ask(lp, ask, commit);
    }
}

/// Run an effect's steps in order. Returns whether a [`Next`] it came from
/// was taken.
async fn run(lp: &mut Loop<'_>, effect: ElectionsEffect) -> bool {
    let mut last = true;
    for step in effect.steps {
        last = match step {
            Step::Send(send) => run_send(lp, *send).await,
            Step::Ask { ask, commit } => run_ask(lp, ask, commit),
            Step::Deliver(cast) => deliver(lp, cast),
        };
    }
    match effect.taken {
        Taken::Yes => true,
        Taken::No => false,
        Taken::ByLastStep => last,
    }
}

/// Ask the VTA, then commit once it was asked (or failed in a way the view
/// shows). Returns which.
fn run_ask(lp: &mut Loop<'_>, ask: VtaAsk, commit: Option<Commit>) -> bool {
    let asked = ask_vta(lp, ask);
    if asked
        && let Some(commit) = commit
        && let Some(view) = view_mut(lp.state)
    {
        commit.apply(view);
    }
    asked
}

/// Send a planned request: look up the key, build, claim and arm
/// ([`community_request::send`]), then commit — or say why not. Returns
/// whether it was dispatched or failed in a way the view now shows; `false`
/// only when nothing happened (a busy lane, a view still waiting).
async fn run_send(lp: &mut Loop<'_>, send: Send) -> bool {
    let Send {
        to,
        persona,
        request,
        purpose,
        commit,
        refusal,
    } = send;
    let commit = |state: &mut State| {
        if let Some(commit) = commit
            && let Some(view) = view_mut(state)
        {
            commit.apply(view);
        }
    };
    match community_request::send::<Elections>(lp, to, persona, request, purpose).await {
        Sent::NoView | Sent::Waiting => false,
        Sent::Failed(purpose, why) => {
            commit(lp.state);
            fail::<Elections>(lp.state, &purpose, why);
            true
        }
        Sent::Unthreaded(purpose) => {
            commit(lp.state);
            fail::<Elections>(lp.state, &purpose, UNTHREADED.into());
            true
        }
        Sent::Busy => {
            if let Some(refusal) = refusal {
                refusal.show(lp.state);
            }
            false
        }
        Sent::Dispatched => {
            commit(lp.state);
            true
        }
    }
}

/// Ask the VTA. Returns whether it was dispatched (or failed in a way the view now shows).
fn ask_vta(lp: &mut Loop<'_>, ask: VtaAsk) -> bool {
    let Some((vtc_did, target, persona)) = lp
        .state
        .main_page
        .content_panel
        .elections
        .view
        .as_ref()
        .map(|v| (v.vtc_did.clone(), v.target.clone(), v.persona))
    else {
        return true;
    };
    let Some(vta) = lp.vta.cloned() else {
        end_flow(
            lp.state,
            Severity::Error,
            "Voting needs your VTA: it holds the voter keys and the ticket. None is \
             connected.",
        );
        return true;
    };
    let Some(context_id) = persona_context(lp.config, persona) else {
        end_flow(
            lp.state,
            Severity::Error,
            "This persona has no VTA context to hold its voter keys.",
        );
        return true;
    };
    let job = VtaJob {
        vta,
        context_id,
        target,
        vtc_did,
        persona,
        ask,
    };
    background_dispatch::dispatch(job, lp.in_flight, lp.dispatch_tx, |_| {})
}

/// One question for the VTA, about the open election's community.
struct VtaJob {
    vta: vta_sdk::client::VtaClient,
    context_id: String,
    /// The registrar: the community holding the election.
    target: String,
    vtc_did: String,
    persona: PersonaId,
    ask: VtaAsk,
}

impl background_dispatch::Job for VtaJob {
    fn domain(&self) -> DispatchDomain {
        VTA
    }

    async fn execute(self) -> DispatchOutcome {
        let voter = Voter {
            vta: &self.vta,
            context_id: &self.context_id,
            community: &self.target,
        };
        let answer = self.ask.run(&voter).await;
        DispatchOutcome::ElectionsVta(ElectionsVtaOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            answer,
        })
    }
}

/// Send the cast to the ballot box, after a random pause.
fn deliver(lp: &mut Loop<'_>, cast: Cast) -> bool {
    let Some((vtc_did, persona, ballot_box)) = lp
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
    let job = CastJob {
        resolver: lp.tdk.did_resolver().clone(),
        ballot_box,
        vtc_did,
        persona,
        cast,
    };
    background_dispatch::dispatch(job, lp.in_flight, lp.dispatch_tx, |_| {})
}

/// One cast on its way to the ballot box.
struct CastJob {
    resolver: affinidi_tdk::did_resolver::DIDCacheClient,
    ballot_box: String,
    vtc_did: String,
    persona: PersonaId,
    cast: Cast,
}

impl background_dispatch::Job for CastJob {
    fn domain(&self) -> DispatchDomain {
        CAST
    }

    async fn execute(self) -> DispatchOutcome {
        let result = elections::deliver_cast(
            &self.resolver,
            &self.ballot_box,
            &self.cast,
            elections::cast_delay(),
        )
        .await;
        DispatchOutcome::ElectionsCast(Box::new(ElectionsCastOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            cast: self.cast,
            result,
        }))
    }
}

/// What a send carries: a request built and signed here, or a document the VTA signed.
pub(crate) enum Outgoing {
    Build(Request),
    Signed(serde_json::Value),
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
fn failed(view: &mut ElectionsView, purpose: &Purpose, why: String) {
    match purpose {
        Purpose::List if view.elections.is_empty() => view.phase = ElectionsPhase::Failed(why),
        Purpose::List | Purpose::Show { .. } | Purpose::Issue { .. } => {
            view.flow = None;
            view.note(Severity::Error, why);
        }
    }
}

/// `y` on the disclosure: read the election presenting the membership it is put to, as the
/// member chose. Nothing is presented before this key (VTI-VOT-016).
fn present(state: &mut State, has_vta: bool) {
    let Some(view) = view_mut(state) else {
        return;
    };
    if view.screen != Screen::Disclose {
        return;
    }
    let Some(d) = view.disclose.take() else {
        return;
    };
    if !has_vta {
        view.screen = Screen::List;
        view.note(
            Severity::Error,
            "Reading this election presents your membership credential, which your VTA holds. \
             None is connected.",
        );
        return;
    }
    view.target = d.held_by;
    view.presenting = Some(d.member_of.clone());
    view.screen = Screen::Detail;
    view.shown = None;
    view.note(
        Severity::Progress,
        "Your VTA is signing the read, presenting your membership…",
    );
    view.next = Some(Next::ReadPresenting {
        election: d.election,
        member_of: d.member_of,
        intent: d.intent,
    });
}

/// `y` on the confirmation: have the VTA build the cast.
fn cast(state: &mut State) {
    let Some(view) = view_mut(state) else {
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
        step: FlowStep::Building,
    });
    view.note(Severity::Progress, FlowStep::Building.words());
    view.next = Some(Next::Vote { ballot });
}

/// `r` on a lost answer: send the same cast again.
fn resend(state: &mut State) {
    let Some(view) = view_mut(state) else {
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
        step: FlowStep::Casting,
    });
    view.note(Severity::Progress, FlowStep::Casting.words());
    view.next = Some(Next::Deliver(cast));
}

/// Open the panel for the Active community at a Communities display index.
fn open(state: &mut State, config: &Config, index: usize) {
    let target = config
        .account
        .communities_for_display(state.main_page.content_panel.communities.show_archived)
        .get(index)
        .filter(|c| c.status.is_active())
        .map(|c| {
            (
                c.vtc_did.clone(),
                c.persona_ref,
                crate::state_handler::community_label(
                    config,
                    &c.vtc_did,
                    c.display_name.as_deref(),
                    256,
                ),
            )
        });
    let Some((vtc, persona, name)) = target else {
        return;
    };
    let me = config
        .identities
        .get(&persona)
        .map(|id| id.persona_did().to_string())
        .unwrap_or_default();
    state.main_page.content_panel.elections.view = Some(ElectionsView::new(vtc, persona, me, name));
}

/// Take the step the view's last answer called for, if its lane is free. The loop calls this
/// after applying replies and outcomes, and on its tick.
pub(crate) async fn advance(lp: &mut Loop<'_>) {
    community_request::advance::<Elections>(lp).await;
}

/// The loop's periodic pass: reply windows, and any step left waiting on a busy lane.
pub(crate) async fn tick(lp: &mut Loop<'_>) {
    community_request::tick::<Elections>(lp).await;
}

/// The request made for `purpose` went unanswered for `secs` seconds.
fn timed_out(view: &mut ElectionsView, purpose: Purpose, secs: u64) {
    match purpose {
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

/// A job ended without an outcome (it panicked): end what it was part of.
pub(crate) fn job_lost(state: &mut State, msg: &str) {
    community_request::job_lost::<Elections>(state, msg);
}

/// Apply the community's answers. Returns whether any was taken, so the loop [`advance`]s.
pub(crate) fn apply_replies(
    state: &mut State,
    pending_replies: &mut PendingReplies,
    replies: Vec<InboundReply>,
) -> bool {
    community_request::apply_replies::<Elections>(state, pending_replies, replies)
}

/// Take the answer to the request made for `purpose`.
fn take_reply(view: &mut ElectionsView, reply: Reply, purpose: Purpose) {
    match (reply, purpose) {
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
                return;
            }
            view.shown = Some(shown);
            match intent {
                Intent::View => view.clear_progress(),
                Intent::Ticket | Intent::Vote => after_show(view),
            }
        }
        (Reply::TicketIssued { raw, .. }, Purpose::Issue { .. }) => {
            if let Some(flow) = view.flow.as_mut() {
                flow.step = FlowStep::Accepting;
            }
            view.note(Severity::Progress, FlowStep::Accepting.words());
            view.next = Some(Next::Accept { issued: raw });
        }
        // A notified election put to the members of another party: its community shows it
        // only to a read presenting that membership (VTI-VOT-015). Offer that read, saying what
        // it shows, and present nothing until the member chooses (VTI-VOT-016).
        (Reply::Refused(r), Purpose::Show { election, intent })
            if r.is("electionUnknown")
                && view.presenting.is_none()
                && view.opening.as_ref().is_some_and(|n| {
                    n.election_id == election && n.audience_is_another_party()
                }) =>
        {
            let Some(n) = view.opening.clone() else {
                return;
            };
            view.flow = None;
            view.status = None;
            view.disclose = Some(Disclose {
                held_by: n.held_by,
                election,
                member_of: n.audience,
                intent,
            });
            view.screen = Screen::Disclose;
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
        flow.step = FlowStep::Registering;
    }
    view.note(Severity::Progress, FlowStep::Registering.words());
    view.next = Some(Next::Register);
}

// ****************************************************************************
// Asking the VTA
// ****************************************************************************

/// One call to the member's VTA.
enum VtaAsk {
    /// The held notifications of the kind `election`.
    Notified,
    /// Sign the read of an election presenting a membership.
    ReadPresenting {
        member: String,
        election: String,
        member_of: String,
        intent: Intent,
    },
    Register {
        shown: Box<ShownElection>,
        /// The persona DID: under a credential roll, the VTA signs the claim as it.
        member: String,
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
    Notified(Result<Vec<NotifiedElection>, String>),
    ReadSigned {
        election: String,
        intent: Intent,
        result: Result<serde_json::Value, String>,
    },
    Registered(Result<Registered, String>),
    Accepted(Result<(), String>),
    Voted(Result<Cast, String>),
    Kept(Result<Kept, String>),
}

impl VtaAsk {
    async fn run(self, v: &Voter<'_>) -> VtaAnswer {
        match self {
            VtaAsk::Notified => VtaAnswer::Notified(
                openvtc_core::notifications::list_elections(v.vta, v.context_id).await,
            ),
            VtaAsk::ReadPresenting {
                member,
                election,
                member_of,
                intent,
            } => {
                let result = async {
                    let credential = held_membership(v, &member_of, &member).await?;
                    elections::read_presenting(v, &member, &election, &member_of, &credential)
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                VtaAnswer::ReadSigned {
                    election,
                    intent,
                    result,
                }
            }
            VtaAsk::Register { shown, member } => {
                let result = async {
                    // Under a credential roll the claim presents the membership the roll names
                    // (VTI-VOT-025); under any other, the VTA builds the request alone.
                    let credential = match shown.credential_roll() {
                        Some(member_of) => Some(held_membership(v, member_of, &member).await?),
                        None => None,
                    };
                    let claim = credential.as_deref().map(|credential| Claim {
                        member: &member,
                        credential,
                    });
                    elections::register(v, &shown, claim)
                        .await
                        .map_err(|e| e.to_string())
                }
                .await;
                VtaAnswer::Registered(result)
            }
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

/// The vault handle of the persona's membership credential from `member_of`, or why there is
/// none to present.
async fn held_membership(v: &Voter<'_>, member_of: &str, member: &str) -> Result<String, String> {
    elections::membership_credential_for(v.vta, member_of, member)
        .await
        .map_err(|e| format!("your VTA's credential vault did not answer: {e}"))?
        .ok_or_else(|| {
            format!(
                "Your VTA holds no valid membership credential that {} issued this persona, so \
                 there is nothing to present.",
                openvtc_core::display::sanitize_display(member_of, 256)
            )
        })
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
            VtaAnswer::Notified(Ok(items)) => view.take_notified(items),
            VtaAnswer::Notified(Err(e)) => {
                view.notified_phase = NotifiedPhase::Unavailable(e);
            }
            VtaAnswer::ReadSigned {
                election,
                intent,
                result: Ok(document),
            } => {
                view.next = Some(Next::SendShowDocument {
                    document,
                    election,
                    intent,
                });
            }
            VtaAnswer::ReadSigned { result: Err(e), .. } => {
                view.flow = None;
                view.note(Severity::Error, e);
            }
            VtaAnswer::Registered(Ok(Registered::Document(document))) => {
                if let Some(flow) = view.flow.as_mut() {
                    flow.step = FlowStep::Issuing;
                }
                view.note(Severity::Progress, FlowStep::Issuing.words());
                view.next = Some(Next::SendIssueDocument(document));
            }
            VtaAnswer::Registered(Ok(Registered::Request(ticket))) => {
                if let Some(flow) = view.flow.as_mut() {
                    flow.step = FlowStep::Issuing;
                }
                view.note(Severity::Progress, FlowStep::Issuing.words());
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
                        .insert((view.target.clone(), flow.election), now);
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
                    flow.step = FlowStep::Casting;
                }
                view.screen = Screen::Result;
                view.note(Severity::Progress, FlowStep::Casting.words());
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
                    flow.step = FlowStep::Keeping;
                }
                view.result = Some(VoteResult::Counted {
                    outcome: receipt.outcome,
                    leaf_index: receipt.leaf_index,
                    kept: None,
                    keep_error: None,
                });
                view.note(Severity::Progress, FlowStep::Keeping.words());
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
