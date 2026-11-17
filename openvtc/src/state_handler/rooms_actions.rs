//! The Rooms panel: a community's data rooms, from the member's side.
//!
//! Opened from Communities with `o`. It shows what every surface the member uses shows —
//! the community's member portal, `pnm`, this client — because it reads the same two
//! records and keeps none of its own ([`openvtc_core::community_rooms`]):
//!
//! - the **community's**, `vtc/rooms/memberships/list`, signed with the persona's key and
//!   sent on its channel off the loop in [`DispatchDomain::Rooms`], exactly as the Repos
//!   panel sends `git-ns/*`: the view waits on the request's thread from before the send
//!   is spawned, and [`apply_replies`] matches the answer that arrives on the inbound
//!   channel;
//! - the **VTA's**, `rooms/keys/list`, in [`DispatchDomain::RoomsVta`].
//!
//! **Accepting** (`⏎`) runs across both: the offer's credentials from the community
//! (`vtc/rooms/offers/list`), the VTA storing them and giving the KeyPackage
//! (`rooms/keys/key-package/0.2` — the one it already holds, if another surface began
//! this acceptance), the acceptance (`vtc/rooms/offers/accept`), and the VTA joining from
//! the Welcome — where `alreadyJoined` means another surface finished first.
//!
//! **Renewals** are collected on every read once a VTA is connected: the offers listing
//! (`vtc/rooms/offers/list/0.4`) carries the renewals the community keeps for the member,
//! and the VTA stores those it does not hold ([`community_rooms::collect_renewals`]) —
//! which is what restores a member suspended while a room was closed. A read that renewed
//! nothing does not read again. Each step's
//! answer sets the view's [`Next`]; [`advance`], which the loop calls after applying
//! replies and outcomes, takes it. After an acceptance ends, either way, the view is read
//! again: the community and the VTA are the record.
//!
//! An action that sends is planned by [`plan`], and a [`Next`] by [`plan_next`]: both are
//! pure, make the changes due before anything is claimed, and return a [`RoomsEffect`] — the
//! steps in order. [`run`] takes them: a send looks up the persona's key, builds, claims and
//! arms ([`community_request::send`]); a question to the VTA claims its lane; each applies
//! its [`Commit`] only once under way and shows its [`Refusal`] when not.

use openvtc_core::community_rooms::{
    self, Joined, Offer, Prepared, Renewal, Reply, Request, RoomCondition, Standing,
};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::RoomsAction as Act;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
pub(crate) use crate::state_handler::community_request::CommunityLoop as Loop;
use crate::state_handler::community_request::{
    self, CommunityFeature, Doc, SendOutcome, Sender, Sent, UNTHREADED,
};
use crate::state_handler::main_page::rooms::{
    AcceptFlow, AcceptStep, Next, Purpose, RoomsPhase, RoomsView, Severity,
};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;
use openvtc_core::pending_replies::PendingReplies;

const SEND: DispatchDomain = DispatchDomain::Rooms;
const KEYS: DispatchDomain = DispatchDomain::RoomsVta;

/// A `vtc/rooms/*` answer as it arrived, threaded on the request it answers
/// ([`openvtc_core::inbound::ThreadedReply`]).
pub(crate) type InboundReply = openvtc_core::inbound::ThreadedReply<Reply>;

fn view_mut(state: &mut State) -> Option<&mut RoomsView> {
    state.main_page.content_panel.rooms.view.as_mut()
}

// ****************************************************************************
// View-only changes
// ****************************************************************************

/// Apply a view-only action. `false` for the actions the runtime loop services.
pub(crate) fn reduce(state: &mut State, action: &Act) -> bool {
    match action {
        Act::Open(_) | Act::Refresh | Act::Accept => false,
        Act::Back => {
            state.main_page.content_panel.rooms.view = None;
            true
        }
        Act::Select(i) => {
            if let Some(view) = view_mut(state) {
                view.selected = (*i).min(view.rooms.len().saturating_sub(1));
            }
            true
        }
    }
}

// ****************************************************************************
// The loop's side
// ****************************************************************************

/// The Rooms panel, on the shared request/reply plumbing
/// ([`community_request`]).
pub(crate) struct Rooms;

impl CommunityFeature for Rooms {
    type View = RoomsView;
    type Purpose = Purpose;
    type Reply = Reply;
    type Next = Next;
    type Request = Request;
    const NAME: &'static str = "rooms";
    const SEND: DispatchDomain = SEND;
    /// Only a community the persona belongs to answers the Rooms panel.
    const RECORDS_THREAD: bool = false;

    fn view_mut(state: &mut State) -> Option<&mut RoomsView> {
        view_mut(state)
    }
    fn pending_mut(view: &mut RoomsView) -> &mut Option<community_request::Pending<Purpose>> {
        &mut view.pending
    }
    fn next_mut(view: &mut RoomsView) -> &mut Option<Next> {
        &mut view.next
    }
    fn community(view: &RoomsView) -> (&str, PersonaId) {
        (&view.vtc_did, view.persona)
    }
    fn note(view: &mut RoomsView, severity: Severity, text: String) {
        view.note(severity, text);
    }
    fn outcome(outcome: SendOutcome) -> DispatchOutcome {
        DispatchOutcome::Rooms(outcome)
    }
    fn build(
        _config: &Config,
        sender: &mut Sender,
        to: &str,
        _persona: PersonaId,
        request: Request,
    ) -> Result<Doc, String> {
        community_rooms::build(&request, &sender.persona_did, to)
            .map(|doc| Doc::Unsigned(Box::new(doc)))
            .map_err(|e| format!("couldn't send: {e}"))
    }
    fn is_refusal(reply: &Reply) -> bool {
        matches!(reply, Reply::Refused(_))
    }
    fn take_reply(view: &mut RoomsView, reply: Reply, purpose: Purpose) {
        take_reply(view, reply, purpose);
    }
    fn timed_out(view: &mut RoomsView, purpose: Purpose, secs: u64) {
        timed_out(view, purpose, secs);
    }
    fn failed(view: &mut RoomsView, purpose: &Purpose, why: String) {
        failed(view, purpose, why);
    }
    fn end_flow(view: &mut RoomsView) {
        view.accept = None;
    }
    async fn step(lp: &mut Loop<'_>, next: Next) -> bool {
        step(lp, next).await
    }
}

// ****************************************************************************
// The loop's side: the reducer
// ****************************************************************************

/// What an action or a [`Next`] asks of the loop once [`plan`] or
/// [`plan_next`] has made its own changes: the steps, in order, and whether a
/// [`Next`] it came from counts as taken.
struct RoomsEffect {
    steps: Vec<Step>,
    taken: Taken,
}

impl RoomsEffect {
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
    /// Send to the open view's community ([`community_request::send`]).
    Send(Box<Send>),
    /// Ask the VTA: claimed in [`DispatchDomain::RoomsVta`], then `commit`
    /// applied; `refusal` shown when it was not asked.
    Ask {
        ask: VtaAsk,
        commit: Option<Commit>,
        refusal: Option<Refusal>,
    },
}

/// A request to the community, planned to everything but the persona's key.
struct Send {
    to: String,
    persona: PersonaId,
    request: Request,
    purpose: Purpose,
    /// Applied once the request is claimed and the view armed.
    commit: Option<Commit>,
    /// Shown when its lane was busy. A key lookup or document that failed
    /// shows its own reason instead.
    refusal: Option<Refusal>,
}

/// A view change made only once its request or question is under way.
#[derive(Debug, PartialEq, Eq)]
enum Commit {
    /// An acceptance of `room` is collecting the offer, saying `progress`.
    Accepting { room: String, progress: String },
    /// The view's renewals went to the VTA.
    RenewalsHandedOver,
}

impl Commit {
    fn apply(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        match self {
            Commit::Accepting { room, progress } => {
                view.accept = Some(AcceptFlow {
                    room,
                    step: AcceptStep::Collecting,
                    offer: None,
                });
                view.note(Severity::Progress, progress);
            }
            Commit::RenewalsHandedOver => view.renewals.clear(),
        }
    }
}

/// What the view says when a step did not start because its lane was busy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The acceptance did not start.
    Accept,
    /// The VTA was not asked which rooms it holds; the record still refreshes.
    Custody,
    /// The record was not read again.
    Record,
}

impl Refusal {
    fn show(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        match self {
            Refusal::Accept => view.note(Severity::Warning, InFlight::busy_message(SEND)),
            Refusal::Record => view.note(
                Severity::Warning,
                format!(
                    "{} The rooms were not read again — press r once it finishes.",
                    InFlight::busy_message(SEND)
                ),
            ),
            Refusal::Custody => {
                view.held_error
                    .get_or_insert_with(|| "your VTA is busy".into());
            }
        }
    }
}

/// A request to the open view's community.
fn to_community(
    view: &RoomsView,
    request: Request,
    purpose: Purpose,
    commit: Option<Commit>,
    refusal: Option<Refusal>,
) -> Step {
    Step::Send(Box::new(Send {
        to: view.vtc_did.clone(),
        persona: view.persona,
        request,
        purpose,
        commit,
        refusal,
    }))
}

/// Plan an action that reads the config or sends. Pure: it makes the changes
/// the action makes before anything is claimed and returns the steps the loop
/// still owes. `has_vta` is whether a VTA session is connected.
fn plan(state: &mut State, config: &Config, has_vta: bool, action: Act) -> RoomsEffect {
    match action {
        Act::Open(index) => {
            open(state, config, index);
            plan_reread(state, has_vta)
        }
        Act::Refresh => plan_reread(state, has_vta),
        Act::Accept => plan_accept(state, has_vta),
        Act::Back | Act::Select(_) => RoomsEffect::done(),
    }
}

/// `r`, or the panel opening: show it loading when it has nothing yet, clear
/// the status line, and read both again.
fn plan_reread(state: &mut State, has_vta: bool) -> RoomsEffect {
    if let Some(view) = view_mut(state) {
        if view.rooms.is_empty() {
            view.phase = RoomsPhase::Loading;
        }
        view.status = None;
    }
    RoomsEffect {
        steps: plan_refresh(state, has_vta),
        taken: Taken::Yes,
    }
}

/// Read the community's record and the VTA's custody again.
fn plan_refresh(state: &mut State, has_vta: bool) -> Vec<Step> {
    let Some(view) = view_mut(state) else {
        return Vec::new();
    };
    view.restart_pages();
    let mut steps = Vec::new();
    if has_vta {
        // Busy with an acceptance step; the record still refreshes.
        steps.push(Step::Ask {
            ask: VtaAsk::Held {
                member: view.me.clone(),
            },
            commit: None,
            refusal: Some(Refusal::Custody),
        });
    } else {
        view.held = None;
        view.held_error =
            Some("no VTA is connected, so which rooms it holds keys for can't be shown".into());
    }
    steps.push(to_community(
        view,
        Request::Memberships { cursor: None },
        Purpose::Memberships,
        None,
        Some(Refusal::Record),
    ));
    steps
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
    state.main_page.content_panel.rooms.view = Some(RoomsView::new(vtc, persona, me, name));
}

/// An acceptance pressed while the view still waits on an earlier request.
const ACCEPT_WAITING: &str =
    "A request to this community is still waiting — try again when it answers.";

/// `⏎` on a room: accept its offer, or finish an acceptance begun elsewhere.
fn plan_accept(state: &mut State, has_vta: bool) -> RoomsEffect {
    let Some(view) = view_mut(state) else {
        return RoomsEffect::done();
    };
    if view.accept.is_some() {
        view.note(Severity::Warning, "An acceptance is already in progress.");
        return RoomsEffect::done();
    }
    let Some(row) = view.selected_row() else {
        return RoomsEffect::done();
    };
    // An archived room, or one being removed, admits nobody: the community would refuse.
    let condition = RoomCondition::of(&row.room);
    if !condition.admits() && row.standing.acceptable() {
        view.note(
            Severity::Warning,
            condition
                .explain()
                .unwrap_or_else(|| "This room admits nobody now.".into()),
        );
        return RoomsEffect::done();
    }
    match row.standing {
        s if s.acceptable() => {}
        Standing::NeedsReadmission => {
            view.note(
                Severity::Warning,
                "Your VTA never joined this room and the community no longer keeps what it \
                 needs to finish: ask an administrator to remove and re-admit you.",
            );
            return RoomsEffect::done();
        }
        Standing::Suspended => {
            view.note(
                Severity::Info,
                condition.explain().unwrap_or_else(|| {
                    "Your access to this room is withdrawn while it is closed; it is restored \
                     if the community reopens it."
                        .into()
                }),
            );
            return RoomsEffect::done();
        }
        Standing::Admitted if !has_vta => {
            view.note(
                Severity::Warning,
                "Whether this room is joined needs your VTA, which holds its keys — none is \
                 connected.",
            );
            return RoomsEffect::done();
        }
        _ => {
            view.note(Severity::Info, "Nothing to accept here.");
            return RoomsEffect::done();
        }
    }
    if !has_vta {
        view.note(
            Severity::Error,
            "Accepting a room needs your VTA: it holds the room's keys and credentials.",
        );
        return RoomsEffect::done();
    }
    let room = row.room.room_id.to_string();
    let progress = format!(
        "Accepting {}… collecting the offer",
        community_rooms::display_label(&row.room)
    );
    if view.pending.is_some() {
        // The view still waits on an earlier request: one request to a
        // community at a time, so the press is refused and nothing is set,
        // leaving it to be pressed again, as Elections refuses.
        view.note(Severity::Warning, ACCEPT_WAITING);
        return RoomsEffect::done();
    }
    // Not sent (lane busy): the press is dropped with the busy message, to be
    // pressed again.
    RoomsEffect::one(to_community(
        view,
        Request::Offers { cursor: None },
        Purpose::Offers { room: room.clone() },
        Some(Commit::Accepting { room, progress }),
        Some(Refusal::Accept),
    ))
}

/// Plan one [`Next`]. Pure, like [`plan`]; `send_busy` is whether the
/// community lane is held.
fn plan_next(state: &mut State, has_vta: bool, send_busy: bool, next: Next) -> RoomsEffect {
    // [`advance`] takes a step only from an open view.
    let Some(view) = view_mut(state) else {
        return RoomsEffect::done();
    };
    match next {
        Next::Refresh => {
            if send_busy || view.pending.is_some() {
                RoomsEffect {
                    steps: Vec::new(),
                    taken: Taken::No,
                }
            } else {
                RoomsEffect {
                    steps: plan_refresh(state, has_vta),
                    taken: Taken::Yes,
                }
            }
        }
        Next::MembershipsPage { cursor } => RoomsEffect::one(to_community(
            view,
            Request::Memberships {
                cursor: Some(cursor),
            },
            Purpose::Memberships,
            None,
            None,
        )),
        Next::OffersPage { room, cursor } => RoomsEffect::one(to_community(
            view,
            Request::Offers {
                cursor: Some(cursor),
            },
            Purpose::Offers { room },
            None,
            None,
        )),
        Next::Prepare => match view.accept.as_ref().and_then(|a| a.offer.clone()) {
            Some(offer) => RoomsEffect::one(Step::Ask {
                ask: VtaAsk::Prepare {
                    offer,
                    member: view.me.clone(),
                },
                commit: None,
                refusal: None,
            }),
            None => RoomsEffect::done(),
        },
        Next::SendAccept { room, key_package } => RoomsEffect::one(to_community(
            view,
            Request::Accept {
                room_id: room.clone(),
                key_package,
            },
            Purpose::Accept { room },
            None,
            None,
        )),
        Next::Join {
            room,
            welcome,
            ratchet_tree,
        } => match view
            .accept
            .as_ref()
            .and_then(|a| a.offer.as_ref())
            .map(|o| o.credentials.invitation.to_string())
        {
            Some(invitation) => RoomsEffect::one(Step::Ask {
                ask: VtaAsk::Join {
                    room,
                    invitation,
                    welcome,
                    ratchet_tree,
                },
                commit: None,
                refusal: None,
            }),
            None => RoomsEffect::done(),
        },
        // Without a VTA there is nowhere to store a renewal, so nothing to read.
        Next::CheckRenewals if !has_vta => RoomsEffect::done(),
        Next::CheckRenewals => RoomsEffect::one(to_community(
            view,
            Request::Offers { cursor: None },
            Purpose::Renewals,
            None,
            None,
        )),
        // The renewals stay in the view until the VTA's lane takes them.
        Next::Renew if view.renewals.is_empty() => RoomsEffect::done(),
        // The VTA went away since they were collected: nothing can store them
        // now, and the first read once one is connected collects them again.
        Next::Renew if !has_vta => {
            tracing::debug!(
                renewals = view.renewals.len(),
                "rooms renewals dropped: no VTA is connected to store them"
            );
            view.renewals.clear();
            RoomsEffect::done()
        }
        Next::Renew => RoomsEffect::one(Step::Ask {
            ask: VtaAsk::Renew {
                renewals: view.renewals.clone(),
                member: view.me.clone(),
            },
            commit: Some(Commit::RenewalsHandedOver),
            refusal: None,
        }),
    }
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
    let effect = plan_next(lp.state, lp.vta.is_some(), lp.in_flight.is_busy(SEND), next);
    run(lp, effect).await
}

/// Run an effect's steps in order. Returns whether a [`Next`] it came from
/// was taken.
async fn run(lp: &mut Loop<'_>, effect: RoomsEffect) -> bool {
    let mut last = true;
    for step in effect.steps {
        last = match step {
            Step::Send(send) => run_send(lp, *send).await,
            Step::Ask {
                ask,
                commit,
                refusal,
            } => {
                let asked = ask_vta(lp, ask);
                if asked {
                    if let Some(commit) = commit {
                        commit.apply(lp.state);
                    }
                } else if let Some(refusal) = refusal {
                    refusal.show(lp.state);
                }
                asked
            }
        };
    }
    match effect.taken {
        Taken::Yes => true,
        Taken::No => false,
        Taken::ByLastStep => last,
    }
}

/// Send a planned request: look up the key, build, claim and arm
/// ([`community_request::send`]), then commit — or say why not. Returns
/// whether it was dispatched or failed in a way the view now shows; `false`
/// only when nothing happened (a busy lane, a view still waiting). A shown
/// failure counts as taken, so a [`Next`] whose key lookup fails is not
/// retried every tick: the reason stays until the person acts again, as in
/// Elections.
async fn run_send(lp: &mut Loop<'_>, send: Send) -> bool {
    let Send {
        to,
        persona,
        request,
        purpose,
        commit,
        refusal,
    } = send;
    match community_request::send::<Rooms>(lp, to, persona, request, purpose).await {
        Sent::NoView => false,
        Sent::Waiting => {
            if let Some(view) = view_mut(lp.state) {
                view.note(
                    Severity::Warning,
                    "Still waiting for the community's answer.",
                );
            }
            false
        }
        // The reason stands alone: the lane was never reached, so it is not
        // said to be busy.
        Sent::Failed(purpose, why) => {
            community_request::fail::<Rooms>(lp.state, &purpose, why);
            true
        }
        Sent::Unthreaded(purpose) => {
            community_request::fail::<Rooms>(lp.state, &purpose, UNTHREADED.into());
            true
        }
        Sent::Busy => {
            if let Some(refusal) = refusal {
                refusal.show(lp.state);
            }
            false
        }
        Sent::Dispatched => {
            if let Some(commit) = commit {
                commit.apply(lp.state);
            }
            true
        }
    }
}

/// Ask the VTA. Returns whether it was dispatched.
fn ask_vta(lp: &mut Loop<'_>, ask: VtaAsk) -> bool {
    let Some(vta) = lp.vta.cloned() else {
        return false;
    };
    let Some((vtc_did, persona)) = lp
        .state
        .main_page
        .content_panel
        .rooms
        .view
        .as_ref()
        .map(|v| (v.vtc_did.clone(), v.persona))
    else {
        return false;
    };
    let job = VtaJob {
        vta,
        vtc_did,
        persona,
        ask,
    };
    background_dispatch::dispatch(job, lp.in_flight, lp.dispatch_tx, |_| {})
}

/// One question for the VTA about the open community's room keys.
struct VtaJob {
    vta: VtaClient,
    vtc_did: String,
    persona: PersonaId,
    ask: VtaAsk,
}

impl background_dispatch::Job for VtaJob {
    fn domain(&self) -> DispatchDomain {
        KEYS
    }

    async fn execute(self) -> DispatchOutcome {
        DispatchOutcome::RoomsVta(RoomsVtaOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            answer: self.ask.run(&self.vta).await,
        })
    }
}

/// Say a request never left, where the view shows it.
fn failed(view: &mut RoomsView, purpose: &Purpose, why: String) {
    match purpose {
        Purpose::Memberships if view.rooms.is_empty() => view.phase = RoomsPhase::Failed(why),
        Purpose::Memberships => view.note(Severity::Error, why),
        Purpose::Offers { .. } | Purpose::Accept { .. } => {
            view.accept = None;
            view.note(Severity::Error, why);
        }
        // A background check: the record is shown regardless.
        Purpose::Renewals => {}
    }
}

/// Take the step the view's last answer called for, if its lane is free. The loop calls
/// this after applying replies and outcomes, and on its tick.
pub(crate) async fn advance(lp: &mut Loop<'_>) {
    community_request::advance::<Rooms>(lp).await;
}

/// The loop's periodic pass: reply windows, and any step left waiting on a busy lane.
pub(crate) async fn tick(lp: &mut Loop<'_>) {
    community_request::tick::<Rooms>(lp).await;
}

/// The request made for `purpose` went unanswered for `secs` seconds.
fn timed_out(view: &mut RoomsView, purpose: Purpose, secs: u64) {
    match purpose {
        Purpose::Memberships if view.rooms.is_empty() => {
            // A community that does not serve the record still answers, with a
            // refusal shown in words, so silence means the request or its answer was
            // lost (R6.4).
            view.phase = RoomsPhase::Failed(format!(
                "no reply within {secs}s. A community that does not serve data rooms says \
                     so, so this is not that: the request or its answer was lost — the \
                     community's VTC is offline or unreachable, or it answered on a route this \
                     persona does not collect. Press r to try again."
            ));
        }
        Purpose::Memberships => {
            view.note(
                Severity::Error,
                format!("no reply to the refresh within {secs}s"),
            );
        }
        Purpose::Offers { .. } | Purpose::Accept { .. } => {
            view.accept = None;
            view.note(
                Severity::Error,
                format!(
                    "No reply within {secs}s. Accepting again is safe: it finishes whatever \
                         was done, here or elsewhere. Refresh (r) first to see where it stands."
                ),
            );
        }
        Purpose::Renewals => {
            view.note(
                Severity::Warning,
                format!(
                    "no reply within {secs}s to the check for renewed access; refresh (r) to \
                         check again"
                ),
            );
        }
    }
}

/// A job ended without an outcome (it panicked): end what it was part of.
pub(crate) fn job_lost(state: &mut State, msg: &str) {
    community_request::job_lost::<Rooms>(state, msg);
}

/// Apply the community's answers. Returns whether any was taken, so the loop
/// [`advance`]s.
pub(crate) fn apply_replies(
    state: &mut State,
    pending_replies: &mut PendingReplies,
    replies: Vec<InboundReply>,
) -> bool {
    community_request::apply_replies::<Rooms>(state, pending_replies, replies)
}

/// Take the answer to the request made for `purpose`.
fn take_reply(view: &mut RoomsView, reply: Reply, purpose: Purpose) {
    match (reply, purpose) {
        (Reply::Memberships(page), Purpose::Memberships) => {
            let next = page.next_cursor.as_ref().map(|c| c.as_str().to_string());
            view.take_page(page.items, next.is_none());
            if let Some(cursor) = next {
                view.next = Some(Next::MembershipsPage { cursor });
            } else {
                view.clear_progress();
                // An acceptance in flight reads the offers itself; otherwise look for
                // renewals the community keeps for the member.
                if view.accept.is_none() {
                    view.next = Some(Next::CheckRenewals);
                }
            }
        }
        // Renewals are listed on the first page (`vtc/rooms/offers/list/0.4`).
        (Reply::Offers(page), Purpose::Renewals) => {
            if !page.renewals.is_empty() {
                view.renewals = page.renewals;
                view.next = Some(Next::Renew);
            }
        }
        (Reply::Offers(page), Purpose::Offers { room }) => {
            match page.items.into_iter().find(|o| o.room_id.as_str() == room) {
                Some(offer) => {
                    if let Some(flow) = view.accept.as_mut() {
                        flow.offer = Some(Box::new(offer));
                        flow.step = AcceptStep::Preparing;
                    }
                    view.note(Severity::Progress, "Your VTA is preparing to join…");
                    view.next = Some(Next::Prepare);
                }
                None => match page.next_cursor {
                    Some(cursor) => {
                        view.next = Some(Next::OffersPage {
                            room,
                            cursor: cursor.to_string(),
                        });
                    }
                    None => {
                        view.accept = None;
                        view.note(
                            Severity::Warning,
                            "The community has no open offer for this room any more — it may \
                             have been withdrawn, or accepted too long ago to finish. Refreshed.",
                        );
                        view.next = Some(Next::Refresh);
                    }
                },
            }
        }
        (Reply::Accepted(r), Purpose::Accept { room }) => match r.welcome {
            Some(welcome) => {
                if let Some(flow) = view.accept.as_mut() {
                    flow.step = AcceptStep::Joining;
                }
                view.note(
                    Severity::Progress,
                    "Admitted — your VTA is joining the room…",
                );
                view.next = Some(Next::Join {
                    room,
                    welcome: welcome.to_string(),
                    ratchet_tree: r.ratchet_tree.as_ref().map(|t| t.as_str().to_string()),
                });
            }
            None => {
                let sealed = view
                    .accept
                    .as_ref()
                    .and_then(|a| a.offer.as_ref())
                    .is_some_and(|o| community_rooms::offer_is_sealed(o));
                view.accept = None;
                if sealed {
                    view.note(
                        Severity::Error,
                        "The community admitted you to a sealed room but sent no Welcome.",
                    );
                } else {
                    view.note(Severity::Success, "Accepted — the room is open to you.");
                }
                view.next = Some(Next::Refresh);
            }
        },
        (Reply::Refused(r), purpose) => match purpose {
            Purpose::Memberships if view.rooms.is_empty() => {
                view.phase = RoomsPhase::Failed(r.explain());
            }
            Purpose::Memberships => view.note(Severity::Error, r.explain()),
            Purpose::Offers { .. } | Purpose::Accept { .. } => {
                view.accept = None;
                view.note(Severity::Error, r.explain());
                view.next = Some(Next::Refresh);
            }
            // The record stands; renewed access is looked for again on the next refresh.
            Purpose::Renewals => view.note(
                Severity::Warning,
                format!("couldn't check for renewed access: {}", r.explain()),
            ),
        },
        (Reply::Unreadable { task, detail }, purpose) => {
            let text = format!(
                "the community's answer to {task} doesn't match what this client expects \
                 ({detail}) — the community or this client may need updating"
            );
            if matches!(purpose, Purpose::Memberships) && view.rooms.is_empty() {
                view.phase = RoomsPhase::Failed(text);
            } else {
                view.accept = None;
                view.note(Severity::Error, text);
            }
        }
        (other, purpose) => {
            tracing::warn!(?purpose, reply = ?std::mem::discriminant(&other), "rooms reply of the wrong kind for its request");
            view.accept = None;
            view.note(
                Severity::Error,
                "The community answered with something else.",
            );
        }
    }
}

// ****************************************************************************
// Asking the VTA
// ****************************************************************************

/// One call to the member's VTA.
enum VtaAsk {
    Renew {
        renewals: Vec<Renewal>,
        member: String,
    },
    Held {
        member: String,
    },
    Prepare {
        offer: Box<Offer>,
        member: String,
    },
    Join {
        room: String,
        invitation: String,
        welcome: String,
        ratchet_tree: Option<String>,
    },
}

/// What the VTA answered.
pub(crate) enum VtaAnswer {
    Renewed(Result<Vec<String>, String>),
    Held(Result<Vec<String>, String>),
    Prepared(Result<Prepared, String>),
    Joined(Result<Joined, String>),
}

impl VtaAsk {
    async fn run(self, vta: &VtaClient) -> VtaAnswer {
        match self {
            VtaAsk::Renew { renewals, member } => {
                VtaAnswer::Renewed(community_rooms::collect_renewals(vta, &renewals, &member).await)
            }
            VtaAsk::Held { member } => VtaAnswer::Held(
                community_rooms::held_rooms(vta, &member)
                    .await
                    .map_err(|e| e.to_string()),
            ),
            VtaAsk::Prepare { offer, member } => {
                VtaAnswer::Prepared(community_rooms::prepare_acceptance(vta, &offer, &member).await)
            }
            VtaAsk::Join {
                room,
                invitation,
                welcome,
                ratchet_tree,
            } => VtaAnswer::Joined(
                community_rooms::join(vta, &room, &invitation, &welcome, ratchet_tree.as_deref())
                    .await,
            ),
        }
    }
}

/// The VTA's answer. Applied on the loop.
pub(crate) struct RoomsVtaOutcome {
    vtc_did: String,
    persona: PersonaId,
    answer: VtaAnswer,
}

impl RoomsVtaOutcome {
    pub(crate) fn apply(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        match self.answer {
            VtaAnswer::Renewed(Ok(rooms)) if rooms.is_empty() => {}
            VtaAnswer::Renewed(Ok(rooms)) => {
                view.note(
                    Severity::Success,
                    format!(
                        "Your VTA stored renewed access to {} room{} the community re-issued.",
                        rooms.len(),
                        if rooms.len() == 1 { "" } else { "s" }
                    ),
                );
                view.next = Some(Next::Refresh);
            }
            VtaAnswer::Renewed(Err(e)) => view.note(
                Severity::Error,
                format!("couldn't store renewed access: {e}"),
            ),
            VtaAnswer::Held(Ok(rooms)) => {
                view.held = Some(rooms);
                view.held_error = None;
            }
            VtaAnswer::Held(Err(e)) => {
                view.held = None;
                view.held_error = Some(format!("couldn't ask your VTA which rooms it holds: {e}"));
            }
            VtaAnswer::Prepared(result) => {
                let Some(room) = view.accept.as_ref().map(|a| a.room.clone()) else {
                    return;
                };
                match result {
                    Ok(Prepared::AlreadyJoined) => {
                        view.accept = None;
                        view.note(
                            Severity::Success,
                            "Already joined — your VTA holds this room, accepted from another \
                             surface.",
                        );
                        view.next = Some(Next::Refresh);
                    }
                    Ok(Prepared::Open) => {
                        if let Some(flow) = view.accept.as_mut() {
                            flow.step = AcceptStep::Accepting;
                        }
                        view.next = Some(Next::SendAccept {
                            room,
                            key_package: None,
                        });
                    }
                    Ok(Prepared::KeyPackage {
                        key_package,
                        already_minted,
                    }) => {
                        if let Some(flow) = view.accept.as_mut() {
                            flow.step = AcceptStep::Accepting;
                        }
                        view.note(
                            Severity::Progress,
                            if already_minted {
                                "Finishing an acceptance begun on another surface…"
                            } else {
                                "Accepting…"
                            },
                        );
                        view.next = Some(Next::SendAccept {
                            room,
                            key_package: Some(key_package),
                        });
                    }
                    Err(e) => {
                        view.accept = None;
                        view.note(Severity::Error, e);
                    }
                }
            }
            VtaAnswer::Joined(result) => {
                view.accept = None;
                match result {
                    Ok(Joined::At(epoch)) => view.note(
                        Severity::Success,
                        format!("Joined — your VTA holds the room, at epoch {epoch}."),
                    ),
                    Ok(Joined::Already) => view.note(
                        Severity::Success,
                        "Joined — another surface had already handed your VTA the Welcome.",
                    ),
                    Err(e) => view.note(Severity::Error, e),
                }
                view.next = Some(Next::Refresh);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::rooms::Pending;
    use openvtc_core::community_rooms::Reply;
    use serde_json::json;
    use std::time::Instant;

    fn state_with_view() -> State {
        let mut state = State::default();
        state.main_page.content_panel.rooms.view = Some(RoomsView::new(
            "did:key:zVtc".into(),
            PersonaId::default(),
            "did:key:zAlice".into(),
            "Community".into(),
        ));
        state
    }

    fn arm(state: &mut State, purpose: Purpose) {
        view_mut(state).unwrap().pending = Some(Pending {
            thid: "t1".into(),
            sent_at: Instant::now(),
            purpose,
            to: "did:key:zVtc".into(),
        });
    }

    fn inbound(reply: Reply) -> InboundReply {
        InboundReply {
            from: "did:key:zVtc".into(),
            issuer: Some("did:key:zVtc".into()),
            thid: "t1".into(),
            reply,
        }
    }

    fn page(items: serde_json::Value, next: Option<&str>) -> Reply {
        let mut v = json!({ "items": items });
        if let Some(n) = next {
            v["nextCursor"] = json!(n);
        }
        Reply::Memberships(Box::new(serde_json::from_value(v).unwrap()))
    }

    fn room(id: &str, state: &str, repeat: bool) -> serde_json::Value {
        let mut v = json!({
            "roomId": id, "host": "did:key:zVtc", "label": "Board pack",
            "visibility": "private", "actions": ["read"],
            "validUntil": "2027-10-01T00:00:00Z", "state": state,
            "offeredAt": "2026-10-14T10:00:00Z", "roomState": "active",
        });
        if repeat {
            v["repeatAcceptUntil"] = json!("2026-10-24T10:00:00Z");
        }
        v
    }

    /// The record is read a page at a time and shown once whole; the standing of each
    /// room comes from it and the VTA's custody together.
    #[test]
    fn the_record_and_the_custody_make_the_standing() {
        let mut state = state_with_view();
        arm(&mut state, Purpose::Memberships);
        assert!(apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(page(
                json!([room("did:key:zR1", "admitted", true)]),
                Some("c1")
            ))]
        ));
        let view = view_mut(&mut state).unwrap();
        assert!(view.rooms.is_empty(), "not shown until the last page");
        assert_eq!(
            view.next,
            Some(Next::MembershipsPage {
                cursor: "c1".into()
            })
        );
        view.next = None;
        arm(&mut state, Purpose::Memberships);
        apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(page(
                json!([room("did:key:zR2", "offered", false)]),
                None,
            ))],
        );
        let view = view_mut(&mut state).unwrap();
        assert_eq!(view.rooms.len(), 2);
        assert_eq!(view.phase, RoomsPhase::Loaded);
        view.held = Some(vec![]);
        let standings: Vec<_> = view.rows().iter().map(|r| r.standing).collect();
        assert_eq!(standings, vec![Standing::Unfinished, Standing::Offered]);
        view.held = Some(vec!["did:key:zR1".into()]);
        assert_eq!(view.rows()[0].standing, Standing::Joined);
    }

    /// An answer is taken only from the community the view asks.
    #[test]
    fn an_answer_from_anyone_else_is_dropped() {
        let mut state = state_with_view();
        arm(&mut state, Purpose::Memberships);
        let mut forged = inbound(page(json!([]), None));
        forged.from = "did:key:zMallory".into();
        assert!(!apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![forged]
        ));
        assert!(view_mut(&mut state).unwrap().pending.is_some());
    }

    /// `alreadyJoined` from the VTA reads as joined: another surface finished first.
    #[test]
    fn a_join_another_surface_finished_is_success() {
        let mut state = state_with_view();
        view_mut(&mut state).unwrap().accept = Some(AcceptFlow {
            room: "did:key:zR1".into(),
            step: AcceptStep::Joining,
            offer: None,
        });
        let persona = view_mut(&mut state).unwrap().persona;
        RoomsVtaOutcome {
            vtc_did: "did:key:zVtc".into(),
            persona,
            answer: VtaAnswer::Joined(Ok(Joined::Already)),
        }
        .apply(&mut state);
        let view = view_mut(&mut state).unwrap();
        assert!(view.accept.is_none());
        assert_eq!(view.status.as_ref().unwrap().severity, Severity::Success);
        assert_eq!(view.next, Some(Next::Refresh));
    }

    /// A refused acceptance ends the flow, says why, and reads the record again.
    #[test]
    fn a_refused_acceptance_reads_the_record_again() {
        let mut state = state_with_view();
        view_mut(&mut state).unwrap().accept = Some(AcceptFlow {
            room: "did:key:zR1".into(),
            step: AcceptStep::Accepting,
            offer: None,
        });
        arm(
            &mut state,
            Purpose::Accept {
                room: "did:key:zR1".into(),
            },
        );
        let refusal: openvtc_core::community_rooms::Refusal =
            openvtc_core::community_rooms::Refusal {
                code: "vtc/rooms/offers/accept:alreadyAccepted".into(),
                message: None,
            };
        assert!(refusal.is_already_accepted());
        apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(Reply::Refused(refusal))],
        );
        let view = view_mut(&mut state).unwrap();
        assert!(view.accept.is_none());
        assert!(view.status.as_ref().unwrap().text.contains("re-admit"));
        assert_eq!(view.next, Some(Next::Refresh));
    }

    /// A whole record leads to a check for renewals; a listing that carries some has the
    /// VTA store them, and one that carries none ends there.
    #[test]
    fn a_whole_record_checks_for_renewals_and_collects_any() {
        let mut state = state_with_view();
        arm(&mut state, Purpose::Memberships);
        apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(page(
                json!([room("did:key:zR1", "admitted", false)]),
                None,
            ))],
        );
        assert_eq!(
            view_mut(&mut state).unwrap().next,
            Some(Next::CheckRenewals)
        );

        // A listing with a renewal: the VTA is asked to store it.
        let view = view_mut(&mut state).unwrap();
        view.next = None;
        arm(&mut state, Purpose::Renewals);
        let offers: Reply = Reply::Offers(Box::new(
            serde_json::from_value(json!({
                "items": [],
                "renewals": [{
                    "roomId": "did:key:zR1", "host": "did:key:zVtc", "label": "Board pack",
                    "visibility": "private", "actions": ["read"],
                    "validUntil": "2027-11-10T00:00:00Z", "renewsAt": "2027-10-01T00:00:00Z",
                    "issuedAt": "2026-11-03T09:00:00Z",
                    "credentials": { "membership": "{}", "authority": "{}" },
                }],
            }))
            .unwrap(),
        ));
        apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(offers)],
        );
        let view = view_mut(&mut state).unwrap();
        assert_eq!(view.next, Some(Next::Renew));
        assert_eq!(view.renewals.len(), 1);

        // A listing with none: nothing more to do, and nothing failed.
        view.next = None;
        view.renewals.clear();
        arm(&mut state, Purpose::Renewals);
        let none: Reply = Reply::Offers(Box::new(
            serde_json::from_value(json!({ "items": [], "renewals": [] })).unwrap(),
        ));
        apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(none)],
        );
        let view = view_mut(&mut state).unwrap();
        assert_eq!(view.next, None);
        assert!(view.status.is_none());
    }

    /// A suspended admission in a closed room reads as suspended, with the room's state
    /// beside it.
    #[test]
    fn a_closed_room_shows_its_members_suspended() {
        let mut state = state_with_view();
        arm(&mut state, Purpose::Memberships);
        let mut r = room("did:key:zR1", "suspended", false);
        r["suspendedAt"] = json!("2026-11-02T10:00:00Z");
        r["roomState"] = json!("archived");
        r["roomAccess"] = json!("noAccess");
        apply_replies(
            &mut state,
            &mut PendingReplies::default(),
            vec![inbound(page(json!([r]), None))],
        );
        let view = view_mut(&mut state).unwrap();
        let row = &view.rows()[0];
        assert_eq!(row.standing, Standing::Suspended);
        assert_eq!(RoomCondition::of(&row.room), RoomCondition::Closed);
        assert!(!RoomCondition::of(&row.room).admits());
    }

    // ---- plan / plan_next: pure, nothing changed before a claim ----

    fn with_offered_room() -> State {
        let mut state = state_with_view();
        let view = view_mut(&mut state).unwrap();
        view.take_page(
            vec![serde_json::from_value(room("did:key:zR1", "offered", false)).unwrap()],
            true,
        );
        view.held = Some(vec![]);
        state
    }

    fn the_send(effect: &RoomsEffect) -> &Send {
        match effect.steps.last() {
            Some(Step::Send(send)) => send,
            _ => panic!("the last step is a send"),
        }
    }

    /// An acceptance is planned as the offers read, its flow committed only once
    /// the read is under way: planning sets nothing.
    #[test]
    fn an_accept_is_planned_with_its_flow_as_the_commit() {
        let mut state = with_offered_room();
        let config = crate::state_handler::dispatch_util::test_config();
        let effect = plan(&mut state, &config, true, Act::Accept);
        assert_eq!(effect.steps.len(), 1);
        let send = the_send(&effect);
        assert_eq!(send.to, "did:key:zVtc");
        assert_eq!(send.request, Request::Offers { cursor: None });
        assert_eq!(
            send.purpose,
            Purpose::Offers {
                room: "did:key:zR1".into()
            }
        );
        assert_eq!(
            send.commit,
            Some(Commit::Accepting {
                room: "did:key:zR1".into(),
                progress: "Accepting Board pack… collecting the offer".into(),
            })
        );
        assert_eq!(send.refusal, Some(Refusal::Accept));
        let view = view_mut(&mut state).unwrap();
        assert!(view.accept.is_none());
        assert!(view.status.is_none());
    }

    /// An acceptance while an earlier request is unanswered sends nothing,
    /// sets nothing and says to try again.
    #[test]
    fn an_accept_while_waiting_is_refused_with_nothing_set() {
        let mut state = with_offered_room();
        arm(&mut state, Purpose::Memberships);
        let config = crate::state_handler::dispatch_util::test_config();
        let effect = plan(&mut state, &config, true, Act::Accept);
        assert!(effect.steps.is_empty());
        let view = view_mut(&mut state).unwrap();
        assert!(view.accept.is_none());
        assert_eq!(view.status.as_ref().unwrap().text, ACCEPT_WAITING);
    }

    /// Without a VTA a refresh says why the custody is not shown and reads only
    /// the record; with one, it asks the VTA first.
    #[test]
    fn a_refresh_asks_the_vta_first_when_there_is_one() {
        let config = crate::state_handler::dispatch_util::test_config();
        let mut state = state_with_view();
        let effect = plan(&mut state, &config, false, Act::Refresh);
        assert_eq!(effect.steps.len(), 1);
        assert_eq!(the_send(&effect).purpose, Purpose::Memberships);
        let view = view_mut(&mut state).unwrap();
        assert_eq!(view.phase, RoomsPhase::Loading);
        assert!(
            view.held_error
                .as_deref()
                .unwrap()
                .starts_with("no VTA is connected")
        );

        let mut state = state_with_view();
        let effect = plan(&mut state, &config, true, Act::Refresh);
        assert!(matches!(
            effect.steps.first(),
            Some(Step::Ask {
                ask: VtaAsk::Held { .. },
                commit: None,
                refusal: Some(Refusal::Custody),
            })
        ));
        assert_eq!(the_send(&effect).purpose, Purpose::Memberships);
        assert!(view_mut(&mut state).unwrap().held_error.is_none());
    }

    /// A refresh step on a busy lane, or while the view waits, is not taken.
    #[test]
    fn a_refresh_step_on_a_busy_lane_is_planned_as_not_taken() {
        let mut state = state_with_view();
        let effect = plan_next(&mut state, true, true, Next::Refresh);
        assert!(effect.steps.is_empty());
        assert_eq!(effect.taken, Taken::No);
        arm(&mut state, Purpose::Memberships);
        assert_eq!(
            plan_next(&mut state, true, false, Next::Refresh).taken,
            Taken::No
        );
    }

    /// The renewals stay in the view until the VTA's lane takes them.
    #[test]
    fn a_renew_step_hands_over_the_renewals_only_as_its_commit() {
        let mut state = state_with_view();
        view_mut(&mut state).unwrap().renewals = vec![
            serde_json::from_value(json!({
                "roomId": "did:key:zR1", "host": "did:key:zVtc", "label": "Board pack",
                "visibility": "private", "actions": ["read"],
                "validUntil": "2027-11-10T00:00:00Z", "renewsAt": "2027-10-01T00:00:00Z",
                "issuedAt": "2026-11-03T09:00:00Z",
                "credentials": { "membership": "{}", "authority": "{}" },
            }))
            .unwrap(),
        ];
        let effect = plan_next(&mut state, true, false, Next::Renew);
        assert_eq!(effect.taken, Taken::ByLastStep);
        assert!(matches!(
            effect.steps.as_slice(),
            [Step::Ask {
                ask: VtaAsk::Renew { renewals, .. },
                commit: Some(Commit::RenewalsHandedOver),
                ..
            }] if renewals.len() == 1
        ));
        assert_eq!(view_mut(&mut state).unwrap().renewals.len(), 1);
    }

    /// Without a VTA the check for renewals has nothing to do, and is taken.
    #[test]
    fn a_renewals_check_without_a_vta_is_planned_as_done() {
        let mut state = state_with_view();
        let effect = plan_next(&mut state, false, false, Next::CheckRenewals);
        assert!(effect.steps.is_empty());
        assert_eq!(effect.taken, Taken::Yes);
    }
}
