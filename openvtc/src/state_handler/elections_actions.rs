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
    self, CommunityFeature, Doc, SendOutcome, Sender, capitalise, fail, sender,
};
use crate::state_handler::main_page::elections::{
    BallotForm, Disclose, ElectionsPhase, ElectionsView, Flow, Intent, Next, NotifiedPhase,
    Purpose, Row, Screen, Severity, Step, VoteResult,
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

/// Send `request` to the open view's community, armed on `purpose`. Returns whether it was
/// dispatched; every early return says why in the view.
async fn send(lp: &mut Loop<'_>, request: Request, purpose: Purpose) -> bool {
    // The list is always the panel's own community's; one election is read from where it
    // is held.
    let to_target = !matches!(request, Request::List { .. });
    send_to(lp, Outgoing::Build(request), purpose, to_target).await
}

/// Carry a document the VTA signed to the view's target community, unchanged.
async fn send_signed(lp: &mut Loop<'_>, document: serde_json::Value, purpose: Purpose) -> bool {
    send_to(lp, Outgoing::Signed(document), purpose, true).await
}

async fn send_to(lp: &mut Loop<'_>, outgoing: Outgoing, purpose: Purpose, to_target: bool) -> bool {
    let Some((vtc_did, target, persona, waiting)) = lp
        .state
        .main_page
        .content_panel
        .elections
        .view
        .as_ref()
        .map(|v| {
            (
                v.vtc_did.clone(),
                v.target.clone(),
                v.persona,
                v.pending.is_some(),
            )
        })
    else {
        return false;
    };
    if waiting {
        return false;
    }
    let to = if to_target { target } else { vtc_did };
    let mut sender = match sender(lp.config, lp.tdk, persona, &to).await {
        Ok(s) => s,
        Err(e) => {
            fail::<Elections>(lp.state, &purpose, e);
            return true;
        }
    };
    let doc = match Elections::build(lp.config, &mut sender, &to, persona, outgoing) {
        Ok(doc) => doc,
        Err(why) => {
            fail::<Elections>(lp.state, &purpose, why);
            return true;
        }
    };
    lp.spawn_send::<Elections>(sender, to, persona, doc, purpose)
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

/// Read the list again, and the VTA's held election notifications beside it.
pub(crate) async fn refresh(lp: &mut Loop<'_>) {
    match view_mut(lp.state) {
        Some(view) => {
            view.restart_pages();
            view.notified_due = true;
        }
        None => return,
    }
    send(lp, Request::List { cursor: None }, Purpose::List).await;
}

/// Read the open election again — presenting the membership the member chose to show for
/// it, and nothing else (VTI-VOT-016). Returns whether it was dispatched.
async fn read_election(lp: &mut Loop<'_>, election: String, intent: Intent) -> bool {
    let presenting = view_mut(lp.state).and_then(|v| v.presenting.clone());
    match presenting {
        Some(member_of) => {
            if let Some(view) = view_mut(lp.state) {
                view.next = Some(Next::ReadPresenting {
                    election,
                    member_of,
                    intent,
                });
            }
            true
        }
        None => {
            send(
                lp,
                Request::Show {
                    election_id: election.clone(),
                },
                Purpose::Show { election, intent },
            )
            .await
        }
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

/// Service an action that reads the config or sends.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: Act) {
    if let Act::Open(index) = action {
        open(ctx, index);
    }
    let mut lp = Loop::from_ctx(ctx);
    match action {
        Act::Open(_) => {
            if let Some(view) = view_mut(lp.state) {
                view.phase = ElectionsPhase::Loading;
            }
            refresh(&mut lp).await;
        }
        Act::Refresh => refresh_screen(&mut lp).await,
        Act::Show => show_selected(&mut lp).await,
        Act::Present => {
            let has_vta = lp.vta.is_some();
            present(lp.state, has_vta);
        }
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
            let sent = read_election(lp, election, Intent::View).await;
            if !sent && let Some(view) = view_mut(lp.state) {
                view.note(Severity::Warning, InFlight::busy_message(SEND));
            }
        }
        (Screen::List, _) => refresh(lp).await,
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
    let election = match view.selected_row() {
        Some(Row::Listed(e)) => {
            let election = e.election_id.to_string();
            view.reset_target();
            election
        }
        Some(Row::Notified(n)) => {
            let n = n.clone();
            if !n.opens_with_a_served_version() {
                view.note(
                    Severity::Warning,
                    "The notification names a way to open this election that this app does not \
                     speak (it reads elections with vtc/elections/show/0.6).",
                );
                return;
            }
            let election = n.election_id.clone();
            // Read without presenting anything first: an election the member can already see
            // shows the community nothing (VTI-VOT-016).
            view.reset_target();
            view.target = n.held_by.clone();
            view.opening = Some(n);
            election
        }
        None => return,
    };
    view.screen = Screen::Detail;
    view.shown = None;
    view.status = None;
    view.note(Severity::Progress, "Reading the election…");
    let sent = send(
        lp,
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
    let sent = read_election(lp, election, intent).await;
    if !sent && let Some(view) = view_mut(lp.state) {
        view.flow = None;
        view.note(Severity::Warning, InFlight::busy_message(SEND));
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
/// after applying replies and outcomes, and on its tick.
pub(crate) async fn advance(lp: &mut Loop<'_>) {
    community_request::advance::<Elections>(lp).await;
}

/// Take one step. Returns whether it was taken (a busy lane keeps it).
async fn step(lp: &mut Loop<'_>, next: Next) -> bool {
    let shown = view_mut(lp.state).and_then(|v| v.shown.clone());
    match next {
        Next::Refresh => {
            if lp.in_flight.is_busy(SEND) || view_mut(lp.state).is_some_and(|v| v.pending.is_some())
            {
                false
            } else {
                refresh(lp).await;
                true
            }
        }
        Next::ReadPresenting {
            election,
            member_of,
            intent,
        } => {
            let member = view_mut(lp.state).map(|v| v.me.clone()).unwrap_or_default();
            ask_vta(
                lp,
                VtaAsk::ReadPresenting {
                    member,
                    election,
                    member_of,
                    intent,
                },
            )
        }
        Next::SendShowDocument {
            document,
            election,
            intent,
        } => send_signed(lp, document, Purpose::Show { election, intent }).await,
        Next::SendIssueDocument(document) => {
            let election = shown
                .as_ref()
                .map(|s| s.election_id().to_string())
                .unwrap_or_default();
            send_signed(lp, document, Purpose::Issue { election }).await
        }
        Next::ListPage { cursor } => {
            send(
                lp,
                Request::List {
                    cursor: Some(cursor),
                },
                Purpose::List,
            )
            .await
        }
        Next::Register => match shown {
            Some(shown) => {
                let member = view_mut(lp.state).map(|v| v.me.clone()).unwrap_or_default();
                ask_vta(lp, VtaAsk::Register { shown, member })
            }
            None => true,
        },
        Next::SendIssue(ticket) => {
            let election = ticket.election_id.clone();
            send(
                lp,
                Request::IssueTicket(ticket),
                Purpose::Issue { election },
            )
            .await
        }
        Next::Accept { issued } => match shown {
            Some(shown) => ask_vta(lp, VtaAsk::Accept { shown, issued }),
            None => true,
        },
        Next::Vote { ballot } => match shown {
            Some(shown) => ask_vta(lp, VtaAsk::Vote { shown, ballot }),
            None => true,
        },
        Next::Deliver(cast) => deliver(lp, cast),
        Next::Keep(receipt) => match shown {
            Some(shown) => ask_vta(
                lp,
                VtaAsk::Keep {
                    election: shown.election_id().to_string(),
                    receipt,
                },
            ),
            None => true,
        },
    }
}

/// Read the VTA's held election notifications, when due and its lane is free (VTI-NTF-063).
fn ask_notified(lp: &mut Loop<'_>) {
    let has_vta = lp.vta.is_some();
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if !view.notified_due || view.flow.is_some() {
        return;
    }
    if !has_vta {
        view.notified_due = false;
        view.notified_phase =
            NotifiedPhase::Unavailable("no VTA is connected, and it holds them".into());
        return;
    }
    if lp.in_flight.is_busy(VTA) {
        return;
    }
    if ask_vta(lp, VtaAsk::Notified)
        && let Some(view) = view_mut(lp.state)
    {
        view.notified_due = false;
    }
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
                flow.step = Step::Accepting;
            }
            view.note(Severity::Progress, Step::Accepting.words());
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
                    flow.step = Step::Issuing;
                }
                view.note(Severity::Progress, Step::Issuing.words());
                view.next = Some(Next::SendIssueDocument(document));
            }
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
