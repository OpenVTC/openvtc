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
//! the Welcome — where `alreadyJoined` means another surface finished first. Each step's
//! answer sets the view's [`Next`]; [`advance`], which the loop calls after applying
//! replies and outcomes, takes it. After an acceptance ends, either way, the view is read
//! again: the community and the VTA are the record.

use std::time::{Duration, Instant};

use affinidi_tdk::TDK;
use openvtc_core::capabilities::{RequestDocument, correlation_thread};
use openvtc_core::community_rooms::{self, Joined, Offer, Prepared, Reply, Request, Standing};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::RoomsAction as Act;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::rooms::{
    AcceptFlow, AcceptStep, Next, Pending, Purpose, RoomsPhase, RoomsView, Severity,
};
use crate::state_handler::repos_actions::{Sender, sender};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

const SEND: DispatchDomain = DispatchDomain::Rooms;
const KEYS: DispatchDomain = DispatchDomain::RoomsVta;

/// How long a request waits for the community's answer (R1.2).
pub(crate) const REPLY_WINDOW: Duration = Duration::from_secs(30);

/// A `vtc/rooms/*` answer as it arrived.
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
    /// Send `request` to the open view's community, armed on `purpose`. Returns whether
    /// it was dispatched; every early return says why in the view.
    async fn send(&mut self, request: Request, purpose: Purpose) -> bool {
        let Some((vtc_did, persona, waiting)) = self
            .state
            .main_page
            .content_panel
            .rooms
            .view
            .as_ref()
            .map(|v| (v.vtc_did.clone(), v.persona, v.pending.is_some()))
        else {
            return false;
        };
        if waiting {
            if let Some(view) = view_mut(self.state) {
                view.note(
                    Severity::Warning,
                    "Still waiting for the community's answer.",
                );
            }
            return false;
        }
        let sender = match sender(self.config, self.tdk, persona, &vtc_did).await {
            Ok(s) => s,
            Err(e) => {
                fail(self.state, &purpose, e);
                return false;
            }
        };
        let doc = match community_rooms::build(&request, &sender.persona_did, &vtc_did) {
            Ok(doc) => doc,
            Err(e) => {
                fail(self.state, &purpose, format!("couldn't send: {e}"));
                return false;
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
            DispatchOutcome::Rooms(job.run().await)
        });
        true
    }

    /// Ask the VTA. Returns whether it was dispatched.
    fn ask_vta(&mut self, ask: VtaAsk) -> bool {
        let Some(vta) = self.vta.cloned() else {
            return false;
        };
        let Some((vtc_did, persona)) = self
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
        if !self.in_flight.try_begin(KEYS) {
            return false;
        }
        background_dispatch::spawn_dispatch(self.dispatch_tx.clone(), KEYS, async move {
            DispatchOutcome::RoomsVta(RoomsVtaOutcome {
                vtc_did,
                persona,
                answer: ask.run(&vta).await,
            })
        });
        true
    }

    /// Read the community's record and the VTA's custody again.
    pub(crate) async fn refresh(&mut self) {
        let me = match view_mut(self.state) {
            Some(view) => {
                view.restart_pages();
                view.me.clone()
            }
            None => return,
        };
        if self.vta.is_none() {
            if let Some(view) = view_mut(self.state) {
                view.held = None;
                view.held_error = Some(
                    "no VTA is connected, so which rooms it holds keys for can't be shown".into(),
                );
            }
        } else if !self.ask_vta(VtaAsk::Held { member: me })
            && let Some(view) = view_mut(self.state)
        {
            // Busy with an acceptance step; the record still refreshes.
            view.held_error
                .get_or_insert_with(|| "your VTA is busy".into());
        }
        self.send(Request::Memberships { cursor: None }, Purpose::Memberships)
            .await;
    }
}

/// Say a request never left, where the view shows it.
fn fail(state: &mut State, purpose: &Purpose, why: String) {
    let Some(view) = view_mut(state) else {
        return;
    };
    match purpose {
        Purpose::Memberships if view.rooms.is_empty() => view.phase = RoomsPhase::Failed(why),
        Purpose::Memberships => view.note(Severity::Error, why),
        Purpose::Offers { .. } | Purpose::Accept { .. } => {
            view.accept = None;
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
        Act::Open(_) | Act::Refresh => {
            if let Some(view) = view_mut(lp.state) {
                if view.rooms.is_empty() {
                    view.phase = RoomsPhase::Loading;
                }
                view.status = None;
            }
            lp.refresh().await;
        }
        Act::Accept => start_accept(&mut lp).await,
        Act::Back | Act::Select(_) => {}
    }
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
    ctx.state.main_page.content_panel.rooms.view = Some(RoomsView::new(vtc, persona, me, name));
}

/// `⏎` on a room: accept its offer, or finish an acceptance begun elsewhere.
async fn start_accept(lp: &mut Loop<'_>) {
    let has_vta = lp.vta.is_some();
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    if view.accept.is_some() {
        view.note(Severity::Warning, "An acceptance is already in progress.");
        return;
    }
    let Some(row) = view.selected_row() else {
        return;
    };
    match row.standing {
        s if s.acceptable() => {}
        Standing::NeedsReadmission => {
            view.note(
                Severity::Warning,
                "Your VTA never joined this room and the community no longer keeps what it \
                 needs to finish: ask an administrator to remove and re-admit you.",
            );
            return;
        }
        Standing::Admitted if !has_vta => {
            view.note(
                Severity::Warning,
                "Whether this room is joined needs your VTA, which holds its keys — none is \
                 connected.",
            );
            return;
        }
        _ => {
            view.note(Severity::Info, "Nothing to accept here.");
            return;
        }
    }
    if !has_vta {
        view.note(
            Severity::Error,
            "Accepting a room needs your VTA: it holds the room's keys and credentials.",
        );
        return;
    }
    let room = row.room.room_id.to_string();
    view.accept = Some(AcceptFlow {
        room: room.clone(),
        step: AcceptStep::Collecting,
        offer: None,
    });
    view.note(
        Severity::Progress,
        format!(
            "Accepting {}… collecting the offer",
            community_rooms::display_label(&row.room)
        ),
    );
    if !lp
        .send(Request::Offers { cursor: None }, Purpose::Offers { room })
        .await
        && let Some(view) = view_mut(lp.state)
        && view.pending.is_none()
    {
        // Not armed (lane busy): try again on the next tick rather than drop the press.
        view.accept = None;
        view.note(Severity::Warning, InFlight::busy_message(SEND));
    }
}

/// Take the step the view's last answer called for, if its lane is free. The loop calls
/// this after applying replies and dispatch outcomes, and on its tick.
pub(crate) async fn advance(lp: &mut Loop<'_>) {
    let Some(next) = view_mut(lp.state).and_then(|v| v.next.take()) else {
        return;
    };
    let taken = match next.clone() {
        Next::Refresh => {
            if lp.in_flight.is_busy(SEND)
                || lp
                    .state
                    .main_page
                    .content_panel
                    .rooms
                    .view
                    .as_ref()
                    .is_some_and(|v| v.pending.is_some())
            {
                false
            } else {
                lp.refresh().await;
                true
            }
        }
        Next::MembershipsPage { cursor } => {
            lp.send(
                Request::Memberships {
                    cursor: Some(cursor),
                },
                Purpose::Memberships,
            )
            .await
        }
        Next::OffersPage { room, cursor } => {
            lp.send(
                Request::Offers {
                    cursor: Some(cursor),
                },
                Purpose::Offers { room },
            )
            .await
        }
        Next::Prepare => {
            let ask = lp
                .state
                .main_page
                .content_panel
                .rooms
                .view
                .as_ref()
                .and_then(|v| {
                    v.accept
                        .as_ref()
                        .and_then(|a| a.offer.clone())
                        .map(|offer| VtaAsk::Prepare {
                            offer,
                            member: v.me.clone(),
                        })
                });
            match ask {
                Some(ask) => lp.ask_vta(ask),
                None => true,
            }
        }
        Next::SendAccept { room, key_package } => {
            lp.send(
                Request::Accept {
                    room_id: room.clone(),
                    key_package,
                },
                Purpose::Accept { room },
            )
            .await
        }
        Next::Join {
            room,
            welcome,
            ratchet_tree,
        } => {
            let invitation = view_mut(lp.state)
                .and_then(|v| v.accept.as_ref())
                .and_then(|a| a.offer.as_ref())
                .map(|o| o.credentials.invitation.to_string());
            match invitation {
                Some(invitation) => lp.ask_vta(VtaAsk::Join {
                    room,
                    invitation,
                    welcome,
                    ratchet_tree,
                }),
                None => true,
            }
        }
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
        }
    }
    advance(lp).await;
}

/// A job ended without an outcome (it panicked): end what it was part of.
pub(crate) fn job_lost(state: &mut State, msg: &str) {
    if let Some(view) = view_mut(state) {
        view.pending = None;
        view.accept = None;
        view.next = None;
        view.note(Severity::Error, msg.to_string());
    }
}

// ****************************************************************************
// Sending to the community
// ****************************************************************************

/// One `vtc/rooms/*` send, off the loop.
pub(crate) struct SendJob {
    sender: Sender,
    vtc_did: String,
    persona: PersonaId,
    doc: RequestDocument,
}

impl SendJob {
    async fn run(mut self) -> RoomsOutcome {
        let thid = correlation_thread(&self.doc).to_string();
        let s = &self.sender;
        let result = async {
            openvtc_core::capabilities::sign_document(&mut self.doc, &s.signer).await?;
            let tsp_mediator =
                openvtc_core::community_send::tsp_mediator_for(s.over_tsp, &self.vtc_did).await;
            openvtc_core::capabilities::send_capability_document(
                &openvtc_core::community_send::Delivery {
                    atm: &s.atm,
                    profile: &s.profile,
                    member_did: &s.persona_did,
                    vtc_did: &self.vtc_did,
                    mediator_did: &s.mediator,
                    tsp_mediator_did: tsp_mediator.as_deref(),
                },
                &self.doc,
            )
            .await
        }
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
        RoomsOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            thid,
            result,
        }
    }
}

/// What a send did. Applied on the loop.
pub(crate) struct RoomsOutcome {
    vtc_did: String,
    persona: PersonaId,
    thid: String,
    result: Result<(), String>,
}

impl RoomsOutcome {
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
            tracing::debug!(thid = %self.thid, "rooms send failed for a request no longer awaited: {e}");
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

/// Apply the community's answers. Returns whether any was taken, so the loop
/// [`advance`]s.
pub(crate) fn apply_replies(state: &mut State, replies: Vec<InboundReply>) -> bool {
    let mut taken = false;
    for inbound in replies {
        let Some(vtc) = view_mut(state).map(|v| v.vtc_did.clone()) else {
            continue;
        };
        // A thread id is a correlation key, not a credential: an answer is taken only
        // from the community the view is asking — sent by it and issued by it.
        // By DID: a did:scid community may name itself with the `?src=` it is
        // resolved through (VTI-KEY-163).
        let from_vtc = vta_sdk::did_scid::same_reference(did_part(&inbound.from), &vtc);
        let issued_by_vtc = inbound
            .issuer
            .as_deref()
            .map(did_part)
            .is_some_and(|issuer| vta_sdk::did_scid::same_reference(issuer, &vtc));
        if !(from_vtc && issued_by_vtc) {
            tracing::warn!(from = %inbound.from, thid = %inbound.thid, "rooms reply not from the community the view is asking — dropped");
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
            tracing::warn!(%thid, "rooms reply matches no pending request — dropped");
        }
        return false;
    }
    let Some(pending) = view.pending.take() else {
        return false;
    };
    match (reply, pending.purpose) {
        (Reply::Memberships(page), Purpose::Memberships) => {
            let next = page.next_cursor.as_ref().map(|c| c.as_str().to_string());
            view.take_page(page.items, next.is_none());
            if let Some(cursor) = next {
                view.next = Some(Next::MembershipsPage { cursor });
            } else {
                view.clear_progress();
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
    true
}

// ****************************************************************************
// Asking the VTA
// ****************************************************************************

/// One call to the member's VTA.
enum VtaAsk {
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
    Held(Result<Vec<String>, String>),
    Prepared(Result<Prepared, String>),
    Joined(Result<Joined, String>),
}

impl VtaAsk {
    async fn run(self, vta: &VtaClient) -> VtaAnswer {
        match self {
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
                        resumable,
                    }) => {
                        if let Some(flow) = view.accept.as_mut() {
                            flow.step = AcceptStep::Accepting;
                        }
                        view.note(
                            Severity::Progress,
                            if already_minted {
                                "Finishing an acceptance begun on another surface…"
                            } else if !resumable {
                                "Accepting… (your VTA is older: if this is interrupted, another \
                                 surface can't finish it)"
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
    use openvtc_core::community_rooms::Reply;
    use serde_json::json;

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
            "offeredAt": "2026-10-14T10:00:00Z",
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
        assert!(!apply_replies(&mut state, vec![forged]));
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
        apply_replies(&mut state, vec![inbound(Reply::Refused(refusal))]);
        let view = view_mut(&mut state).unwrap();
        assert!(view.accept.is_none());
        assert!(view.status.as_ref().unwrap().text.contains("re-admit"));
        assert_eq!(view.next, Some(Next::Refresh));
    }
}
