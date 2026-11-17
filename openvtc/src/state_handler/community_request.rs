//! One request to a community at a time, and the answer it waits for — the
//! plumbing the panels that speak to a community share.
//!
//! A panel (Rooms, Elections) plans a request, and from here on it is the same
//! for each: [`send`] looks up the persona's signing key, has the panel build
//! the document ([`CommunityFeature::build`]), claims the lane and arms the
//! view on the request's thread *before* the send is spawned
//! ([`CommunityLoop::spawn_send`]), and reports how it went ([`Sent`]) for the
//! panel to commit or refuse — the answer travels the inbound
//! channel, not the dispatch one, and can overtake the send's own outcome; a
//! send that failed ends the wait while the view still waits on it
//! ([`send_failed`]); an answer is taken only from the community the request
//! went to, sent and issued by it, on the thread the view waits on
//! ([`apply_replies`]); a request unanswered within [`REPLY_WINDOW`] ends
//! ([`tick`]); a job that panicked ends what it was part of ([`job_lost`]); and
//! the step a view's last answer called for is taken when its lane is free
//! ([`advance`]). What differs — what a request is, what an answer means, what
//! a timeout or a failure says — is the panel's, behind [`CommunityFeature`].
//!
//! A panel whose requests may go to a community this persona holds no
//! membership with ([`CommunityFeature::RECORDS_THREAD`]) also records the
//! thread in the runtime's [`PendingReplies`], so the inbound gate admits that
//! community's answer, and forgets it when the view stops waiting.
//!
//! The Repos panel keeps two waits (a request and a link poll) with their own
//! windows, so it uses only the shared pieces below the engine: the loop's
//! borrows ([`CommunityLoop`]), the sender ([`sender`], [`sign_and_send`]) and
//! the sender check ([`answered_by`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_tdk::TDK;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use openvtc_core::capabilities::{RequestDocument, correlation_thread};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::inbound::ThreadedReply;
use openvtc_core::pending_replies::{self, PendingReplies, ReplyKind};
use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::client::VtaClient;

use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::repos::Severity;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

/// How long a request waits for the community's answer (R1.2).
pub(crate) const REPLY_WINDOW: Duration = Duration::from_secs(30);

/// The first letter upper-cased.
pub(crate) fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// The DID part of a DID or DID URL.
pub(crate) fn did_part(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

/// Whether an answer is `community`'s own: sent by it and issued by it. A
/// thread id is a correlation key, not a credential — anyone who learned one
/// could otherwise answer for the community. Compared by DID: a did:scid
/// community may name itself with the `?src=` it is resolved through
/// (VTI-KEY-163).
pub(crate) fn answered_by(community: &str, from: &str, issuer: Option<&str>) -> bool {
    let is_community = |did: &str| vta_sdk::did_scid::same_reference(did_part(did), community);
    is_community(from) && issuer.is_some_and(is_community)
}

// ****************************************************************************
// The loop's borrows
// ****************************************************************************

/// What a send, a VTA call or a reply needs from the loop, borrowed. The action
/// path ([`ActionCtx`]) and the loop's own tick, reply and outcome arms each
/// build one.
pub(crate) struct CommunityLoop<'a> {
    pub(crate) state: &'a mut State,
    pub(crate) config: &'a Config,
    pub(crate) tdk: &'a TDK,
    pub(crate) vta: Option<&'a VtaClient>,
    pub(crate) dispatch_tx: &'a UnboundedSender<DispatchOutcome>,
    pub(crate) in_flight: &'a mut InFlight,
    /// The runtime's replies awaited by thread ([`CommunityFeature::RECORDS_THREAD`]).
    pub(crate) pending_replies: &'a mut PendingReplies,
}

impl<'a> CommunityLoop<'a> {
    /// Borrow what the loop lent an action.
    pub(crate) fn from_ctx(ctx: &'a mut ActionCtx<'_>) -> Self {
        Self {
            state: &mut *ctx.state,
            config: ctx.config,
            tdk: ctx.tdk,
            vta: ctx.admin_vta,
            dispatch_tx: ctx.dispatch_tx,
            in_flight: &mut *ctx.in_flight,
            pending_replies: &mut *ctx.pending_replies,
        }
    }
}

// ****************************************************************************
// Sending
// ****************************************************************************

/// Everything a send needs, resolved on the loop thread.
pub(crate) struct Sender {
    pub(crate) atm: ATM,
    pub(crate) profile: Arc<ATMProfile>,
    pub(crate) persona_did: String,
    pub(crate) mediator: String,
    /// The membership was joined over TSP, so its requests go over TSP: the
    /// community answers on the transport a request arrived on, and a persona
    /// that joined over TSP may not collect a DIDComm answer at all.
    pub(crate) over_tsp: bool,
    pub(crate) signer: Box<Secret>,
}

/// Resolve the persona's messaging identity and signing key. The key comes
/// from the TDK secrets resolver, an in-memory store populated at startup —
/// not I/O — which is what lets the job own a plain `Secret`.
pub(crate) async fn sender(
    config: &Config,
    tdk: &TDK,
    persona: PersonaId,
    vtc_did: &str,
) -> Result<Sender, String> {
    let id = config
        .identities
        .get(&persona)
        .ok_or_else(|| "this persona has no messaging identity".to_string())?;
    let atm = tdk
        .atm
        .as_ref()
        .ok_or_else(|| "messaging is unavailable".to_string())?
        .clone();
    let keys = config
        .get_persona_keys_for(persona, tdk)
        .await
        .map_err(|e| format!("couldn't read this persona's signing key: {e}"))?;
    Ok(Sender {
        atm,
        profile: id.profile().clone(),
        persona_did: id.persona_did().to_string(),
        mediator: id.mediator_did.clone().unwrap_or_default(),
        over_tsp: config
            .account
            .membership(vtc_did, persona)
            .is_some_and(|c| c.joined_over_tsp()),
        signer: Box::new(keys.authentication.secret.clone()),
    })
}

/// Sign `doc` as the persona and send it to `vtc_did`, over TSP when the
/// membership was joined over it.
pub(crate) async fn sign_and_send(
    s: &Sender,
    vtc_did: &str,
    doc: &mut RequestDocument,
) -> Result<(), String> {
    async {
        openvtc_core::capabilities::sign_document(doc, &s.signer).await?;
        let tsp_mediator =
            openvtc_core::community_send::tsp_mediator_for(s.over_tsp, vtc_did).await;
        openvtc_core::capabilities::send_capability_document(
            &openvtc_core::community_send::Delivery {
                atm: &s.atm,
                profile: &s.profile,
                member_did: &s.persona_did,
                vtc_did,
                mediator_did: &s.mediator,
                tsp_mediator_did: tsp_mediator.as_deref(),
            },
            doc,
        )
        .await
    }
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Send a document the VTA signed, unchanged, on the community's transport.
async fn send_signed_document(
    s: &Sender,
    vtc_did: &str,
    doc: &serde_json::Value,
) -> Result<(), String> {
    let id = doc
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let tsp_mediator = openvtc_core::community_send::tsp_mediator_for(s.over_tsp, vtc_did).await;
    openvtc_core::community_send::send_document(
        &openvtc_core::community_send::Delivery {
            atm: &s.atm,
            profile: &s.profile,
            member_did: &s.persona_did,
            vtc_did,
            mediator_did: &s.mediator,
            tsp_mediator_did: tsp_mediator.as_deref(),
        },
        id,
        doc.clone(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// A document on its way to the community.
pub(crate) enum Doc {
    /// Built here: signed as the persona before it goes.
    Unsigned(Box<RequestDocument>),
    /// Signed by the VTA as the member, carrying a presentation: sent exactly as it answered.
    Signed(serde_json::Value),
}

impl Doc {
    /// The thread its answer carries: the document's id.
    pub(crate) fn thread(&self) -> Option<String> {
        match self {
            Doc::Unsigned(doc) => Some(correlation_thread(doc).to_string()),
            Doc::Signed(doc) => doc
                .get("id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_string),
        }
    }
}

/// One send, off the loop.
struct SendJob {
    sender: Sender,
    vtc_did: String,
    persona: PersonaId,
    doc: Doc,
}

impl SendJob {
    async fn run(mut self) -> SendOutcome {
        let thid = self.doc.thread().unwrap_or_default();
        let result = match &mut self.doc {
            Doc::Unsigned(doc) => sign_and_send(&self.sender, &self.vtc_did, doc).await,
            Doc::Signed(doc) => send_signed_document(&self.sender, &self.vtc_did, doc).await,
        };
        SendOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            thid,
            result,
        }
    }
}

/// What a send did. Applied on the loop by [`send_failed`].
pub(crate) struct SendOutcome {
    /// The community it went to.
    pub(crate) vtc_did: String,
    pub(crate) persona: PersonaId,
    /// The thread the view was armed with for it.
    pub(crate) thid: String,
    pub(crate) result: Result<(), String>,
}

// ****************************************************************************
// The engine
// ****************************************************************************

/// A request awaiting the community's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending<P> {
    pub thid: String,
    pub sent_at: Instant,
    pub purpose: P,
    /// The community it went to: the panel's own, or (Elections) the one
    /// holding a notified election.
    pub to: String,
}

/// A panel that sends one request to a community at a time and waits for its
/// answer. Everything here is the panel's; the waiting is [this module](self)'s.
pub(crate) trait CommunityFeature: 'static {
    type View;
    /// What a request was for, and so what its answer means.
    type Purpose: std::fmt::Debug;
    /// The community's classified answer.
    type Reply;
    /// The step an answer calls for, taken by [`advance`].
    type Next: Clone;
    /// What the panel asks the community, before it is a document.
    type Request;

    /// For log lines (`"rooms"`, `"elections"`).
    const NAME: &'static str;
    /// The lane its sends take.
    const SEND: DispatchDomain;
    /// Whether a request's thread is recorded in the runtime's
    /// [`PendingReplies`] ([`ReplyKind::ElectionAnswer`]), so the inbound gate
    /// admits the answer of a community this persona holds no membership with.
    const RECORDS_THREAD: bool;

    fn view_mut(state: &mut State) -> Option<&mut Self::View>;
    fn pending_mut(view: &mut Self::View) -> &mut Option<Pending<Self::Purpose>>;
    fn next_mut(view: &mut Self::View) -> &mut Option<Self::Next>;
    /// The panel's community, and the persona it speaks as.
    fn community(view: &Self::View) -> (&str, PersonaId);
    /// Say something on the view's status line.
    fn note(view: &mut Self::View, severity: Severity, text: String);
    /// Wrap a send's outcome for the dispatch channel.
    fn outcome(outcome: SendOutcome) -> DispatchOutcome;
    /// The document `request` makes, from `sender` to `to` — `sender` adjusted
    /// for `to` first where the panel needs it. `Err` is what the view is told.
    fn build(
        config: &Config,
        sender: &mut Sender,
        to: &str,
        persona: PersonaId,
        request: Self::Request,
    ) -> Result<Doc, String>;

    /// A refusal, which may answer another panel's request too, so one that
    /// matches nothing here is dropped without a warning.
    fn is_refusal(reply: &Self::Reply) -> bool;
    /// Take the answer to the request made for `purpose` (no longer pending).
    fn take_reply(view: &mut Self::View, reply: Self::Reply, purpose: Self::Purpose);
    /// The request made for `purpose` went unanswered for `secs` seconds.
    fn timed_out(view: &mut Self::View, purpose: Self::Purpose, secs: u64);
    /// The request made for `purpose` never left, for `why`.
    fn failed(view: &mut Self::View, purpose: &Self::Purpose, why: String);
    /// End whatever multi-step flow is in progress (a job was lost).
    fn end_flow(view: &mut Self::View);

    /// Take `next`. Returns whether it was taken; one that was not (a busy
    /// lane) is kept for the next tick.
    async fn step(lp: &mut CommunityLoop<'_>, next: Self::Next) -> bool;
    /// Anything to do before a step is taken.
    fn before_step(_lp: &mut CommunityLoop<'_>) {}
}

/// Say a request never left, where the view shows it.
pub(crate) fn fail<F: CommunityFeature>(state: &mut State, purpose: &F::Purpose, why: String) {
    if let Some(view) = F::view_mut(state) {
        F::failed(view, purpose, why);
    }
}

/// What a document without an id is said to be when it cannot be sent.
pub(crate) const UNTHREADED: &str = "couldn't send: a request without an id";

/// How [`send`] went. A failure is returned, not yet shown, so the panel
/// orders it against its own commit or refusal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sent<P> {
    /// No view is open.
    NoView,
    /// The view still waits on an earlier request: nothing was sent.
    Waiting,
    /// The persona's key or the document failed, before any claim, for the
    /// reason given.
    Failed(P, String),
    /// The document has no id to thread its answer on ([`UNTHREADED`]).
    Unthreaded(P),
    /// The lane is busy: nothing claimed, nothing armed.
    Busy,
    /// Claimed and spawned, the view armed on its thread.
    Dispatched,
}

/// Send `request` to `to` as `persona`, for `purpose`, in order: the view is
/// checked for an earlier request still unanswered, the persona's signing key
/// looked up ([`sender`]), the document built ([`CommunityFeature::build`]),
/// the lane claimed and the view armed ([`CommunityLoop::spawn_send`]). The
/// key lookup comes before the claim, so a persona whose key cannot be read is
/// told so even on a busy lane.
pub(crate) async fn send<F: CommunityFeature>(
    lp: &mut CommunityLoop<'_>,
    to: String,
    persona: PersonaId,
    request: F::Request,
    purpose: F::Purpose,
) -> Sent<F::Purpose> {
    let Some(waiting) = F::view_mut(lp.state).map(|v| F::pending_mut(v).is_some()) else {
        return Sent::NoView;
    };
    if waiting {
        return Sent::Waiting;
    }
    let mut sender = match sender(lp.config, lp.tdk, persona, &to).await {
        Ok(s) => s,
        Err(e) => return Sent::Failed(purpose, e),
    };
    let doc = match F::build(lp.config, &mut sender, &to, persona, request) {
        Ok(doc) => doc,
        Err(why) => return Sent::Failed(purpose, why),
    };
    if doc.thread().is_none() {
        return Sent::Unthreaded(purpose);
    }
    if lp.spawn_send::<F>(sender, to, persona, doc, purpose) {
        Sent::Dispatched
    } else {
        Sent::Busy
    }
}

impl CommunityLoop<'_> {
    /// Arm the open view on `doc`'s thread and spawn its send to `to`. Returns
    /// whether it was dispatched — or failed in a way the view now shows; `false`
    /// only for a busy lane, with nothing armed.
    ///
    /// Armed in the same loop turn as the spawn, never from its outcome: a
    /// community that answers at once could otherwise have its answer applied
    /// first — to find nothing pending, be dropped, and leave the view to time
    /// out on a request that was answered.
    pub(crate) fn spawn_send<F: CommunityFeature>(
        &mut self,
        sender: Sender,
        to: String,
        persona: PersonaId,
        doc: Doc,
        purpose: F::Purpose,
    ) -> bool {
        let Some(thid) = doc.thread() else {
            fail::<F>(self.state, &purpose, UNTHREADED.into());
            return true;
        };
        let job = FeatureSend::<F> {
            job: SendJob {
                sender,
                vtc_did: to.clone(),
                persona,
                doc,
            },
            feature: std::marker::PhantomData,
        };
        if !background_dispatch::dispatch(job, self.in_flight, self.dispatch_tx, |_| {}) {
            return false;
        }
        if F::RECORDS_THREAD {
            // Its answer is admitted from this community on this thread, member or not.
            self.pending_replies
                .record(&thid, &to, pending_replies::Purpose::ElectionAnswer);
        }
        if let Some(view) = F::view_mut(self.state) {
            *F::pending_mut(view) = Some(Pending {
                thid,
                sent_at: Instant::now(),
                purpose,
                to,
            });
        }
        true
    }
}

/// A [`SendJob`] on feature `F`'s lane, its outcome wrapped as `F`'s.
struct FeatureSend<F> {
    job: SendJob,
    feature: std::marker::PhantomData<fn() -> F>,
}

impl<F: CommunityFeature> background_dispatch::Job for FeatureSend<F> {
    fn domain(&self) -> DispatchDomain {
        F::SEND
    }

    async fn execute(self) -> DispatchOutcome {
        F::outcome(self.job.run().await)
    }
}

/// Stop waiting on `thid` at the inbound gate, for a panel that records threads.
fn forget<F: CommunityFeature>(pending_replies: &mut PendingReplies, thid: &str) {
    if F::RECORDS_THREAD {
        pending_replies.forget(ReplyKind::ElectionAnswer, thid);
    }
}

/// Say the send never left — while the view still waits on this request. A
/// send that did needs nothing: the view was armed before it was spawned, and
/// its answer may already be applied.
pub(crate) fn send_failed<F: CommunityFeature>(
    state: &mut State,
    pending_replies: &mut PendingReplies,
    outcome: SendOutcome,
) {
    let Err(e) = outcome.result else {
        return;
    };
    forget::<F>(pending_replies, &outcome.thid);
    let Some(view) = F::view_mut(state) else {
        return;
    };
    let (_, persona) = F::community(view);
    let awaited = persona == outcome.persona
        && F::pending_mut(view)
            .as_ref()
            .is_some_and(|p| p.thid == outcome.thid && p.to == outcome.vtc_did);
    if !awaited {
        tracing::debug!(
            thid = %outcome.thid,
            "{} send failed for a request no longer awaited: {e}",
            F::NAME
        );
        return;
    }
    if let Some(p) = F::pending_mut(view).take() {
        F::failed(
            view,
            &p.purpose,
            format!("couldn't reach the community: {e}"),
        );
    }
}

/// Apply the community's answers. Returns whether any was taken, so the loop
/// [`advance`]s.
pub(crate) fn apply_replies<F: CommunityFeature>(
    state: &mut State,
    pending_replies: &mut PendingReplies,
    replies: Vec<ThreadedReply<F::Reply>>,
) -> bool {
    let mut taken = false;
    for inbound in replies {
        // The community the outstanding request went to.
        let Some(community) = F::view_mut(state).map(|v| {
            let own = F::community(v).0.to_string();
            F::pending_mut(v).as_ref().map_or(own, |p| p.to.clone())
        }) else {
            continue;
        };
        if !answered_by(&community, &inbound.from, inbound.issuer.as_deref()) {
            tracing::warn!(
                from = %inbound.from,
                thid = %inbound.thid,
                "{} reply not from the community the view is asking — dropped",
                F::NAME
            );
            continue;
        }
        taken |= apply_reply::<F>(state, pending_replies, &inbound.thid, inbound.reply);
    }
    taken
}

fn apply_reply<F: CommunityFeature>(
    state: &mut State,
    pending_replies: &mut PendingReplies,
    thid: &str,
    reply: F::Reply,
) -> bool {
    let Some(view) = F::view_mut(state) else {
        return false;
    };
    let slot = F::pending_mut(view);
    if slot.as_ref().is_none_or(|p| p.thid != thid) {
        if !F::is_refusal(&reply) {
            tracing::warn!(%thid, "{} reply matches no pending request — dropped", F::NAME);
        }
        return false;
    }
    let Some(pending) = slot.take() else {
        return false;
    };
    forget::<F>(pending_replies, &pending.thid);
    F::take_reply(view, reply, pending.purpose);
    true
}

/// The loop's periodic pass: the reply window, and any step left waiting on a
/// busy lane.
pub(crate) async fn tick<F: CommunityFeature>(lp: &mut CommunityLoop<'_>) {
    let now = Instant::now();
    if let Some(view) = F::view_mut(lp.state) {
        let slot = F::pending_mut(view);
        if slot
            .as_ref()
            .is_some_and(|p| now.duration_since(p.sent_at) > REPLY_WINDOW)
            && let Some(p) = slot.take()
        {
            forget::<F>(lp.pending_replies, &p.thid);
            F::timed_out(view, p.purpose, REPLY_WINDOW.as_secs());
        }
    }
    advance::<F>(lp).await;
}

/// Take the step the view's last answer called for, if its lane is free. The
/// loop calls this after applying replies and dispatch outcomes, and on its
/// tick.
pub(crate) async fn advance<F: CommunityFeature>(lp: &mut CommunityLoop<'_>) {
    F::before_step(lp);
    let Some(next) = F::view_mut(lp.state).and_then(|v| F::next_mut(v).take()) else {
        return;
    };
    let taken = F::step(lp, next.clone()).await;
    // A lane that was busy: keep the step for the next tick.
    if !taken && let Some(view) = F::view_mut(lp.state) {
        F::next_mut(view).get_or_insert(next);
    }
}

/// A job ended without an outcome (it panicked): end what it was part of.
pub(crate) fn job_lost<F: CommunityFeature>(state: &mut State, msg: &str) {
    if let Some(view) = F::view_mut(state) {
        *F::pending_mut(view) = None;
        *F::next_mut(view) = None;
        F::end_flow(view);
        F::note(view, Severity::Error, msg.to_string());
    }
}

#[cfg(test)]
mod tests {
    //! The engine, driven through the real panels: Rooms (whose answers come
    //! only from a community the persona belongs to) and Elections (whose
    //! threads are recorded at the inbound gate).

    use super::*;
    use crate::state_handler::elections_actions::Elections;
    use crate::state_handler::main_page::elections::{self as el, ElectionsView};
    use crate::state_handler::main_page::rooms::{self as rm, RoomsView};
    use crate::state_handler::rooms_actions::Rooms;
    use openvtc_core::community_rooms::{Refusal, Reply};

    const VTC: &str = "did:key:zVtc";

    fn rooms_state() -> State {
        let mut state = State::default();
        state.main_page.content_panel.rooms.view = Some(RoomsView::new(
            VTC.into(),
            PersonaId::default(),
            "did:key:zAlice".into(),
            "Community".into(),
        ));
        state
    }

    fn rooms(state: &mut State) -> &mut RoomsView {
        Rooms::view_mut(state).unwrap()
    }

    fn arm_rooms(state: &mut State, thid: &str, sent_at: Instant) {
        rooms(state).pending = Some(Pending {
            thid: thid.into(),
            sent_at,
            purpose: rm::Purpose::Renewals,
            to: VTC.into(),
        });
    }

    fn refused(thid: &str, from: &str) -> ThreadedReply<Reply> {
        ThreadedReply {
            from: from.into(),
            issuer: Some(from.into()),
            thid: thid.into(),
            reply: Reply::Refused(Refusal {
                code: "vtc/rooms/offers/list:unavailable".into(),
                message: None,
            }),
        }
    }

    fn outcome(thid: &str, persona: PersonaId, result: Result<(), String>) -> SendOutcome {
        SendOutcome {
            vtc_did: VTC.into(),
            persona,
            thid: thid.into(),
            result,
        }
    }

    fn status(state: &mut State) -> String {
        rooms(state)
            .status
            .as_ref()
            .map(|s| s.text.clone())
            .unwrap_or_default()
    }

    #[test]
    fn capitalise_upper_cases_only_the_first_letter() {
        assert_eq!(capitalise("no reply"), "No reply");
        assert_eq!(capitalise("éclair"), "Éclair");
        assert_eq!(capitalise(""), "");
    }

    /// An answer is the community's only when it both sent and issued it,
    /// compared by DID — a fragment or a did:scid `?src=` makes no difference.
    #[test]
    fn an_answer_is_the_communitys_only_when_sent_and_issued_by_it() {
        assert!(answered_by(VTC, VTC, Some(&format!("{VTC}#key-1"))));
        assert!(!answered_by(VTC, VTC, None));
        assert!(!answered_by(VTC, "did:key:zMallory", Some(VTC)));
        assert!(!answered_by(VTC, VTC, Some("did:key:zMallory")));
        let scid = "did:scid:vh:1:QmScid";
        assert!(answered_by(
            scid,
            &format!("{scid}?src=vtc.example"),
            Some(scid)
        ));
    }

    /// A VTA-signed document threads on its `id`; one without an id has no
    /// thread to wait on.
    #[test]
    fn a_signed_document_threads_on_its_id() {
        let doc = Doc::Signed(serde_json::json!({ "id": "urn:uuid:x" }));
        assert_eq!(doc.thread().as_deref(), Some("urn:uuid:x"));
        assert_eq!(Doc::Signed(serde_json::json!({ "id": "" })).thread(), None);
        assert_eq!(Doc::Signed(serde_json::json!({})).thread(), None);
    }

    /// The answer on the thread the view waits on, from the community asked,
    /// is taken once; one from anyone else, or on another thread, is dropped
    /// and the wait goes on.
    #[test]
    fn an_answer_is_taken_once_and_only_on_its_thread_from_its_community() {
        let mut state = rooms_state();
        let mut table = PendingReplies::default();
        arm_rooms(&mut state, "t1", Instant::now());

        assert!(!apply_replies::<Rooms>(
            &mut state,
            &mut table,
            vec![refused("t1", "did:key:zMallory")]
        ));
        assert!(!apply_replies::<Rooms>(
            &mut state,
            &mut table,
            vec![refused("t2", VTC)]
        ));
        assert!(rooms(&mut state).pending.is_some(), "still waiting");

        assert!(apply_replies::<Rooms>(
            &mut state,
            &mut table,
            vec![refused("t1", VTC)]
        ));
        assert!(rooms(&mut state).pending.is_none());
        assert!(
            !apply_replies::<Rooms>(&mut state, &mut table, vec![refused("t1", VTC)]),
            "a second answer on the thread matches nothing"
        );
    }

    /// A send's failure ends only the wait it belongs to: not a newer request's,
    /// not another persona's — and it says why where the view shows it.
    #[test]
    fn a_failed_send_ends_only_its_own_wait() {
        let mut state = rooms_state();
        let mut table = PendingReplies::default();
        let persona = rooms(&mut state).persona;
        arm_rooms(&mut state, "t2", Instant::now());

        send_failed::<Rooms>(
            &mut state,
            &mut table,
            outcome("t1", persona, Err("down".into())),
        );
        assert!(rooms(&mut state).pending.is_some(), "a stale failure");
        send_failed::<Rooms>(
            &mut state,
            &mut table,
            outcome("t2", PersonaId::new(), Err("down".into())),
        );
        assert!(rooms(&mut state).pending.is_some(), "another persona's");
        send_failed::<Rooms>(&mut state, &mut table, outcome("t2", persona, Ok(())));
        assert!(rooms(&mut state).pending.is_some(), "a send that left");

        send_failed::<Rooms>(
            &mut state,
            &mut table,
            outcome("t2", persona, Err("down".into())),
        );
        assert!(rooms(&mut state).pending.is_none());
    }

    /// A job that panicked ends the wait, the flow and the next step, and says so.
    #[test]
    fn a_lost_job_ends_what_it_was_part_of() {
        let mut state = rooms_state();
        arm_rooms(&mut state, "t1", Instant::now());
        rooms(&mut state).next = Some(rm::Next::Refresh);
        rooms(&mut state).accept = Some(rm::AcceptFlow {
            room: "did:key:zR1".into(),
            step: rm::AcceptStep::Collecting,
            offer: None,
        });
        job_lost::<Rooms>(&mut state, "Data room request failed (internal error)");
        let view = rooms(&mut state);
        assert!(view.pending.is_none() && view.next.is_none() && view.accept.is_none());
        assert_eq!(
            view.status.as_ref().unwrap().severity,
            crate::state_handler::main_page::status::Severity::Error
        );
    }

    /// Ticks inside the window leave the wait; the first past it ends it, says
    /// so in the panel's words, and — for a panel whose threads the gate admits
    /// — stops the gate admitting an answer on it. A step whose lane is busy is
    /// kept for the next tick.
    #[tokio::test]
    async fn the_window_closes_a_wait_and_a_busy_step_is_kept() {
        let config = crate::state_handler::dispatch_util::test_config();
        let tdk = crate::state_handler::dispatch_util::test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut in_flight = InFlight::default();
        let mut table = PendingReplies::default();

        // Rooms: inside the window, then past it.
        let mut state = rooms_state();
        arm_rooms(&mut state, "t1", Instant::now());
        // The lane is busy, so the refresh it calls for waits.
        assert!(in_flight.try_begin(DispatchDomain::Rooms));
        rooms(&mut state).next = Some(rm::Next::Refresh);
        {
            let mut lp = CommunityLoop {
                state: &mut state,
                config: &config,
                tdk: &tdk,
                vta: None,
                dispatch_tx: &tx,
                in_flight: &mut in_flight,
                pending_replies: &mut table,
            };
            tick::<Rooms>(&mut lp).await;
        }
        assert!(rooms(&mut state).pending.is_some());
        assert_eq!(rooms(&mut state).next, Some(rm::Next::Refresh), "kept");

        arm_rooms(
            &mut state,
            "t1",
            Instant::now() - REPLY_WINDOW - Duration::from_secs(1),
        );
        {
            let mut lp = CommunityLoop {
                state: &mut state,
                config: &config,
                tdk: &tdk,
                vta: None,
                dispatch_tx: &tx,
                in_flight: &mut in_flight,
                pending_replies: &mut table,
            };
            tick::<Rooms>(&mut lp).await;
        }
        assert!(rooms(&mut state).pending.is_none());
        assert!(status(&mut state).contains("within 30s"));

        // Elections: the gate stops admitting the thread too.
        let mut state = State::default();
        state.main_page.content_panel.elections.view = Some(ElectionsView::new(
            VTC.into(),
            PersonaId::default(),
            "did:key:zAlice".into(),
            "Community".into(),
        ));
        Elections::view_mut(&mut state).unwrap().pending = Some(Pending {
            thid: "e1".into(),
            sent_at: Instant::now() - REPLY_WINDOW - Duration::from_secs(1),
            purpose: el::Purpose::Issue {
                election: "agm".into(),
            },
            to: "did:key:zHolder".into(),
        });
        table.record(
            "e1",
            "did:key:zHolder",
            pending_replies::Purpose::ElectionAnswer,
        );
        {
            let mut lp = CommunityLoop {
                state: &mut state,
                config: &config,
                tdk: &tdk,
                vta: None,
                dispatch_tx: &tx,
                in_flight: &mut in_flight,
                pending_replies: &mut table,
            };
            tick::<Elections>(&mut lp).await;
        }
        assert!(Elections::view_mut(&mut state).unwrap().pending.is_none());
        assert!(!table.is_awaited(ReplyKind::ElectionAnswer, "did:key:zHolder", "e1"));
    }
}
