//! Capability queries and toggles, off the loop thread (R14).
//!
//! Opening the capabilities view, refreshing it, and committing a toggle each
//! *send* a governance document to the community; the community's answer
//! arrives later on the inbound channel and is matched by the document's
//! thread id. So the await these arms carried was a send, not a round trip — but a
//! send through `send_message_with_retry` still retries against an unreachable
//! peer, which is seconds of the state-handler thread doing nothing else.
//!
//! Worse, it is the *inbound* channel that carries the reply, and that channel
//! is serviced by the very loop the send was blocking. Nothing could be received
//! while a send was retrying, including the reply being waited for.
//!
//! What stays on the loop is deliberate: resolving the persona's DID, messaging
//! profile and mediator from `Config`, reading its signing key, and building
//! the request document. The key read is an `await`, but on the TDK secrets
//! resolver, which is an in-memory store populated at startup. It is not I/O,
//! and keeping it here is what lets the job own a plain `Secret` instead of a
//! `Config` borrow.
//!
//! Building the document here is what fixes its id — the thread the reply is
//! matched on — before the send is spawned, so the view is armed with it
//! straight away ([`CapabilitySend::arm`]). Armed only when the send reported
//! back, a community answering within a millisecond (a refusal from a host
//! that offers no capability management does) beat it: the reply found no
//! pending thread, was dropped, and the view sat out the 30 s reply window to
//! report a host that had in fact answered.

use std::sync::Arc;
use std::time::Instant;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::state_handler::main_page::content::{CapabilitiesPhase, CapabilitiesView};
use crate::state_handler::state::State;
use openvtc_core::capabilities::RequestDocument;
use openvtc_core::config::account::PersonaId;

/// Which document a job sends.
pub(crate) enum Verb {
    /// `governance/capability/list` — ask what the community offers. Signed
    /// like every request, with the persona's authentication key.
    List { signing_secret: Box<Secret> },
    /// `governance/capability/enable|disable` — ask it to change one. Signed
    /// with the persona's authentication key.
    Toggle {
        slug: String,
        version: String,
        enable: bool,
        signing_secret: Box<Secret>,
    },
}

/// Everything the send needs, resolved on the loop thread.
pub(crate) struct CapabilityJob {
    pub(crate) atm: ATM,
    pub(crate) profile: Arc<ATMProfile>,
    pub(crate) persona_did: String,
    pub(crate) mediator: String,
    pub(crate) vtc_did: String,
    pub(crate) persona: PersonaId,
    pub(crate) verb: Verb,
    /// The membership was joined over TSP, so the request goes over TSP: the
    /// community answers on the transport a request arrived on.
    pub(crate) over_tsp: bool,
}

impl CapabilityJob {
    /// Build the request document, on the loop thread. Its id — and so the
    /// thread the community's reply carries — is fixed from here on.
    pub(crate) fn prepare(self) -> CapabilitySend {
        let (doc, toggle, signing_secret) = match self.verb {
            Verb::List { signing_secret } => (
                openvtc_core::capabilities::build_list_document(&self.persona_did, &self.vtc_did),
                None,
                signing_secret,
            ),
            Verb::Toggle {
                slug,
                version,
                enable,
                signing_secret,
            } => (
                openvtc_core::capabilities::build_toggle_document(
                    &self.persona_did,
                    &self.vtc_did,
                    &slug,
                    &version,
                    enable,
                ),
                Some((slug, enable)),
                signing_secret,
            ),
        };
        CapabilitySend {
            atm: self.atm,
            profile: self.profile,
            persona_did: self.persona_did,
            mediator: self.mediator,
            vtc_did: self.vtc_did,
            persona: self.persona,
            over_tsp: self.over_tsp,
            toggle,
            doc,
            signing_secret,
        }
    }
}

/// A request built and ready to sign and send.
pub(crate) struct CapabilitySend {
    atm: ATM,
    profile: Arc<ATMProfile>,
    persona_did: String,
    mediator: String,
    vtc_did: String,
    persona: PersonaId,
    over_tsp: bool,
    /// `Some((slug, enable))` for a toggle, which words its status differently.
    toggle: Option<(String, bool)>,
    /// Unsigned: signing waits for the job, but nothing it does changes the id.
    doc: RequestDocument,
    signing_secret: Box<Secret>,
}

impl CapabilitySend {
    /// The thread the community's reply will carry.
    pub(crate) fn thread(&self) -> &str {
        openvtc_core::capabilities::correlation_thread(&self.doc)
    }

    /// Arm the view to await this request's reply. Called on the loop, before
    /// the send is spawned, so a reply that overtakes the send's own report is
    /// still matched.
    pub(crate) fn arm(&self, state: &mut State) {
        arm(
            state,
            &self.vtc_did,
            self.persona,
            self.thread(),
            self.toggle
                .as_ref()
                .map(|(slug, enable)| (slug.as_str(), *enable)),
        );
    }

    /// Sign and send. I/O only.
    pub(crate) async fn run(mut self) -> CapabilityOutcome {
        let thid = self.thread().to_string();
        let result = async {
            openvtc_core::capabilities::sign_document(&mut self.doc, &self.signing_secret).await?;
            let tsp_mediator =
                openvtc_core::community_send::tsp_mediator_for(self.over_tsp, &self.vtc_did).await;
            openvtc_core::capabilities::send_capability_document(
                &openvtc_core::community_send::Delivery {
                    atm: &self.atm,
                    profile: &self.profile,
                    member_did: &self.persona_did,
                    vtc_did: &self.vtc_did,
                    mediator_did: &self.mediator,
                    tsp_mediator_did: tsp_mediator.as_deref(),
                },
                &self.doc,
            )
            .await
        }
        .await;
        CapabilityOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            thid,
            toggle: self.toggle,
            result: result.map(|_| ()).map_err(|e| format!("{e}")),
        }
    }
}

/// Arm the view for `vtc_did` to await the reply threaded on `thid`. Nothing
/// is armed on a view that has closed or shows another community.
fn arm(
    state: &mut State,
    vtc_did: &str,
    persona: PersonaId,
    thid: &str,
    toggle: Option<(&str, bool)>,
) {
    let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() else {
        return;
    };
    if view.vtc_did != vtc_did || view.persona != persona {
        return;
    }
    view.pending_thid = Some(thid.to_string());
    view.sent_at = Some(Instant::now());
    if let Some((slug, enable)) = toggle {
        view.status_message = Some(format!(
            "{} {slug}… awaiting the community's reply",
            if enable { "enabling" } else { "disabling" }
        ));
    }
}

/// What the send did. Data only; applied on the loop thread.
pub(crate) struct CapabilityOutcome {
    vtc_did: String,
    persona: PersonaId,
    /// The thread the view was armed with for this request.
    thid: String,
    toggle: Option<(String, bool)>,
    /// Why the send failed, if it did.
    result: Result<(), String>,
}

impl CapabilityOutcome {
    /// Report a send that never left. A send that did needs nothing: the view
    /// was armed before it was spawned, and its reply may already be applied.
    ///
    /// A failure is applied only while the view still waits on *this*
    /// request's thread. The UI stays live while a send retries, so by the time
    /// it gives up the operator may have closed the view, moved to another
    /// community, or sent a newer request — whose wait a stale failure must not
    /// end.
    pub(crate) fn apply(self, state: &mut State) {
        let Err(e) = self.result else {
            return;
        };
        let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() else {
            return;
        };
        if view.vtc_did != self.vtc_did
            || view.persona != self.persona
            || view.pending_thid.as_deref() != Some(self.thid.as_str())
        {
            tracing::debug!(
                thid = %self.thid,
                "capability send failed for a request the view no longer waits on: {e}"
            );
            return;
        }
        view.pending_thid = None;
        view.sent_at = None;
        match self.toggle {
            // A failed *write* keeps the list on screen — it is still valid,
            // the change simply did not go out.
            Some(_) => {
                view.status_message = Some(format!("couldn't send the change: {e}"));
                tracing::error!("capability toggle failed: {e}");
            }
            // A failed *query* has nothing to show, so the view says so.
            None => {
                view.phase = CapabilitiesPhase::Failed(format!("could not send the query: {e}"));
            }
        }
    }
}

/// The status line for a toggle the community refused. `detail` is the
/// refusal's own message, already formatted as ` — …` (or empty).
///
/// Enabling and disabling a capability is an administrator's act: the
/// community refuses anyone else with `permissionDenied`. The client cannot
/// tell beforehand — administration is the community's own ACL, which a member
/// cannot read, and the role credential a member holds names the roles it was
/// issued with, not the ACL as it stands — so `e` is offered to every member
/// and the refusal is what says who may. Reported as a bare code it read like a
/// fault.
pub(crate) fn toggle_refusal(code: &str, detail: &str) -> String {
    match code {
        "permissionDenied" | "forbidden" => {
            "only the community's administrators can enable or disable capabilities".to_string()
        }
        _ => format!("the community rejected the change: {code}{detail}"),
    }
}

/// Report that there is no messaging identity to send as. Rare — it means the
/// persona has no resolved identity or the ATM is absent — but silence here
/// would leave the view spinning on a query that was never sent.
pub(crate) fn send_unavailable(state: &mut State) {
    if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() {
        view.phase = CapabilitiesPhase::Failed("messaging is unavailable".to_string());
    }
}

/// Open a fresh view for `vtc_did`, replacing whatever was there.
pub(crate) fn open_view(state: &mut State, vtc_did: String, persona: PersonaId, name: String) {
    state.main_page.content_panel.capabilities.view =
        Some(CapabilitiesView::new(vtc_did, persona, name));
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvtc_core::capabilities::CapabilityReply;

    const VTC: &str = "did:webvh:QmScidCommunity:example.com:acme";

    /// `PersonaId::default()` mints a fresh v4 UUID on every call, so a test
    /// that used it twice would compare two different personas — and the guard
    /// would (correctly) drop the outcome for reasons the test did not intend.
    fn persona() -> PersonaId {
        PersonaId(uuid::Uuid::nil())
    }

    fn view_open(state: &mut State, vtc: &str) {
        open_view(state, vtc.to_string(), persona(), "Acme".into());
        if let Some(v) = state.main_page.content_panel.capabilities.view.as_mut() {
            v.phase = CapabilitiesPhase::Loading;
        }
    }

    fn view(state: &State) -> &CapabilitiesView {
        state
            .main_page
            .content_panel
            .capabilities
            .view
            .as_ref()
            .unwrap()
    }

    fn view_mut(state: &mut State) -> &mut CapabilitiesView {
        state
            .main_page
            .content_panel
            .capabilities
            .view
            .as_mut()
            .unwrap()
    }

    /// Arm as `spawn_capability_job` does, before the send is spawned.
    fn sent(state: &mut State, thid: &str, toggle: Option<bool>) {
        arm(state, VTC, persona(), thid, toggle.map(|e| ("chat", e)));
    }

    fn outcome(
        vtc: &str,
        thid: &str,
        result: Result<(), String>,
        enable: Option<bool>,
    ) -> CapabilityOutcome {
        CapabilityOutcome {
            vtc_did: vtc.to_string(),
            persona: persona(),
            thid: thid.to_string(),
            toggle: enable.map(|e| ("chat".to_string(), e)),
            result,
        }
    }

    fn reply(state: &mut State, thid: &str, reply: CapabilityReply) {
        crate::state_handler::apply_capability_replies(
            state,
            vec![(VTC.to_string(), thid.to_string(), reply)],
        );
    }

    fn unsupported() -> CapabilityReply {
        CapabilityReply::Rejected {
            code: "unsupportedType".into(),
            message: None,
        }
    }

    /// A query is awaited from the moment it is sent, with the thread id its
    /// reply will carry.
    #[test]
    fn a_sent_query_arms_the_view() {
        let mut state = State::default();
        view_open(&mut state, VTC);

        sent(&mut state, "thid-1", None);

        let v = view(&state);
        assert_eq!(v.pending_thid.as_deref(), Some("thid-1"));
        assert!(v.sent_at.is_some());
    }

    /// **The race.** A community that offers no capability management refuses
    /// in well under a millisecond — before the send's own outcome is applied.
    /// The view was armed before the send, so the refusal is matched; the
    /// outcome that follows changes nothing.
    #[test]
    fn a_reply_that_overtakes_the_send_is_still_matched() {
        let mut state = State::default();
        view_open(&mut state, VTC);
        sent(&mut state, "thid-1", None);

        reply(&mut state, "thid-1", unsupported());
        outcome(VTC, "thid-1", Ok(()), None).apply(&mut state);

        let v = view(&state);
        assert!(
            matches!(&v.phase, CapabilitiesPhase::Failed(m) if m.contains("does not offer")),
            "{:?}",
            v.phase
        );
        assert!(v.pending_thid.is_none(), "answered; not re-armed");
        assert!(v.sent_at.is_none(), "nothing left for the 30 s sweep");
    }

    /// The same for a toggle: its answer may land before its send reports.
    #[test]
    fn a_toggle_reply_that_overtakes_the_send_is_still_matched() {
        let mut state = State::default();
        view_open(&mut state, VTC);
        view_mut(&mut state).phase = CapabilitiesPhase::Loaded;
        sent(&mut state, "toggle-1", Some(true));

        reply(
            &mut state,
            "toggle-1",
            CapabilityReply::Toggled {
                capability: "chat".into(),
                enabled: true,
            },
        );
        outcome(VTC, "toggle-1", Ok(()), Some(true)).apply(&mut state);

        let v = view(&state);
        assert!(v.pending_thid.is_none());
        assert_eq!(v.status_message.as_deref(), Some("chat is now enabled"));
    }

    /// A query that never left has nothing to show, so the view fails outright.
    #[test]
    fn a_failed_query_fails_the_view() {
        let mut state = State::default();
        view_open(&mut state, VTC);
        sent(&mut state, "thid-1", None);

        outcome(VTC, "thid-1", Err("peer unreachable".into()), None).apply(&mut state);

        let v = view(&state);
        assert!(matches!(v.phase, CapabilitiesPhase::Failed(ref m) if m.contains("unreachable")));
        assert!(v.pending_thid.is_none());
    }

    /// A failure that lands after a newer request was sent is for a question
    /// nobody is waiting on any more: it must not end the newer one's wait.
    #[test]
    fn a_late_failure_for_a_superseded_request_keeps_the_current_wait() {
        let mut state = State::default();
        view_open(&mut state, VTC);
        sent(&mut state, "thid-1", None);
        sent(&mut state, "thid-2", None);

        outcome(VTC, "thid-1", Err("peer unreachable".into()), None).apply(&mut state);

        let v = view(&state);
        assert_eq!(v.pending_thid.as_deref(), Some("thid-2"));
        assert!(v.sent_at.is_some());
        assert!(
            matches!(v.phase, CapabilitiesPhase::Loading),
            "{:?}",
            v.phase
        );
    }

    /// A failed *toggle* keeps the list — it is still valid; only the write
    /// failed — and says so in the status line instead.
    #[test]
    fn a_failed_toggle_keeps_the_list() {
        let mut state = State::default();
        view_open(&mut state, VTC);
        sent(&mut state, "toggle-1", Some(true));

        outcome(VTC, "toggle-1", Err("peer unreachable".into()), Some(true)).apply(&mut state);

        let v = view(&state);
        assert!(
            matches!(v.phase, CapabilitiesPhase::Loading),
            "phase untouched"
        );
        assert!(
            v.status_message
                .as_deref()
                .is_some_and(|m| m.contains("couldn't send")),
            "{:?}",
            v.status_message
        );
    }

    /// The UI stays live while a send retries, so the operator can switch
    /// communities before it lands. Neither arming nor a failure reaches a view
    /// showing another community.
    #[test]
    fn another_communitys_request_does_not_touch_the_view() {
        let mut state = State::default();
        view_open(&mut state, "did:webvh:QmScidOther:example.com:other");

        sent(&mut state, "thid-1", None);
        assert!(
            view(&state).pending_thid.is_none(),
            "another community's thid must not arm this view"
        );

        outcome(VTC, "thid-1", Err("peer unreachable".into()), None).apply(&mut state);
        assert!(matches!(view(&state).phase, CapabilitiesPhase::Loading));
    }

    /// A closed view is not resurrected.
    #[test]
    fn an_outcome_with_no_view_is_dropped() {
        let mut state = State::default();
        sent(&mut state, "thid-1", None);
        outcome(VTC, "thid-1", Err("peer unreachable".into()), None).apply(&mut state);
        assert!(state.main_page.content_panel.capabilities.view.is_none());
    }

    /// Enabling and disabling is an administrator's act; a member refused
    /// for it is told so, not shown a bare code.
    #[test]
    fn a_member_refused_a_toggle_is_told_it_is_for_administrators() {
        let mut state = State::default();
        view_open(&mut state, VTC);
        view_mut(&mut state).phase = CapabilitiesPhase::Loaded;
        sent(&mut state, "toggle-1", Some(true));

        reply(
            &mut state,
            "toggle-1",
            CapabilityReply::Rejected {
                code: "permissionDenied".into(),
                message: Some("not an administrator".into()),
            },
        );

        let v = view(&state);
        assert_eq!(
            v.status_message.as_deref(),
            Some("only the community's administrators can enable or disable capabilities")
        );
        assert!(
            matches!(v.phase, CapabilitiesPhase::Loaded),
            "the list stays"
        );
    }

    /// Any other refusal still carries its code and message.
    #[test]
    fn another_toggle_refusal_keeps_its_code() {
        assert_eq!(
            toggle_refusal("malformedRequest", " — bad version"),
            "the community rejected the change: malformedRequest — bad version"
        );
    }
}
