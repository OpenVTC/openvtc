//! Capability queries and toggles, off the loop thread (R14).
//!
//! Opening the capabilities view, refreshing it, and committing a toggle each
//! *send* a governance document to the community and return its thread id; the
//! community's answer arrives later on the inbound channel and is matched by
//! that id. So the await these arms carried was a send, not a round trip — but a
//! send through `send_message_with_retry` still retries against an unreachable
//! peer, which is seconds of the state-handler thread doing nothing else.
//!
//! Worse, it is the *inbound* channel that carries the reply, and that channel
//! is serviced by the very loop the send was blocking. Nothing could be received
//! while a send was retrying, including the reply being waited for.
//!
//! What stays on the loop is deliberate: resolving the persona's DID, messaging
//! profile and mediator from `Config`, and — for a toggle — reading its signing
//! key. That last one is an `await`, but on the TDK secrets resolver, which is
//! an in-memory store populated at startup. It is not I/O, and keeping it here
//! is what lets the job own a plain `Secret` instead of a `Config` borrow.

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::state_handler::main_page::content::{CapabilitiesPhase, CapabilitiesView};
use crate::state_handler::state::State;
use openvtc_core::config::account::PersonaId;

/// Which document a job sends.
pub(crate) enum Verb {
    /// `governance/capability/list` — ask what the community offers.
    List,
    /// `governance/capability/enable|disable` — ask it to change one. Signed,
    /// because it is a write.
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
}

impl CapabilityJob {
    /// Build, sign where required, and send. I/O only.
    pub(crate) async fn run(self) -> CapabilityOutcome {
        let enable = match &self.verb {
            Verb::List => None,
            Verb::Toggle { enable, .. } => Some(*enable),
        };
        let slug = match &self.verb {
            Verb::List => None,
            Verb::Toggle { slug, .. } => Some(slug.clone()),
        };

        let result = async {
            let doc = match &self.verb {
                Verb::List => openvtc_core::capabilities::build_list_document(
                    &self.persona_did,
                    &self.vtc_did,
                ),
                Verb::Toggle {
                    slug,
                    version,
                    enable,
                    signing_secret,
                } => {
                    let mut doc = openvtc_core::capabilities::build_toggle_document(
                        &self.persona_did,
                        &self.vtc_did,
                        slug,
                        version,
                        *enable,
                    );
                    // Signed with the authentication key (#key-2), not the
                    // assertionMethod signing key: enabling or disabling a
                    // capability is acting on the community, not making a
                    // claim to be held to later, and #key-2 is listed only
                    // under `authentication` in the DID document.
                    openvtc_core::capabilities::sign_document_as(
                        &mut doc,
                        signing_secret,
                        "authentication",
                    )
                    .await?;
                    doc
                }
            };
            openvtc_core::capabilities::send_capability_document(
                &self.atm,
                &self.profile,
                &self.persona_did,
                &self.vtc_did,
                &self.mediator,
                &doc,
            )
            .await
        }
        .await;

        CapabilityOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            enable,
            slug,
            result: result.map_err(|e| format!("{e}")),
        }
    }
}

/// What the send did. Data only; applied on the loop thread.
pub(crate) struct CapabilityOutcome {
    vtc_did: String,
    persona: PersonaId,
    /// `Some` for a toggle, which words its status differently.
    enable: Option<bool>,
    slug: Option<String>,
    /// The thread id to match the community's reply against, or why the send
    /// failed.
    result: Result<String, String>,
}

impl CapabilityOutcome {
    /// Arm the view to await a reply, or report that the send never left.
    ///
    /// Dropped if the view has since closed or moved to another community: the
    /// UI stays live while a send retries, so the operator can do exactly that,
    /// and a thread id armed on the wrong community would match a reply that
    /// answers a question nobody asked there.
    pub(crate) fn apply(self, state: &mut State) {
        let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        match self.result {
            Ok(thid) => {
                view.pending_thid = Some(thid);
                view.sent_at = Some(std::time::Instant::now());
                if let (Some(enable), Some(slug)) = (self.enable, self.slug.as_ref()) {
                    view.status_message = Some(format!(
                        "{} {slug}… awaiting the community's reply",
                        if enable { "enabling" } else { "disabling" }
                    ));
                }
            }
            Err(e) => match self.enable {
                // A failed *write* keeps the list on screen — it is still valid,
                // the change simply did not go out.
                Some(_) => {
                    view.status_message = Some(format!("couldn't send the change: {e}"));
                    tracing::error!("capability toggle failed: {e}");
                }
                // A failed *query* has nothing to show, so the view says so.
                None => {
                    view.phase =
                        CapabilitiesPhase::Failed(format!("could not send the query: {e}"));
                }
            },
        }
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

    fn outcome(
        vtc: &str,
        result: Result<String, String>,
        enable: Option<bool>,
    ) -> CapabilityOutcome {
        CapabilityOutcome {
            vtc_did: vtc.to_string(),
            persona: persona(),
            enable,
            slug: enable.map(|_| "chat".to_string()),
            result,
        }
    }

    /// A sent query arms the view with the thread id the reply will carry.
    #[test]
    fn a_sent_query_arms_the_view() {
        let mut state = State::default();
        view_open(&mut state, VTC);

        outcome(VTC, Ok("thid-1".into()), None).apply(&mut state);

        let v = state
            .main_page
            .content_panel
            .capabilities
            .view
            .as_ref()
            .unwrap();
        assert_eq!(v.pending_thid.as_deref(), Some("thid-1"));
        assert!(v.sent_at.is_some());
    }

    /// A query that never left has nothing to show, so the view fails outright.
    #[test]
    fn a_failed_query_fails_the_view() {
        let mut state = State::default();
        view_open(&mut state, VTC);

        outcome(VTC, Err("peer unreachable".into()), None).apply(&mut state);

        let v = state
            .main_page
            .content_panel
            .capabilities
            .view
            .as_ref()
            .unwrap();
        assert!(matches!(v.phase, CapabilitiesPhase::Failed(ref m) if m.contains("unreachable")));
    }

    /// A failed *toggle* keeps the list — it is still valid; only the write
    /// failed — and says so in the status line instead.
    #[test]
    fn a_failed_toggle_keeps_the_list() {
        let mut state = State::default();
        view_open(&mut state, VTC);

        outcome(VTC, Err("peer unreachable".into()), Some(true)).apply(&mut state);

        let v = state
            .main_page
            .content_panel
            .capabilities
            .view
            .as_ref()
            .unwrap();
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
    /// communities before it lands. Arming that thread id on the new view would
    /// match a reply answering a question nobody asked there.
    #[test]
    fn an_outcome_for_another_community_is_dropped() {
        let mut state = State::default();
        view_open(&mut state, "did:webvh:QmScidOther:example.com:other");

        outcome(VTC, Ok("thid-1".into()), None).apply(&mut state);

        let v = state
            .main_page
            .content_panel
            .capabilities
            .view
            .as_ref()
            .unwrap();
        assert!(
            v.pending_thid.is_none(),
            "another community's thid must not arm this view"
        );
    }

    /// A closed view is not resurrected.
    #[test]
    fn an_outcome_with_no_view_is_dropped() {
        let mut state = State::default();
        outcome(VTC, Ok("thid-1".into()), None).apply(&mut state);
        assert!(state.main_page.content_panel.capabilities.view.is_none());
    }
}
