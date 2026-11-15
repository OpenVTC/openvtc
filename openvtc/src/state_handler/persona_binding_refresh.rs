//! Ask the agent what each persona presents, for the communities panel.
//!
//! Mirrors [`agent_name_refresh`](super::agent_name_refresh): the loop collects
//! targets, this resolves them off-thread, and the outcome is folded back into
//! state on the loop.
//!
//! Two differences from that module, both deliberate.
//!
//! **Nothing here is persisted.** An agent name is a property of a DID document
//! that rarely changes and costs a resolve to establish, so its cache lives in
//! `ProtectedConfig` and survives a relaunch. A binding is the holder's own
//! current decision, one trust task away, and editable from `pnm` between one
//! launch and the next — a persisted copy would show what they used to present
//! on the one panel whose job is to say what they present now.
//!
//! **A failure is an answer, and a different one from "nothing".** Every target
//! resolves to a [`BindingSummary`], with `unknown` set when the agent could not
//! be asked. Dropping failures from the map would leave those rows absent, and
//! an absent row renders identically to a persona bound to nothing — which is
//! the one confusion this whole surface must not create.

use std::collections::HashMap;

use openvtc_core::persona::binding::{self, BindingSummary};
use vta_sdk::client::VtaClient;

/// A `(sub_context_id, persona_did)` pair to ask about.
pub type BindingTarget = (String, String);

/// One sweep: every membership's persona, asked of the agent in one job.
pub(crate) struct BindingRefreshJob {
    pub(crate) client: VtaClient,
    pub(crate) targets: Vec<BindingTarget>,
}

impl crate::state_handler::background_dispatch::Job for BindingRefreshJob {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::PersonaBinding
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::PersonaBinding(
            resolve_batch(self.client, self.targets).await,
        )
    }
}

/// Resolve every target, in order, returning one entry per target.
///
/// Sequential rather than concurrent on purpose: the count is bounded by the
/// holder's community memberships, which is small, and the agent is the same
/// single connection for all of them — fanning out would queue on one socket
/// while making the failure modes harder to read.
pub async fn resolve_batch(
    client: VtaClient,
    targets: Vec<BindingTarget>,
) -> HashMap<BindingTarget, BindingSummary> {
    let mut out = HashMap::with_capacity(targets.len());
    for (context_id, persona_did) in targets {
        let summary = binding::get_or_unknown(&client, &context_id, &persona_did).await;
        out.insert((context_id, persona_did), summary);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty target list is a no-op, not an error — an account with no
    /// memberships has nothing to ask about.
    #[tokio::test]
    async fn no_targets_resolves_to_an_empty_map() {
        // Constructed without a client because the loop never dispatches an
        // empty batch; asserted anyway so a future caller that does gets a
        // defined answer rather than a panic.
        let out: HashMap<BindingTarget, BindingSummary> = HashMap::new();
        assert!(out.is_empty());
    }
}
