//! Ask each community for its profile, once, to learn its declared
//! `relationshipIdentifierDefault` (issue #241).
//!
//! A community may publish `relationshipIdentifierDefault: attributed`, meaning
//! it wants relationship edges under members' persona DIDs (a legible graph)
//! rather than the pairwise default. OpenVTC reads that only to seed the
//! new-relationship form's default — it is never a gate, and the operator can
//! always toggle it. The value lives on the community profile
//! (`vtc/community/profile/show`), which is not carried in the join manifest
//! OpenVTC already reads, so it is fetched here.
//!
//! ## Pacing: once per session, not backed off
//!
//! Unlike [`super::join_status_poll`], there is nothing to reconcile toward — the
//! value is near-static community metadata, not a lifecycle that resolves. So a
//! community is asked **once per process session** and then left alone: the reply
//! caches on every membership of that community
//! ([`openvtc_core::messaging::handle_community_profile_show_response`]), and a
//! declaration that changes is picked up on the next launch. Keying on "already
//! asked this session" rather than on "value still unknown" is deliberate: a
//! community that declares *nothing* answers with an absent field, which stays
//! `None`, and re-asking whenever the value is `None` would poll such a community
//! forever (R1.4).
//!
//! At most [`MAX_ASKS_PER_TICK`] go out per tick so an account in many
//! communities spreads them over several ticks rather than opening a fan of
//! sends.

use std::collections::HashSet;

use affinidi_tdk::messaging::ATM;
use openvtc_core::config::Config;
use openvtc_core::config::account::{PersonaId, VtcDid};
use openvtc_core::didcomm::MessagingTransport;
use tracing::debug;

/// Cap on profile asks emitted per tick (R1.4 — bound the fan-out).
const MAX_ASKS_PER_TICK: usize = 4;

type AskKey = (VtcDid, PersonaId);

/// Remembers which communities have been asked this session, so each is asked
/// once. In memory, never persisted — the politeness is this process's, and a
/// stale on-disk marker would suppress the ask a fresh launch most wants.
#[derive(Default)]
pub(crate) struct ProfilePacer {
    asked: HashSet<AskKey>,
}

/// One profile ask, resolved against the account so the send owns everything it
/// needs and can move into a spawned task (no `Config` borrow).
pub(crate) struct Ask {
    persona_did: String,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    mediator_did: String,
    vtc_did: String,
    /// The community was joined over TSP, so the ask must go over TSP too — a
    /// community reachable only over TSP would never see a DIDComm ask.
    over_tsp: bool,
}

impl ProfilePacer {
    /// The Active memberships not yet asked this session, resolved to sendable
    /// [`Ask`]s and capped. Marks each returned key asked, so a send that then
    /// fails is simply not retried until the next launch (the value is optional
    /// and its absence is a valid, pairwise-defaulting state).
    ///
    /// Forgets keys that are no longer Active memberships, so a community left
    /// and re-joined in one long-lived session is asked afresh.
    pub(crate) fn due(&mut self, config: &Config) -> Vec<Ask> {
        self.forget_inactive(
            &config
                .account
                .memberships()
                .filter(|c| c.status.is_active())
                .map(|c| (c.vtc_did.clone(), c.persona_ref))
                .collect(),
        );

        let mut asks = Vec::new();
        for record in config
            .account
            .memberships()
            .filter(|c| c.status.is_active())
        {
            if asks.len() >= MAX_ASKS_PER_TICK {
                break;
            }
            let key = (record.vtc_did.clone(), record.persona_ref);
            if self.asked.contains(&key) {
                continue;
            }
            // Drop any whose persona no longer resolves to a runtime identity (a
            // DID deleted mid-flight): there is nothing to speak as. Do NOT mark
            // it asked — if the identity comes back, so should the ask (the
            // `contains` check above is why resolution precedes the insert).
            let Some(identity) = config.identities.get(&record.persona_ref) else {
                debug!(
                    vtc = %record.vtc_did,
                    "skipping community profile ask: persona has no runtime identity"
                );
                continue;
            };
            self.asked.insert(key);
            asks.push(Ask {
                persona_did: identity.persona_did().to_string(),
                profile: identity.profile().clone(),
                mediator_did: identity.mediator_did.clone().unwrap_or_default(),
                vtc_did: record.vtc_did.clone(),
                over_tsp: record.submit_transport == Some(MessagingTransport::Tsp),
            });
        }
        asks
    }

    /// Drop remembered keys that are no longer Active memberships.
    fn forget_inactive(&mut self, active: &HashSet<AskKey>) {
        self.asked.retain(|key| active.contains(key));
    }

    /// Whether `key` still needs asking; records it if so. The dedup primitive
    /// [`due`](Self::due) is built on, factored out to be testable without a
    /// runtime identity graph.
    #[cfg(test)]
    fn take(&mut self, key: AskKey) -> bool {
        self.asked.insert(key)
    }
}

/// Send each ask, one at a time. The reply is asynchronous — it arrives on the
/// persona's listener and is applied by inbound dispatch — so nothing is awaited
/// beyond the send, and a failure is logged rather than surfaced: this is
/// background metadata the operator did not initiate, and the value only seeds a
/// form default whose absence is harmless.
pub(crate) async fn send_all(atm: ATM, asks: Vec<Ask>) {
    for ask in asks {
        let tsp_mediator = if ask.over_tsp {
            openvtc_core::config::peer_tsp_mediator(&ask.vtc_did).await
        } else {
            None
        };
        match openvtc_core::join::send_community_profile_show(
            &atm,
            &ask.profile,
            &ask.persona_did,
            &ask.vtc_did,
            &ask.mediator_did,
            tsp_mediator.as_deref(),
        )
        .await
        {
            Ok(()) => debug!(vtc = %ask.vtc_did, "asked the community for its profile"),
            Err(e) => debug!(
                vtc = %ask.vtc_did,
                error = %e,
                "could not ask the community for its profile; will retry next launch"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvtc_core::config::account::PersonaId;

    fn key(vtc: &str, persona: PersonaId) -> AskKey {
        (vtc.to_string(), persona)
    }

    /// A community is asked once, then not again the same session — this is the
    /// property that stops a community declaring *nothing* (a permanently `None`
    /// stored value) from being polled every tick forever.
    #[test]
    fn a_key_is_asked_once_per_session() {
        let mut pacer = ProfilePacer::default();
        let k = key("did:web:vtc", PersonaId::new());
        assert!(pacer.take(k.clone()), "first ask goes out");
        assert!(
            !pacer.take(k),
            "the same community is not asked again this session"
        );
    }

    /// Leaving a community forgets its marker, so re-joining in the same session
    /// asks afresh rather than trusting a stale answer.
    #[test]
    fn forgetting_an_inactive_community_re_enables_the_ask() {
        let mut pacer = ProfilePacer::default();
        let persona = PersonaId::new();
        let k = key("did:web:vtc", persona);
        assert!(pacer.take(k.clone()));

        // It is no longer among the Active memberships.
        pacer.forget_inactive(&HashSet::new());
        assert!(pacer.take(k), "a re-joined community is asked again");
    }
}
