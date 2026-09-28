//! Community sends, off the loop thread (R14).
//!
//! Two verbs address a community directly: leaving it (`members/self-remove`)
//! and issuing it the reciprocal membership credential (`members/vmc`). Both
//! were awaited inline, and both send to a peer that may be exactly the thing
//! that has gone wrong — leaving a community whose VTC is unreachable is a
//! *likely* reason to leave it, and that is precisely when the send retries
//! longest.
//!
//! The post-send work differs in kind, which is why leaving needs more than the
//! shared apply path: a successful leave also tears down that community's
//! messaging session, and the session manager lives in the runtime loop. The
//! outcome therefore *reports* the teardown it needs — `apply` returns the
//! community to deregister — and the runtime loop performs it. The degraded
//! loop has no sessions to tear down and ignores the answer.

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;

use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;

/// Which document a job sends to the community.
pub(crate) enum Verb {
    /// `members/self-remove` — leave. On success the membership is marked Left
    /// and its session torn down; the community's receipt is advisory.
    ///
    /// Carries the persona's signing key because the task declares `proof`
    /// REQUIRED: leaving is a document the community keeps, and the authcrypt
    /// sender attributes the carriage rather than the document.
    /// `signing_secret` is the persona's **authentication** key: it signs the
    /// request document.
    Leave { signing_secret: Box<Secret> },
    /// `members/vmc` — issue the reciprocal membership credential, signed by the
    /// member, acknowledging `grant`.
    ///
    /// `grant` is the community-issued VMC as it arrived, resolved on the loop
    /// thread with everything else this job needs. The acknowledgement carries a
    /// digest of it, and that digest must cover the document the community will
    /// recompute it over — so the wire form travels here rather than being
    /// re-derived from a parse.
    IssueVmc {
        /// assertionMethod key — signs the credential.
        signing_secret: Box<Secret>,
        /// authentication key — signs the request document.
        document_signer: Box<Secret>,
        grant: Box<serde_json::Value>,
    },
    /// `members/personhood/challenge` — ask for the nonce an assertion must
    /// carry. The reply arrives asynchronously and lands via
    /// [`crate::state_handler::message_dispatch`]; nothing here waits for it.
    RequestPersonhoodChallenge { document_signer: Box<Secret> },
    /// `members/personhood/assert` — present the evidence over that nonce.
    ///
    /// `credentials` are presented whole: `eddsa-jcs-2022` credentials cannot
    /// be redacted, so a member discloses each one entire or not at all.
    AssertPersonhood {
        signing_secret: Box<Secret>,
        challenge_id: uuid::Uuid,
        credentials: Vec<serde_json::Value>,
    },
}

/// What a job did, for the apply path to report.
///
/// Replaces the `leaving: bool` this carried when there were two verbs. A
/// boolean cannot say which of four things happened, and the arm that got it
/// wrong would report the wrong thing to the member rather than fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Performed {
    Leave,
    IssueVmc,
    RequestPersonhoodChallenge,
    AssertPersonhood,
}

/// Everything the send needs, resolved on the loop thread.
pub(crate) struct CommunityJob {
    pub(crate) atm: ATM,
    pub(crate) profile: Arc<ATMProfile>,
    pub(crate) member_did: String,
    pub(crate) mediator: String,
    pub(crate) vtc_did: String,
    pub(crate) persona: PersonaId,
    pub(crate) verb: Verb,
}

impl CommunityJob {
    /// Do the send. I/O only.
    pub(crate) async fn run(self) -> CommunityOutcome {
        let performed = match &self.verb {
            Verb::Leave { .. } => Performed::Leave,
            Verb::IssueVmc { .. } => Performed::IssueVmc,
            Verb::RequestPersonhoodChallenge { .. } => Performed::RequestPersonhoodChallenge,
            Verb::AssertPersonhood { .. } => Performed::AssertPersonhood,
        };
        // The personhood verbs share one route; building it once keeps the
        // member/community/mediator triple from being re-spelled per arm.
        let route = openvtc_core::personhood::Route {
            atm: &self.atm,
            profile: &self.profile,
            member_did: &self.member_did,
            vtc_did: &self.vtc_did,
            mediator_did: &self.mediator,
            // TSP selection is the session's to make; this path sends over the
            // established DIDComm leg, as the other community verbs do.
            tsp_mediator_did: None,
        };
        // What the send produced, where it produces something worth keeping. The
        // member's own acknowledgement is the one credential in this exchange
        // that nothing on this side used to retain.
        let mut issued: Option<serde_json::Value> = None;
        let result = match &self.verb {
            Verb::Leave { signing_secret } => openvtc_core::join::submit_self_remove(
                &self.atm,
                &self.profile,
                &self.member_did,
                signing_secret,
                &self.vtc_did,
                &self.mediator,
                None,
            )
            .await
            .map(|_| ()),
            Verb::IssueVmc {
                signing_secret,
                document_signer,
                grant,
            } => openvtc_core::members::issue_and_send_member_vmc(
                &openvtc_core::members::Delivery {
                    atm: &self.atm,
                    profile: &self.profile,
                    member_did: &self.member_did,
                    vtc_did: &self.vtc_did,
                    mediator_did: &self.mediator,
                },
                signing_secret,
                document_signer,
                grant,
                // Unprompted re-issue: there is no open join to close.
                None,
            )
            .await
            .map(|(_, vmc)| issued = Some(vmc)),
            Verb::RequestPersonhoodChallenge { document_signer } => {
                // The member asks for their own. An administrator minting one
                // for somebody else is a community-side action, not something
                // this client offers.
                openvtc_core::personhood::request_challenge(
                    &route,
                    document_signer,
                    &self.member_did,
                )
                .await
                .map(|_| ())
            }
            Verb::AssertPersonhood {
                signing_secret,
                challenge_id,
                credentials,
            } => openvtc_core::personhood::assert_personhood(
                &route,
                signing_secret,
                challenge_id,
                credentials.clone(),
            )
            .await
            .map(|_| ()),
        };
        CommunityOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            performed,
            error: result.err().map(|e| format!("{e}")),
            issued,
        }
    }
}

/// What the send did. Data only; applied on the loop thread.
pub(crate) struct CommunityOutcome {
    vtc_did: String,
    persona: PersonaId,
    /// Which verb ran — a leave also changes the membership record.
    performed: Performed,
    error: Option<String>,
    /// The credential the send produced, where it produced one — the member's
    /// own acknowledgement. Carried back rather than written by the job, because
    /// the job holds no `Config`: every record change happens on the apply path.
    issued: Option<serde_json::Value>,
}

impl CommunityOutcome {
    /// Apply the record change and the status line, and say whether the loop
    /// still owes this community a session teardown.
    ///
    /// The teardown is reported rather than done because the session manager and
    /// the messaging service belong to the runtime loop, and this runs from the
    /// shared apply path that both loops call.
    pub(crate) fn apply(
        self,
        state: &mut State,
        config: &mut Config,
        save: &mut SaveScheduler,
    ) -> Option<(String, PersonaId)> {
        // Set through a local rather than a long-lived `&mut` into `state`:
        // two of the arms also want to log, which needs `main_page` again.
        fn status(state: &mut State, msg: String) {
            state.main_page.content_panel.communities.status_message = Some(msg);
        }
        match (self.error, self.performed) {
            (None, Performed::Leave) => {
                // The record moves on the send, not on a receipt: the community's
                // acknowledgement is advisory, and a member who has announced a
                // departure should not still be shown as a member if it never
                // answers.
                if let Some(c) = config.account.membership_mut(&self.vtc_did, self.persona) {
                    c.leave();
                }
                save.mark_dirty();
                status(state, "Left the community.".to_string());
                state.main_page.sync_from_config(config);
                return Some((self.vtc_did, self.persona));
            }
            (None, Performed::IssueVmc) => {
                // Keep our half before saying anything about it. This is the
                // only moment the document exists on this side.
                if let Some(vmc) = self.issued
                    && let Some(c) = config.account.membership_mut(&self.vtc_did, self.persona)
                {
                    c.member_vmc = Some(vmc);
                    save.mark_dirty();
                }
                // Only the *send* succeeded. A DIDComm `Ok` means the frame was
                // accepted for delivery locally; it says nothing about whether
                // the community took the credential, and for the entire life of
                // this feature it did not — every delivery was rejected and this
                // line said otherwise. The wording now matches the two
                // personhood verbs beside it, which have always been honest
                // about the difference.
                status(
                    state,
                    "Membership credential sent — waiting for the community to acknowledge it."
                        .to_string(),
                );
            }
            (None, Performed::RequestPersonhoodChallenge) => {
                // Only the *send* succeeded. The challenge itself arrives in
                // the community's reply, so the message says what is being
                // waited for rather than implying the ceremony has moved on.
                status(
                    state,
                    "Asked the community for a personhood challenge — waiting for its reply."
                        .to_string(),
                );
            }
            (None, Performed::AssertPersonhood) => {
                status(
                    state,
                    "Personhood assertion sent — waiting for the community's decision.".to_string(),
                );
            }
            (Some(e), Performed::Leave) => {
                state.main_page.log_error("Leave failed", e.as_str());
                status(state, format!("Couldn't leave: {e}"));
            }
            (Some(e), Performed::IssueVmc) => {
                state
                    .main_page
                    .log_error("Issue membership credential failed", e.as_str());
                status(
                    state,
                    format!("Couldn't issue the membership credential: {e}"),
                );
            }
            (Some(e), Performed::RequestPersonhoodChallenge) => {
                state
                    .main_page
                    .log_error("Personhood challenge request failed", e.as_str());
                status(state, format!("Couldn't ask for a challenge: {e}"));
            }
            (Some(e), Performed::AssertPersonhood) => {
                // The challenge is single-use, but a send that never left does
                // not spend it — so the member keeps the one they have and can
                // retry rather than starting the ceremony again.
                state
                    .main_page
                    .log_error("Personhood assertion failed", e.as_str());
                status(state, format!("Couldn't assert personhood: {e}"));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    const VTC: &str = "did:webvh:QmScidCommunity:example.com:acme";

    fn outcome(performed: Performed, error: Option<&str>) -> CommunityOutcome {
        CommunityOutcome {
            vtc_did: VTC.to_string(),
            persona: PersonaId(uuid::Uuid::nil()),
            performed,
            error: error.map(ToString::to_string),
            issued: None,
        }
    }

    /// Read the status line the panel would show.
    fn status_of(state: &State) -> Option<&str> {
        state
            .main_page
            .content_panel
            .communities
            .status_message
            .as_deref()
    }

    /// A successful leave asks the loop to tear the session down. Nothing else
    /// can: the session manager is not reachable from the shared apply path.
    #[test]
    fn a_successful_leave_asks_for_a_session_teardown() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister = outcome(Performed::Leave, None).apply(&mut state, &mut config, &mut save);

        assert_eq!(deregister.map(|(v, _)| v).as_deref(), Some(VTC));
        assert!(save.is_pending(), "the record change must be persisted");
    }

    /// A *failed* leave must not tear anything down — the membership is still
    /// live, and the session is what would carry a retry.
    #[test]
    fn a_failed_leave_keeps_the_session() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister = outcome(Performed::Leave, Some("peer unreachable")).apply(
            &mut state,
            &mut config,
            &mut save,
        );

        assert!(deregister.is_none());
        assert!(
            state
                .main_page
                .content_panel
                .communities
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("Couldn't leave")),
        );
    }

    /// Issuing a credential never touches the session or the record — it is a
    /// send with a status line.
    #[test]
    fn issuing_a_credential_touches_neither_session_nor_record() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister =
            outcome(Performed::IssueVmc, None).apply(&mut state, &mut config, &mut save);

        assert!(deregister.is_none());
        assert!(!save.is_pending(), "nothing to persist");
        assert!(
            state
                .main_page
                .content_panel
                .communities
                .status_message
                .as_deref()
                // The status must say the credential was *sent*, not accepted:
                // a DIDComm `Ok` is a local hand-off. This assertion used to
                // look for "issued", which is what the old wording claimed.
                .is_some_and(|m| m.contains("sent") && m.contains("waiting")),
        );
    }

    /// A failed issue reports why, and still changes nothing.
    #[test]
    fn a_failed_issue_reports_the_reason() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        let deregister = outcome(Performed::IssueVmc, Some("vault refused")).apply(
            &mut state,
            &mut config,
            &mut save,
        );

        assert!(deregister.is_none());
        assert!(
            state
                .main_page
                .activity_log
                .iter()
                .any(|e| e.summary.contains("vault refused")),
        );
    }

    /// A successful challenge request has **not** obtained a challenge — only
    /// sent the ask. The reply carries the nonce, so a status line claiming
    /// otherwise would have the member looking for a match code that has not
    /// arrived.
    #[test]
    fn a_sent_challenge_request_says_it_is_waiting() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        outcome(Performed::RequestPersonhoodChallenge, None).apply(
            &mut state,
            &mut config,
            &mut save,
        );

        let msg = status_of(&state).expect("a status line");
        assert!(
            msg.contains("waiting"),
            "the send is not the challenge; got: {msg}"
        );
        assert!(
            !save.is_pending(),
            "asking for a challenge changes nothing worth persisting"
        );
    }

    /// Likewise for the assertion: the community decides, and its decision
    /// arrives later.
    #[test]
    fn a_sent_assertion_says_it_is_waiting_on_the_community() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        outcome(Performed::AssertPersonhood, None).apply(&mut state, &mut config, &mut save);

        let msg = status_of(&state).expect("a status line");
        assert!(
            msg.contains("waiting"),
            "a sent assertion is not an asserted personhood; got: {msg}"
        );
    }

    /// Each verb reports its own failure. With the previous `leaving: bool`
    /// this could not be expressed — two of the four would have had to borrow
    /// another's wording and tell the member the wrong thing went wrong.
    #[test]
    fn each_verb_reports_its_own_failure() {
        for (performed, expected) in [
            (Performed::Leave, "Couldn't leave"),
            (Performed::IssueVmc, "Couldn't issue"),
            (
                Performed::RequestPersonhoodChallenge,
                "Couldn't ask for a challenge",
            ),
            (Performed::AssertPersonhood, "Couldn't assert personhood"),
        ] {
            let mut state = State::default();
            let mut config = test_config();
            let mut save = SaveScheduler::new("test");

            outcome(performed, Some("peer unreachable")).apply(&mut state, &mut config, &mut save);

            let msg = status_of(&state).expect("a status line");
            assert!(
                msg.contains(expected),
                "{performed:?} should report {expected:?}, got: {msg}"
            );
        }
    }
}
