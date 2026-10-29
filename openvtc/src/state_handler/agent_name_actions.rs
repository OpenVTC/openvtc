//! Agent-name management, off the loop thread (R14).
//!
//! The four verbs behind the agent-name overlay — open, claim, park/resume,
//! remove — are Trust Tasks against the VTA, each with a 60-second timeout
//! ([`agent_name_manage`]), and a mutation is *two* round trips: the change,
//! then a re-read of the registry, which is authoritative. Run inline on the
//! state-handler thread that was up to two minutes with no inbound DIDComm
//! serviced, no listener lifecycle applied, and no key read — including `q`.
//!
//! The overlay's `Working` phase locks its own input, so the freeze was easy to
//! miss from inside the overlay. It was not local to the overlay: it stopped the
//! whole application.
//!
//! Shape follows [`inbox_actions`](super::inbox_actions) and
//! [`relationship_actions`](super::relationship_actions): the loop resolves what
//! the job needs and hands over owned values, the job does I/O only, and every
//! mutation happens back on the loop in [`AgentNameOutcome::apply`].

use vta_sdk::client::VtaClient;

use crate::state_handler::agent_name_manage;
use crate::state_handler::agent_name_manage::AgentNameEntry;
use crate::state_handler::main_page::content::{AgentNameManagerPhase, AgentNameRow};
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;
use openvtc_core::config::Config;

/// Which verb a job runs. `Open` is a read; the rest mutate and then re-read.
pub(crate) enum Verb {
    /// Load the registry for a persona whose overlay has just opened.
    Open,
    /// Bind `name`, after a fast availability check.
    Claim(String),
    /// Stop `name` resolving while keeping it reserved to this DID.
    Park(String),
    /// Resume a parked `name`.
    Resume(String),
    /// Release `name` — anyone may then reclaim it. Destructive.
    Remove(String),
}

impl Verb {
    /// Present-tense status shown while the job runs.
    pub(crate) fn status(&self) -> String {
        match self {
            Verb::Open => "Loading agent names…".to_string(),
            Verb::Claim(n) => format!("Claiming @{n}…"),
            Verb::Park(n) => format!("Parking @{n}…"),
            Verb::Resume(n) => format!("Resuming @{n}…"),
            Verb::Remove(n) => format!("Removing @{n}…"),
        }
    }
}

/// Everything the spawned job needs, already resolved on the loop thread.
pub(crate) struct AgentNameJob {
    pub(crate) vta: VtaClient,
    pub(crate) persona_did: String,
    /// Host the persona's DID is served from, for the display-cache entry.
    pub(crate) host: String,
    pub(crate) verb: Verb,
}

impl AgentNameJob {
    /// Run the verb, then re-read the registry. I/O only — no `State`, no
    /// `Config`, nothing that has to be mutated on the loop.
    pub(crate) async fn run(self) -> AgentNameOutcome {
        let mut out = AgentNameOutcome {
            persona_did: self.persona_did.clone(),
            host: self.host,
            message: None,
            log: None,
            names: None,
            clear_input: false,
        };
        let did = &self.persona_did;

        match &self.verb {
            Verb::Open => {}
            Verb::Claim(name) => {
                // Fast-path rejection: a reserved or already-taken name fails
                // the check before any publish, with a clearer reason than the
                // set error. A check *failure* is non-fatal — fall through to
                // `set`, which is authoritative (and closes the check→set race
                // if someone claims it in between).
                if let Ok(avail) = agent_name_manage::check_name(&self.vta, did, name).await
                    && !avail.available
                {
                    let why = if avail.reserved {
                        "a reserved name"
                    } else {
                        "already taken on this domain"
                    };
                    out.message = Some(format!("@{name} is {why} ({}).", avail.domain));
                    // The registry did not change; leave the list alone.
                    return out;
                }
                match agent_name_manage::set_name(&self.vta, did, name).await {
                    Ok(_) => {
                        out.log = Some(format!("Claimed agent name @{name}"));
                        out.clear_input = true;
                    }
                    Err(e) => {
                        out.message = Some(format!("Could not claim @{name}: {e:#}"));
                        return out;
                    }
                }
            }
            Verb::Park(name) | Verb::Resume(name) => {
                let parking = matches!(self.verb, Verb::Park(_));
                let result = if parking {
                    agent_name_manage::disable_name(&self.vta, did, name).await
                } else {
                    agent_name_manage::enable_name(&self.vta, did, name).await
                };
                match result {
                    Ok(_) => {
                        out.log = Some(format!(
                            "{} agent name @{name}",
                            if parking { "Parked" } else { "Resumed" }
                        ));
                    }
                    Err(e) => {
                        out.message = Some(format!(
                            "Could not {} @{name}: {e:#}",
                            if parking { "park" } else { "resume" }
                        ));
                        return out;
                    }
                }
            }
            Verb::Remove(name) => {
                match agent_name_manage::remove_name(&self.vta, did, name).await {
                    Ok(_) => out.log = Some(format!("Removed agent name @{name}")),
                    Err(e) => {
                        out.message = Some(format!("Could not remove @{name}: {e:#}"));
                        return out;
                    }
                }
            }
        }

        // The registry is authoritative, so every path that changed it re-reads
        // it rather than patching the list locally.
        out.names = Some(
            agent_name_manage::list_names(&self.vta, did)
                .await
                .map_err(|e| format!("{e:#}")),
        );
        if out.names.as_ref().is_some_and(Result::is_err) && out.log.is_some() {
            // The mutation landed and only the read-back failed. Say both, in
            // that order: the claim is done, the list is unknown.
            out.message = Some(format!(
                "Applied, but could not reload the list: {}",
                out.names
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .cloned()
                    .unwrap_or_default()
            ));
        }
        out
    }
}

/// What the job learned. Data only; applied on the loop thread.
pub(crate) struct AgentNameOutcome {
    persona_did: String,
    host: String,
    /// Status line for the overlay.
    message: Option<String>,
    /// Activity-log line, for a mutation that actually landed.
    log: Option<String>,
    /// The registry as re-read afterwards. `None` means it was deliberately
    /// left alone (a rejected claim changed nothing).
    names: Option<Result<Vec<AgentNameEntry>, String>>,
    /// A successful claim empties the input.
    clear_input: bool,
}

impl AgentNameOutcome {
    /// Apply on the loop thread: overlay rows and status, the persisted display
    /// name, and the activity log.
    ///
    /// The config half runs even when the overlay has since been closed or
    /// switched to another persona — a verified name that was just claimed is
    /// worth caching either way — while the overlay half is dropped, because it
    /// would otherwise write one persona's registry over another's.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        let overlay_matches = state
            .main_page
            .agent_names
            .as_ref()
            .is_some_and(|o| o.persona_did == self.persona_did);

        if let Some(line) = self.log {
            state.main_page.log(line);
        }

        // Persisted display name: the first *served* name, host-qualified.
        if let Some(Ok(names)) = self.names.as_ref() {
            let cached = names
                .iter()
                .find(|n| n.enabled)
                .filter(|_| !self.host.is_empty())
                .map(|n| format!("{}/@{}", self.host, n.name));
            config.set_cached_agent_name(&self.persona_did, cached, chrono::Utc::now());
            save.mark_dirty();
            state.main_page.sync_from_config(config);
        }

        if !overlay_matches {
            return;
        }
        let Some(o) = state.main_page.agent_names.as_mut() else {
            return;
        };
        o.phase = AgentNameManagerPhase::Ready;
        if self.clear_input {
            o.input.reset();
        }
        match self.names {
            Some(Ok(names)) => {
                o.names = names
                    .into_iter()
                    .map(|e| AgentNameRow {
                        name: e.name,
                        enabled: e.enabled,
                    })
                    .collect();
                o.selected = o.selected.min(o.names.len().saturating_sub(1));
                o.list_stale = false;
                o.message = self.message;
            }
            Some(Err(_)) => {
                // The read failed, so what is on screen is not the registry.
                o.list_stale = true;
                o.message = self.message;
            }
            None => o.message = self.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::AgentNameManagerState;

    const DID: &str = "did:webvh:QmScidPersona:example.com:alice";

    fn entry(name: &str, enabled: bool) -> AgentNameEntry {
        AgentNameEntry::builder()
            .name(name)
            .enabled(enabled)
            .try_into()
            .unwrap()
    }

    fn open_overlay(state: &mut State, did: &str) {
        state.main_page.agent_names = Some(AgentNameManagerState {
            persona_did: did.to_string(),
            host: "example.com".to_string(),
            phase: AgentNameManagerPhase::Working,
            ..Default::default()
        });
    }

    fn outcome(names: Option<Result<Vec<AgentNameEntry>, String>>) -> AgentNameOutcome {
        AgentNameOutcome {
            persona_did: DID.to_string(),
            host: "example.com".to_string(),
            message: None,
            log: None,
            names,
            clear_input: false,
        }
    }

    /// The happy path: rows land, the phase unlocks, and the first *served*
    /// name becomes the persona's persisted display name.
    #[test]
    fn a_listing_populates_the_overlay_and_caches_the_served_name() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        open_overlay(&mut state, DID);

        outcome(Some(Ok(vec![entry("parked", false), entry("alice", true)]))).apply(
            &mut state,
            &mut config,
            &mut save,
        );

        let o = state.main_page.agent_names.as_ref().unwrap();
        assert_eq!(o.phase, AgentNameManagerPhase::Ready);
        assert_eq!(o.names.len(), 2);
        assert!(!o.list_stale);
        assert_eq!(config.agent_name_for(DID), Some("example.com/@alice"));
        assert!(save.is_pending());
    }

    /// A failed read-back marks the registry unknown rather than rendering an
    /// empty list as "no names" — the claim may well have succeeded.
    #[test]
    fn a_failed_read_back_marks_the_list_stale() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        open_overlay(&mut state, DID);

        outcome(Some(Err("vault unreachable".to_string()))).apply(
            &mut state,
            &mut config,
            &mut save,
        );

        let o = state.main_page.agent_names.as_ref().unwrap();
        assert!(o.list_stale);
        assert_eq!(o.phase, AgentNameManagerPhase::Ready);
    }

    /// The UI is responsive while the job runs, so the operator can close the
    /// overlay or open another persona's before it lands. The overlay half is
    /// then dropped — writing one persona's registry into another's overlay is
    /// exactly the confusion the whole listener-identity work was about.
    #[test]
    fn an_outcome_for_another_persona_does_not_touch_the_overlay() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        open_overlay(&mut state, "did:webvh:QmScidOther:example.com:bob");

        outcome(Some(Ok(vec![entry("alice", true)]))).apply(&mut state, &mut config, &mut save);

        let o = state.main_page.agent_names.as_ref().unwrap();
        assert!(
            o.names.is_empty(),
            "another persona's rows must not land here"
        );
        assert_eq!(o.phase, AgentNameManagerPhase::Working);
    }

    /// …but the persisted name still applies, because it is a fact about the
    /// DID and not about what happens to be on screen.
    #[test]
    fn the_cached_name_applies_even_with_the_overlay_closed() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        outcome(Some(Ok(vec![entry("alice", true)]))).apply(&mut state, &mut config, &mut save);

        assert!(state.main_page.agent_names.is_none());
        assert_eq!(config.agent_name_for(DID), Some("example.com/@alice"));
    }

    /// A rejected claim changed nothing, so the list is left exactly as it was
    /// rather than being re-read or blanked.
    #[test]
    fn a_rejected_claim_leaves_the_list_untouched() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        open_overlay(&mut state, DID);
        if let Some(o) = state.main_page.agent_names.as_mut() {
            o.names = vec![AgentNameRow {
                name: "existing".to_string(),
                enabled: true,
            }];
        }

        let mut out = outcome(None);
        out.message = Some("@taken is already taken on this domain (example.com).".to_string());
        out.apply(&mut state, &mut config, &mut save);

        let o = state.main_page.agent_names.as_ref().unwrap();
        assert_eq!(o.names.len(), 1, "the existing row must survive");
        assert_eq!(o.names[0].name, "existing");
        assert!(o.message.as_deref().is_some_and(|m| m.contains("taken")));
        assert_eq!(o.phase, AgentNameManagerPhase::Ready);
    }
}
