//! VIC (Verifiable Invitation Credential) vault management.
//!
//! Thin async helpers over the VTA credential-vault lifecycle tasks, backing the
//! VTA Service panel's invitation-credential manager: list / import / archive /
//! unarchive / soft-delete / restore / purge the VICs a holder holds
//! (`purpose = "invite"`). Everything goes through the always-on admin VTA
//! session's credential vault. The list is built from descriptors only — a
//! query result never carries the credential body, so nothing here fetches one.

use anyhow::Result;
use vta_sdk::client::VtaClient;

use crate::state_handler::main_page::content::VicSummary;
use crate::state_handler::state::State;
use openvtc_core::config::Config;

/// Reason string stamped on lifecycle mutations (shows in the VTA audit log).
const REASON: &str = "via OpenVTC";

/// List the holder's invitation credentials. With `include_inactive`, archived
/// and soft-deleted VICs are surfaced too (so the panel can offer restore /
/// purge); otherwise only active ones are returned. `purpose = "invite"`
/// satisfies the vault's ≥1-filter requirement; the include flags are modifiers.
pub(crate) async fn list_vics(
    admin_vta: &VtaClient,
    include_inactive: bool,
) -> Result<Vec<VicSummary>> {
    let mut filter = serde_json::json!({ "purpose": "invite" });
    if include_inactive {
        filter["includeArchived"] = serde_json::Value::Bool(true);
        filter["includeDeleted"] = serde_json::Value::Bool(true);
    }
    let listing = admin_vta.cred_vault_query(filter).await?;
    let creds = listing
        .get("credentials")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    Ok(creds.iter().map(VicSummary::from_descriptor).collect())
}

// ****************************************************************************
// Background refresh
// ****************************************************************************

/// The result of one backgrounded VIC-list refresh, carried back to the runtime
/// loop as a [`DispatchOutcome::Vic`](crate::state_handler::background_dispatch::DispatchOutcome::Vic).
///
/// Data only — the job does the vault round-trip and nothing else, so every
/// mutation still happens on the loop thread in [`Self::apply`] (the
/// single-mutator invariant). The error is pre-formatted here because the job
/// cannot hand an `anyhow::Error` across the channel and the loop has no way to
/// re-derive the cause once the client is out of scope.
pub(crate) struct VicRefreshOutcome {
    /// The listing, or the failure text (`{e:#}`, so an anyhow cause chain
    /// survives — R6.4: "vault unreachable" must not read like "no VICs").
    result: Result<Vec<VicSummary>, String>,
    /// Whether the query asked for archived/deleted entries too. Recorded so the
    /// applied list can be discarded when the operator has flipped `i` since the
    /// job was spawned, rather than briefly showing the wrong set.
    include_inactive: bool,
}

impl VicRefreshOutcome {
    /// Run the vault query. The whole body of the spawned job — no state, no
    /// config, no mutation.
    pub(crate) async fn run(admin_vta: VtaClient, include_inactive: bool) -> Self {
        Self {
            result: list_vics(&admin_vta, include_inactive)
                .await
                .map_err(|e| format!("{e:#}")),
            include_inactive,
        }
    }

    /// Apply the listing on the loop thread: swap the list in, clamp the
    /// selection, and re-annotate issuers with their verified agent names.
    ///
    /// A result whose `include_inactive` no longer matches the panel is dropped:
    /// the operator pressed `i` while it was in flight, so a fresh job for the
    /// new filter is already queued behind this one and applying the stale set
    /// would flash the wrong rows.
    pub(crate) fn apply(self, state: &mut State, config: &Config) {
        state.main_page.content_panel.vta.vic_loading = false;
        if self.include_inactive != state.main_page.content_panel.vta.vic_show_inactive {
            return;
        }
        match self.result {
            Ok(list) => {
                let vta = &mut state.main_page.content_panel.vta;
                vta.vic_selected_index = vta.vic_selected_index.min(list.len().saturating_sub(1));
                vta.vics = list.into();
                state.main_page.sync_vic_agent_names(config);
            }
            Err(e) => state
                .main_page
                .log_error("Listing invitation credentials failed", e.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::VicLifecycle;

    fn summary(id: &str) -> VicSummary {
        VicSummary {
            id: id.to_string(),
            issuer: "did:webvh:example.com:vtc".to_string(),
            issuer_agent_name: None,
            status: "valid".to_string(),
            lifecycle: VicLifecycle::Active,
            valid_until: String::new(),
        }
    }

    /// The happy path: the listing replaces the panel's list and clears the
    /// loading flag, so the "reading the vault…" affordance can't outlive the
    /// query that set it.
    #[test]
    fn apply_swaps_in_the_listing_and_clears_loading() {
        let mut state = State::default();
        let config = test_config();
        state.main_page.content_panel.vta.vic_loading = true;

        VicRefreshOutcome {
            result: Ok(vec![summary("urn:vic:1"), summary("urn:vic:2")]),
            include_inactive: false,
        }
        .apply(&mut state, &config);

        let vta = &state.main_page.content_panel.vta;
        assert_eq!(vta.vics.len(), 2);
        assert!(
            !vta.vic_loading,
            "the loading flag must not outlive the job"
        );
    }

    /// A selection pointing past the end of the new listing is clamped, so the
    /// lifecycle verbs (which index into it) can't act on a row that is gone.
    #[test]
    fn apply_clamps_a_selection_past_the_end() {
        let mut state = State::default();
        let config = test_config();
        state.main_page.content_panel.vta.vic_selected_index = 5;

        VicRefreshOutcome {
            result: Ok(vec![summary("urn:vic:1")]),
            include_inactive: false,
        }
        .apply(&mut state, &config);

        assert_eq!(state.main_page.content_panel.vta.vic_selected_index, 0);
    }

    /// A result for a filter the operator has since flipped is discarded rather
    /// than flashed: `i` toggles inactive visibility, and a listing in flight
    /// when it was pressed answers the *old* question. The refresh queued behind
    /// it carries the right one.
    #[test]
    fn apply_drops_a_listing_for_a_superseded_filter() {
        let mut state = State::default();
        let config = test_config();
        state.main_page.content_panel.vta.vics = vec![summary("urn:vic:keep")].into();
        // The panel now wants inactive entries; this job asked without them.
        state.main_page.content_panel.vta.vic_show_inactive = true;
        state.main_page.content_panel.vta.vic_loading = true;

        VicRefreshOutcome {
            result: Ok(vec![summary("urn:vic:stale-1"), summary("urn:vic:stale-2")]),
            include_inactive: false,
        }
        .apply(&mut state, &config);

        let vta = &state.main_page.content_panel.vta;
        assert_eq!(vta.vics.len(), 1, "the superseded listing must not apply");
        assert_eq!(vta.vics[0].id, "urn:vic:keep");
        assert!(!vta.vic_loading);
    }

    /// A failed query leaves the previous list in place and logs the reason —
    /// the panel must not render "no invitation credentials" for a vault it
    /// could not reach (VTI R6.4).
    #[test]
    fn apply_keeps_the_previous_list_on_failure() {
        let mut state = State::default();
        let config = test_config();
        state.main_page.content_panel.vta.vics = vec![summary("urn:vic:1")].into();
        state.main_page.content_panel.vta.vic_loading = true;

        VicRefreshOutcome {
            result: Err("vault unreachable: connection refused".to_string()),
            include_inactive: false,
        }
        .apply(&mut state, &config);

        let vta = &state.main_page.content_panel.vta;
        assert_eq!(vta.vics.len(), 1, "a failed read must not empty the list");
        assert!(!vta.vic_loading);
        assert!(
            state
                .main_page
                .activity_log
                .iter()
                .any(|e| e.summary.contains("connection refused")),
            "the failure reason must reach the log"
        );
    }
}

// ****************************************************************************
// Background mutations
// ****************************************************************************

/// A vault mutation, already resolved to the id (or body) it acts on.
///
/// Import is split at the validation boundary: the paste is parsed and checked
/// on the loop thread, because that is local, instant, and decides whether the
/// operator stays on the input field to fix it. Only the store round-trip is
/// carried here.
pub(crate) enum VicVerb {
    /// Store a validated invitation credential.
    Add(serde_json::Value),
    /// Hide from query/presentation, restorable.
    Archive(String),
    /// Return an archived VIC to active.
    Unarchive(String),
    /// Restore a soft-deleted VIC.
    Restore(String),
    /// Soft-delete.
    Delete(String),
    /// Irreversible purge.
    Purge(String),
}

impl VicVerb {
    /// Past-tense word for the activity-log line, and the noun the error uses.
    fn verb(&self) -> &'static str {
        match self {
            VicVerb::Add(_) => "Stored",
            VicVerb::Archive(_) => "Archived",
            VicVerb::Unarchive(_) => "Unarchived",
            VicVerb::Restore(_) => "Restored",
            VicVerb::Delete(_) => "Deleted",
            VicVerb::Purge(_) => "Purged",
        }
    }
}

/// One backgrounded vault mutation.
pub(crate) struct VicJob {
    pub(crate) admin_vta: VtaClient,
    pub(crate) verb: VicVerb,
}

impl VicJob {
    /// Do the round-trip. I/O only.
    pub(crate) async fn run(self) -> VicMutationOutcome {
        let verb = self.verb.verb();
        let is_add = matches!(self.verb, VicVerb::Add(_));
        // An invitation is stored only once its proof verifies against the
        // issuing community's DID document: the vault is where the join flow
        // later picks invitations from, and it must not hold forgeries.
        if let VicVerb::Add(vic) = &self.verb
            && let Err(e) = verify_before_storing(vic).await
        {
            return VicMutationOutcome {
                verb,
                is_add,
                error: Some(e),
            };
        }
        let result = match self.verb {
            VicVerb::Add(vic) => self
                .admin_vta
                .cred_vault_receive(vic, None)
                .await
                .map(|_| ()),
            VicVerb::Archive(id) => self
                .admin_vta
                .cred_vault_archive(&id, Some(REASON))
                .await
                .map(|_| ()),
            VicVerb::Unarchive(id) => self
                .admin_vta
                .cred_vault_unarchive(&id, Some(REASON))
                .await
                .map(|_| ()),
            VicVerb::Restore(id) => self
                .admin_vta
                .cred_vault_restore(&id, Some(REASON))
                .await
                .map(|_| ()),
            VicVerb::Delete(id) => self
                .admin_vta
                .cred_vault_delete(&id, /* force */ false, Some(REASON))
                .await
                .map(|_| ()),
            VicVerb::Purge(id) => self
                .admin_vta
                .cred_vault_purge(&id, Some(REASON))
                .await
                .map(|_| ()),
        };
        VicMutationOutcome {
            verb,
            is_add,
            error: result.err().map(|e| format!("{e}")),
        }
    }
}

/// Verify a pasted invitation before it is stored.
async fn verify_before_storing(vic: &serde_json::Value) -> Result<(), String> {
    let resolver = affinidi_tdk::did_resolver::DIDCacheClient::new(
        affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    .map_err(|e| format!("could not start a DID resolver to check the invitation: {e}"))?;
    openvtc_core::join::verify_invitation_credential(vic, &resolver, chrono::Utc::now()).await
}

/// What a vault mutation did. Data only; applied on the loop thread.
pub(crate) struct VicMutationOutcome {
    verb: &'static str,
    /// The import overlay only exists for `Add`, and only it has phases to move.
    is_add: bool,
    error: Option<String>,
}

impl VicMutationOutcome {
    /// Apply on the loop thread, and ask for the listing to be re-read.
    ///
    /// The re-read is requested rather than started: mutations and refreshes
    /// share the `Vic` domain, so the refresh cannot begin until this outcome
    /// has freed it. Setting the queued flag hands that to the dispatch arm,
    /// which re-issues it the moment the domain is free — the same path a
    /// refresh rejected by the busy-guard already takes.
    pub(crate) fn apply(self, state: &mut State) {
        use crate::state_handler::main_page::content::AddVicPhase;

        state.main_page.content_panel.vta.vic_refresh_queued = true;

        match self.error {
            None => {
                if self.is_add
                    && let Some(o) = state.main_page.add_vic.as_mut()
                {
                    o.phase = AddVicPhase::Done;
                    o.messages.push("Invitation credential stored.".to_string());
                }
                state
                    .main_page
                    .log(format!("{} invitation credential.", self.verb));
            }
            Some(e) => {
                if self.is_add
                    && let Some(o) = state.main_page.add_vic.as_mut()
                {
                    // A storage failure is terminal for this attempt; a bad
                    // paste never reaches here, because it is rejected on the
                    // loop before the job is spawned.
                    o.phase = AddVicPhase::Failed;
                    o.messages.push(format!("Failed: {e}"));
                }
                state.main_page.log_error(
                    format!("VIC {} failed", self.verb.to_lowercase()),
                    e.as_str(),
                );
            }
        }
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::*;
    use crate::state_handler::main_page::content::AddVicPhase;

    fn outcome(verb: &'static str, is_add: bool, error: Option<&str>) -> VicMutationOutcome {
        VicMutationOutcome {
            verb,
            is_add,
            error: error.map(ToString::to_string),
        }
    }

    /// Every mutation asks for the listing to be re-read, because the vault is
    /// authoritative and the panel has just been invalidated. It *asks* rather
    /// than starting one: mutation and refresh share a domain, so the refresh
    /// cannot begin until this outcome frees it.
    #[test]
    fn a_mutation_requests_a_refresh() {
        let mut state = State::default();
        outcome("Archived", false, None).apply(&mut state);
        assert!(state.main_page.content_panel.vta.vic_refresh_queued);
    }

    /// A failed mutation still asks: the vault's state is now unknown, which is
    /// exactly when a stale list is most misleading.
    #[test]
    fn a_failed_mutation_still_requests_a_refresh() {
        let mut state = State::default();
        outcome("Purged", false, Some("vault refused")).apply(&mut state);
        assert!(state.main_page.content_panel.vta.vic_refresh_queued);
        assert!(
            state
                .main_page
                .activity_log
                .iter()
                .any(|e| e.summary.contains("vault refused")),
            "the reason must reach the log"
        );
    }

    /// A successful import completes the overlay; a failed store is terminal
    /// for that attempt. A *bad paste* never reaches here — it is rejected on
    /// the loop before a job is spawned, so the operator keeps the input field.
    #[test]
    fn an_import_moves_the_overlay_to_a_terminal_phase() {
        use crate::state_handler::main_page::content::AddVicState;
        for (error, want) in [(None, AddVicPhase::Done), (Some("no"), AddVicPhase::Failed)] {
            let mut state = State::default();
            state.main_page.add_vic = Some(AddVicState {
                phase: AddVicPhase::Working,
                ..Default::default()
            });
            outcome("Stored", true, error).apply(&mut state);
            assert_eq!(state.main_page.add_vic.as_ref().unwrap().phase, want);
        }
    }

    /// A lifecycle verb has no overlay to move, and must not invent one.
    #[test]
    fn a_lifecycle_verb_leaves_the_import_overlay_alone() {
        let mut state = State::default();
        outcome("Deleted", false, None).apply(&mut state);
        assert!(state.main_page.add_vic.is_none());
    }
}
