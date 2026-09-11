//! Background-dispatch pattern for network-bound runtime actions (R13).
//!
//! # The problem
//!
//! The runtime `tokio::select!` loop in [`super`] services exactly one arm at a
//! time. Several action dispatches `.await` network I/O *inline* in their arm,
//! so the whole loop is parked for the duration. The worst case is a mediator
//! change / reconnect, which calls
//! [`super::didcomm::reconnect_persona_listener_io`] and waits up to **30
//! seconds** for the listener to connect (`wait_connected(.., 30s)`). While that
//! future is
//! pending, no other select arm runs: queued keystrokes pile up, inbound DIDComm
//! events in the bounded channel get dropped, and even `q` / Exit is dead.
//!
//! # The pattern
//!
//! Startup already solves this (`super::StateHandler::main_loop`'s
//! `MainPageDeferred` arm): the slow load runs as a spawned task that streams
//! progress/completion back into a responsive select loop over a channel. This
//! module generalises that for *runtime* actions:
//!
//! * The background task does **I/O only** and returns a [`DispatchOutcome`]
//!   over an mpsc the loop owns.
//! * **All mutation stays on the loop thread**: a dedicated select arm applies
//!   the outcome (config changes, save/sync helpers, status), so the
//!   single-mutator / unidirectional-data-flow invariant is preserved.
//! * A per-domain [`InFlight`] busy-guard rejects a second action on a busy
//!   domain with a visible status message instead of running it concurrently or
//!   queueing it blind — matching today's effectively-serialised behaviour.
//!
//! R13 migrates the mediator change/reconnect path as the single proving case;
//! R14 migrates the remaining network dispatches onto the same mechanism.

use openvtc_core::config::Config;

use crate::state_handler::didcomm::ReconnectOutcome;
use crate::state_handler::inbox_actions::InboxOutcome;
use crate::state_handler::relationship_actions::{DidDeleteOutcome, RelationshipOutcome};
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::{self, State};

/// A domain that can have at most one background dispatch in flight at a time.
///
/// The set is intentionally small and matches the "one mutating task" model the
/// loop already had: serialising per domain means a user can't, e.g., fire two
/// mediator reconnects at once, while still leaving distinct domains independent
/// (a relationship dispatch and a mediator reconnect don't block each other).
///
/// R14 keeps the granularity conservative: every relationship-panel network
/// action (create / ping / remove) shares one `Relationship` domain, and every
/// inbox network action (accept / reject) shares one `Inbox` domain. Two actions
/// on the *same* domain — even if they target different relationships — are
/// serialised (the second is rejected with a status), matching the loop's
/// pre-R14 "one in-flight mutating await at a time" behaviour. Distinct domains
/// stay independent (a ping and an inbox accept can run concurrently).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum DispatchDomain {
    /// Mediator change / manual reconnect — replaces the persona listener and
    /// waits for it to connect (up to 30 s).
    Mediator,
    /// Relationship-panel network actions: create (VTA round-trip + send), ping
    /// (`send_message_with_retry` ~6 s on a dead peer), remove (`remove_listener`).
    Relationship,
    /// Inbox network actions: accept/reject a relationship request, accept/reject
    /// a VRC request — all do a (retrying) DIDComm send.
    Inbox,
    /// Context-DID deletion: `delete_did_webvh` at the VTA + listener teardown.
    Did,
    /// Agent-name refresh: a batch DID→name verification sweep. One job resolves
    /// many DIDs (the busy-guard is per-domain, so per-DID jobs would serialise),
    /// each a network round-trip; read-only, off the loop.
    AgentName,
    /// VTA transport probe: resolve the VTA's DID document to learn which
    /// transports it advertises. Read-only, one resolve, off the loop.
    VtaTransports,
    /// Agent-name management: the overlay's open / claim / park / resume /
    /// remove verbs. Each is a Trust Task with a 60 s timeout, and a mutation
    /// is two of them (the change, then the authoritative re-read) — so this
    /// domain is the longest-running of the lot, and the one whose inline
    /// await could park the loop for two minutes.
    ///
    /// Separate from [`Self::AgentName`], which is the periodic *display-name*
    /// sweep: sharing a domain would let a background refresh delay an operator
    /// who is claiming a name, and the two touch different state.
    AgentNameManage,
    /// Minting a standalone persona: several VTA trust tasks (find a hosting
    /// server, mint the DID, create three keys), reported step by step.
    Persona,
    /// Requesting a verifiable relationship credential from a peer.
    Credential,
    /// A send addressed to a community: leaving it, or issuing it the
    /// reciprocal membership credential. Serialised together because both
    /// address the same peer and both are user-initiated one at a time.
    Community,
    /// Capability query / toggle: one governance document sent to a community.
    /// The community's *answer* is not part of this — it arrives later on the
    /// inbound channel and is matched by thread id — so what this domain
    /// serialises is the sending, which retries against an unreachable peer.
    Capabilities,
    /// What each persona presents, for the communities panel.
    PersonaBinding,
    /// The identity pane's own reads and writes — the attribute pool, the
    /// profiles over it, and the bindings it sets. One domain for both
    /// directions, so a listing cannot overtake the write that invalidated it.
    PersonaManage,
    /// Invitation-credential (VIC) list refresh: one credential-vault query
    /// against the always-on admin VTA session (30 s timeout in the SDK).
    /// Read-only. Backgrounded because it is bound to *navigation* — Tab into
    /// the VIC list, `i` to flip the filter — and an inline await made the
    /// focus change itself wait on the round-trip, which read as a frozen key.
    Vic,
    /// A vetting send: a request, session, card, statement, decline,
    /// withdrawal or requirements fetch. One at a time, like every peer send.
    Vetting,
    /// Registering the contexts memberships already name at the VTA — the ids
    /// joins recorded before OpenVTC created them. Read-then-create, off the loop.
    CommunityContexts,
    /// A holder's action on one membership's context: previewing or deleting
    /// it, and reading, granting or revoking device access in it. Serialised
    /// together so a listing can never overtake the grant or revoke that
    /// changed it, and two deletions never run at once.
    CommunityAccess,
    /// Reading every membership context's device grants once a run, so the
    /// communities panel's detail can show them without being asked.
    DeviceGrantSweep,
    /// Checking whether a community revoked a vetter's grant: one HTTPS fetch of
    /// its status list. Never claimed with `try_begin` — each check is started
    /// by an inbound acceptance, not a person, is independent of the others,
    /// and must not hold up a vetting send the person is making.
    VettingStatus,
}

impl DispatchDomain {
    /// Human-readable label for the "already in progress" status message.
    fn label(self) -> &'static str {
        match self {
            DispatchDomain::Mediator => "Mediator reconnect",
            DispatchDomain::Relationship => "Relationship action",
            DispatchDomain::Inbox => "Inbox action",
            DispatchDomain::Did => "Identity deletion",
            DispatchDomain::AgentName => "Agent name refresh",
            DispatchDomain::VtaTransports => "VTA transport probe",
            DispatchDomain::AgentNameManage => "Agent name change",
            DispatchDomain::Persona => "Persona creation",
            DispatchDomain::Credential => "Credential request",
            DispatchDomain::Community => "Community request",
            DispatchDomain::Capabilities => "Capability request",
            DispatchDomain::PersonaBinding => "Persona binding refresh",
            DispatchDomain::PersonaManage => "Identity request",
            DispatchDomain::Vic => "Invitation credential refresh",
            DispatchDomain::Vetting => "Vetting send",
            DispatchDomain::CommunityContexts => "Community context registration",
            DispatchDomain::CommunityAccess => "Community context request",
            DispatchDomain::DeviceGrantSweep => "Device access refresh",
            DispatchDomain::VettingStatus => "Vetter grant check",
        }
    }
}

/// Per-domain in-flight guard: at most one background dispatch per
/// [`DispatchDomain`].
///
/// `try_begin` is the gate at every backgrounded call site — it returns `false`
/// (and the caller surfaces a status) when that domain is already busy. The loop
/// clears the flag in [`apply_outcome`] when the matching outcome arrives, so the
/// flag's lifetime brackets exactly the spawned task.
#[derive(Default)]
pub(crate) struct InFlight {
    domains: std::collections::HashSet<DispatchDomain>,
}

impl InFlight {
    /// Attempt to claim `domain`. Returns `true` if it was free (now marked
    /// busy); `false` if a dispatch is already in flight for it.
    pub(crate) fn try_begin(&mut self, domain: DispatchDomain) -> bool {
        self.domains.insert(domain)
    }

    /// Release `domain` once its outcome has been applied.
    pub(crate) fn finish(&mut self, domain: DispatchDomain) {
        self.domains.remove(&domain);
    }

    /// Whether `domain` currently has a dispatch in flight — for tests, and for
    /// a background job that should wait for another domain to finish first.
    pub(crate) fn is_busy(&self, domain: DispatchDomain) -> bool {
        self.domains.contains(&domain)
    }

    /// Status message for a rejected start, e.g. when the user fires a second
    /// mediator reconnect while one is still connecting.
    pub(crate) fn busy_message(domain: DispatchDomain) -> String {
        format!("{} already in progress — please wait.", domain.label())
    }
}

/// The result of a backgrounded network dispatch, delivered into the runtime
/// select loop over an mpsc the loop owns. Each variant carries the I/O result
/// (data/errors only — never a `&mut State`); the loop applies it via
/// [`apply_outcome`], keeping all mutation on the loop thread.
///
/// R14 extends this enum (and [`apply_outcome`]) as it migrates the relationship
/// / inbox / settings / delete-DID dispatches onto the same channel.
pub(crate) enum DispatchOutcome {
    /// A mediator change / manual reconnect finished (success or failure). The
    /// payload is exactly the [`ReconnectOutcome`] the inline path produced, so
    /// the applied state is identical to the pre-R13 synchronous behaviour.
    MediatorReconnect(ReconnectOutcome),
    /// A relationship-panel network action (create / ping / remove) finished.
    /// The payload owns the send result plus the data the post-send config
    /// mutation needs; [`RelationshipOutcome::apply`] reproduces the old inline
    /// success/error block exactly.
    Relationship(RelationshipOutcome),
    /// An inbox network action (accept/reject relationship, accept/reject VRC)
    /// finished. [`InboxOutcome::apply`] reproduces the old inline block.
    Inbox(InboxOutcome),
    /// A context-DID deletion finished (VTA delete + listener teardown done in
    /// the task; local cleanup + save applied here).
    Did(DidDeleteOutcome),
    /// A batch agent-name refresh finished. Carries `(did, resolved_name)` for
    /// each DID resolved — `resolved_name` is `None` for a DID with no
    /// verifiable name (a cached negative). Applied on the loop thread.
    AgentName(Vec<(String, Option<String>)>),
    /// A VTA transport probe finished. Carries what the VTA's DID document
    /// advertises, or the reason the probe could not tell. Display-only — it
    /// touches no `Config`, so it never marks the config dirty.
    VtaTransports(crate::state_handler::main_page::content::AdvertisedTransports),
    /// An agent-name verb finished (open / claim / park / resume / remove).
    /// [`AgentNameOutcome::apply`](crate::state_handler::agent_name_actions::AgentNameOutcome::apply)
    /// applies the registry, the overlay status and the persisted display name.
    AgentNameManage(crate::state_handler::agent_name_actions::AgentNameOutcome),
    /// A job reporting a step it has reached, while still running.
    ///
    /// The only outcome that does **not** finish its domain: the job that sent
    /// it is still going, and finishing here would let a second job start
    /// alongside it. It exists because a long job's steps are worth showing —
    /// minting a persona is half a dozen VTA round-trips, and a spinner that
    /// says nothing for that long is indistinguishable from a hang.
    Progress(ProgressUpdate),
    /// A standalone persona mint finished. On success the persist is still
    /// owed — see [`AfterApply::PersistPersona`].
    ///
    /// Boxed because a `MintedPersona` carries a whole `SetupState` (~2 KB),
    /// and every other outcome is two orders of magnitude smaller: unboxed, the
    /// enum would cost that on every dispatch of every domain.
    Persona(Box<crate::state_handler::create_persona::MintOutcome>),
    /// A VRC request was sent to a peer (or failed to send).
    Credential(crate::state_handler::credential_actions::VrcRequestOutcome),
    /// A community send finished (leave / issue membership credential).
    Community(crate::state_handler::community_actions::CommunityOutcome),
    /// A capability query or toggle was sent (or failed to send).
    Capabilities(crate::state_handler::capability_actions::CapabilityOutcome),
    PersonaBinding(
        std::collections::HashMap<
            crate::state_handler::persona_binding_refresh::BindingTarget,
            openvtc_core::persona::binding::BindingSummary,
        >,
    ),
    /// A VIC vault mutation finished (import / archive / unarchive / restore /
    /// delete / purge). Shares the `Vic` domain with the listing, so the
    /// re-read it asks for cannot start until this outcome frees it.
    VicMutation(crate::state_handler::vic::VicMutationOutcome),
    /// An identity-pane read or write finished.
    PersonaManage(crate::state_handler::persona_actions::PersonaOutcome),
    /// A VIC list refresh finished. [`VicRefreshOutcome::apply`](crate::state_handler::vic::VicRefreshOutcome::apply)
    /// swaps in the
    /// listing (or logs why it could not be read); display-only, so it touches
    /// no `Config` and never marks it dirty.
    Vic(crate::state_handler::vic::VicRefreshOutcome),
    /// A spawned dispatch job panicked (or was cancelled) and so never produced a
    /// real outcome. Synthesised by [`spawn_dispatch`] from the `JoinError` so the
    /// domain's busy-flag is still cleared (a panicking job that sent nothing would
    /// otherwise leave its domain busy forever) and a generic failure status is
    /// surfaced. Carries the domain to release + label.
    Panicked(DispatchDomain),
    /// A vetting send finished (or failed, and was undone).
    Vetting(crate::state_handler::vetting_actions::VettingOutcome),
    /// A vetter grant's revocation check finished. Its own domain, so it never
    /// releases the `Vetting` domain a person's send holds.
    VettingStatus(crate::state_handler::vetting_actions::GrantChecked),
    /// Membership contexts were checked at the VTA: each context id, and
    /// whether it had to be created or why it could not be.
    CommunityContexts(Vec<(String, Result<bool, String>)>),
    /// A holder's action on a membership's context finished — a deletion
    /// preview or delete, or a device-access read, grant or revoke.
    CommunityContext(crate::state_handler::community_context_actions::ContextOutcome),
    /// Every membership context's device grants were read: each context id and
    /// its grants, or why they could not be read.
    DeviceGrantSweep(
        Vec<(
            String,
            Result<Vec<openvtc_core::community_access::DeviceGrant>, String>,
        )>,
    ),
}

impl DispatchOutcome {
    /// The domain whose busy-flag this outcome releases. `pub(crate)` because
    /// the degraded (State-A) loop has to free the flag directly on the one path
    /// where it cannot apply an outcome — see its dispatch arm.
    pub(crate) fn domain(&self) -> DispatchDomain {
        match self {
            DispatchOutcome::MediatorReconnect(_) => DispatchDomain::Mediator,
            DispatchOutcome::Relationship(_) => DispatchDomain::Relationship,
            DispatchOutcome::Inbox(_) => DispatchDomain::Inbox,
            DispatchOutcome::Did(_) => DispatchDomain::Did,
            DispatchOutcome::AgentName(_) => DispatchDomain::AgentName,
            DispatchOutcome::VtaTransports(_) => DispatchDomain::VtaTransports,
            DispatchOutcome::AgentNameManage(_) => DispatchDomain::AgentNameManage,
            DispatchOutcome::Progress(update) => update.domain(),
            DispatchOutcome::Persona(_) => DispatchDomain::Persona,
            DispatchOutcome::Credential(_) => DispatchDomain::Credential,
            DispatchOutcome::Community(_) => DispatchDomain::Community,
            DispatchOutcome::Capabilities(_) => DispatchDomain::Capabilities,
            DispatchOutcome::PersonaBinding(_) => DispatchDomain::PersonaBinding,
            DispatchOutcome::PersonaManage(_) => DispatchDomain::PersonaManage,
            DispatchOutcome::Vic(_) => DispatchDomain::Vic,
            DispatchOutcome::VicMutation(_) => DispatchDomain::Vic,
            DispatchOutcome::Vetting(_) => DispatchDomain::Vetting,
            DispatchOutcome::VettingStatus(_) => DispatchDomain::VettingStatus,
            DispatchOutcome::CommunityContexts(_) => DispatchDomain::CommunityContexts,
            DispatchOutcome::CommunityContext(_) => DispatchDomain::CommunityAccess,
            DispatchOutcome::DeviceGrantSweep(_) => DispatchDomain::DeviceGrantSweep,
            DispatchOutcome::Panicked(domain) => *domain,
        }
    }
}

/// A step a running job has reached. Typed per consumer rather than a bare
/// string, so the applier knows where the text belongs without a domain lookup
/// and a new consumer cannot silently borrow another's display surface.
pub(crate) enum ProgressUpdate {
    /// A step of a standalone persona mint, for the create-persona overlay.
    PersonaMint(String),
}

impl ProgressUpdate {
    /// The domain whose job is reporting. Not finished — see
    /// [`DispatchOutcome::Progress`].
    fn domain(&self) -> DispatchDomain {
        match self {
            ProgressUpdate::PersonaMint(_) => DispatchDomain::Persona,
        }
    }
}

/// Spawn a background dispatch job whose future resolves to a [`DispatchOutcome`],
/// delivering the result over `tx`. **Resilience guarantee:** if the job panics or
/// is cancelled it produces no outcome, which would leave `domain`'s busy-flag set
/// forever (every subsequent action on that domain rejected as "in progress").
/// This wrapper joins the inner task and, on a `JoinError`, synthesises a
/// [`DispatchOutcome::Panicked`] so `apply_outcome` always clears the flag.
pub(crate) fn spawn_dispatch<F>(
    tx: tokio::sync::mpsc::UnboundedSender<DispatchOutcome>,
    domain: DispatchDomain,
    fut: F,
) where
    F: std::future::Future<Output = DispatchOutcome> + Send + 'static,
{
    tokio::spawn(async move {
        let outcome = match tokio::spawn(fut).await {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!(domain = ?domain, error = %e, "dispatch job panicked/cancelled");
                DispatchOutcome::Panicked(domain)
            }
        };
        let _ = tx.send(outcome);
    });
}

/// Apply a completed [`DispatchOutcome`] to `state` and clear the domain's
/// busy-flag. **Pure** over `(&mut State, &mut InFlight, outcome)` — no I/O — so
/// it is unit-testable and is the single place the loop's outcome arm mutates
/// from.
///
/// The mediator-reconnect arm reproduces, byte for byte, the status/log strings
/// the old inline `run_persona_reconnect` set on completion: the only observable
/// difference from before R13 is *when* it runs (after a responsive wait rather
/// than blocking the loop), not *what* it does.
///
/// R14 widens the signature to also take `&mut Config` + `profile`: unlike the
/// mediator reconnect (which mutates `State` only), the migrated relationship /
/// inbox / delete-DID paths persist config changes (the relationship record, the
/// task removal, the issued VRC) that today happen *after* the network send.
/// Doing them here — on the loop thread, only on success — preserves the
/// pre-R14 ordering and durability.
///
/// A send failure records an error status and creates no *task/record that the
/// old inline `Ok` branch would have created* — matching the pre-R14
/// `match … { Ok => persist, Err => status }`. It is not a literal no-op on
/// `Config`, and was never meant to be: it mirrors the in-memory state the old
/// inline path had reached *before* the send. Specifically, the relationship
/// Create path records the minted R-DID `key_info` on both success and failure
/// (key creation happened before the send pre-R14; only the success save
/// persists it), and removes the provisional `RequestSent` record it pre-inserted
/// (see [`RelationshipOutcome::apply`]) so a failed send leaves no relationship
/// record — exactly the pre-R14 net state.
/// Work an outcome needs that [`apply_outcome`] itself cannot do, handed back
/// to whichever loop called it.
///
/// This exists because `apply_outcome` is shared by the runtime loop and the
/// degraded loop, and they hold different things. Rather than widen the
/// signature with parameters one caller cannot supply — a session manager the
/// degraded loop has no equivalent of, or an `async` persist the pure applier
/// has no business awaiting — the outcome says what is still owed and the loop
/// that can do it, does it.
pub(crate) enum AfterApply {
    /// Everything was applied here.
    Nothing,
    /// A community was left; its messaging session is still registered. Only
    /// the runtime loop owns a session manager, so only it can honour this.
    Deregister(String, openvtc_core::config::account::PersonaId),
    /// A persona was minted at the VTA and must now be written into the config.
    /// The persist is `async` and mutates `Config`, so it runs in the loop.
    PersistPersona(Box<crate::state_handler::create_persona::MintedPersona>),
}

pub(crate) fn apply_outcome(
    state: &mut State,
    config: &mut Config,
    save: &mut SaveScheduler,
    in_flight: &mut InFlight,
    outcome: DispatchOutcome,
) -> AfterApply {
    let domain = outcome.domain();

    // Progress is the one outcome that leaves its domain busy: the job is still
    // running. Handled before the match so the `finish` at the end cannot be
    // reached for it.
    if let DispatchOutcome::Progress(update) = outcome {
        match update {
            ProgressUpdate::PersonaMint(step) => {
                if let Some(o) = state.main_page.create_persona.as_mut() {
                    o.messages.push(step);
                }
            }
        }
        return AfterApply::Nothing;
    }

    match outcome {
        DispatchOutcome::MediatorReconnect(result) => match result {
            ReconnectOutcome::Connected => {
                state.connection.status = state::MediatorStatus::Connected;
                state.connection.messaging_active = true;
                state.main_page.log("Reconnected to mediator");
            }
            ReconnectOutcome::Failed(reason) => {
                state.connection.status = state::MediatorStatus::Failed(reason.clone());
                state.main_page.log(format!("Reconnect failed: {reason}"));
            }
        },
        DispatchOutcome::Relationship(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::Vetting(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::VettingStatus(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::Inbox(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::Did(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::AgentName(results) => {
            // Fold each verified (or negatively-verified) lookup into the
            // persisted cache on the loop thread — the single mutator.
            //
            // Two independent "did anything change?" tests, to avoid needless
            // work: persist when a mapping is genuinely new or its name changed
            // (a checked-at-only bump is not worth a save), and rebuild the UI
            // only when a *displayed* name changed. A DID going from uncached to
            // "no name" is worth persisting (so we don't re-resolve it every
            // launch) but changes nothing on screen.
            let now = chrono::Utc::now();
            let mut cache_changed = false;
            let mut display_changed = false;
            for (did, name) in results {
                let had_entry = config.private.agent_names.contains_key(&did);
                let prior_name = config.agent_name_for(&did).map(str::to_owned);
                if prior_name != name {
                    display_changed = true;
                }
                if !had_entry || prior_name != name {
                    cache_changed = true;
                }
                config.set_cached_agent_name(&did, name, now);
            }
            if cache_changed {
                save.mark_dirty();
            }
            if display_changed {
                state.main_page.sync_from_config(config);
            }
        }
        DispatchOutcome::VtaTransports(advertised) => {
            // Display-only: assign straight onto the panel state. Deliberately
            // NOT written through `sync_from_config`, which rebuilds the panel
            // from `Config` and would drop a field the config does not hold.
            state.main_page.content_panel.vta.transports.advertised = Some(advertised);
        }
        DispatchOutcome::AgentNameManage(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::Community(outcome) => {
            let pending = outcome.apply(state, config, save);
            in_flight.finish(domain);
            return match pending {
                Some((vtc, persona)) => AfterApply::Deregister(vtc, persona),
                None => AfterApply::Nothing,
            };
        }
        DispatchOutcome::Persona(outcome) => {
            let pending = outcome.apply(state);
            in_flight.finish(domain);
            return match pending {
                Some(minted) => AfterApply::PersistPersona(Box::new(minted)),
                None => AfterApply::Nothing,
            };
        }
        DispatchOutcome::Credential(outcome) => outcome.apply(state, config, save),
        DispatchOutcome::Capabilities(outcome) => outcome.apply(state),
        // Merged, not replaced. A sweep only carries the targets it was given,
        // and replacing the map would blank every row the sweep did not cover
        // — which reads on screen as those personas having stopped presenting
        // anything.
        DispatchOutcome::PersonaBinding(results) => {
            state
                .main_page
                .content_panel
                .identity
                .bindings
                .extend(results);
        }
        DispatchOutcome::PersonaManage(outcome) => outcome.apply(state),
        // Log-only: nothing on screen depends on a context existing, and a
        // failure is retried on the next launch.
        DispatchOutcome::CommunityContexts(results) => {
            for (context_id, result) in results {
                match result {
                    Ok(true) => state.main_page.log(format!(
                        "Registered community context {context_id} at the VTA."
                    )),
                    Ok(false) => {}
                    Err(e) => state.main_page.log(format!(
                        "Could not register community context {context_id}: {e}"
                    )),
                }
            }
        }
        DispatchOutcome::CommunityContext(outcome) => {
            // A context deleted with its persona removes the finished
            // membership's record too; any session it still holds belongs to
            // the runtime loop's session manager.
            let pending = outcome.membership_removed();
            outcome.apply(state, config, save);
            in_flight.finish(domain);
            return match pending {
                Some((vtc, persona)) => AfterApply::Deregister(vtc, persona),
                None => AfterApply::Nothing,
            };
        }
        DispatchOutcome::DeviceGrantSweep(results) => {
            crate::state_handler::community_context_actions::apply_sweep(state, results);
        }
        DispatchOutcome::Vic(outcome) => outcome.apply(state, config),
        DispatchOutcome::VicMutation(outcome) => outcome.apply(state),
        // Handled above, before the domain is finished. Listed because the
        // match must stay exhaustive.
        DispatchOutcome::Progress(_) => unreachable!("progress returns before this match"),
        DispatchOutcome::Panicked(domain) => {
            // The job panicked and produced no real outcome. Surface a generic
            // failure so the user isn't left staring at a stuck "in progress"; the
            // busy-flag is cleared below (via `domain()`), freeing the domain.
            let msg = format!("{} failed (internal error)", domain.label());
            state.main_page.log(msg);
        }
    }
    in_flight.finish(domain);
    AfterApply::Nothing
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    /// The busy-guard serialises per domain: the first claim succeeds, a second
    /// while in flight is rejected, and after `finish` the domain frees up
    /// again. This is the state machine that backs "a second action on a busy
    /// domain is rejected with a status, not queued blind".
    #[test]
    fn busy_guard_serialises_per_domain() {
        let mut in_flight = InFlight::default();

        // First claim succeeds and marks the domain busy.
        assert!(in_flight.try_begin(DispatchDomain::Mediator));
        assert!(in_flight.is_busy(DispatchDomain::Mediator));

        // A second claim while in flight is rejected (would be surfaced as a
        // status via `busy_message`).
        assert!(!in_flight.try_begin(DispatchDomain::Mediator));

        // Releasing frees the domain for the next dispatch.
        in_flight.finish(DispatchDomain::Mediator);
        assert!(!in_flight.is_busy(DispatchDomain::Mediator));
        assert!(in_flight.try_begin(DispatchDomain::Mediator));
    }

    /// The R14 domains (Relationship / Inbox / Did) each serialise independently:
    /// claiming one does not block another, but a re-claim of the same domain is
    /// rejected until it is `finish`ed. This backs the "one in-flight per domain"
    /// model for the migrated network dispatches.
    #[test]
    fn r14_domains_serialise_independently() {
        let mut in_flight = InFlight::default();
        for domain in [
            DispatchDomain::Relationship,
            DispatchDomain::Inbox,
            DispatchDomain::Did,
        ] {
            // Each domain is independent: claiming it succeeds regardless of the
            // others already being busy.
            assert!(in_flight.try_begin(domain), "{domain:?} should be free");
            // A second claim on the same domain is rejected while in flight.
            assert!(
                !in_flight.try_begin(domain),
                "{domain:?} second claim must be rejected"
            );
        }
        // All three are concurrently in flight without blocking each other.
        assert!(in_flight.is_busy(DispatchDomain::Relationship));
        assert!(in_flight.is_busy(DispatchDomain::Inbox));
        assert!(in_flight.is_busy(DispatchDomain::Did));
        // …and a Mediator dispatch is still independently available.
        assert!(in_flight.try_begin(DispatchDomain::Mediator));

        // Releasing one frees only that domain.
        in_flight.finish(DispatchDomain::Inbox);
        assert!(!in_flight.is_busy(DispatchDomain::Inbox));
        assert!(in_flight.is_busy(DispatchDomain::Relationship));
        assert!(in_flight.try_begin(DispatchDomain::Inbox));
    }

    /// Applying a `Connected` outcome reproduces the old inline success state
    /// (status + messaging flag + log line) and clears the busy-flag.
    #[test]
    fn apply_connected_outcome_sets_connected_and_clears_flag() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::Mediator));

        apply_outcome(
            &mut state,
            &mut config,
            &mut save,
            &mut in_flight,
            DispatchOutcome::MediatorReconnect(ReconnectOutcome::Connected),
        );

        assert!(matches!(
            state.connection.status,
            state::MediatorStatus::Connected
        ));
        assert!(state.connection.messaging_active);
        assert!(
            !in_flight.is_busy(DispatchDomain::Mediator),
            "busy-flag must be cleared once the outcome is applied"
        );
    }

    /// Applying a `Failed` outcome reproduces the old inline failure state
    /// (Failed status carrying the reason) and clears the busy-flag.
    #[test]
    fn apply_failed_outcome_sets_failed_and_clears_flag() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::Mediator));

        apply_outcome(
            &mut state,
            &mut config,
            &mut save,
            &mut in_flight,
            DispatchOutcome::MediatorReconnect(ReconnectOutcome::Failed("dead mediator".into())),
        );

        match &state.connection.status {
            state::MediatorStatus::Failed(reason) => assert_eq!(reason, "dead mediator"),
            other => panic!("expected Failed status, got {other:?}"),
        }
        assert!(!state.connection.messaging_active);
        assert!(!in_flight.is_busy(DispatchDomain::Mediator));
    }

    /// Applying a `Panicked` outcome clears the busy-flag (so the domain isn't
    /// stuck "in progress" forever) and surfaces a generic failure log line. This
    /// backs the Fix-3 resilience guarantee: a spawned job that panics still frees
    /// its domain.
    #[test]
    fn apply_panicked_outcome_clears_flag() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::Relationship));

        apply_outcome(
            &mut state,
            &mut config,
            &mut save,
            &mut in_flight,
            DispatchOutcome::Panicked(DispatchDomain::Relationship),
        );

        assert!(
            !in_flight.is_busy(DispatchDomain::Relationship),
            "a panicked job's domain must be freed, not left busy forever"
        );
    }

    /// `spawn_dispatch` converts a panicking job into a synthetic
    /// [`DispatchOutcome::Panicked`] for the right domain, rather than silently
    /// dropping the outcome (which would leave the domain busy forever).
    #[tokio::test]
    async fn spawn_dispatch_panic_yields_panicked_outcome() {
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::unbounded_channel::<DispatchOutcome>();
        spawn_dispatch(tx, DispatchDomain::Inbox, async {
            panic!("boom");
            #[allow(unreachable_code)]
            DispatchOutcome::Panicked(DispatchDomain::Inbox)
        });
        let outcome = rx.recv().await.expect("an outcome must be delivered");
        assert!(matches!(
            outcome,
            DispatchOutcome::Panicked(DispatchDomain::Inbox)
        ));
    }

    /// The busy message names the domain so the UI tells the user *what* is
    /// already running.
    #[test]
    fn busy_message_names_the_domain() {
        let msg = InFlight::busy_message(DispatchDomain::Mediator);
        assert!(msg.contains("Mediator reconnect"));
        assert!(msg.contains("in progress"));
    }

    /// The whole point of R13: a backgrounded dispatch must NOT block the select
    /// loop. This drives a miniature replica of the runtime loop's structure — an
    /// action channel and a dispatch-outcome channel selected together — and
    /// proves that while a (slow) dispatch is still in flight, an interleaved nav
    /// action (`MainPanelSwitch`) is processed and `Exit` is honoured.
    ///
    /// The "slow dispatch" is modelled by a oneshot we hold open: the outcome is
    /// only delivered after we have already observed the nav action take effect,
    /// so the loop demonstrably did real work mid-flight. (The production loop is
    /// not factored into a test-callable unit — see the coverage note in the
    /// PR — so this asserts the *pattern* with the same channel shapes.)
    #[tokio::test]
    async fn loop_processes_nav_and_exit_while_dispatch_in_flight() {
        use crate::state_handler::actions::Action;
        use crate::state_handler::main_page::MainPanel;
        use tokio::sync::mpsc;

        let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
        let (dispatch_tx, mut dispatch_rx) = mpsc::unbounded_channel::<DispatchOutcome>();
        // The "in flight" dispatch: a task that only completes when we release it.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let mut state = State::default();
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut in_flight = InFlight::default();

        // Begin a dispatch (busy-flag set) and spawn its "I/O" — it parks on the
        // oneshot, modelling the up-to-30 s `wait_connected` against a dead
        // mediator, then reports Connected.
        assert!(in_flight.try_begin(DispatchDomain::Mediator));
        let bg_tx = dispatch_tx.clone();
        tokio::spawn(async move {
            let _ = release_rx.await;
            let _ = bg_tx.send(DispatchOutcome::MediatorReconnect(
                ReconnectOutcome::Connected,
            ));
        });

        // Queue a nav action and then an Exit. Both must be serviced *before* the
        // dispatch completes (which can't happen until we send on `release_tx`).
        action_tx
            .send(Action::MainPanelSwitch(MainPanel::ContentPanel))
            .unwrap();
        action_tx.send(Action::Exit).unwrap();

        let mut nav_seen = false;
        // Run the replica select loop. The dispatch is still in flight the whole
        // time (we never release it inside the loop), proving the loop is live.
        // The loop breaks `true` once Exit is honoured.
        let exited = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => {
                    if crate::state_handler::handle_nav_action(&mut state, &action) {
                        nav_seen = true;
                        // The nav action took effect mid-flight while the
                        // dispatch is unmistakably still pending.
                        assert!(in_flight.is_busy(DispatchDomain::Mediator));
                        assert!(state.main_page.content_panel.selected);
                    } else if matches!(action, Action::Exit) {
                        break true;
                    }
                }
                Some(outcome) = dispatch_rx.recv() => {
                    apply_outcome(&mut state, &mut config, &mut save, &mut in_flight, outcome);
                }
            }
        };

        assert!(
            nav_seen,
            "nav action must be processed while dispatch in flight"
        );
        assert!(exited, "Exit must be honoured while dispatch in flight");
        assert!(
            in_flight.is_busy(DispatchDomain::Mediator),
            "dispatch was never released, so it is still in flight — the loop did \
             real work without waiting on it"
        );

        // Releasing now would deliver the outcome, but the loop already exited;
        // the point is proven. Drop the sender to avoid an unused warning.
        let _ = release_tx;
    }

    /// Applying an agent-name batch outcome writes the verified names into the
    /// config, frees the `AgentName` domain, marks the config dirty on a real
    /// change, and leaves it clean when nothing changed.
    #[test]
    fn apply_agent_name_outcome_updates_cache_and_frees_domain() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut in_flight = InFlight::default();
        assert!(in_flight.try_begin(DispatchDomain::AgentName));

        // A new positive lookup and a new negative lookup.
        apply_outcome(
            &mut state,
            &mut config,
            &mut save,
            &mut in_flight,
            DispatchOutcome::AgentName(vec![
                (
                    "did:webvh:example.com:alice".to_string(),
                    Some("example.com/@alice".to_string()),
                ),
                ("did:webvh:example.com:nameless".to_string(), None),
            ]),
        );

        assert!(
            !in_flight.is_busy(DispatchDomain::AgentName),
            "the batch's domain must be freed after apply"
        );
        assert_eq!(
            config.agent_name_for("did:webvh:example.com:alice"),
            Some("example.com/@alice")
        );
        assert!(
            config
                .agent_name_for("did:webvh:example.com:nameless")
                .is_none()
        );
        assert!(
            save.is_pending(),
            "a new mapping must mark the config dirty"
        );

        // Re-applying the identical results changes nothing: no new dirty mark.
        let mut save2 = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        assert!(in_flight.try_begin(DispatchDomain::AgentName));
        apply_outcome(
            &mut state,
            &mut config,
            &mut save2,
            &mut in_flight,
            DispatchOutcome::AgentName(vec![
                (
                    "did:webvh:example.com:alice".to_string(),
                    Some("example.com/@alice".to_string()),
                ),
                ("did:webvh:example.com:nameless".to_string(), None),
            ]),
        );
        assert!(
            !save2.is_pending(),
            "an unchanged sweep must not re-dirty the config"
        );
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};

    /// Progress is the one outcome that must NOT free its domain: the job that
    /// sent it is still running, and freeing it would let a second mint start
    /// alongside the first.
    #[tokio::test]
    async fn progress_renders_a_step_without_freeing_the_domain() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let mut in_flight = InFlight::default();
        state.main_page.create_persona = Some(CreatePersonaState {
            phase: CreatePersonaPhase::Working,
            ..Default::default()
        });
        assert!(in_flight.try_begin(DispatchDomain::Persona));

        apply_outcome(
            &mut state,
            &mut config,
            &mut save,
            &mut in_flight,
            DispatchOutcome::Progress(ProgressUpdate::PersonaMint("Minting the DID…".into())),
        );

        assert!(
            in_flight.is_busy(DispatchDomain::Persona),
            "the job is still running, so its domain must stay claimed"
        );
        let messages = &state.main_page.create_persona.as_ref().unwrap().messages;
        assert_eq!(
            messages.last().map(String::as_str),
            Some("Minting the DID…")
        );
        assert_eq!(
            state.main_page.create_persona.as_ref().unwrap().phase,
            CreatePersonaPhase::Working,
            "progress never moves the phase — only the final outcome does"
        );
    }

    /// A progress update for an overlay that has since closed is dropped, not
    /// resurrected into one.
    #[tokio::test]
    async fn progress_for_a_closed_overlay_is_dropped() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let mut in_flight = InFlight::default();

        apply_outcome(
            &mut state,
            &mut config,
            &mut save,
            &mut in_flight,
            DispatchOutcome::Progress(ProgressUpdate::PersonaMint("Minting…".into())),
        );

        assert!(state.main_page.create_persona.is_none());
    }
}
