use crate::{
    Interrupted, Terminator,
    state_handler::{
        actions::Action,
        main_page::MainPanel,
        state::{ActivePage, State},
    },
};
use affinidi_tdk::{TDK, common::config::TDKConfig};
use anyhow::Result;
use openvtc_core::config::{Config, UnlockCode, public_config::PublicConfig};
use openvtc_core::display::truncate_did;
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver},
};
use tracing::{debug, error, warn};

/// Tail-truncate a DID for log-message display, fixed at 30 chars.
pub(crate) fn log_did(did: &str) -> std::borrow::Cow<'_, str> {
    truncate_did(did, 30)
}

/// Resolve a DID to a human-readable display name.
///
/// Precedence: **user alias → verified agent name → truncated DID.** The user's
/// own alias wins — it is unspoofable by definition and an explicit labelling
/// choice; a verified agent name (`example.com/@alice`, already round-tripped
/// before caching) comes next; the truncated DID is the last resort. The same
/// order applies when a remote R-DID resolves through to its persona DID.
/// What to call a community on screen.
///
/// Precedence: the user's explicit display name, then the community's verified
/// agent name, then its DID shortened to `max_len`.
///
/// Exists because the middle step kept being missed. Three separate places
/// wrote `display_name.unwrap_or_else(|| vtc_did)` — the header, the membership
/// credential builder and the capabilities view — so a community with a
/// perfectly good agent name still announced itself as `did:webvh:QmXi1…` in
/// each of them, and each had to be found and fixed on its own. One helper, one
/// precedence.
pub(crate) fn community_label(
    config: &openvtc_core::config::Config,
    vtc_did: &str,
    display_name: Option<&str>,
    max_len: usize,
) -> String {
    display_name
        .map(str::to_owned)
        .or_else(|| config.agent_name_for(vtc_did).map(str::to_owned))
        .unwrap_or_else(|| openvtc_core::display::truncate_did(vtc_did, max_len).into_owned())
}

/// Render a listener lifecycle event for the activity log.
///
/// A listener is identified by its DID, so every message here runs the
/// identifier through [`resolve_did_to_display`] — the operator sees
/// `webvh.storm.ws/@magic-depart` rather than 90 characters of `did:webvh:`.
/// The logger task cannot do this itself: it is detached and has no `Config`,
/// which is exactly why these lines showed raw DIDs.
///
/// Only the *display* changes. The listener id remains the DID everywhere it is
/// used as an identity — it is a map key for cycling detection and reconnect
/// matching, and DIDs sharing a trailing path segment across hosts would
/// collide if it were shortened.
/// A lifecycle line for the activity log: what the operator reads, plus the
/// diagnostic detail behind `Enter`.
pub(crate) struct LifecycleLine {
    /// The one-line summary.
    pub summary: String,
    /// Identifying detail, when there is a listener to identify.
    pub detail: Option<String>,
}

/// Render a listener lifecycle event for the activity log.
///
/// The summary names the listener the way the rest of the UI names identities —
/// alias, else verified agent name, else truncated DID — but a name **alone is
/// not an identity**. `resolve_did_to_display` is many-to-one: an alias or an
/// agent name can stand for more than one listener, and a relationship R-DID
/// resolves through to its peer's name. Two different listeners could therefore
/// produce byte-identical lines, and did: a report of one listener "cycling"
/// turned out to be indistinguishable, on screen, from several listeners
/// reconnecting on their own schedules.
///
/// So every line that names a listener also carries the listener id it resolved
/// from — abbreviated in the summary when a name was substituted, in full in the
/// detail. The id is what correlates with the mediator's logs; the name is only
/// what makes the line readable.
pub(crate) fn format_lifecycle_log(
    config: &openvtc_core::config::Config,
    event: &didcomm::LifecycleLog,
) -> LifecycleLine {
    use didcomm::LifecycleLog;

    /// `'name' (did:webvh:Qm…)` — the parenthetical only when a name was
    /// actually substituted, so an unnamed listener is not printed twice.
    fn who(config: &openvtc_core::config::Config, listener_id: &str) -> String {
        let display = resolve_did_to_display(config, listener_id);
        let truncated = log_did(listener_id);
        if display == truncated {
            format!("'{display}'")
        } else {
            format!("'{display}' ({truncated})")
        }
    }

    fn detail_for(config: &openvtc_core::config::Config, listener_id: &str) -> String {
        format!(
            "listener id: {listener_id}\ndisplayed as: {}",
            resolve_did_to_display(config, listener_id)
        )
    }

    match event {
        LifecycleLog::Connected { listener_id } => LifecycleLine {
            summary: format!("Listener {} connected", who(config, listener_id)),
            detail: Some(detail_for(config, listener_id)),
        },
        LifecycleLog::Disconnected { listener_id, error } => {
            // An absent error is not the same as an unexplained drop, and the
            // line used to render both as a bare "disconnected". Saying which
            // one it was is the difference between "the peer closed the socket"
            // and "we lost it and do not know why" (VTI R6.4).
            let reason = match error {
                Some(e) => format!(": {e}"),
                None => " (no transport error reported)".to_string(),
            };
            LifecycleLine {
                // "still" is load-bearing: a drop is held for the reconnect
                // grace before it reaches here, so this line means the listener
                // did not come back on its own, not merely that it dropped.
                summary: format!(
                    "Listener {} is still disconnected{reason}",
                    who(config, listener_id)
                ),
                detail: Some(match error {
                    Some(e) => format!("{}\nerror: {e}", detail_for(config, listener_id)),
                    None => format!(
                        "{}\nerror: none reported — the connection closed without a transport \
                         error, and did not come back within the reconnect grace period",
                        detail_for(config, listener_id)
                    ),
                }),
            }
        }
        LifecycleLog::Reconnected {
            listener_id,
            down_for,
        } => LifecycleLine {
            // One calm line for the pair. Says what was observed and nothing
            // more: the *cause* is not on the wire, so naming one here would be
            // a claim this code cannot back.
            summary: format!(
                "Listener {} reconnected after {:.1}s",
                who(config, listener_id),
                down_for.as_secs_f64()
            ),
            detail: Some(format!(
                "{}\ndown for: {:.1}s\nA drop this brief is the expected reconnect: the \
                 mediator's access token is refreshed before it expires and the socket is \
                 re-established as part of that, roughly every 12 minutes per listener. A drop \
                 that does not come back is reported as a disconnect instead.",
                detail_for(config, listener_id),
                down_for.as_secs_f64()
            )),
        },
        LifecycleLog::CyclingRapidly { listener_id } => LifecycleLine {
            summary: format!(
                "WARNING: Listener {} cycling rapidly — possible duplicate connection",
                who(config, listener_id)
            ),
            detail: Some(format!(
                "{}\nthis listener dropped twice within the cycling window",
                detail_for(config, listener_id)
            )),
        },
        LifecycleLog::Restarting {
            listener_id,
            attempt,
            delay,
        } => LifecycleLine {
            summary: format!(
                "Listener {} restarting (attempt {attempt}, backoff {delay:?})",
                who(config, listener_id)
            ),
            detail: Some(detail_for(config, listener_id)),
        },
        LifecycleLog::Missed { count } => LifecycleLine {
            summary: format!("Missed {count} lifecycle event(s)"),
            detail: None,
        },
    }
}

pub(crate) fn resolve_did_to_display(config: &openvtc_core::config::Config, did: &str) -> String {
    // 1. User alias on the DID directly.
    if let Some(contact) = config.private.contacts.find_contact(did)
        && let Some(alias) = &contact.alias
    {
        return alias.clone();
    }
    // 2. Verified agent name for the DID.
    if let Some(name) = config.agent_name_for(did) {
        return name.to_string();
    }
    // 3. R-DID → persona DID → its alias / agent name / truncation.
    let did_arc = std::sync::Arc::new(did.to_string());
    if let Some(rel) = config.private.relationships.find_by_remote_did(&did_arc) {
        let p_did = rel.remote_p_did.to_string();
        if let Some(contact) = config.private.contacts.find_contact(&p_did)
            && let Some(alias) = &contact.alias
        {
            return alias.clone();
        }
        if let Some(name) = config.agent_name_for(&p_did) {
            return name.to_string();
        }
        return log_did(&p_did).into_owned();
    }
    log_did(did).into_owned()
}

pub mod actions;
mod agent_name_actions;
mod agent_name_manage;
mod agent_name_refresh;
mod background_dispatch;
mod capability_actions;
mod community_actions;
mod community_context_actions;
mod create_persona;
mod credential_actions;
mod persona_actions;
mod persona_binding_refresh;
/// The DIDComm transport module, which now lives in `openvtc-core`.
///
/// Re-exported under its former path so every `didcomm::…` / `super::didcomm::…`
/// call site in `state_handler` keeps resolving. It moved because `openvtc` is a
/// binary-only crate and nothing there can be integration-tested — see
/// [`openvtc_core::didcomm`] for the full rationale (#189). Keeping the shim
/// means the move itself changed no call sites, so a regression in the messaging
/// layer cannot hide inside an import churn diff.
pub use openvtc_core::didcomm;
mod device_presence;
mod dispatch_util;
mod inbox_actions;
pub mod join;
mod join_flow;
mod join_status_poll;
pub mod main_page;
mod message_dispatch;
mod relationship_actions;
mod runtime_actions;
mod save_coalesce;
mod session_manager;
mod settings_actions;
pub mod setup_sequence;
mod setup_token_actions;
mod setup_vta_actions;
mod setup_wizard;
pub mod state;
mod vetting_actions;
mod vic;
mod vta_transports;

pub struct DeferredLoad {
    pub profile: String,
    pub public_config: PublicConfig,
    pub unlock_passphrase: Option<UnlockCode>,
    #[cfg(feature = "openpgp-card")]
    pub user_pin: SecretString,
}

pub enum StartingMode {
    NotSet,
    // Eager main-page boot path, superseded by `MainPageDeferred` (which main.rs
    // now constructs). The match-arm handler is retained for the eager path.
    #[allow(dead_code)]
    MainPage(Box<Config>, TDK),
    MainPageDeferred(DeferredLoad),
    SetupWizard,
}

pub struct StateHandler {
    state_tx: tokio::sync::watch::Sender<State>,
    profile: String,
    starting_mode: StartingMode,
    /// Invitation credential (VIC) supplied at launch via `--invitation`, seeded
    /// into the loop's initial [`State`] so the join flow can present it.
    invitation_credential: Option<serde_json::Value>,
}

pub(crate) enum SetupWizardExit {
    Interrupted(Interrupted),
    Config(Box<Config>),
}

/// Multi-line detail for the degraded-load activity-log entry, so the report
/// survives past the startup screen the user acknowledged it on.
fn integrity_detail(integrity: &openvtc_core::config::integrity::LoadIntegrity) -> String {
    let mut out = String::new();
    for persona in &integrity.degraded_personas {
        out.push_str(&format!(
            "persona {}: {}\n",
            persona.did,
            persona.reason.summary()
        ));
    }
    for membership in &integrity.stranded_memberships {
        out.push_str(&format!(
            "community {} is inactive: its persona did not load\n",
            membership
                .label
                .clone()
                .unwrap_or_else(|| membership.vtc_did.clone())
        ));
    }
    for key_id in &integrity.orphaned_key_ids {
        out.push_str(&format!("orphaned key record: {key_id}\n"));
    }
    out
}

/// Build a startup [`Diagnosis`](openvtc_core::diagnostics::Diagnosis) for an
/// error that arrived as an `anyhow::Error`.
///
/// The load task keeps the typed `OpenVTCError` inside the `anyhow` wrapper, so
/// the classification that drives the whole failure screen is available here.
/// Anything that is genuinely not an `OpenVTCError` (a TDK init failure, a join
/// panic) still gets the generic diagnosis rather than no help at all.
fn diagnose_startup(err: &anyhow::Error, profile: &str) -> openvtc_core::diagnostics::Diagnosis {
    use openvtc_core::{
        diagnostics::{DiagnosisContext, diagnose},
        errors::OpenVTCError,
    };
    let ctx = DiagnosisContext::new(profile);
    let mut diagnosis = match err.downcast_ref::<OpenVTCError>() {
        Some(typed) => diagnose(typed, &ctx),
        None => {
            let mut d = diagnose(&OpenVTCError::Config(err.to_string()), &ctx);
            d.error = format!("{err:#}");
            d
        }
    };

    // The report goes to the log and to a file as well as to the screen: the
    // screen version scrolls away with the terminal, and a support request is
    // far more useful with the whole thing attached than with a photograph of
    // the top of it.
    error!("startup failed\n{}", diagnosis.render_plain());
    if let Some(path) = diagnosis.write_report(profile) {
        diagnosis
            .context
            .push(("Full report".to_string(), path.display().to_string()));
    }
    diagnosis
}

impl StateHandler {
    pub fn new(
        profile: &str,
        starting_mode: StartingMode,
    ) -> (Self, tokio::sync::watch::Receiver<State>) {
        let (state_tx, state_rx) = tokio::sync::watch::channel(State::default());

        (
            StateHandler {
                state_tx,
                profile: profile.to_string(),
                starting_mode,
                invitation_credential: None,
            },
            state_rx,
        )
    }

    /// Seed the invitation credential (VIC) to present when joining, parsed from
    /// the `--invitation <file>` launch argument. No-op when `None`.
    pub fn set_invitation_credential(&mut self, vic: Option<serde_json::Value>) {
        self.invitation_credential = vic;
    }

    pub async fn main_loop(
        mut self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> Result<Interrupted> {
        // Carry the launch-supplied invitation credential into the live state so
        // the join flow can present it (it survives `JoinState::reset`, which
        // only clears the transient join sub-state).
        let mut state = State {
            invitation_credential: self.invitation_credential.take(),
            ..State::default()
        };

        let starting_mode = std::mem::replace(&mut self.starting_mode, StartingMode::NotSet);
        // The third element is the live admin VTA session handed back by
        // `load_step2` (PERF #1) for reuse below; `None` for the modes that
        // don't open one (they fall back to building one as before).
        let (tdk, config, loaded_admin_vta) = match starting_mode {
            StartingMode::MainPage(config, tdk) => {
                state.active_page = ActivePage::Main;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = (&config).into();
                state.main_page.log("Configuration loaded");

                (tdk.to_owned(), config, None)
            }
            StartingMode::SetupWizard => {
                // Instantiate TDK
                let tdk = TDK::new(
                    TDKConfig::builder().with_load_environment(false).build()?,
                    None,
                )
                .await?;

                match self
                    .setup_wizard(&mut action_rx, &mut interrupt_rx, &mut state)
                    .await
                {
                    Ok(SetupWizardExit::Config(mut config)) => {
                        let overrides = crate::env_overrides::apply_env_overrides(&mut config);
                        crate::env_overrides::surface(&overrides, &mut state.main_page);

                        // Show the loading screen during the slow post-setup work
                        // (keyring read, VTA round-trip, mediator handshake)
                        // instead of a not-yet-interactive main page; it switches
                        // to Main once the connection is ready.
                        state.active_page = ActivePage::Loading;
                        state.main_page.menu_panel.selected = true;
                        state.main_page.sync_from_config(&config);
                        state.connection.status =
                            state::MediatorStatus::Initializing("Loading credentials...".into());
                        let _ = self.state_tx.send(state.clone());

                        // The setup wizard saved the config but the TDK secrets
                        // resolver is empty. Load persona key secrets so the
                        // DIDComm service can authenticate with the mediator.
                        // R-A-5: a State-A account has no persona, so there are no
                        // secrets to load — skip it (and the VTA round-trip).
                        if config.active_identity().is_some()
                            && let Err(e) = config.load_persona_secrets(&tdk).await
                        {
                            state
                                .main_page
                                .log_error("Warning: failed to load persona keys", &e);
                        }
                        state.main_page.log("Setup complete — configuration loaded");

                        (tdk, config, None)
                    }
                    Ok(SetupWizardExit::Interrupted(interrupted)) => {
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        return Ok(interrupted);
                    }
                    Err(e) => {
                        let err = Interrupted::SystemError(format!("Setup Wizard failed: {e}"));
                        if let Err(e) = terminator.terminate(err.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        return Ok(err);
                    }
                }
            }
            StartingMode::MainPageDeferred(deferred) => {
                // Show the loading screen while the config decrypts and the
                // mediator connection is established; it switches to Main once
                // ready (or stays up to show a startup error).
                state.active_page = ActivePage::Loading;
                state.main_page.menu_panel.selected = true;
                state.main_page.config = main_page::MainMenuConfigState {
                    name: deferred.public_config.friendly_name.clone(),
                    // The persona DID now lives in the encrypted account, which
                    // isn't decrypted yet at this pre-load render. It (and the
                    // working community name) populate from the full Config once
                    // load_step2 completes.
                    did: std::sync::Arc::new(String::new()),
                    // The account isn't decrypted yet, so no name is available.
                    agent_name: None,
                    community: String::new(),
                };
                state.connection.status = state::MediatorStatus::Initializing("Starting...".into());
                let _ = self.state_tx.send(state.clone());

                // Spawn TDK init + config load as a background task with
                // hierarchical progress reporting: each event is (major, sub).
                let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<(String, String)>();

                // Dedicated channel for token-touch events.  The notifier sends a bool
                // (true = touch required, false = touch completed) and the StateHandler's
                // select loop below is the sole authority that updates `state` and
                // broadcasts it to the UI.  This preserves unidirectional data flow and
                // eliminates the previous race-prone Arc<Mutex<State>> pattern.
                //
                // The channel is always created so the select! branch below can be
                // unconditional; when the openpgp-card feature is disabled the sender is
                // dropped inside the spawn and recv() immediately returns None.
                let (token_touch_tx, mut token_touch_rx) = mpsc::unbounded_channel::<bool>();

                // `deferred` (and its profile) moves into the load task, so the
                // failure handler below needs its own copy to diagnose with.
                let profile = self.profile.clone();

                let mut load_handle = tokio::spawn(async move {
                    let on_progress = |major: &str, sub: &str| {
                        if let Err(e) = progress_tx.send((major.to_string(), sub.to_string())) {
                            debug!("Failed to send progress event: {e}");
                        }
                    };

                    on_progress("Local configuration", "Starting TDK");
                    let mut tdk = TDK::new(
                        TDKConfig::builder()
                            .with_load_environment(false)
                            .build()
                            .map_err(|e| anyhow::anyhow!("TDK config failed: {e}"))?,
                        None,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("TDK init failed: {e}"))?;

                    // TokenInteractions impl for openpgp-card.
                    // Sends a plain bool through the dedicated channel instead of
                    // directly mutating shared state, keeping state transitions
                    // inside the StateHandler's main select loop.
                    #[cfg(feature = "openpgp-card")]
                    let token_notifier = {
                        use openvtc_core::config::TokenInteractions;

                        struct TokenNotifier {
                            touch_tx: mpsc::UnboundedSender<bool>,
                        }
                        impl TokenInteractions for TokenNotifier {
                            fn touch_notify(&self) {
                                let _ = self.touch_tx.send(true);
                            }
                            fn touch_completed(&self) {
                                let _ = self.touch_tx.send(false);
                            }
                        }
                        TokenNotifier {
                            touch_tx: token_touch_tx,
                        }
                    };
                    // When openpgp-card is disabled, drop the sender so the receiver
                    // in the select loop sees a closed channel immediately.
                    #[cfg(not(feature = "openpgp-card"))]
                    drop(token_touch_tx);

                    // PERF #1: load_step2 returns its live admin VTA session for
                    // reuse downstream instead of opening a second one here.
                    let (config, admin_session) = Config::load_step2(
                        &mut tdk,
                        &deferred.profile,
                        deferred.public_config,
                        deferred.unlock_passphrase.as_ref(),
                        #[cfg(feature = "openpgp-card")]
                        &deferred.user_pin,
                        #[cfg(feature = "openpgp-card")]
                        &token_notifier,
                        Some(&on_progress),
                    )
                    .await
                    // Keep the typed `OpenVTCError` rather than formatting it
                    // away: the failure handler downcasts it to build a
                    // cause-specific diagnosis, which a string cannot support.
                    .map_err(anyhow::Error::new)?;

                    Ok::<_, anyhow::Error>((tdk, config, admin_session))
                });

                // Listen for progress updates + handle user actions while
                // loading. `progress` drives the hierarchical loading model,
                // stamping each sub-step/major with its duration as the next
                // begins (and the whole thing when the load finishes).
                let mut progress = state::LoadingProgress::default();
                let (tdk, config, loaded_admin_vta) = loop {
                    tokio::select! {
                        Some((major, sub)) = progress_rx.recv() => {
                            progress.begin(&mut state.loading, &major, &sub);
                            state.tip_index = state.tip_index.wrapping_add(1);
                            state.connection.status =
                                state::MediatorStatus::Initializing(
                                    format!("{major} — {sub}"),
                                );
                            let _ = self.state_tx.send(state.clone());
                        }
                        // Token-touch notifications arrive through the dedicated channel
                        // so that state is mutated only here, inside the StateHandler loop.
                        Some(pending) = token_touch_rx.recv() => {
                            state.token_touch_pending = pending;
                            self.state_tx.send(state.clone())?;
                        }
                        result = &mut load_handle => {
                            match result {
                                Ok(Ok((tdk, config, admin_session))) => {
                                    // Stamp the final step + major as Done.
                                    progress.finish(&mut state.loading);
                                    break (tdk, config, admin_session);
                                }
                                Ok(Err(e)) => {
                                    progress.fail(&mut state.loading);
                                    state.startup_diagnosis =
                                        Some(std::sync::Arc::new(diagnose_startup(&e, &profile)));
                                    state.connection.status =
                                        state::MediatorStatus::Failed(format!("{e}"));
                                    let _ = self.state_tx.send(state.clone());
                                    // No config loaded here — join is unavailable.
                                    return self
                                        .run_degraded_loop_terminal(
                                            &mut action_rx,
                                            &mut interrupt_rx,
                                            &mut terminator,
                                            &mut state,
                                            None,
                                        )
                                        .await;
                                }
                                Err(join_err) => {
                                    progress.fail(&mut state.loading);
                                    state.startup_diagnosis = Some(std::sync::Arc::new(
                                        diagnose_startup(
                                            &anyhow::anyhow!("internal error: {join_err}"),
                                            &profile,
                                        ),
                                    ));
                                    state.connection.status =
                                        state::MediatorStatus::Failed(
                                            format!("Internal error: {join_err}"),
                                        );
                                    let _ = self.state_tx.send(state.clone());
                                    return self
                                        .run_degraded_loop_terminal(
                                            &mut action_rx,
                                            &mut interrupt_rx,
                                            &mut terminator,
                                            &mut state,
                                            None,
                                        )
                                        .await;
                                }
                            }
                        }
                        Some(action) = action_rx.recv() => {
                            if matches!(action, Action::Exit) {
                                load_handle.abort();
                                if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                                    debug!("Failed to send terminate signal: {e}");
                                }
                                return Ok(Interrupted::UserInt);
                            }
                        }
                        Ok(interrupted) = interrupt_rx.recv() => {
                            load_handle.abort();
                            return Ok(interrupted);
                        }
                    }
                };

                let mut config = config;
                let overrides = crate::env_overrides::apply_env_overrides(&mut config);
                crate::env_overrides::surface(&overrides, &mut state.main_page);

                let config = Box::new(config);
                // Sync all display state from the loaded config
                state.main_page.sync_from_config(&config);
                state.main_page.refresh_storage_warning(&self.profile);

                // A degraded load is still a load — but it does not get to look
                // like a clean one. The report gates the startup screen on an
                // acknowledgement and stays in the activity log afterwards.
                if config.integrity.is_clean() {
                    state.main_page.log("Configuration loaded");
                } else {
                    let integrity = config.integrity.clone();
                    state
                        .main_page
                        .log_detailed(integrity.headline(), integrity_detail(&integrity));
                    for persona in &integrity.degraded_personas {
                        state.main_page.log(format!(
                            "Persona unavailable: {} — {}",
                            persona.label.clone().unwrap_or_else(|| {
                                openvtc_core::display::truncate_did(&persona.did, 40).into_owned()
                            }),
                            persona.reason.summary()
                        ));
                    }
                    state.integrity = Some(std::sync::Arc::new(integrity));
                }
                if let Some(warning) = state
                    .main_page
                    .content_panel
                    .settings
                    .storage_warning
                    .clone()
                {
                    // Loud enough to be seen without opening Settings: losing a
                    // profile to a reboot is not something to discover later.
                    state.main_page.log(format!("WARNING: {warning}"));
                }

                (tdk, config, loaded_admin_vta)
            }
            StartingMode::NotSet => {
                let err = Interrupted::SystemError("Starting Mode is Not Set!".to_string());
                if let Err(e) = terminator.terminate(err.clone()) {
                    debug!("Failed to send terminate signal: {e}");
                }
                return Ok(err);
            }
        };

        // Set the profile name once (doesn't change during runtime)
        state.main_page.content_panel.vta.profile = self.profile.clone();

        // The always-on admin VTA session for VTA backends. It stays open for
        // the whole time openvtc runs and is reused by every runtime VTA op
        // (context-name fetch, relationship creation, and future community joins
        // / context creation), so the admin DID holds ONE mediator connection
        // instead of reconnecting per operation. It is shut down at every exit
        // path below (degraded returns + end of the main loop).
        //
        // PERF #1: prefer the session `load_step2` already opened (handed back
        // as `loaded_admin_vta`) so the whole runtime uses a SINGLE admin
        // connection. Only fall back to opening one here when there isn't one
        // (the SetupWizard / pre-loaded-Config modes, or a State-A account that
        // had no persona to open a session for).
        let admin_vta: Option<vta_sdk::client::VtaClient> = if loaded_admin_vta.is_some() {
            loaded_admin_vta
        } else if matches!(
            &config.key_backend,
            openvtc_core::config::KeyBackend::Vta { .. }
        ) {
            openvtc_core::config::build_runtime_vta_client(&config.key_backend)
                .await
                .ok()
        } else {
            None
        };

        // D13: make this install visible to the rest of the account, and notice
        // the others. Spawned rather than awaited — registration is diagnostic,
        // and a slow or device-slice-less VTA must not delay startup by a
        // single frame. Uses its OWN client clone so the heartbeat loop can
        // outlive any one borrow of the admin session.
        let (presence_tx, mut presence_rx) =
            mpsc::unbounded_channel::<device_presence::PresenceReport>();
        if let Some(client) = admin_vta.as_ref() {
            // The DID this install authenticates as. It owns our device binding,
            // so it is how the presence task recognises our own row in the
            // listing — the device id is only ever learned on a first launch.
            let self_did = match &config.key_backend {
                openvtc_core::config::KeyBackend::Vta { credential_did, .. } => {
                    Some(credential_did.clone())
                }
                openvtc_core::config::KeyBackend::Bip32 { .. } => None,
            };
            tokio::spawn(device_presence::run(
                client.clone(),
                self.profile.clone(),
                self_did,
                presence_tx,
            ));
        }

        // Put any membership credential this account holds into the VTA's
        // credential vault, if it is not there already. Idempotent, and covers
        // three cases with one mechanism: a join that just completed, one
        // received while the VTA was unreachable, and the back-fill of every
        // membership from before credentials were stored there at all.
        //
        // This is what makes membership recovery work: `rebuild` reconstructs a
        // membership from the credential the community signed, and that
        // credential has to be somewhere other than the config file a rebuild
        // exists because you no longer have.
        if let Some(client) = admin_vta.as_ref() {
            let report =
                openvtc_core::credential_sync::sync_membership_credentials(&config, client).await;
            if report.stored > 0 {
                // Worth an activity-log line rather than only a debug one:
                // this is the moment the account becomes recoverable, and a
                // user who has just joined a community should be able to see
                // that it happened.
                state.main_page.log(format!(
                    "Stored {} membership credential(s) at the VTA — this account can now \
                     be recovered from its Trust Context",
                    report.stored
                ));
            }
            if report.failed > 0 {
                // Costs recoverability rather than anything working now, so it
                // is worth saying but not worth alarming about.
                state.main_page.log(format!(
                    "{} membership credential(s) could not be stored at the VTA — \
                     this account may not be fully recoverable until they are",
                    report.failed
                ));
            }
        }

        // Fetch VTA context name, reusing the always-on admin session.
        if let Some(client) = admin_vta.as_ref()
            && let Ok(resp) = client.list_contexts().await
        {
            if let Some(ctx) = resp
                .contexts
                .iter()
                .find(|c| c.did.as_deref() == Some(config.persona_did()))
            {
                state.main_page.content_panel.vta.context_name = Some(ctx.name.clone());
            } else if let Some(ctx) = resp.contexts.first() {
                // Fallback to first context
                state.main_page.content_panel.vta.context_name = Some(ctx.name.clone());
            }
        }

        // Phase 1 (config load + VTA) is complete. Stay on the loading screen
        // and offer "Press Enter to continue" — but kick off phase 2 (the
        // per-community DIDComm connection) right away below, so the work is
        // already happening in the background regardless of when the user hits
        // Enter. Dismissing the loading screen (Enter) reveals the main page.
        state.loading_complete = true;

        // The messaging runtime comes up HERE, before the State-A branch, and
        // empty: `Messaging::start` runs its dispatcher before the first
        // transport exists, so a service with no listeners is a supported state.
        //
        // The ordering is the point. A State-A join used to run with no messaging
        // at all, so the applicant persona had no socket while the community
        // decided — and a community auto-admitting an invited join answers in
        // under a second. Its reply was therefore stored, not streamed, and the
        // mediator only ever redelivers a stored inbox to a socket that
        // *displaces* another one, so the hot-start below never heard about it.
        // That is the first join a new operator makes, which is the worst
        // possible place for it. Starting the runtime first lets `join_flow`
        // connect the applicant before it submits, exactly as the runtime-loop
        // join already does.
        //
        // Unbounded, deliberately: by the time an event reaches this channel the
        // delivery layer has already acked the message, so a bounded channel's
        // overflow drop destroys a membership credential or join verdict rather
        // than deferring it (#221, fixed in #224). Full rationale on
        // `didcomm::DIDCOMM_EVENT_CHANNEL_CAPACITY`.
        let (didcomm_event_tx, mut didcomm_event_rx) = mpsc::unbounded_channel();
        let shutdown_token = tokio_util::sync::CancellationToken::new();
        let didcomm_service =
            didcomm::start_empty_service(didcomm_event_tx.clone(), shutdown_token.clone());

        // A State-A account has no persona/community yet (R-A-5): there is no
        // DID to open a DIDComm session for *yet*. Run the responsive degraded
        // loop so the user can still navigate, open the Communities page, and
        // start a join — with the live (empty) messaging runtime, so a join made
        // there gets its applicant socket up before submitting.
        //
        // Hot-start: if the user *joins* a community in the degraded loop, the
        // join mints a persona into `config.identities` (so `active_identity()`
        // flips None→Some). The degraded loop detects that and hands the runtime
        // context back as `DegradedOutcome::Joined` instead of looping, so we
        // fall through to the messaging setup below — no process restart needed
        // to receive the approval credential.
        let (tdk, mut config, admin_vta) = if config.active_identity().is_none() {
            state.connection.status = state::MediatorStatus::NoActiveCommunity;
            let _ = self.state_tx.send(state.clone());
            // No persona yet (State A). Hand the always-on admin session to the
            // degraded loop so the Communities `j` → join flow (R-A-5 Stage 4)
            // can reuse it; the loop closes it on exit (or hands it back on a
            // successful in-session join).
            let join_ctx = DegradedJoinContext {
                tdk,
                config,
                admin_vta,
                profile: self.profile.clone(),
            };
            match self
                .run_degraded_loop(
                    &mut action_rx,
                    &mut interrupt_rx,
                    &mut terminator,
                    &mut state,
                    Some(join_ctx),
                    Some(&didcomm_service),
                )
                .await?
            {
                DegradedOutcome::Exit(interrupted) => {
                    // Drop every socket the State-A join may have opened, rather
                    // than leaving one racing the next process for the same DID.
                    shutdown_token.cancel();
                    return Ok(interrupted);
                }
                DegradedOutcome::Joined(ctx) => {
                    state.main_page.sync_from_config(&ctx.config);
                    (ctx.tdk, ctx.config, ctx.admin_vta)
                }
            }
        } else {
            (tdk, config, admin_vta)
        };

        // Point the runtime active identity at the default working community and
        // refilter the community-scoped panels before the first paint (D10 /
        // R-C-6) — otherwise a multi-persona account renders empty panels until
        // the first event re-syncs (the per-path syncs above run with no
        // selection set yet).
        state.reconcile_selected_community_among(
            &config.account,
            Some(&config.identities.keys().copied().collect()),
        );
        let initial_active = state
            .selected_community
            .as_ref()
            .map(|(_, persona)| *persona);
        config.set_active_persona(initial_active);
        state.main_page.sync_from_config(&config);

        // Send initial state immediately so the UI renders without blocking
        state.connection.status = state::MediatorStatus::Connecting;
        let _ = self.state_tx.send(state.clone());

        // Install this account's listeners on the runtime started above. Skips
        // any that already exist, so a State-A join's own persona listener is
        // bound to rather than duplicated (one websocket per DID).
        //
        // The specs are built here because that needs `Config`, which is not
        // `Clone` and cannot cross into a task. Bringing the listeners *up* is
        // the expensive half — a mediator auth handshake and a websocket connect
        // each, in series — and that half runs off this thread. This is the only
        // thread that services UI actions, and the loading screen has already
        // been told to offer "Press Enter to continue": awaiting the connects
        // here meant the keypress sat unread in the action channel until the last
        // socket was up, and the main page then arrived in one late jump.
        let listener_specs = didcomm::build_listener_configs(&config, &tdk).await;
        let _listener_install =
            didcomm::spawn_install_listeners(didcomm_service.clone(), listener_specs);

        // Process-lifetime LRU of inbound message IDs. Backstop for replay
        // and mediator-pickup duplicates beyond what the TDK already filters.
        let mut seen_messages = openvtc_core::messaging::SeenMessages::new();

        // Forward lifecycle events (connect/disconnect/restart) to the activity log
        let (lifecycle_log_tx, mut lifecycle_log_rx) =
            mpsc::unbounded_channel::<didcomm::LifecycleLog>();
        let _lifecycle_handle = didcomm::spawn_lifecycle_logger(&didcomm_service, lifecycle_log_tx);

        // Phase 2 (community/persona DIDComm connection) runs ASYNCHRONOUSLY: we
        // do NOT block the UI waiting for the listener. The main page is already
        // showing (Connecting); the persona connection proceeds in the
        // background and the runtime loop below flips the status to Connected the
        // moment a `ListenerEvent::Connected` arrives — and back to Connecting on
        // a disconnect. Subscribe to typed lifecycle events for that.
        let mut listener_events = didcomm_service.subscribe();

        // Supervised multi-session manager (D11/D15): one persona-session per
        // active community (a reused persona shares one), tracking per-session
        // connection status over the listeners `start_service` already launched.
        // Messaging runs through it from here on; at N=1 it holds one session and
        // behaves identically to the previous single global flag.
        let mut session_manager = session_manager::SessionManager::default();
        {
            use session_manager::RegisterOutcome;
            // NOTE: a mid-session leave/reject/expire does NOT yet deregister its
            // session (that is T6/T7), so until then `any_connected()` can read
            // live for a persona whose communities have all gone inactive. Startup
            // registers exactly the communities that require a live session at load
            // time (`IdentityRegistry::sessions`).
            let registry = openvtc_core::identity::IdentityRegistry::new(&config.account);
            let mut at_capacity = 0usize;
            for (persona_id, vtcs) in registry.sessions() {
                let Some(ctx) = config.identities.get(&persona_id) else {
                    // A live community whose persona didn't resolve to an identity
                    // has no listener either — surfaced here for parity, not silent.
                    debug!(%persona_id, "live-community persona missing from resolved identities — not tracked");
                    continue;
                };
                let lid = didcomm::persona_listener_id(&ctx.did);
                for vtc in vtcs {
                    if matches!(
                        session_manager.register(persona_id, &lid, vtc.clone()),
                        RegisterOutcome::AtCapacity
                    ) {
                        at_capacity += 1;
                        warn!(%persona_id, vtc = %vtc, "session manager at capacity — community not tracked");
                    }
                }
            }
            // No silent caps (D15): tell the user if any community exceeded the bound.
            if at_capacity > 0 {
                state.main_page.log(format!(
                    "Warning: {at_capacity} communit{} exceeded the session limit ({}) and are not actively connected.",
                    if at_capacity == 1 { "y" } else { "ies" },
                    session_manager.max_sessions(),
                ));
            }
        }

        // Seed the indicator from the messaging layer's *live* state rather than
        // assuming nothing is up yet. `ListenerStatus` is edge-triggered, and a
        // State-A join has already brought its persona listener up and connected
        // by the time this loop subscribes — the install step above binds to that
        // socket instead of reinstalling it, so no second `Connected` edge is
        // coming. Without this seed the session sits `Connecting` for the life of
        // the process over a perfectly live socket, which is the "Inbox:
        // Connecting…" that only a restart appeared to fix.
        state.connection.status = state::MediatorStatus::Connecting;
        state.connection.messaging_active = false;
        reconcile_sessions(&mut session_manager, &didcomm_service, &mut state);
        if matches!(state.connection.status, state::MediatorStatus::Connected) {
            state.main_page.log("Connected to the mediator.");
        } else {
            state.main_page.log("Connecting to the mediator…");
        }
        let _ = self.state_tx.send(state.clone());

        // Track when a manual trust-ping was sent (for activity log latency display).
        let mut ping_sent_at: Option<std::time::Instant> = None;

        // Background-dispatch plumbing (R13). Network-bound actions whose await
        // would otherwise park the whole select loop are spawned as background
        // tasks; they do I/O only and send their result back as a
        // `DispatchOutcome` on this channel. The select arm below applies the
        // outcome on the loop thread (the single mutator), keeping the loop live
        // during the wait. `in_flight` rejects a second action on a busy domain.
        let (dispatch_tx, mut dispatch_rx) =
            mpsc::unbounded_channel::<background_dispatch::DispatchOutcome>();
        let mut in_flight = background_dispatch::InFlight::default();
        // Membership contexts already checked at the VTA this run. A failure is
        // logged and retried on the next launch rather than every tick.
        let mut contexts_checked: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Whether this run has read the membership contexts' device grants for
        // the communities panel. Once a run; the device-access view re-reads on
        // demand.
        let mut grants_swept = false;

        // Coalesced + offloaded config persistence (R11). Mutation sites mark the
        // config dirty on the loop thread instead of saving inline; the
        // `deadline` arm below debounces a burst into a single `spawn_blocking`
        // save, with at most one in flight at a time. Durability-critical points
        // (Exit, passphrase/protection change, export) force-flush synchronously.
        let mut save = save_coalesce::SaveScheduler::new(self.profile.clone());
        // Channel carrying a completed background save's success flag, so the loop
        // can clear the in-flight flag and re-arm if the config was dirtied again
        // while the save ran. Save failures are surfaced as a status/log here,
        // matching the pre-R11 inline `save_config` failure handling.
        let (save_done_tx, mut save_done_rx) = mpsc::unbounded_channel::<Result<(), String>>();

        // 7-day Pending timeout sweep (R-B-7 / D16). `interval`'s first tick fires
        // immediately, so a Pending that aged out while the app was closed expires
        // on launch; thereafter it sweeps hourly.
        let mut pending_expiry_tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        // Reply-window sweep for the capabilities view (cheap no-op when the
        // view is closed or idle).
        let mut capabilities_sweep = tokio::time::interval(std::time::Duration::from_secs(5));
        // Backstop for the edge-triggered listener-status stream. A transition
        // that reaches nobody — the broadcast receiver lagging, a listener
        // adopted after its connect — would otherwise latch a session's status
        // (and the indicator) wrong until the next real edge, which for a healthy
        // socket may never come. Cheap: a read of the transports' live state, no
        // I/O and no allocation beyond the listener ids.
        let mut session_reconcile_tick = tokio::time::interval(std::time::Duration::from_secs(15));
        // Agent-name refresh sweep. The first tick fires immediately so names
        // resolve shortly after launch; thereafter it picks up newly-added DIDs
        // (a fresh relationship/contact) and re-verifies stale entries every few
        // minutes. Cheap when there is nothing to do — it only spawns a job when
        // `agent_name_refresh_targets` finds uncached/stale DIDs, and the resolver
        // caches keep repeat sweeps quiet.
        let mut agent_name_tick = tokio::time::interval(std::time::Duration::from_secs(300));
        // Reconcile Pending joins with their communities. The first tick fires
        // immediately, which is the point: a join still Pending at launch is the
        // one whose answer may have been lost, and asking is how we find out
        // rather than waiting to be told again. Per-record backoff lives in the
        // pacer, so a minute-by-minute tick does not mean a minute-by-minute
        // poll; ticks over an account with no Pending join do no work at all.
        let mut join_status_tick = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut join_status_pacer = join_status_poll::PollPacer::default();

        let result = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    Action::Exit => {
                        if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                            debug!("Failed to send terminate signal: {e}");
                        }

                        break Interrupted::UserInt;
                    },

                    Action::UXError(interrupted) => {
                        // An error has occurred on the UX side
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }

                        break interrupted;
                    },

                    Action::StartJoin => {
                        // State-B join from the live runtime: reuse the always-on
                        // admin VTA session. The DIDComm service keeps running in
                        // the background; the join flow owns the screen until the
                        // user returns. Restart is required to activate the new
                        // community (hot-start is a deliberate follow-up).
                        match self
                            .join_flow(
                                &mut action_rx,
                                &mut interrupt_rx,
                                &mut state,
                                &tdk,
                                &mut config,
                                admin_vta.as_ref(),
                                self.profile.as_str(),
                                Some(&didcomm_service),
                            )
                            .await
                        {
                            Ok(join_flow::JoinExit::Returned(joined)) => {
                                state.active_page = state::ActivePage::Main;
                                // R-B-5 / D11: bring the new community's session up
                                // live so the VTC's async receipt is received now,
                                // not only after a restart.
                                if let Some(joined) = joined {
                                    register_joined_session(
                                        &mut session_manager,
                                        &didcomm_service,
                                        &tdk,
                                        &config,
                                        joined,
                                        &mut state,
                                    )
                                    .await;
                                }
                            }
                            Ok(join_flow::JoinExit::Exit(interrupted)) => {
                                break interrupted;
                            }
                            Err(e) => {
                                state.main_page.log_error("Join flow failed", &e);
                                state.active_page = state::ActivePage::Main;
                            }
                        }
                    },
                    // Everything else acts on state and the resources below,
                    // and lives in `runtime_actions` where a test can call it.
                    // Only the three arms above need what a loop has and a
                    // handler cannot be given: the terminator, the action
                    // receiver, and the ability to `break` with this loop's own
                    // outcome type.
                    action => {
                        let mut ctx = runtime_actions::ActionCtx {
                            state: &mut state,
                            config: &mut config,
                            save: &mut save,
                            in_flight: &mut in_flight,
                            dispatch_tx: &dispatch_tx,
                            tdk: &tdk,
                            admin_vta: admin_vta.as_ref(),
                            didcomm_service: &didcomm_service,
                            session_manager: &mut session_manager,
                            ping_sent_at: &mut ping_sent_at,
                            state_tx: &self.state_tx,
                            profile: self.profile.as_str(),
                        };
                        if matches!(
                            runtime_actions::handle_action(&mut ctx, action).await,
                            runtime_actions::Handled::ExitUserInt
                        ) {
                            // A confirmed profile wipe. The handler cannot break
                            // this loop or reach the terminator, so it says so.
                            if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                                debug!("Failed to send terminate signal: {e}");
                            }
                            break Interrupted::UserInt;
                        }
                    },
                },
                // DIDComm inbound message events
                Some(event) = didcomm_event_rx.recv() => {
                    match event {
                        didcomm::DIDCommEvent::InboundMessage { message, transport, .. } => {
                            // Capture message info before processing for detailed logging
                            let msg_type = message.typ.clone();
                            let msg_from = message.from.clone().unwrap_or_else(|| "unknown".into());
                            let msg_to = message.to.as_ref().and_then(|v| v.first()).cloned().unwrap_or_default();
                            let msg_thid = message.thid.clone().unwrap_or_else(|| "none".into());

                            let mut effects = message_dispatch::InboundEffects::default();
                            let dispatched = message_dispatch::process_inbound_message(
                                &mut config,
                                &tdk,
                                &didcomm_service,
                                &mut seen_messages,
                                &message,
                                &mut effects,
                            )
                            .await;
                            let message_dispatch::InboundEffects {
                                inactivated,
                                capability_replies,
                                personhood_challenges,
                            } = effects;

                            // A live challenge is display state, not account
                            // state: single-use, ten-minute life, and worthless
                            // after a restart. It is folded in here rather than
                            // persisted, and unconditionally — a reply that
                            // arrived is a reply the member should see whether
                            // or not the message also changed the config.
                            for reply in personhood_challenges {
                                // The challenge belongs to the persona it was
                                // addressed to. Without one we cannot sign for
                                // it, so there is nothing to offer the member —
                                // and silently showing an unanswerable code
                                // would be worse than saying nothing.
                                let Some(persona) = config.account.persona_id_for_did(&msg_to)
                                else {
                                    warn!(
                                        vtc = %msg_from,
                                        to = %msg_to,
                                        "personhood challenge addressed to a DID this account \
                                         holds no persona for — ignoring",
                                    );
                                    continue;
                                };
                                state.main_page.content_panel.communities.personhood_challenge =
                                    Some(crate::state_handler::main_page::content::PersonhoodChallengeView {
                                        vtc_did: msg_from.clone(),
                                        persona,
                                        challenge_id: reply.challenge_id,
                                        match_code: reply.match_code.clone(),
                                        expires_at: reply.expires_at,
                                    });
                                state.main_page.content_panel.communities.status_message = Some(
                                    format!(
                                        "Personhood challenge received — confirm the code {} with \
                                         whoever is vetting you, then assert.",
                                        reply.match_code
                                    ),
                                );
                            }

                            match dispatched
                            {
                                Ok(true) => {
                                    // R11: a config-mutating inbound message used
                                    // to save inline here — the per-message cost
                                    // that turned a mediator redelivery burst into
                                    // N sequential keyring+file+card writes. Now we
                                    // mark dirty (coalesced + offloaded); the UI
                                    // sync stays immediate.
                                    save.mark_dirty();
                                    // R-S-3: a community resolved to an inactive
                                    // status (e.g. a rejection) — tear down its
                                    // live session so a dead community stops
                                    // holding a mediator connection.
                                    for (vtc, persona) in &inactivated {
                                        deregister_inactive_community(
                                            &mut session_manager,
                                            &didcomm_service,
                                            &config,
                                            &mut state,
                                            vtc,
                                            *persona,
                                        )
                                        .await;
                                    }
                                    state.main_page.sync_from_config(&config);
                                    let short_type = openvtc_core::display::task_label(&msg_type);
                                    state.main_page.log_detailed(
                                        format!("Inbound {transport}: {short_type}"),
                                        format!(
                                            "Inbound {transport} Message\n\
                                             ───────────────────────\n\
                                             Type:    {msg_type}\n\
                                             From:    {msg_from}\n\
                                             To:      {msg_to}\n\
                                             thid:    {msg_thid}",
                                        ),
                                    );
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    state.main_page.log_detailed(
                                        format!("Message error: {e}"),
                                        format!(
                                            "Failed Inbound Message\n\
                                             ──────────────────────\n\
                                             Type:    {msg_type}\n\
                                             From:    {msg_from}\n\
                                             To:      {msg_to}\n\
                                             thid:    {msg_thid}\n\
                                             Error:   {e}",
                                        ),
                                    );
                                    debug!("message dispatch error: {e}");
                                }
                            }
                            apply_capability_replies(&mut state, capability_replies);
                        }
                        didcomm::DIDCommEvent::TrustPingReceived { from, listener_id, message_id } => {
                            let sender = from.as_deref().unwrap_or("unknown");
                            let sender_arc = std::sync::Arc::new(sender.to_string());

                            // Only respond to pings from the mediator or established relationships
                            let is_mediator = sender == config.mediator_did();
                            let has_relationship = config
                                .private
                                .relationships
                                .find_by_remote_did(&sender_arc)
                                .map(|r| {
                                    r.state == openvtc_core::relationships::RelationshipState::Established
                                })
                                .unwrap_or(false);

                            if is_mediator || has_relationship {
                                // Send pong to verified sender, setting `from` to our
                                // listener's DID so the recipient can identify us.
                                let our_listener_did = didcomm_service
                                    .listener_did(&listener_id)
                                    .await
                                    .unwrap_or_else(|| config.persona_did().to_string());
                                if let Some(ref from_did) = from
                                    && let Ok(pong_msg) =
                                        build_trust_pong(&our_listener_did, from_did, &message_id)
                                    && let Err(e) = didcomm::send_message_via(
                                        &didcomm_service,
                                        &pong_msg,
                                        &listener_id,
                                        from_did,
                                    )
                                    .await
                                {
                                    state.main_page.log_error("Failed to send pong", &e);
                                }
                                let ping_display = resolve_did_to_display(&config, sender);
                                state.main_page.log_detailed(
                                    format!("Ping from {ping_display} — pong sent"),
                                    format!(
                                        "Trust-Ping Received\n\
                                         ───────────────────\n\
                                         From (display):  {ping_display}\n\
                                         From (DID):      {sender}\n\
                                         Listener:        {listener_id}\n\
                                         Response:        pong sent",
                                    ),
                                );
                            } else {
                                state.main_page.log_detailed(
                                    format!(
                                        "Ping from {} — ignored",
                                        resolve_did_to_display(&config, sender)
                                    ),
                                    format!(
                                        "Trust-Ping Rejected\n\
                                         ───────────────────\n\
                                         From (DID):      {sender}\n\
                                         Reason:          no established relationship",
                                    ),
                                );
                            }
                        }
                        didcomm::DIDCommEvent::TrustPongReceived { from } => {
                            debug!(from = ?from, "TrustPongReceived event");
                            let sender_did = from.as_deref().unwrap_or("");
                            // Pong often has no `from` field. Resolve by looking
                            // at our most recent outbound ping task to determine
                            // who we pinged.
                            let sender_display = if sender_did.is_empty() {
                                // Find the most recent TrustPing task to get the target
                                config
                                    .private
                                    .tasks
                                    .tasks
                                    .values()
                                    .filter_map(|task| {
                                        if let openvtc_core::tasks::TaskType::TrustPing { to, .. } = &task.type_ {
                                            Some(resolve_did_to_display(&config, to))
                                        } else {
                                            None
                                        }
                                    })
                                    .next()
                                    .unwrap_or_else(|| "unknown".to_string())
                            } else {
                                resolve_did_to_display(&config, sender_did)
                            };
                            let ms = ping_sent_at
                                .take()
                                .map(|sent_at| sent_at.elapsed().as_millis());
                            let latency_str = ms
                                .map(|v| format!(" ({v}ms)"))
                                .unwrap_or_default();
                            state.main_page.log_detailed(
                                format!("Pong from {sender_display}{latency_str}"),
                                format!(
                                    "Trust-Pong Received\n\
                                     ───────────────────\n\
                                     From (display):  {sender_display}\n\
                                     From (DID):      {sender_did}\n\
                                     Latency:         {}",
                                    ms.map(|v| format!("{v}ms")).unwrap_or_else(|| "n/a".into()),
                                ),
                            );
                        }
                    }
                },
                // Background-dispatch completions (R13). A network-bound action
                // that was spawned off the loop (e.g. the mediator reconnect)
                // delivers its result here; the outcome is applied on this thread
                // (the single mutator) and the domain's busy-flag is cleared.
                // Because this is just another select arm, nav actions, `q`/Exit,
                // and inbound DIDComm events are all serviced *while* the spawned
                // I/O is still pending.
                Some(outcome) = dispatch_rx.recv() => {
                    let after = background_dispatch::apply_outcome(
                        &mut state,
                        &mut config,
                        &mut save,
                        &mut in_flight,
                        outcome,
                    );
                    let pending_deregistration = settle_after_apply(
                        after, &mut state, &mut config, &tdk, self.profile.as_str(),
                    )
                    .await;
                    // A community we have just left still holds a messaging
                    // session. The session manager lives here, not in the shared
                    // apply path, so the outcome reports the teardown and this
                    // arm performs it. Local work — removing a listener — not a
                    // network call.
                    if let Some((vtc, persona)) = pending_deregistration {
                        deregister_inactive_community(
                            &mut session_manager,
                            &didcomm_service,
                            &config,
                            &mut state,
                            &vtc,
                            persona,
                        )
                        .await;
                        state.main_page.sync_from_config(&config);
                    }
                    // A refresh asked for while the vault was busy is re-issued
                    // here, now that the domain is free — see `vic_refresh_queued`.
                    if state.main_page.content_panel.vta.vic_refresh_queued {
                        state.main_page.content_panel.vta.vic_refresh_queued = false;
                        spawn_vic_refresh(&dispatch_tx, &mut in_flight, &mut state, admin_vta.as_ref());
                    }
                    // Same rule for the identity pane: a write that just landed
                    // asked for the listing it invalidated, and could not start
                    // it while its own outcome held the domain.
                    if state.main_page.content_panel.identity.refresh_queued {
                        state.main_page.content_panel.identity.refresh_queued = false;
                        spawn_persona_effect(
                            &dispatch_tx,
                            &mut in_flight,
                            &mut state,
                            admin_vta.as_ref(),
                            persona_actions::PersonaEffect::Read,
                        );
                    }
                },
                // D13 presence: another install using this account, or a
                // report that we could not tell. The task never touches
                // `State` — everything lands here, in the single mutator.
                Some(report) = presence_rx.recv() => {
                    match report {
                        device_presence::PresenceReport::Registered { device_id } => {
                            debug!(%device_id, "this install is registered with the VTA");
                            state.self_device_id = Some(device_id);
                        }
                        device_presence::PresenceReport::NewSiblings(siblings) => {
                            if let Some(warning) =
                                openvtc_core::devices::sibling_warning(&siblings)
                            {
                                state.main_page.log_detailed(
                                    format!("WARNING: {warning}"),
                                    siblings
                                        .iter()
                                        .map(|d| {
                                            format!(
                                                "{} — last seen {}",
                                                d.label(),
                                                d.last_seen_at.as_deref().unwrap_or("unknown")
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n"),
                                );
                            }
                            state.live_siblings = siblings;
                            let _ = self.state_tx.send(state.clone());
                        }
                        device_presence::PresenceReport::Unavailable(reason) => {
                            // Said once, so an absence of sibling warnings is
                            // not mistaken for an absence of siblings.
                            debug!("device presence unavailable: {reason}");
                        }
                    }
                },
                // Lifecycle log messages from the Messaging
                Some(event) = lifecycle_log_rx.recv() => {
                    // Formatted here, not in the logger task: naming a listener
                    // needs `config`, which only this thread holds.
                    let line = format_lifecycle_log(&config, &event);
                    match line.detail {
                        Some(detail) => state.main_page.log_detailed(line.summary, detail),
                        None => state.main_page.log(line.summary),
                    }
                },
                // Typed listener lifecycle events → drive the connection status
                // asynchronously (phase 2). The persona listener connecting flips
                // the status to Connected; a disconnect drops back to Connecting
                // while the service auto-reconnects.
                ev = listener_events.recv() => {
                                        if let Ok(ev) = ev {
                        // Route persona-listener lifecycle through the session
                        // manager (D11/D15), which holds per-session status; a
                        // disconnect carrying an error is recorded as that one
                        // session failing (isolated — others are untouched). The
                        // SDK keeps retrying per its restart policy, so a restart
                        // or clean drop is "not connected" until the next connect.
                        // Events for R-DID listeners (not persona sessions) match
                        // nothing and are ignored.
                        let changed = match ev {
                            didcomm::ListenerStatus::Connected { listener_id } => {
                                session_manager.mark_connected(&listener_id)
                            }
                            didcomm::ListenerStatus::Disconnected { listener_id, error } => {
                                match error {
                                    Some(e) => session_manager.mark_failed(&listener_id, e),
                                    None => session_manager.mark_disconnected(&listener_id),
                                }
                            }
                        };
                        // Derive the global connection indicator from the
                        // aggregate of all persona-sessions (a per-community
                        // status panel is future UI work).
                        if changed {
                            apply_session_aggregate(&session_manager, &mut state);
                        }
                    }
                },
                _ = session_reconcile_tick.tick() => {
                    // The loop tail broadcasts `state`, so a change here reaches
                    // the UI without an explicit send.
                    reconcile_sessions(&mut session_manager, &didcomm_service, &mut state);
                }
                // Coalesced-save debounce (R11). Fires when the debounce window
                // since the first dirty mark of a burst elapses. Builds an owned
                // snapshot on this (the single mutator) thread and runs the heavy
                // serialize+encrypt+keyring+card I/O on a blocking thread so the
                // loop stays responsive. At most one save is in flight; a mark
                // that lands while a save runs is re-scheduled on completion.
                // When nothing is scheduled the arm parks forever (no busy-wait).
                _ = capabilities_sweep.tick() => {
                    // R4.3: a capability query has a defined reply window. The
                    // send was fire-and-forget; if no correlated reply arrived,
                    // fail the view closed with a distinct, actionable message.
                    if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut()
                        && view.pending_thid.is_some()
                        && view.sent_at.is_some_and(|t| t.elapsed() > std::time::Duration::from_secs(30))
                    {
                        view.pending_thid = None;
                        view.sent_at = None;
                        if matches!(view.phase, crate::state_handler::main_page::content::CapabilitiesPhase::Loading) {
                            view.phase = crate::state_handler::main_page::content::CapabilitiesPhase::Failed(
                                "no reply within 30s — the community's governance host may be offline".to_string(),
                            );
                        } else {
                            view.status_message = Some(
                                "no reply to the change within 30s — refresh (r) to re-check".to_string(),
                            );
                        }
                    }
                }
                _ = pending_expiry_tick.tick() => {
                    // R-B-7: expire Pending joins unanswered for 7 days — or for
                    // the `decisionSla` a vetting community publishes — raising
                    // actions-required, and tear down each one's now-dead session
                    // (R-S-3). Records are retained read-only (R-S-1).
                    let vetting = &config.private.vetting;
                    let default_timeout = chrono::TimeDelta::days(
                        openvtc_core::config::account::PENDING_TIMEOUT_DAYS,
                    );
                    let timeouts: std::collections::HashMap<_, _> = config
                        .account
                        .memberships()
                        .filter_map(|c| {
                            vetting
                                .decision_sla(&c.vtc_did, c.persona_ref)
                                .map(|sla| ((c.vtc_did.clone(), c.persona_ref), sla))
                        })
                        .collect();
                    let expired = config.account.expire_stale_pending_with(chrono::Utc::now(), |c| {
                        timeouts
                            .get(&(c.vtc_did.clone(), c.persona_ref))
                            .copied()
                            .unwrap_or(default_timeout)
                    });
                    if !expired.is_empty() {
                        save.mark_dirty();
                        for (vtc, persona) in &expired {
                            deregister_inactive_community(
                                &mut session_manager,
                                &didcomm_service,
                                &config,
                                &mut state,
                                vtc,
                                *persona,
                            )
                            .await;
                        }
                        state.main_page.sync_from_config(&config);
                        state.main_page.log(format!(
                            "{} pending join{} expired (no decision within the time allowed).",
                            expired.len(),
                            if expired.len() == 1 { "" } else { "s" },
                        ));
                        let _ = self.state_tx.send(state.clone());
                    }
                },
                _ = join_status_tick.tick() => {
                    // Ask each community about a join it has not resolved.
                    // Only joins recorded against the *community's* request id
                    // are askable — see `join_status_poll` — so a join that
                    // never got any reply is not covered here; that one is
                    // recovered by collecting the mail its reply is sitting in.
                    //
                    // Spawned detached rather than through `background_dispatch`:
                    // there is no outcome to apply on the loop thread (the reply
                    // arrives on the persona's listener and goes through inbound
                    // dispatch like any other), and the pacer already prevents
                    // pile-up by marking a record polled before the send.
                    let candidates = config.account.pollable_pending();
                    if !candidates.is_empty()
                        && let Some(atm) = tdk.atm.clone()
                    {
                        let due = join_status_pacer.due(candidates, std::time::Instant::now());
                        let polls = join_status_poll::build(&config, due);
                        if !polls.is_empty() {
                            tokio::spawn(join_status_poll::send_all(atm, polls));
                        }
                    }
                },
                _ = agent_name_tick.tick() => {
                    // Collect DIDs whose agent name is uncached or stale and, if
                    // any, resolve them in one background job (read-only I/O).
                    // Results are folded into the persisted cache on the loop
                    // thread by `apply_outcome`. The busy-guard drops the tick if
                    // a prior sweep is still running, so ticks never pile up.
                    let targets = config.agent_name_refresh_targets(chrono::Utc::now());
                    if !targets.is_empty()
                        && in_flight.try_begin(background_dispatch::DispatchDomain::AgentName)
                    {
                        let resolver = tdk.did_resolver().clone();
                        background_dispatch::spawn_dispatch(
                            dispatch_tx.clone(),
                            background_dispatch::DispatchDomain::AgentName,
                            async move {
                                let results =
                                    agent_name_refresh::resolve_batch(resolver, targets).await;
                                background_dispatch::DispatchOutcome::AgentName(results)
                            },
                        );
                    }

                    // Ask what each persona presents. Shares this tick for the
                    // same reason as the transport probe — the loop gains no
                    // extra timer — and re-asks every sweep rather than on a
                    // TTL, because the answer is the holder's own decision and
                    // they may have changed it from `pnm` a moment ago. The
                    // busy-guard keeps a slow agent from stacking sweeps.
                    let binding_targets: Vec<persona_binding_refresh::BindingTarget> = config
                        .account
                        .memberships()
                        .filter_map(|c| {
                            config
                                .account
                                .personas
                                .get(&c.persona_ref)
                                .map(|p| (c.sub_context_id.clone(), p.did.clone()))
                        })
                        .collect();
                    if !binding_targets.is_empty()
                        && let Some(client) = admin_vta.as_ref()
                        && in_flight.try_begin(background_dispatch::DispatchDomain::PersonaBinding)
                    {
                        let client = client.clone();
                        background_dispatch::spawn_dispatch(
                            dispatch_tx.clone(),
                            background_dispatch::DispatchDomain::PersonaBinding,
                            async move {
                                background_dispatch::DispatchOutcome::PersonaBinding(
                                    persona_binding_refresh::resolve_batch(client, binding_targets)
                                        .await,
                                )
                            },
                        );
                    }

                    // Register the contexts memberships name. Joins before
                    // per-community contexts recorded an id without creating it;
                    // faces worn there worked only because nothing checked.
                    let top_context_id = config.account.top_context_id.clone();
                    let unchecked: Vec<String> = config
                        .account
                        .memberships()
                        .map(|c| c.sub_context_id.clone())
                        .filter(|id| {
                            openvtc_core::config::community_context::is_sub_context(
                                id,
                                &top_context_id,
                            ) && !contexts_checked.contains(id)
                        })
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    if !unchecked.is_empty()
                        && let Some(client) = admin_vta.as_ref()
                        && in_flight
                            .try_begin(background_dispatch::DispatchDomain::CommunityContexts)
                    {
                        contexts_checked.extend(unchecked.iter().cloned());
                        let client = client.clone();
                        background_dispatch::spawn_dispatch(
                            dispatch_tx.clone(),
                            background_dispatch::DispatchDomain::CommunityContexts,
                            async move {
                                let mut results = Vec::with_capacity(unchecked.len());
                                for context_id in unchecked {
                                    let name = openvtc_core::config::context_path::parse_sub_context_id(
                                        &context_id,
                                    )
                                    .map_or(context_id.clone(), |(_, slug)| slug.to_string());
                                    let result =
                                        openvtc_core::config::community_context::ensure_context(
                                            &client,
                                            &top_context_id,
                                            &context_id,
                                            &name,
                                        )
                                        .await
                                        .map_err(|e| e.to_string());
                                    results.push((context_id, result));
                                }
                                background_dispatch::DispatchOutcome::CommunityContexts(results)
                            },
                        );
                    }

                    // Read each membership context's device grants, once a run,
                    // after registration has made sure the contexts exist — a
                    // grant listing for a context not yet created would read as
                    // a failure.
                    if !grants_swept
                        && !in_flight.is_busy(background_dispatch::DispatchDomain::CommunityContexts)
                        && let Some(client) = admin_vta.as_ref()
                    {
                        let targets = community_context_actions::sweep_targets(&config);
                        if !targets.is_empty()
                            && in_flight
                                .try_begin(background_dispatch::DispatchDomain::DeviceGrantSweep)
                        {
                            grants_swept = true;
                            background_dispatch::spawn_dispatch(
                                dispatch_tx.clone(),
                                background_dispatch::DispatchDomain::DeviceGrantSweep,
                                community_context_actions::sweep(client.clone(), targets),
                            );
                        }
                    }

                    // Probe what transports the VTA advertises, for the VTA
                    // panel. Runs on this tick rather than its own so the loop
                    // gains no extra timer. Re-probed only while the answer is
                    // still missing or failed — once a VTA has answered, its
                    // advertised services are stable for the session, so a
                    // healthy setup probes exactly once per launch (R1.4).
                    let needs_probe = state
                        .main_page
                        .content_panel
                        .vta
                        .transports
                        .advertised
                        .as_ref()
                        .is_none_or(|a| a.error.is_some());
                    if needs_probe
                        && let openvtc_core::config::KeyBackend::Vta { vta_did, .. } =
                            &config.key_backend
                        && !vta_did.is_empty()
                        && in_flight.try_begin(background_dispatch::DispatchDomain::VtaTransports)
                    {
                        let vta_did = vta_did.clone();
                        background_dispatch::spawn_dispatch(
                            dispatch_tx.clone(),
                            background_dispatch::DispatchDomain::VtaTransports,
                            async move {
                                background_dispatch::DispatchOutcome::VtaTransports(
                                    vta_transports::probe(vta_did).await,
                                )
                            },
                        );
                    }
                },
                _ = save.wait_deadline() => {
                    match save.take_for_save(|| config.clone_for_save()) {
                        Ok(Ok(pending)) => {
                            let done_tx = save_done_tx.clone();
                            tokio::task::spawn_blocking(move || {
                                let result = pending.run().map_err(|e| format!("{e}"));
                                let _ = done_tx.send(result);
                            });
                        }
                        // Snapshot failed: surface like an inline save failure.
                        // The scheduler kept the config dirty + re-armed, so it
                        // retries on the next deadline.
                        Ok(Err(e)) => {
                            state.main_page.log_error("Failed to save config", &e);
                        }
                        // NotDirty / InFlight — nothing to start right now.
                        Err(_) => {}
                    }
                },
                // A backgrounded coalesced save finished (R11). Clear the
                // in-flight flag and re-arm if the config was dirtied again. A
                // failed save is surfaced exactly as the old inline `save_config`
                // failure did (status + log) and left dirty for retry.
                Some(result) = save_done_rx.recv() => {
                    match &result {
                        Ok(()) => {}
                        Err(reason) => {
                            state
                                .main_page
                                .log_error("Failed to save config", &anyhow::anyhow!("{reason}"));
                        }
                    }
                    save.finish(result.is_ok());
                },
                // (keepalive removed — WebSocket-level pings handle connectivity)
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            // Keep the working-context selection valid against any account change
            // this iteration applied (join/leave/status transition) before the UI
            // re-renders from the broadcast (D10 / R-C-6), then point the runtime
            // active identity at the selected community's persona so all
            // identity-derived reads scope to the working community. When the
            // working persona actually changes (e.g. the active community left and
            // the default shifted), refilter the community-scoped panels so the UI
            // reflects the new context this frame.
            state.reconcile_selected_community_among(
                &config.account,
                Some(&config.identities.keys().copied().collect()),
            );
            let active_persona = state
                .selected_community
                .as_ref()
                .map(|(_, persona)| *persona);
            if active_persona != config.active_persona {
                config.set_active_persona(active_persona);
                state.main_page.sync_from_config(&config);
            }
            let _ = self.state_tx.send(state.clone());
        };

        // R11: if a backgrounded coalesced save was still running when the loop
        // broke, wait for it to complete before the force-flush below. A
        // `spawn_blocking` task is NOT cancelled when its `JoinHandle` is dropped,
        // so that save is still live; running the shutdown save concurrently would
        // mean two `Config::save`s racing the same (non-atomic) file + keyring
        // writes. Draining the completion channel serialises shutdown after it.
        // After `finish`, `needs_flush()` is only still true if the config was
        // dirtied *after* the in-flight save's snapshot — exactly what the
        // force-flush must persist.
        if save.in_flight()
            && let Some(result) = save_done_rx.recv().await
        {
            save.finish(result.is_ok());
        }

        // R11 force-flush: persist the latest state before tearing down, so
        // coalescing never loses the final mutation on Exit/interrupt. Runs a
        // direct blocking save (the loop has broken; there is no runtime arm left
        // to schedule against). `needs_flush` is true when the config is dirty or
        // a background save was still in flight when the loop broke.
        if save.needs_flush() {
            match save.snapshot_now(&config) {
                Ok(pending) => {
                    if let Err(e) = pending.run() {
                        state
                            .main_page
                            .log_error("Failed to save config on exit", &e);
                    }
                }
                Err(e) => {
                    state
                        .main_page
                        .log_error("Failed to snapshot config on exit", &e);
                }
            }
        }

        // Shut down the DIDComm service gracefully
        shutdown_token.cancel();
        didcomm_service.shutdown().await;

        // Close the always-on admin VTA session.
        if let Some(c) = admin_vta {
            c.shutdown().await;
        }

        Ok(result)
    }

    /// Minimal event loop for when there is no active community / messaging
    /// (State-A) or after an init failure — keeps the UI alive so the user can
    /// navigate, exit, and (when `join_ctx` is supplied) start a join.
    ///
    /// `join_ctx` carries the runtime pieces the join flow needs (TDK, the live
    /// `Config`, the always-on admin VTA session, profile). The early
    /// load-failure callers have no loaded config, so they pass `None` and
    /// `StartJoin` is a no-op there.
    ///
    /// `messaging` is the live (initially listener-less) DIDComm runtime, so a
    /// join started here can bring the applicant persona's socket up **before**
    /// it submits. Without it the first join an account ever makes is also the
    /// one join with no live recipient while the community decides — see the
    /// ordering note in `run`. The early load-failure callers pass `None`; they
    /// cannot join at all.
    ///
    /// Returns [`DegradedOutcome::Joined`] when an in-session join succeeds
    /// (State-A → member). The caller then installs the remaining listeners
    /// without a restart (hot-start). All other exits return
    /// [`DegradedOutcome::Exit`] after closing the admin session.
    ///
    /// # Invariant: this loop must never own a live listener across an iteration
    ///
    /// Its `select!` has exactly two arms — `action_rx` and `interrupt_rx`. There
    /// is **no inbound arm**: nothing here drains the DIDComm event channel that
    /// `dispatch_inbound` feeds. A listener opened here is therefore a socket
    /// whose mail the SDK acknowledges (and the mediator then deletes) while no
    /// consumer runs — inbound survives only as far as the channel's 256-slot
    /// buffer, and only until the runtime loop drains it.
    ///
    /// So every path that opens a listener must exit via
    /// [`DegradedOutcome::Joined`] in the same iteration. The `StartJoin` arm
    /// enforces this for itself *and* re-checks `list_listeners()` as a backstop,
    /// because the cost of getting it wrong is silent, permanent message loss
    /// that looks like a community that never answered.
    async fn run_degraded_loop(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        terminator: &mut Terminator,
        state: &mut State,
        mut join_ctx: Option<DegradedJoinContext>,
        messaging: Option<&didcomm::Messaging>,
    ) -> Result<DegradedOutcome> {
        // R11: the degraded loop persists only via `remove_community` (State-A
        // community withdrawal); `join_flow` saves itself synchronously. Coalesce
        // here too and force-flush on every exit path so a withdrawal isn't lost.
        let mut save = save_coalesce::SaveScheduler::new(self.profile.clone());
        // State A reaches the VTA panel too (an account with no community still
        // manages personas and VICs there), so it needs the same off-loop path
        // for the vault query — otherwise Tab is responsive after the first join
        // and sluggish before it, on the very screen a new account lives in.
        // Only the VIC domain is dispatched here; every other network action is
        // inert in this loop.
        let (dispatch_tx, mut dispatch_rx) =
            tokio::sync::mpsc::unbounded_channel::<background_dispatch::DispatchOutcome>();
        let mut in_flight = background_dispatch::InFlight::default();
        let result = loop {
            tokio::select! {
                Some(action) = action_rx.recv() => match action {
                    // Shared nav reducer first — degraded mode now routes the exact
                    // same pure-state nav set as the runtime loop (previously these
                    // arms were duplicated here and the VTA DID-manager nav arms were
                    // silently dropped by the trailing `_ => {}`).
                    _ if handle_nav_action(state, &action) => {}
                    Action::Exit => {
                        if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        break DegradedOutcome::Exit(Interrupted::UserInt);
                    }
                    Action::UXError(interrupted) => {
                        if let Err(e) = terminator.terminate(interrupted.clone()) {
                            debug!("Failed to send terminate signal: {e}");
                        }
                        break DegradedOutcome::Exit(interrupted);
                    }
                    Action::DeleteCommunity(i) => {
                        if let Some(ctx) = join_ctx.as_mut() {
                            remove_community(state, &mut ctx.config, &mut save, i);
                            // The degraded loop has no debounce arm and a `Joined`
                            // handoff carries the config into the runtime loop, so
                            // force-flush this single destructive action now rather
                            // than risk losing it on handoff. (Low-traffic State-A
                            // path — no burst to coalesce.)
                            if save.needs_flush()
                                && let Err(e) = save.flush(&ctx.config).await
                            {
                                state
                                    .main_page
                                    .log_error("Failed to save after removing community", &e);
                            }
                        }
                    }
                    Action::StartJoin => {
                        // Set when a join succeeded: the loop then breaks `Joined`
                        // so `run()` can start messaging.
                        let mut joined_a_community = false;
                        if let Some(ctx) = join_ctx.as_mut() {
                            match self
                                .join_flow(
                                    action_rx,
                                    interrupt_rx,
                                    state,
                                    &ctx.tdk,
                                    &mut ctx.config,
                                    ctx.admin_vta.as_ref(),
                                    ctx.profile.as_str(),
                                    // The live runtime, so the applicant persona
                                    // is connected before the submit goes out and
                                    // an auto-admitted join's reply is streamed
                                    // rather than stored unread. `None` only for
                                    // the early load-failure callers, which
                                    // cannot reach a join anyway.
                                    messaging,
                                )
                                .await
                            {
                                // The joined session is ignored here: a join from
                                // State A flips `joined_a_community`, breaking
                                // `Joined` so `run()` restarts into the full pipeline,
                                // whose startup registration (`IdentityRegistry`)
                                // brings the new session up (R-B-5). Live in-loop
                                // registration is only needed in the runtime loop.
                                Ok(join_flow::JoinExit::Returned(joined)) => {
                                    // Back on the main page; resume the degraded loop.
                                    state.active_page = state::ActivePage::Main;
                                    // Gated on the *join*, never on whether it minted
                                    // the account's first identity. This used to read
                                    // `!had_identity && …`, on the assumption that the
                                    // only way to already hold an identity here was the
                                    // messaging-startup-failure path. It is not: the
                                    // `CreatePersonaSubmit` arm below mints one in this
                                    // very loop, and `active_identity()` falls back to
                                    // the first persona in the map — so the ordinary
                                    // first-run order (create persona, *then* join)
                                    // left `had_identity` true, skipped the hand-off,
                                    // and stranded the account in a loop that has no
                                    // inbound arm. The community's reply was ACKed by
                                    // the SDK, deleted at the mediator, and dropped.
                                    joined_a_community =
                                        joined.is_some() && ctx.config.active_identity().is_some();
                                }
                                Ok(join_flow::JoinExit::Exit(interrupted)) => {
                                    if let Err(e) = terminator.terminate(interrupted.clone()) {
                                        debug!("Failed to send terminate signal: {e}");
                                    }
                                    break DegradedOutcome::Exit(interrupted);
                                }
                                Err(e) => {
                                    state
                                        .main_page
                                        .log_error("Join flow failed", &e);
                                    state.active_page = state::ActivePage::Main;
                                }
                            }
                        } else {
                            state
                                .main_page
                                .log("Cannot join: no active VTA session.");
                        }
                        // Hot-start: the borrow on `join_ctx` has ended, so take
                        // the context and hand it back to `run()`, which brings up
                        // the new persona's DIDComm listener without a restart.
                        //
                        // `holds_listener` is the backstop for the same class of
                        // bug the condition above fixes: this loop has no inbound
                        // arm, so *any* live listener it owns is a mailbox nobody
                        // reads. Whatever opened one — this join, or some future
                        // arm — the only safe move is to hand off to the runtime
                        // loop that drains the event channel. See the invariant on
                        // `run_degraded_loop`.
                        let holds_listener = match messaging {
                            Some(m) => !m.list_listeners().await.is_empty(),
                            None => false,
                        };
                        if must_hand_off(joined_a_community, holds_listener, join_ctx.is_some()) {
                            state.main_page.log(if joined_a_community {
                                "Joined — starting secure messaging…"
                            } else {
                                "Starting secure messaging…"
                            });
                            let _ = self.state_tx.send(state.clone());
                            break DegradedOutcome::Joined(Box::new(
                                join_ctx
                                    .take()
                                    .expect("join_ctx present, just checked is_some"),
                            ));
                        }
                    }
                    Action::CreatePersonaSubmit => {
                        // Minting needs only the admin VTA session + account
                        // context, both present in State-A — so a brand-new account
                        // (which runs here) can create its first persona DID.
                        if let Some(ctx) = join_ctx.as_ref() {
                            spawn_persona_mint(
                                &dispatch_tx, &mut in_flight, state, &ctx.config, &ctx.tdk,
                                ctx.admin_vta.as_ref(),
                            );
                        } else if let Some(o) = state.main_page.create_persona.as_mut() {
                            o.phase = main_page::content::CreatePersonaPhase::Failed;
                            o.messages = vec![
                                "VTA session unavailable — cannot create a persona right now."
                                    .to_string(),
                            ];
                        }
                    }
                    // Agent-name management, for the persona this loop just
                    // minted. State A is where an account's FIRST persona is
                    // created, so it is also the first place anyone wants to
                    // name one — and `g` reached a loop that had no arm for it
                    // and dropped it into the catch-all below. Nothing happened
                    // and nothing said why, on a screen that had just reported
                    // "Created persona DID …".
                    //
                    // The session is cloned rather than borrowed because the
                    // mutating verbs need `&mut ctx.config` at the same time;
                    // a `VtaClient` clone is cheap and shares the connection.
                    Action::StartAgentNameManager(index) => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.clone());
                        if let Some(did) = open_agent_name_overlay(state, index) {
                            spawn_agent_name_job(
                                &dispatch_tx, &mut in_flight, state, av.as_ref(),
                                did, agent_name_actions::Verb::Open,
                            );
                        }
                    }
                    Action::AgentNameManagerClaim => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.clone());
                        if let Some((did, name)) = agent_name_to_claim(state) {
                            spawn_agent_name_job(
                                &dispatch_tx, &mut in_flight, state, av.as_ref(),
                                did, agent_name_actions::Verb::Claim(name),
                            );
                        }
                    }
                    Action::AgentNameManagerToggle => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.clone());
                        if let Some((did, name, enabled)) = selected_agent_name(state) {
                            let verb = if enabled {
                                agent_name_actions::Verb::Park(name)
                            } else {
                                agent_name_actions::Verb::Resume(name)
                            };
                            spawn_agent_name_job(
                                &dispatch_tx, &mut in_flight, state, av.as_ref(), did, verb,
                            );
                        }
                    }
                    Action::AgentNameManagerRemove => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.clone());
                        if let Some((did, name, _)) = selected_agent_name(state) {
                            spawn_agent_name_job(
                                &dispatch_tx, &mut in_flight, state, av.as_ref(),
                                did, agent_name_actions::Verb::Remove(name),
                            );
                        }
                    }
                    // Settings are config-only: `settings_actions::dispatch`
                    // takes the config, the state and the save scheduler, and
                    // touches no messaging and no VTA session. So every one of
                    // them is serviceable here — and all of them were being
                    // dropped, which is a State-A account unable to change its
                    // own protection, logging or mediator.
                    //
                    // `ReconnectMediator` is the one outcome this loop cannot
                    // honour: there is no persona listener to rebuild yet. The
                    // setting itself is already persisted by the dispatch above,
                    // so it takes effect when messaging starts.
                    Action::Settings(sa) => {
                        if let Some(ctx) = join_ctx.as_mut() {
                            match settings_actions::dispatch(
                                sa,
                                &mut ctx.config,
                                state,
                                &self.state_tx,
                                &mut save,
                                &self.profile,
                            )
                            .await
                            {
                                settings_actions::SettingsOutcome::Continue => {}
                                settings_actions::SettingsOutcome::ExitUserInt => {
                                    if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                                        debug!("Failed to send terminate signal: {e}");
                                    }
                                    break DegradedOutcome::Exit(Interrupted::UserInt);
                                }
                                settings_actions::SettingsOutcome::ReconnectMediator => {
                                    state.main_page.log(
                                        "Mediator saved — it takes effect once messaging starts.",
                                    );
                                }
                            }
                        }
                    }
                    // Removing a persona, for the same reason as creating one:
                    // State A is where an account's first persona is minted, so
                    // it is where a mistaken one gets thrown away. This was
                    // listed as "intentionally inert" below, but the pieces it
                    // needs are all here — the confirm prompt is armed by a nav
                    // action that already works, and `prepare_delete_context_did`
                    // is what clears it. Dropping the `y` left the prompt on
                    // screen with nothing behind it, which reads as a hang.
                    Action::DeleteDid(i) => {
                        let domain = background_dispatch::DispatchDomain::Did;
                        match (join_ctx.as_mut(), messaging) {
                            (Some(ctx), Some(service)) => {
                                if !in_flight.try_begin(domain) {
                                    let msg = background_dispatch::InFlight::busy_message(domain);
                                    state.main_page.log(msg);
                                } else {
                                    let av = ctx.admin_vta.clone();
                                    if let Some(job) = prepare_delete_context_did(
                                        state,
                                        &mut ctx.config,
                                        av.as_ref(),
                                        service,
                                        i,
                                    ) {
                                        background_dispatch::spawn_dispatch(
                                            dispatch_tx.clone(),
                                            domain,
                                            async move {
                                                background_dispatch::DispatchOutcome::Did(
                                                    job.run().await,
                                                )
                                            },
                                        );
                                    } else {
                                        // A guard rejected it (logged inline).
                                        in_flight.finish(domain);
                                    }
                                }
                            }
                            // No session or no messaging runtime: say so and
                            // disarm, rather than leaving the prompt hanging.
                            _ => {
                                state.main_page.content_panel.identity.confirm =
                                    main_page::content::PersonaConfirm::None;
                                state
                                    .main_page
                                    .log("Cannot remove an identity right now — no VTA session.");
                            }
                        }
                    }
                    Action::Persona(persona_action) => {
                        // Serviced in State A as well: the attribute pool is
                        // holder-scoped and the admin session that reads it
                        // exists before any community does. The pane has no
                        // personas or memberships to show yet, which is a true
                        // answer rather than a missing one.
                        let effect = persona_actions::apply(state, &persona_action);
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.as_ref());
                        spawn_persona_effect(&dispatch_tx, &mut in_flight, state, av, effect);
                    }
                    Action::VicRefresh => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.as_ref());
                        spawn_vic_refresh(&dispatch_tx, &mut in_flight, state, av);
                    }
                    Action::VicToggleInactive => {
                        state.main_page.content_panel.vta.vic_show_inactive =
                            !state.main_page.content_panel.vta.vic_show_inactive;
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.as_ref());
                        spawn_vic_refresh(&dispatch_tx, &mut in_flight, state, av);
                    }
                    Action::AddVicSubmit => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.clone());
                        if let Some(vic) = vic_to_import(state) {
                            spawn_vic_mutation(
                                &dispatch_tx, &mut in_flight, state, av.as_ref(),
                                vic::VicVerb::Add(vic),
                            );
                        }
                    }
                    Action::VicArchive(i)
                    | Action::VicUnarchive(i)
                    | Action::VicRestore(i)
                    | Action::DeleteVic(i)
                    | Action::PurgeVic(i) => {
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.clone());
                        if let Some(verb) = vic_lifecycle_verb(state, &action, i) {
                            spawn_vic_mutation(
                                &dispatch_tx, &mut in_flight, state, av.as_ref(), verb,
                            );
                        }
                    }
                    Action::CreatePersonaCopy => {
                        if let Some(did) = state
                            .main_page
                            .create_persona
                            .as_ref()
                            .and_then(|o| o.did.clone())
                        {
                            let copied = crate::clipboard::copy_to_clipboard(&did).is_ok();
                            if let Some(o) = state.main_page.create_persona.as_mut() {
                                o.copied = copied;
                            }
                        }
                    }
                    // Messaging-only actions (Inbox / Relationship / Credential /
                    // Settings / Contact) are intentionally inert in the
                    // degraded loop — there's no live messaging/admin context to
                    // service them. The pure nav arms they previously shared this
                    // catch-all with now go through `handle_nav_action` above.
                    //
                    // Leaves a breadcrumb, because this arm is also where an
                    // action lands that *should* have been serviced and simply
                    // has no arm yet — the agent-name verbs sat here, and the
                    // only symptom was a key that did nothing. A dropped action
                    // is now visible in a debug log instead of being inferred
                    // from silence. (The action is not named: `Action` carries
                    // credential and key material in some variants and
                    // deliberately has no `Debug`.)
                    // ---- Everything below is listed so this match stays EXHAUSTIVE ----
                    //
                    // There is deliberately no `_` arm. This loop's coverage was
                    // a hand-written list next to a silent catch-all, and three
                    // surfaces were quietly missing from it (#235): the
                    // agent-name verbs, `DeleteDid`, and every setting. Each one
                    // presented as a key that did nothing. Without a catch-all a
                    // new `Action` variant cannot be added without deciding,
                    // here, what an account with no community does with it — the
                    // compiler asks, instead of a user reporting a dead key.
                    //
                    // The `openpgp-card` arms are split out because those
                    // variants do not exist in a default build: one flat list
                    // compiles under a single feature set and breaks the other,
                    // which is what CI caught the first time round.

                    // Serviced by `handle_nav_action` in the guard arm above.
                    // Unreachable here; listed for exhaustiveness only.
                    Action::MainMenuSelected(..) | Action::MainPanelSwitch(..) |
                    Action::DismissLoading | Action::CapabilitiesClose | Action::CapabilitiesUp |
                    Action::CapabilitiesDown | Action::CapabilitiesDetail |
                    Action::CapabilitiesToggleArm | Action::CapabilitiesToggleCancel |
                    Action::CommunitySelect(..) | Action::CommunityConfirmDelete(..) |
                    Action::CommunityCancelDelete | Action::CommunityConfirmLeave(..) |
                    Action::CommunityCancelLeave | Action::CommunityConfirmWithdraw(..) |
                    Action::CommunityCancelWithdraw | Action::CommunitySwitcherMove(..) |
                    Action::CloseCommunitySwitcher | Action::DidSelect(..) |
                    Action::DidConfirmDelete(..) | Action::DidCancelDelete |
                    Action::StartCreatePersona | Action::CreatePersonaInput(..) |
                    Action::CreatePersonaClose | Action::CreatePersonaContextSelect(..) |
                    Action::CreatePersonaContextSlug(..) | Action::CreatePersonaBack |
                    Action::AgentNameManagerInput(..) |
                    Action::AgentNameManagerSelect(..) | Action::AgentNameManagerConfirmRemove |
                    Action::AgentNameManagerCancelRemove | Action::AgentNameManagerClose |
                    Action::VicSelect(..) | Action::VicConfirmDelete(..) |
                    Action::VicCancelDelete | Action::VicConfirmPurge(..) | Action::VicCancelPurge |
                    Action::StartAddVic | Action::AddVicInput(..) | Action::AddVicPaste(..) |
                    Action::AddVicClose => {}

                    // Owned by the join-flow and setup-wizard sub-loops, which
                    // run their own action loops and never delegate to this one.
                    Action::ActivateMainMenu | Action::JoinSubmitVtc(..) |
                    Action::JoinIdentitySelect(..) | Action::JoinIdentityChoose |
                    Action::JoinReuseConfirm | Action::JoinReuseCancel |
                    Action::JoinInvitationSelect(..) | Action::JoinInvitationChoose |
                    Action::JoinContextSelect(..) | Action::JoinContextSlug(..) |
                    Action::JoinContextChoose |
                    Action::JoinCancel | Action::JoinPasteVic(..) | Action::JoinPasteFromClipboard |
                    Action::JoinClearVic | Action::ImportConfig(..) | Action::SetProtection(..) |
                    Action::VtaSubmitDid(..) | Action::VtaStartProvision(..) |
                    Action::RecoverPlanContext |
                    Action::SetupCompleted(..) => {}
                    #[cfg(feature = "openpgp-card")]
                    Action::GetTokens | Action::SetAdminPin(..) | Action::SetTouchPolicy(..) |
                    Action::SetTokenName(..) | Action::FactoryReset(..) | Action::TokenWriteKeys(..) => {}

                    // Vetting sends and receives peer messages as a persona, and
                    // this loop has neither a persona nor an inbound arm.
                    Action::Vetting(..) => {
                        state.main_page.log(
                            "Vetting needs a persona — create one under My Identity, then \
                             restart OpenVTC to apply or to vet.",
                        );
                    }

                    // Genuinely unavailable: these need a live community and the
                    // messaging runtime that comes with it. Inert, but not
                    // silent — a dead key is indistinguishable from a broken one.
                    Action::Inbox(..) | Action::Relationship(..) | Action::Credential(..) |
                    Action::IssueMemberVmc(..) | Action::CapabilitiesOpen(..) |
                    Action::RequestPersonhoodChallenge(..) | Action::AssertPersonhood |
                    Action::CapabilitiesRefresh | Action::CapabilitiesToggleCommit |
                    Action::SetActiveCommunity(..) | Action::ToggleFavourite(..) |
                    Action::AcknowledgeCommunity(..) | Action::LeaveCommunity(..) |
                    Action::WithdrawJoin(..) | Action::ArchiveCommunity(..) |
                    Action::ToggleShowArchived | Action::OpenCommunitySwitcher |
                    Action::CommunitySwitcherSelect | Action::CommunityContext(..) => {
                        debug!("action needs a community — not serviced in State A");
                        state
                            .main_page
                            .log("Not available yet — join a community first.");
                    }
                },
                Some(outcome) = dispatch_rx.recv() => {
                    // Applying needs the config the outcome is annotated against.
                    // It lives in `join_ctx`, which is `take`n on hand-off to the
                    // runtime loop — a listing that lands in that window has
                    // nowhere to go, but its domain must still be freed or the
                    // guard stays set for the life of the loop.
                    match join_ctx.as_mut() {
                        // State A holds no messaging sessions, so a pending
                        // deregistration cannot arise here — and could not be
                        // honoured if it did.
                        Some(ctx) => {
                            let after = background_dispatch::apply_outcome(
                                state,
                                &mut ctx.config,
                                &mut save,
                                &mut in_flight,
                                outcome,
                            );
                            // State A holds no messaging sessions, so a pending
                            // deregistration cannot arise here; a persona
                            // persist very much can — this is where an account's
                            // first one is minted.
                            let _ = settle_after_apply(
                                after,
                                state,
                                &mut ctx.config,
                                &ctx.tdk,
                                self.profile.as_str(),
                            )
                            .await;
                        }
                        None => in_flight.finish(outcome.domain()),
                    }
                    if state.main_page.content_panel.vta.vic_refresh_queued {
                        state.main_page.content_panel.vta.vic_refresh_queued = false;
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.as_ref());
                        spawn_vic_refresh(&dispatch_tx, &mut in_flight, state, av);
                    }
                    if state.main_page.content_panel.identity.refresh_queued {
                        state.main_page.content_panel.identity.refresh_queued = false;
                        let av = join_ctx.as_ref().and_then(|c| c.admin_vta.as_ref());
                        spawn_persona_effect(
                            &dispatch_tx,
                            &mut in_flight,
                            state,
                            av,
                            persona_actions::PersonaEffect::Read,
                        );
                    }
                }
                Ok(interrupted) = interrupt_rx.recv() => {
                    break DegradedOutcome::Exit(interrupted);
                }
            }
            let _ = self.state_tx.send(state.clone());
        };

        // Close the always-on admin VTA session owned by the join context, if
        // any. On a `Joined` outcome the context was already `take`n above (so
        // `join_ctx` is None here) and the session is carried into the messaging
        // path — this shutdown is correctly skipped.
        if let Some(ctx) = join_ctx
            && let Some(c) = ctx.admin_vta
        {
            c.shutdown().await;
        }

        Ok(result)
    }

    /// Run the degraded loop for a path that cannot hot-start (no loaded config),
    /// collapsing the outcome to an [`Interrupted`]. `DegradedOutcome::Joined` is
    /// unreachable for these callers — only the State-A entry can transition
    /// None→Some. They have no messaging runtime either, and no config to build
    /// one from.
    async fn run_degraded_loop_terminal(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        terminator: &mut Terminator,
        state: &mut State,
        join_ctx: Option<DegradedJoinContext>,
    ) -> Result<Interrupted> {
        match self
            .run_degraded_loop(action_rx, interrupt_rx, terminator, state, join_ctx, None)
            .await?
        {
            DegradedOutcome::Exit(interrupted) => Ok(interrupted),
            DegradedOutcome::Joined(_) => {
                unreachable!("degraded loop transitioned to messaging on a terminal path")
            }
        }
    }
}

/// Runtime context the degraded loop hands to [`StateHandler::join_flow`].
///
/// Owns the live `Config` (mutated + persisted by a successful join), the TDK,
/// the always-on admin VTA session, and the profile name. The admin session is
/// shut down when the degraded loop returns.
struct DegradedJoinContext {
    tdk: TDK,
    config: Box<Config>,
    admin_vta: Option<vta_sdk::client::VtaClient>,
    profile: String,
}

/// Outcome of [`StateHandler::run_degraded_loop`].
enum DegradedOutcome {
    /// The user exited or an interrupt fired. The admin session (if any) was
    /// closed by the loop before returning.
    Exit(Interrupted),
    /// An in-session join minted the account's first persona. The runtime
    /// context (with its still-open admin session) is handed back so `run()` can
    /// bring up the persona's DIDComm listener without a process restart.
    ///
    /// Boxed because it dwarfs `Exit`: it carries the whole runtime context
    /// including the `VtaClient`, which grew when the client gained its TSP leg.
    /// Every `Exit` — the overwhelmingly common outcome — would otherwise pay for
    /// the join case's size.
    Joined(Box<DegradedJoinContext>),
}

/// Apply correlated `governance/capability/*` replies to the open
/// capabilities view. Uncorrelated replies (view closed, or thid from an
/// older query) are dropped — the reply is stale by definition.
fn apply_capability_replies(
    state: &mut State,
    replies: Vec<(String, openvtc_core::capabilities::CapabilityReply)>,
) {
    use crate::state_handler::main_page::content::CapabilitiesPhase;
    use openvtc_core::capabilities::CapabilityReply;
    if replies.is_empty() {
        return;
    }
    let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() else {
        return;
    };
    for (thid, reply) in replies {
        if view.pending_thid.as_deref() != Some(thid.as_str()) {
            continue;
        }
        view.pending_thid = None;
        view.sent_at = None;
        match reply {
            CapabilityReply::Listing(items) => {
                view.selected = view.selected.min(items.len().saturating_sub(1));
                view.items = items;
                view.phase = CapabilitiesPhase::Loaded;
            }
            CapabilityReply::Toggled {
                capability,
                enabled,
            } => {
                if let Some(item) = view.items.iter_mut().find(|i| i.slug == capability) {
                    item.enabled = enabled;
                }
                view.status_message = Some(format!(
                    "{capability} is now {}",
                    if enabled { "enabled" } else { "disabled" }
                ));
                view.phase = CapabilitiesPhase::Loaded;
            }
            CapabilityReply::Rejected { code, message } => {
                let detail = message.map(|m| format!(" — {m}")).unwrap_or_default();
                match view.phase {
                    CapabilitiesPhase::Loaded => {
                        // A rejected toggle: keep the listing, surface the code.
                        view.status_message =
                            Some(format!("the community rejected the change: {code}{detail}"));
                    }
                    _ => {
                        view.phase = CapabilitiesPhase::Failed(match code.as_str() {
                            "unsupportedType" => {
                                "this community does not offer capability management".to_string()
                            }
                            _ => format!("the community rejected the query: {code}{detail}"),
                        });
                    }
                }
            }
        }
    }
}

/// Do the work an outcome handed back because [`background_dispatch::apply_outcome`]
/// could not: it is shared by both loops, and they hold different things.
///
/// Split out so both loops honour it identically — a persona minted in State A
/// must be persisted exactly as one minted at runtime.
async fn settle_after_apply(
    after: background_dispatch::AfterApply,
    state: &mut State,
    config: &mut Config,
    tdk: &TDK,
    profile: &str,
) -> Option<(String, openvtc_core::config::account::PersonaId)> {
    use main_page::content::CreatePersonaPhase;

    match after {
        background_dispatch::AfterApply::Nothing => None,
        // Only the runtime loop owns a session manager, so it is handed back up.
        background_dispatch::AfterApply::Deregister(vtc, persona) => Some((vtc, persona)),
        background_dispatch::AfterApply::PersistPersona(minted) => {
            match minted.persist(config, tdk, profile).await {
                Ok(_) => {
                    let did = minted.did.clone();
                    let copied = crate::clipboard::copy_to_clipboard(&did).is_ok();
                    if let Some(o) = state.main_page.create_persona.as_mut() {
                        o.phase = CreatePersonaPhase::Done;
                        o.did = Some(did.clone());
                        o.copied = copied;
                        o.messages.push("Persona created.".to_string());
                    }
                    // Refresh the VTA panel so the new orphan persona is listed.
                    state.main_page.sync_from_config(config);
                    state.main_page.log(format!("Created persona DID {did}"));
                }
                Err(e) => {
                    // The DID exists at the VTA but is not in the config. Say so
                    // plainly: it is not lost, and a retry would mint a second.
                    if let Some(o) = state.main_page.create_persona.as_mut() {
                        o.phase = CreatePersonaPhase::Failed;
                        o.messages
                            .push(format!("Minted, but could not be saved: {e}"));
                    }
                    state
                        .main_page
                        .log_error("Persona minted but not saved", &e);
                }
            }
            None
        }
    }
}

/// Start a standalone persona mint off the loop, shared by both loops.
///
/// The label is validated here — empty is an instant, local rejection that
/// should keep the operator in the field — and the `Config` reads the mint needs
/// are taken here too, so the job carries no borrow.
///
/// `progress_tx` is the dispatch channel itself: the job reports each step as a
/// non-terminal [`background_dispatch::DispatchOutcome::Progress`], which the
/// applier renders into the overlay without freeing the domain.
fn spawn_persona_mint(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    config: &Config,
    tdk: &TDK,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) {
    use main_page::content::CreatePersonaPhase;

    fn fail(state: &mut State, msg: &str, terminal: bool) {
        if let Some(o) = state.main_page.create_persona.as_mut() {
            if terminal {
                o.phase = CreatePersonaPhase::Failed;
            }
            o.messages = vec![msg.to_string()];
        }
    }
    let Some(overlay) = state.main_page.create_persona.clone() else {
        return;
    };
    let label = overlay.label.value().trim().to_string();
    match overlay.phase {
        // The label is checked, then the contexts it can live in are offered —
        // no VTA call yet, so this stays on the loop.
        CreatePersonaPhase::Label => {
            if label.is_empty() {
                return fail(state, "Enter a label first.", false);
            }
            if config.account.top_context_id.is_empty() {
                return fail(
                    state,
                    "No account context yet — finish setup before creating a persona.",
                    true,
                );
            }
            let (options, slug) = create_persona::context_choice(config, &label);
            if let Some(o) = state.main_page.create_persona.as_mut() {
                o.context_options = options;
                o.context_selected = 0;
                o.context_slug = slug;
                o.messages.clear();
                o.phase = CreatePersonaPhase::Context;
            }
            return;
        }
        CreatePersonaPhase::Context => {}
        CreatePersonaPhase::Working | CreatePersonaPhase::Done | CreatePersonaPhase::Failed => {
            return;
        }
    }
    let context_id = match create_persona::chosen_context(
        config,
        &overlay.context_options,
        overlay.context_selected,
        &overlay.context_slug,
    ) {
        Ok(context_id) => context_id,
        Err(e) => return fail(state, &e, false),
    };
    let Some(admin_vta) = admin_vta else {
        return fail(
            state,
            "VTA session unavailable — cannot create a persona right now.",
            true,
        );
    };
    let domain = background_dispatch::DispatchDomain::Persona;
    if !in_flight.try_begin(domain) {
        return fail(
            state,
            &background_dispatch::InFlight::busy_message(domain),
            false,
        );
    }

    if let Some(o) = state.main_page.create_persona.as_mut() {
        o.phase = CreatePersonaPhase::Working;
        o.messages = vec![format!(
            "Creating persona \u{201c}{label}\u{201d} in {context_id}\u{2026}"
        )];
    }

    let job = create_persona::MintJob {
        admin_vta: admin_vta.clone(),
        tdk: tdk.clone(),
        inputs: create_persona::MintInputs::from_config(config, context_id),
        label,
        progress_tx: dispatch_tx.clone(),
    };
    background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
        background_dispatch::DispatchOutcome::Persona(Box::new(job.run().await))
    });
}

/// Send a document addressed to a community, off the loop.
///
/// The busy-guard serialises leave and issue-credential together: both address
/// the same peer, both are user-initiated one at a time, and a second send while
/// one is retrying would tell the community two things at once.
fn spawn_community_job(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    job: community_actions::CommunityJob,
) {
    let domain = background_dispatch::DispatchDomain::Community;
    if !in_flight.try_begin(domain) {
        state.main_page.content_panel.communities.status_message =
            Some(background_dispatch::InFlight::busy_message(domain));
        return;
    }
    background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
        background_dispatch::DispatchOutcome::Community(job.run().await)
    });
}

/// Resolve the messaging identity a capability document is sent as.
///
/// Kept on the loop because it reads `Config`; everything it returns is owned,
/// so the job that follows borrows nothing.
fn capability_sender(
    config: &Config,
    tdk: &TDK,
    persona_id: openvtc_core::config::account::PersonaId,
) -> Option<(
    affinidi_tdk::messaging::ATM,
    std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    String,
    String,
)> {
    let id = config.identities.get(&persona_id)?;
    let atm = tdk.atm.as_ref()?.clone();
    Some((
        atm,
        id.profile().clone(),
        id.persona_did().to_string(),
        id.mediator_did.clone().unwrap_or_default(),
    ))
}

/// Send a capability document off the loop.
///
/// The busy-guard is what stops a held key queueing a fan of identical
/// governance documents at a community: the view is armed with exactly one
/// pending thread id, and a second send would orphan the first.
fn spawn_capability_job(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    job: capability_actions::CapabilityJob,
) {
    let domain = background_dispatch::DispatchDomain::Capabilities;
    if !in_flight.try_begin(domain) {
        if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() {
            view.status_message = Some(background_dispatch::InFlight::busy_message(domain));
        }
        return;
    }
    background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
        background_dispatch::DispatchOutcome::Capabilities(job.run().await)
    });
}

/// Start a VIC vault mutation off the loop, shared by both loops.
///
/// The import's *validation* stays on the loop deliberately: parsing the paste
/// and checking it is an invitation credential is local and instant, and it is
/// what decides whether the operator stays on the input field to fix it. Only
/// the vault round-trip is backgrounded.
///
/// Mutations share the `Vic` domain with the listing, so a mutation and a
/// refresh cannot overlap and produce a list that reflects neither. The refresh
/// that follows is *requested* by the outcome rather than started here — see
/// [`vic::VicMutationOutcome::apply`].
fn spawn_vic_mutation(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
    verb: vic::VicVerb,
) {
    let domain = background_dispatch::DispatchDomain::Vic;
    let Some(admin_vta) = admin_vta else { return };
    if !in_flight.try_begin(domain) {
        state
            .main_page
            .log(background_dispatch::InFlight::busy_message(domain));
        return;
    }
    let job = vic::VicJob {
        admin_vta: admin_vta.clone(),
        verb,
    };
    background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
        background_dispatch::DispatchOutcome::VicMutation(job.run().await)
    });
}

/// Validate the pasted invitation credential on the loop, returning the parsed
/// body to store. A bad paste keeps the operator on the input field with the
/// reason, exactly as it did when the whole import ran inline.
fn vic_to_import(state: &mut State) -> Option<serde_json::Value> {
    use main_page::content::AddVicPhase;

    let json = match state.main_page.add_vic.as_ref() {
        Some(o) if o.phase == AddVicPhase::Input => o.input.value().to_string(),
        _ => return None,
    };
    fn fail(state: &mut State, msg: String) -> Option<serde_json::Value> {
        if let Some(o) = state.main_page.add_vic.as_mut() {
            o.messages = vec![msg];
        }
        None
    }
    if json.trim().is_empty() {
        return fail(
            state,
            "Paste an invitation credential (VIC) first.".to_string(),
        );
    }
    let vic: serde_json::Value = match serde_json::from_str(json.trim()) {
        Ok(v) => v,
        Err(e) => return fail(state, format!("Failed: not valid JSON: {e}")),
    };
    if let Err(e) = openvtc_core::join::validate_invitation_credential(&vic) {
        return fail(state, format!("Failed: {e}"));
    }
    if let Some(o) = state.main_page.add_vic.as_mut() {
        o.phase = AddVicPhase::Working;
        o.messages = vec!["Storing invitation credential…".to_string()];
    }
    Some(vic)
}

/// The vault verb an armed lifecycle key acts on, with its target id.
fn vic_lifecycle_verb(state: &mut State, action: &Action, index: usize) -> Option<vic::VicVerb> {
    // The confirmation arms are resolved either way.
    state.main_page.content_panel.vta.confirm_delete_vic = None;
    state.main_page.content_panel.vta.confirm_purge_vic = None;

    let id = state
        .main_page
        .content_panel
        .vta
        .vics
        .get(index)
        .map(|v| v.id.clone())?;
    Some(match action {
        Action::VicArchive(_) => vic::VicVerb::Archive(id),
        Action::VicUnarchive(_) => vic::VicVerb::Unarchive(id),
        Action::VicRestore(_) => vic::VicVerb::Restore(id),
        Action::DeleteVic(_) => vic::VicVerb::Delete(id),
        Action::PurgeVic(_) => vic::VicVerb::Purge(id),
        _ => return None,
    })
}

/// Start an agent-name verb off the loop, shared by both loops.
///
/// The loop resolves what the job needs — which persona, which name, the host
/// for the display-cache entry — and hands over owned values; the job does the
/// Trust Tasks and nothing else. Every verb is up to two 60 s round trips, and
/// awaiting them here parked the whole application: no inbound DIDComm, no
/// listener lifecycle, no keys, including `q`.
///
/// The overlay is put into `Working` (or `Loading`, on open) *before* the spawn,
/// so its own input stays locked for the duration exactly as it did when this
/// ran inline. What changes is that everything else keeps running.
fn spawn_agent_name_job(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
    persona_did: String,
    verb: agent_name_actions::Verb,
) {
    use main_page::content::AgentNameManagerPhase;

    let domain = background_dispatch::DispatchDomain::AgentNameManage;
    let opening = matches!(verb, agent_name_actions::Verb::Open);
    let status = verb.status();

    let Some(admin_vta) = admin_vta else {
        if let Some(o) = state.main_page.agent_names.as_mut() {
            o.phase = AgentNameManagerPhase::Ready;
            o.message =
                Some("VTA session unavailable — cannot manage agent names right now.".to_string());
        }
        return;
    };
    if !in_flight.try_begin(domain) {
        if let Some(o) = state.main_page.agent_names.as_mut() {
            o.message = Some(background_dispatch::InFlight::busy_message(domain));
        }
        return;
    }

    if let Some(o) = state.main_page.agent_names.as_mut() {
        o.phase = if opening {
            AgentNameManagerPhase::Loading
        } else {
            AgentNameManagerPhase::Working
        };
        o.message = Some(status);
        // The confirm (if any) has served its purpose — the mutation is now
        // running; don't leave it armed over the refreshed list.
        o.confirm_remove = None;
    }

    let job = agent_name_actions::AgentNameJob {
        vta: admin_vta.clone(),
        host: agent_name_manage::derive_host(&persona_did).unwrap_or_default(),
        persona_did,
        verb,
    };
    background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
        background_dispatch::DispatchOutcome::AgentNameManage(job.run().await)
    });
}

/// Record what a refresh request does to the panel, and answer whether the
/// caller should actually start a job. Split out from [`spawn_vic_refresh`]
/// so the guard rules are testable without a live `VtaClient`.
///
/// The three outcomes, and why each is what it is, are documented on
/// [`spawn_vic_refresh`].
fn begin_vic_refresh(
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    has_session: bool,
) -> bool {
    if !has_session {
        state.main_page.content_panel.vta.vic_loading = false;
        return false;
    }
    if !in_flight.try_begin(background_dispatch::DispatchDomain::Vic) {
        state.main_page.content_panel.vta.vic_refresh_queued = true;
        return false;
    }
    state.main_page.content_panel.vta.vic_loading = true;
    true
}

/// Start a background VIC-list refresh, shared by both loops.
///
/// The vault query is a trust task with a 30 s SDK timeout. It used to run
/// inline in the action arm, which meant a key pressed behind it — a two-line
/// in-memory change — could not be applied until the network answered: asking
/// for the Invitation Credentials list took as long as the round trip, with
/// nothing on screen to say why. Here the loop only *starts* the query, so the
/// keypress lands on the next frame and the list fills in when it arrives.
///
/// Guarding rules, in the order they apply:
///
/// * **No session, no query.** Without the always-on admin VTA session there is
///   no vault to read; the loading flag is cleared so the panel doesn't claim a
///   query is running.
/// * **One in flight per domain** ([`background_dispatch::InFlight`]), so
///   leaning on Tab cannot open an unbounded fan of vault queries (VTI R1.4).
/// * **Rejected means deferred, not dropped.** The in-flight query was issued
///   before whatever prompted this one (a lifecycle mutation, an `i` filter
///   flip), so its result is already stale. The request is remembered in
///   `vic_refresh_queued` and re-issued by the dispatch arm once the domain
///   frees — silently discarding it would leave, say, a just-archived VIC
///   rendered as active until the operator refreshed by hand.
fn spawn_vic_refresh(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) {
    if !begin_vic_refresh(in_flight, state, admin_vta.is_some()) {
        return;
    }
    let admin_vta = admin_vta.expect("checked by begin_vic_refresh").clone();
    let include_inactive = state.main_page.content_panel.vta.vic_show_inactive;
    background_dispatch::spawn_dispatch(
        dispatch_tx.clone(),
        background_dispatch::DispatchDomain::Vic,
        async move {
            background_dispatch::DispatchOutcome::Vic(
                vic::VicRefreshOutcome::run(admin_vta, include_inactive).await,
            )
        },
    );
}

/// Start the identity pane's network work off the loop, shared by both loops.
///
/// Reads and writes share one domain, so the two cannot interleave and leave a
/// listing that reflects neither.
///
/// A **read** rejected by the busy-guard is *deferred* rather than dropped: the
/// in-flight call was issued before whatever prompted this one, so its answer is
/// already stale, and silently discarding the new request would leave a
/// just-saved attribute missing from the list until the operator refreshed by
/// hand.
///
/// A **write** is not deferrable. Its arguments were resolved against the state
/// as it was, so replaying it later could apply an edit to a row the operator
/// has since moved off. It is refused instead — and the form it came from is
/// handed back, because a submitted form is locked until an answer arrives and
/// a request that never left has no answer coming.
///
/// Without an admin session there is nothing to ask: the pane says so rather
/// than leaving a spinner running against a session that does not exist.
fn spawn_persona_effect(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<background_dispatch::DispatchOutcome>,
    in_flight: &mut background_dispatch::InFlight,
    state: &mut State,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
    effect: persona_actions::PersonaEffect,
) {
    use persona_actions::PersonaEffect;

    let domain = background_dispatch::DispatchDomain::PersonaManage;
    if matches!(effect, PersonaEffect::None) {
        return;
    }
    let Some(admin_vta) = admin_vta else {
        let reason =
            "No VTA session — your identity is held by the agent, which cannot be reached \
             right now."
                .to_string();
        let p = &mut state.main_page.content_panel.identity;
        p.loading = false;
        p.load_error = Some(reason.clone());
        if matches!(effect, PersonaEffect::Job(_)) {
            persona_actions::release_form(state, reason);
        }
        return;
    };
    if !in_flight.try_begin(domain) {
        match effect {
            PersonaEffect::Read => {
                state.main_page.content_panel.identity.refresh_queued = true;
            }
            _ => persona_actions::release_form(
                state,
                background_dispatch::InFlight::busy_message(domain),
            ),
        }
        return;
    }

    match effect {
        PersonaEffect::None => unreachable!("returned above"),
        PersonaEffect::Read => {
            let job = persona_actions::PersonaReadJob {
                admin_vta: admin_vta.clone(),
                include_values: state.main_page.content_panel.identity.show_values,
                targets: persona_actions::PersonaReadJob::targets(state),
                needs_claim_types: !state.main_page.content_panel.identity.claim_types_loaded,
            };
            state.main_page.content_panel.identity.loading = true;
            background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
                background_dispatch::DispatchOutcome::PersonaManage(job.run().await)
            });
        }
        PersonaEffect::Job(job) => {
            let job = persona_actions::PersonaJobRun {
                admin_vta: admin_vta.clone(),
                job,
            };
            background_dispatch::spawn_dispatch(dispatch_tx.clone(), domain, async move {
                background_dispatch::DispatchOutcome::PersonaManage(job.run().await)
            });
        }
    }
}

/// The typed name to claim, once it is non-empty and the overlay is idle.
fn agent_name_to_claim(state: &mut State) -> Option<(String, String)> {
    use main_page::content::AgentNameManagerPhase;
    let o = state.main_page.agent_names.as_mut()?;
    if o.phase != AgentNameManagerPhase::Ready {
        return None;
    }
    let name = o.input.value().trim().to_string();
    if name.is_empty() {
        o.message = Some("Enter a name first.".to_string());
        return None;
    }
    Some((o.persona_did.clone(), name))
}
/// The `(persona_did, name, enabled)` of the overlay's selected row, if the
/// overlay is open, `Ready`, and has a selection.
/// The persona an agent-name overlay would open for, and the label/host to
/// show while it loads. `None` (with a reason logged) when the selection
/// points at no row.
fn open_agent_name_overlay(state: &mut State, index: usize) -> Option<String> {
    use main_page::content::{AgentNameManagerPhase, AgentNameManagerState};

    let Some(persona) = state
        .main_page
        .content_panel
        .identity
        .personas
        .get(index)
        .cloned()
    else {
        // No persona under the selection: the account has none yet, or the
        // index outlived the row it pointed at. Either way say so — an
        // unexplained no-op here is what makes `g` look broken.
        state
            .main_page
            .log("No persona selected — create or select a persona DID first.");
        return None;
    };
    state.main_page.agent_names = Some(AgentNameManagerState {
        persona_did: persona.did.clone(),
        persona_label: persona.label.clone(),
        host: agent_name_manage::derive_host(&persona.did).unwrap_or_default(),
        phase: AgentNameManagerPhase::Loading,
        ..Default::default()
    });
    Some(persona.did)
}
fn selected_agent_name(state: &State) -> Option<(String, String, bool)> {
    use crate::state_handler::main_page::content::AgentNameManagerPhase;
    let o = state.main_page.agent_names.as_ref()?;
    if o.phase != AgentNameManagerPhase::Ready {
        return None;
    }
    let row = o.names.get(o.selected)?;
    Some((o.persona_did.clone(), row.name.clone(), row.enabled))
}
/// Loop-thread preparation for deleting an **orphan** context identity
/// (persona DID) at `index` in the VTA DID manager. Runs the guards (DID
/// resolution + the community-bound check — a community-bound identity must
/// not be deleted out from under its membership) and snapshots the persona /
/// key ids, then returns a [`relationship_actions::DidDeleteJob`] for the loop
/// to run off-thread (VTA `delete_did_webvh` + listener teardown). The local
/// cleanup (persona/identity/key removal + save + sync) is applied later by
/// [`relationship_actions::DidDeleteOutcome`].
///
/// Returns `None` (and logs inline) when a guard rejects the delete, so the
/// caller can release the busy-domain without spawning anything.
fn prepare_delete_context_did(
    state: &mut State,
    config: &mut Config,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
    didcomm_service: &openvtc_core::didcomm::Messaging,
    index: usize,
) -> Option<relationship_actions::DidDeleteJob> {
    state.main_page.content_panel.identity.confirm = main_page::content::PersonaConfirm::None;
    let did = state
        .main_page
        .content_panel
        .identity
        .personas
        .get(index)
        .map(|d| d.did.clone())?;

    // Resolve the persona for this DID + its key ids.
    let Some(persona) = config.account.personas.values().find(|p| p.did == did) else {
        state.main_page.log("DID not found — nothing removed.");
        return None;
    };
    let persona_id = persona.persona_id;
    let key_ids: Vec<String> = persona.key_refs.iter().map(|k| k.key_id.clone()).collect();

    // Guard: refuse to delete an identity any community still presents.
    let bound = config
        .account
        .memberships()
        .filter(|c| c.persona_ref == persona_id)
        .count();
    if bound > 0 {
        state.main_page.log(format!(
            "Can't delete — {bound} communit{} still use this identity; leave them first.",
            if bound == 1 { "y" } else { "ies" }
        ));
        return None;
    }

    state.main_page.log(format!("Removing identity {did}…"));

    Some(relationship_actions::DidDeleteJob {
        admin_vta: admin_vta.cloned(),
        service: didcomm_service.clone(),
        did,
        persona_id,
        key_ids,
    })
}
/// Remove the community at `index` in the Communities display list: withdraw
/// a live (Pending/Active) membership first (R-C-8 — for a pending join this
/// is the withdrawal), then delete the record, persist, and refresh the
/// panel. Surfaces the outcome as a status message.
fn remove_community(
    state: &mut State,
    config: &mut Config,
    save: &mut save_coalesce::SaveScheduler,
    index: usize,
) {
    let Some((vtc, persona)) = config
        .account
        .communities_for_display(state.main_page.content_panel.communities.show_archived)
        .get(index)
        .map(|c| (c.vtc_did.clone(), c.persona_ref))
    else {
        return;
    };
    // The confirmation is now resolved.
    state.main_page.content_panel.communities.confirm_delete = None;
    // Delete is inactive-only (R-C-8): an Active/Pending community must be
    // left first (the `d` key is gated to inactive rows, and `delete_membership`
    // re-checks). We no longer silently `leave()` here — that conflated leave
    // with delete and skipped the protocol self-removal.
    match config.account.delete_membership(&vtc, persona) {
        Ok(_) => {
            // R11: coalesced save (was an inline `config.save`). The
            // Exit/shutdown force-flush guarantees the deletion is persisted
            // even if the user quits within the debounce window.
            save.mark_dirty();
            state.main_page.sync_from_config(config);
            state.main_page.content_panel.communities.status_message =
                Some("Community removed.".to_string());
        }
        Err(e) => {
            state.main_page.content_panel.communities.status_message =
                Some(format!("Could not remove community: {e}"));
        }
    }
}

/// Apply a pure navigation action to `state`, shared by the runtime loop and the
/// degraded loop so both modes route the same nav set from exactly one place.
///
/// Returns `true` if `action` was a nav action and was handled here; `false`
/// otherwise, signalling the caller to fall through to its loop-specific arms
/// (DIDComm events for the runtime loop; join hot-start etc. for degraded).
///
/// Only arms that mutate `&mut State` and nothing else live here. Loop-local
/// arms stay in their loops because they need resources this signature can't
/// carry cleanly:
///   * `Exit` / `UXError` — must signal the terminator and `break` with the
///     loop's own outcome type (`Interrupted` vs `DegradedOutcome`).
///   * `DeleteCommunity` / `DeleteDid` — `async`, and reach into the live
///     `Config`, the admin VTA session, and the DIDComm service to tear down
///     listeners; the two loops genuinely differ here.
///   * `StartJoin` — `async`; drives `join_flow` with loop-specific context and
///     (degraded only) the join hot-start handoff.
fn handle_nav_action(state: &mut State, action: &Action) -> bool {
    match action {
        Action::DismissLoading => {
            // Phase 1 done + user pressed Enter — reveal the main page
            // (phase-2 connection is already running in the background).
            //
            // When the load was degraded, this Enter IS the acknowledgement.
            // Record that it was given, so the activity log shows the user was
            // told rather than leaving it ambiguous whether they ever saw it.
            if let Some(integrity) = state.integrity.take() {
                state
                    .main_page
                    .log(format!("Acknowledged: {}", integrity.headline()));
            }
            state.active_page = state::ActivePage::Main;
        }
        Action::MainMenuSelected(menu_item) => {
            // User has changed main menu selection.
            state.main_page.menu_panel.selected_menu = menu_item.clone();
        }
        Action::MainPanelSwitch(panel) => match panel {
            MainPanel::ContentPanel => {
                // When switching to ContentPanel, move focus to the content panel.
                state.main_page.menu_panel.selected = false;
                state.main_page.content_panel.selected = true;
            }
            MainPanel::MainMenu => {
                // When switching to MainMenu, move focus back to the menu.
                state.main_page.menu_panel.selected = true;
                state.main_page.content_panel.selected = false;
            }
        },
        Action::CapabilitiesClose => {
            state.main_page.content_panel.capabilities.view = None;
        }
        Action::CapabilitiesUp => {
            if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() {
                view.selected = view.selected.saturating_sub(1);
                view.confirm_toggle = None;
            }
        }
        Action::CapabilitiesDown => {
            if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() {
                if view.selected + 1 < view.items.len() {
                    view.selected += 1;
                }
                view.confirm_toggle = None;
            }
        }
        Action::CapabilitiesDetail => {
            if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() {
                view.detail = !view.detail;
            }
        }
        Action::CapabilitiesToggleArm => {
            if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut()
                && !view.items.is_empty()
            {
                view.confirm_toggle = Some(view.selected);
            }
        }
        Action::CapabilitiesToggleCancel => {
            if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut() {
                view.confirm_toggle = None;
            }
        }
        Action::CommunitySelect(i) => {
            state.main_page.content_panel.communities.selected_index = *i;
        }
        Action::CommunityConfirmDelete(i) => {
            state.main_page.content_panel.communities.confirm_delete = Some(*i);
        }
        Action::CommunityCancelDelete => {
            state.main_page.content_panel.communities.confirm_delete = None;
        }
        Action::CommunityConfirmLeave(i) => {
            state.main_page.content_panel.communities.confirm_leave = Some(*i);
        }
        Action::CommunityCancelLeave => {
            state.main_page.content_panel.communities.confirm_leave = None;
        }
        Action::CommunityConfirmWithdraw(i) => {
            state.main_page.content_panel.communities.confirm_withdraw = Some(*i);
        }
        Action::CommunityCancelWithdraw => {
            state.main_page.content_panel.communities.confirm_withdraw = None;
        }
        Action::CommunitySwitcherMove(i) => {
            if let Some(switcher) = state.main_page.switcher.as_mut() {
                switcher.selected = (*i).min(switcher.items.len().saturating_sub(1));
            }
        }
        Action::CloseCommunitySwitcher => {
            state.main_page.switcher = None;
        }
        Action::DidSelect(i) => {
            state.main_page.content_panel.identity.persona_selected = *i;
        }
        Action::DidConfirmDelete(i) => {
            state.main_page.content_panel.identity.confirm =
                main_page::content::PersonaConfirm::DeletePersona(*i);
        }
        Action::DidCancelDelete => {
            state.main_page.content_panel.identity.confirm =
                main_page::content::PersonaConfirm::None;
        }
        Action::VicSelect(i) => {
            state.main_page.content_panel.vta.vic_selected_index = *i;
        }
        Action::VicConfirmDelete(i) => {
            state.main_page.content_panel.vta.confirm_delete_vic = Some(*i);
            state.main_page.content_panel.vta.confirm_purge_vic = None;
        }
        Action::VicCancelDelete => {
            state.main_page.content_panel.vta.confirm_delete_vic = None;
        }
        Action::VicConfirmPurge(i) => {
            state.main_page.content_panel.vta.confirm_purge_vic = Some(*i);
            state.main_page.content_panel.vta.confirm_delete_vic = None;
        }
        Action::VicCancelPurge => {
            state.main_page.content_panel.vta.confirm_purge_vic = None;
        }
        Action::StartAddVic => {
            state.main_page.add_vic = Some(main_page::content::AddVicState::default());
        }
        Action::AddVicInput(key) => {
            use tui_input::backend::crossterm::EventHandler;
            if let Some(overlay) = state.main_page.add_vic.as_mut()
                && overlay.phase == main_page::content::AddVicPhase::Input
            {
                overlay
                    .input
                    .handle_event(&crossterm::event::Event::Key(*key));
            }
        }
        Action::AddVicPaste(text) => {
            if let Some(overlay) = state.main_page.add_vic.as_mut()
                && overlay.phase == main_page::content::AddVicPhase::Input
            {
                overlay.input = tui_input::Input::new(text.clone());
            }
        }
        Action::AddVicClose => {
            state.main_page.add_vic = None;
        }
        Action::StartCreatePersona => {
            // Open the overlay on its label-entry phase (the mint runs later, in
            // the loop, on CreatePersonaSubmit).
            state.main_page.create_persona =
                Some(main_page::content::CreatePersonaState::default());
        }
        Action::CreatePersonaInput(key) => {
            use tui_input::backend::crossterm::EventHandler;
            if let Some(overlay) = state.main_page.create_persona.as_mut()
                && overlay.phase == main_page::content::CreatePersonaPhase::Label
            {
                overlay
                    .label
                    .handle_event(&crossterm::event::Event::Key(*key));
            }
        }
        Action::CreatePersonaClose => {
            state.main_page.create_persona = None;
        }
        Action::CreatePersonaContextSelect(i) => {
            if let Some(o) = state.main_page.create_persona.as_mut()
                && o.phase == main_page::content::CreatePersonaPhase::Context
            {
                o.context_selected = (*i).min(o.context_options.len().saturating_sub(1));
                o.messages.clear();
            }
        }
        Action::CreatePersonaContextSlug(slug) => {
            // Only the new sub-context's row takes a typed name.
            if let Some(o) = state.main_page.create_persona.as_mut()
                && o.phase == main_page::content::CreatePersonaPhase::Context
                && o.context_options.get(o.context_selected).is_some_and(|c| {
                    c.kind == openvtc_core::config::community_context::ContextKind::New
                })
            {
                o.context_slug = slug.chars().take(64).collect();
                o.messages.clear();
            }
        }
        Action::CreatePersonaBack => {
            if let Some(o) = state.main_page.create_persona.as_mut()
                && o.phase == main_page::content::CreatePersonaPhase::Context
            {
                o.phase = main_page::content::CreatePersonaPhase::Label;
                o.messages.clear();
            }
        }
        Action::CommunityContext(action) => {
            return community_context_actions::reduce(state, action);
        }
        Action::AgentNameManagerInput(key) => {
            use tui_input::backend::crossterm::EventHandler;
            if let Some(o) = state.main_page.agent_names.as_mut()
                && o.phase == main_page::content::AgentNameManagerPhase::Ready
            {
                o.input.handle_event(&crossterm::event::Event::Key(*key));
            }
        }
        Action::AgentNameManagerSelect(down) => {
            if let Some(o) = state.main_page.agent_names.as_mut()
                && !o.names.is_empty()
            {
                if *down {
                    o.selected = (o.selected + 1).min(o.names.len() - 1);
                } else {
                    o.selected = o.selected.saturating_sub(1);
                }
            }
        }
        Action::AgentNameManagerConfirmRemove => {
            // Arm the confirm on the selected row (only when there is one and the
            // overlay is idle). The network remove runs on `AgentNameManagerRemove`.
            if let Some(o) = state.main_page.agent_names.as_mut()
                && o.phase == main_page::content::AgentNameManagerPhase::Ready
                && !o.names.is_empty()
            {
                o.confirm_remove = Some(o.selected);
            }
        }
        Action::AgentNameManagerCancelRemove => {
            if let Some(o) = state.main_page.agent_names.as_mut() {
                o.confirm_remove = None;
            }
        }
        Action::AgentNameManagerClose => {
            state.main_page.agent_names = None;
        }
        _ => return false,
    }
    true
}

/// Bring a just-joined community's session live (R-B-5 / D11): register it with
/// the multi-session manager and, when that creates a fresh session, start the
/// persona's DIDComm listener now so the VTC's asynchronous receipt arrives
/// without a restart. `add_listener` returns promptly — the mediator connect
/// proceeds under the listener's restart policy, and the `ListenerEvent::Connected`
/// handler flips the session to `Connected`. Failures are non-fatal (a restart
/// recovers the session) and surfaced to the activity log.
///
/// On the common path the listener is **already installed**: the join sequence
/// brings the applicant online before it submits, so a reply that arrives during
/// the submit is not stranded at the mediator (`join_flow::start_persona_listener`).
/// This is then the step that binds the community's session to it. The install
/// arm still matters — a State-A join, a listener that could not be opened before
/// the submit, or a reused persona whose session was dropped all land here.
/// Tear down a community's live session after it transitioned to an inactive
/// status (rejected, expired) — the lifecycle twin of [`register_joined_session`]
/// (R-S-3 / D15). Deregisters the session and, if its persona now serves no live
/// community, stops + removes the persona's listener so a dead community stops
/// holding a mediator connection. The community **record is retained** (R-S-1);
/// only the live session is dropped. Also drops the global messaging indicator to
/// `NoActiveCommunity` when the account has no live community left.
async fn deregister_inactive_community(
    session_manager: &mut session_manager::SessionManager,
    service: &openvtc_core::didcomm::Messaging,
    config: &Config,
    state: &mut State,
    vtc: &openvtc_core::config::account::VtcDid,
    pid: openvtc_core::config::account::PersonaId,
) {
    let removed = session_manager.deregister(pid, vtc);
    // The persona's listener stays up while it still serves any live membership
    // (it may belong to several communities, or this same VTC as another state).
    let still_live = config
        .account
        .memberships()
        .any(|c| c.persona_ref == pid && c.is_live());
    if !still_live && let Some(did) = config.identities.get(&pid).map(|id| id.did.clone()) {
        // Prefer the listener id the manager recorded; fall back to deriving it.
        let listener_id = removed
            .map(|s| s.listener_id)
            .unwrap_or_else(|| didcomm::persona_listener_id(&did));
        service.remove_listener(&listener_id).await;
        state
            .main_page
            .log("Community inactive — persona listener stopped.");
    }
    // Drop the global messaging indicator when no persona has a live community.
    if !config.account.memberships().any(|c| c.is_live()) {
        state.connection.status = state::MediatorStatus::NoActiveCommunity;
        state.connection.messaging_active = false;
    }
}

/// Whether a degraded-loop iteration must hand its runtime context back to
/// `run()` — see the invariant on [`StateHandler::run_degraded_loop`].
///
/// Two independent reasons, either sufficient:
///
/// - **`joined_a_community`** — a join succeeded, so a reply is coming to a loop
///   that cannot receive it. Deliberately *not* "…and this was the account's
///   first identity": that extra clause is what broke the ordinary first-run
///   order (create persona → join), because `Config::active_identity()` reports
///   `Some` for any persona at all, including one minted moments earlier by this
///   same loop's `CreatePersonaSubmit` arm.
/// - **`holds_listener`** — the messaging runtime owns a socket whatever opened
///   it. A listener with no consumer loses mail permanently, so this is a
///   hand-off condition in its own right.
///
/// `has_ctx` gates both: there is nothing to hand back without a runtime context.
fn must_hand_off(joined_a_community: bool, holds_listener: bool, has_ctx: bool) -> bool {
    (joined_a_community || holds_listener) && has_ctx
}

/// Reconcile every registered session against the messaging layer's live
/// connection state and re-derive the global indicator. Returns `true` if any
/// session's status changed. See [`session_manager::SessionManager::reconcile`]
/// for why the event stream alone is not enough.
fn reconcile_sessions(
    session_manager: &mut session_manager::SessionManager,
    service: &openvtc_core::didcomm::Messaging,
    state: &mut State,
) -> bool {
    let mut changed = false;
    for lid in session_manager.listener_ids() {
        let connected =
            service.listener_state(&lid) == Some(openvtc_core::didcomm::ConnState::Connected);
        changed |= session_manager.reconcile(&lid, connected);
    }
    if changed {
        apply_session_aggregate(session_manager, state);
    }
    changed
}

/// Drive the global connection indicator from the aggregate of all
/// persona-sessions. A `NoActiveCommunity` state is left untouched when no
/// session exists — "no community" is not "not connected".
fn apply_session_aggregate(session_manager: &session_manager::SessionManager, state: &mut State) {
    if session_manager.any_connected() {
        state.connection.status = state::MediatorStatus::Connected;
        state.connection.messaging_active = true;
    } else if session_manager.session_count() > 0 {
        state.connection.status = state::MediatorStatus::Connecting;
        state.connection.messaging_active = false;
    }
}

async fn register_joined_session(
    session_manager: &mut session_manager::SessionManager,
    service: &openvtc_core::didcomm::Messaging,
    tdk: &TDK,
    config: &Config,
    joined: join_flow::JoinedSession,
    state: &mut State,
) {
    use session_manager::RegisterOutcome;

    let lid = didcomm::persona_listener_id(&joined.persona_did);
    match session_manager.register(joined.persona_id, &lid, joined.vtc_did.clone()) {
        RegisterOutcome::JoinedExisting => {
            // A reused persona that is already live — the new community shares its
            // session; no new listener (D1/D11).
            state
                .main_page
                .log("New community attached to an existing live session.");
        }
        RegisterOutcome::AtCapacity => {
            // No silent caps (D15): the join succeeded but the bound is reached.
            state.main_page.log(format!(
                "Joined, but its live session is not active yet: the session limit ({}) is \
                 reached. It will connect when one frees up or on next launch.",
                session_manager.max_sessions(),
            ));
        }
        RegisterOutcome::Created => {
            // SessionManager had no session for this persona, but the DIDComm
            // service may already hold a listener for it — a persona reused across
            // communities can already be live via the relationship path, or a
            // listener SessionManager isn't tracking may linger. `add_listener`
            // errors on a duplicate id ("Listener already exists"), so reuse the
            // existing listener rather than failing the join's live session (D1).
            if service.has_listener(&lid).await {
                if service.listener_state(&lid) == Some(openvtc_core::didcomm::ConnState::Connected)
                {
                    session_manager.mark_connected(&lid);
                    // "its persona's", not "the persona's existing": on a fresh
                    // join this is usually the session the join sequence opened
                    // moments ago, and calling that pre-existing reads as if the
                    // operator had joined this community before.
                    state
                        .main_page
                        .log("New community bound to its persona's live session.");
                } else {
                    // The listener exists but isn't Running (Stopped/Failed): leave
                    // the session Connecting (as `register` set it) and let the
                    // restart policy / next launch bring it back — don't re-add it.
                    state
                        .main_page
                        .log("New community bound to its persona's session (reconnecting…).");
                }
                return;
            }
            match didcomm::persona_listener_config_for(config, tdk, joined.persona_id).await {
                Some(cfg) => {
                    if let Err(e) = didcomm::add_listener(service, &cfg).await {
                        session_manager.mark_failed(&lid, format!("{e:#}"));
                        state.main_page.log(format!(
                            "Joined, but couldn't start its live session now (it will connect \
                             on next launch): {e}"
                        ));
                    } else {
                        state.main_page.log("New community session connecting…");
                    }
                }
                None => {
                    // The join just wrote this identity, so this is unexpected — but
                    // never leave a registered session with no listener behind it.
                    session_manager.deregister(joined.persona_id, &joined.vtc_did);
                    state.main_page.log(
                        "Joined, but its identity could not be resolved to start a live session.",
                    );
                }
            }
        }
    }
}

// Per-domain action dispatch lives in the corresponding sub-module:
//   inbox_actions::dispatch
//   relationship_actions::dispatch
//   credential_actions::dispatch
//   settings_actions::dispatch

/// Build a DIDComm trust-pong message in response to a verified ping.
/// Used inline by the trust-ping handler in the main loop.
fn build_trust_pong(
    from: &str,
    to: &str,
    ping_id: &str,
) -> Result<affinidi_tdk::didcomm::Message, anyhow::Error> {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let message = affinidi_tdk::didcomm::Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping-response".to_string(),
        serde_json::Value::Null,
    )
    .from(from.to_string())
    .to(to.to_string())
    .thid(ping_id.to_string())
    .created_time(now)
    .finalize();

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::menu::MainMenu;

    /// The regression this function exists for.
    ///
    /// The degraded loop has no inbound arm, so a join made there must hand off
    /// to the runtime loop or the community's reply is ACKed by the SDK, deleted
    /// at the mediator, and dropped — leaving the join `Pending` forever with a
    /// clean log on both sides.
    ///
    /// The old condition also required the join to have minted the account's
    /// *first* identity. Creating a persona and then joining — the ordinary
    /// first-run order, and both actions the degraded loop serves — made that
    /// false and silently disabled the hand-off. Only the join matters.
    #[test]
    fn a_join_hands_off_even_when_a_persona_already_existed() {
        assert!(
            must_hand_off(true, false, true),
            "a successful join must hand off; whether a persona already existed \
             (CreatePersonaSubmit ran first) is irrelevant — requiring it to be \
             the first identity is the bug this test pins"
        );
    }

    /// The backstop: a live listener is a mailbox with no reader, whatever
    /// opened it.
    #[test]
    fn a_live_listener_alone_forces_the_hand_off() {
        assert!(
            must_hand_off(false, true, true),
            "a listener this loop cannot drain must force the hand-off even with \
             no join, so a future arm that opens one cannot silently lose mail"
        );
    }

    /// Nothing open, nothing joined: stay in the loop.
    #[test]
    fn an_idle_iteration_stays_in_the_degraded_loop() {
        assert!(!must_hand_off(false, false, true));
    }

    /// No runtime context, nothing to hand back — must not break out (the
    /// `join_ctx.take().expect(..)` below would panic).
    #[test]
    fn no_context_never_hands_off() {
        assert!(!must_hand_off(true, true, false));
    }

    /// Lifecycle log lines name the listener by its verified agent name — and
    /// carry the listener id it resolved from, because a name is not an
    /// identity: `resolve_did_to_display` is many-to-one, so without the id two
    /// different listeners can produce byte-identical lines.
    #[test]
    fn lifecycle_log_shows_the_agent_name_and_the_listener_id() {
        const DID: &str = "did:webvh:QmScidAAAAAAAAAAAAAAAAAAAAAAAA:webvh.storm.ws:magic-depart";

        let mut config = crate::state_handler::dispatch_util::test_config();
        config.set_cached_agent_name(
            DID,
            Some("webvh.storm.ws/@magic-depart".into()),
            chrono::Utc::now(),
        );

        let line = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Connected {
                listener_id: DID.to_string(),
            },
        );
        assert!(
            line.summary.contains("'webvh.storm.ws/@magic-depart'"),
            "{}",
            line.summary
        );
        assert!(
            line.summary.contains("did:webvh:QmScid"),
            "the name must not be the only identifier: {}",
            line.summary
        );
        assert!(line.summary.ends_with(" connected"), "{}", line.summary);
        assert!(
            line.detail.as_deref().is_some_and(|d| d.contains(DID)),
            "the full id belongs in the detail: {:?}",
            line.detail
        );

        // The error detail survives, alongside the resolved name.
        let line = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Disconnected {
                listener_id: DID.to_string(),
                error: Some("connection reset".into()),
            },
        );
        assert!(
            line.summary.ends_with("disconnected: connection reset"),
            "{}",
            line.summary
        );
    }

    /// Two listeners that render under the same name still produce
    /// distinguishable lines. This is the reported failure: a relationship
    /// R-DID resolves through to its peer's agent name, so a persona and an
    /// R-DID pointed at that same peer both read as `host/@name` — and a log
    /// full of one name gives no way to tell one listener reconnecting in a
    /// loop from several reconnecting on their own schedules.
    #[test]
    fn two_listeners_sharing_a_name_are_still_told_apart() {
        const PERSONA: &str = "did:webvh:QmScidAAAAAAAAAAAAAAAAAAAAAAAA:example.com:alice";
        const OTHER: &str = "did:webvh:QmScidZZZZZZZZZZZZZZZZZZZZZZZZ:example.com:alice-two";

        let mut config = crate::state_handler::dispatch_util::test_config();
        let now = chrono::Utc::now();
        config.set_cached_agent_name(PERSONA, Some("example.com/@alice".into()), now);
        config.set_cached_agent_name(OTHER, Some("example.com/@alice".into()), now);

        let one = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Disconnected {
                listener_id: PERSONA.to_string(),
                error: None,
            },
        );
        let two = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Disconnected {
                listener_id: OTHER.to_string(),
                error: None,
            },
        );

        assert_ne!(
            one.summary, two.summary,
            "distinct listeners must not render identically"
        );
        assert_ne!(one.detail, two.detail);
    }

    /// A drop with no transport error is reported as such. It used to render as
    /// a bare "disconnected", identical to a drop whose error was simply not
    /// captured — so "the socket closed cleanly" and "we lost it and cannot say
    /// why" were the same line.
    #[test]
    fn a_drop_without_an_error_says_so() {
        const DID: &str = "did:webvh:QmScidCCCCCCCCCCCCCCCCCCCCCCCC:example.com:quiet";
        let config = crate::state_handler::dispatch_util::test_config();

        let line = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Disconnected {
                listener_id: DID.to_string(),
                error: None,
            },
        );
        assert!(
            line.summary.contains("no transport error reported"),
            "{}",
            line.summary
        );
        assert!(
            line.detail
                .as_deref()
                .is_some_and(|d| d.contains("none reported")),
            "{:?}",
            line.detail
        );
    }

    /// The routine reconnect gets one calm line. It used to arrive as a
    /// disconnect *plus* a recovery every ~12 minutes — making the log's most
    /// alarming line the one it printed most often, which is how a real
    /// disconnect loses its meaning.
    #[test]
    fn a_brief_reconnect_reads_as_one_event_not_a_fault() {
        const DID: &str = "did:webvh:QmScidDDDDDDDDDDDDDDDDDDDDDDDD:example.com:brief";
        let config = crate::state_handler::dispatch_util::test_config();

        let line = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Reconnected {
                listener_id: DID.to_string(),
                down_for: std::time::Duration::from_millis(2100),
            },
        );
        assert!(
            line.summary.contains("reconnected after 2.1s"),
            "{}",
            line.summary
        );
        assert!(
            !line.summary.to_lowercase().contains("warning")
                && !line.summary.contains("disconnected"),
            "a routine reconnect must not read as a fault: {}",
            line.summary
        );
        assert!(
            line.detail
                .as_deref()
                .is_some_and(|d| d.contains("token is refreshed")),
            "{:?}",
            line.detail
        );
    }

    /// A drop only reaches the log after the reconnect grace, so the line has to
    /// say the listener is *still* down — otherwise it reads as the transient it
    /// has already been proven not to be.
    #[test]
    fn a_reported_drop_says_it_is_still_down() {
        const DID: &str = "did:webvh:QmScidEEEEEEEEEEEEEEEEEEEEEEEE:example.com:gone";
        let config = crate::state_handler::dispatch_util::test_config();

        let line = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Disconnected {
                listener_id: DID.to_string(),
                error: None,
            },
        );
        assert!(
            line.summary.contains("is still disconnected"),
            "{}",
            line.summary
        );
    }

    /// Without a verified name the line stays on the DID rather than going
    /// blank — and a lagged-stream notice carries no identifier at all.
    #[test]
    fn lifecycle_log_falls_back_to_the_did() {
        const DID: &str = "did:webvh:QmScidBBBBBBBBBBBBBBBBBBBBBBBB:example.com:nameless";

        let config = crate::state_handler::dispatch_util::test_config();
        let line = format_lifecycle_log(
            &config,
            &didcomm::LifecycleLog::Connected {
                listener_id: DID.to_string(),
            },
        )
        .summary;
        assert!(line.starts_with("Listener '"), "{line}");
        assert!(line.ends_with("' connected"), "{line}");
        assert!(
            !line.contains("@"),
            "no name exists, so none may appear: {line}"
        );
        // With no name substituted there is nothing to disambiguate, so the id
        // is not repeated in parentheses.
        assert!(!line.contains(") connected"), "id printed twice: {line}");

        let missed = format_lifecycle_log(&config, &didcomm::LifecycleLog::Missed { count: 3 });
        assert_eq!(missed.summary, "Missed 3 lifecycle event(s)");
        assert!(
            missed.detail.is_none(),
            "a lagged-stream notice identifies no listener"
        );
    }

    /// `resolve_did_to_display` precedence: a verified agent name is shown when
    /// present, but a user alias overrides it, and an unknown DID falls back to
    /// the truncated form.
    #[test]
    fn resolve_did_to_display_prefers_alias_then_agent_name() {
        use crate::state_handler::dispatch_util::test_config;

        let did = "did:webvh:example.com:alice";
        let mut config = test_config();

        // No alias, no cached name → truncated DID.
        assert_eq!(
            resolve_did_to_display(&config, did),
            openvtc_core::display::truncate_did(did, 30)
        );

        // A verified agent name is now shown.
        config.set_cached_agent_name(did, Some("example.com/@alice".into()), chrono::Utc::now());
        assert_eq!(resolve_did_to_display(&config, did), "example.com/@alice");

        // A user alias on the same DID overrides the agent name.
        let key = std::sync::Arc::new(did.to_string());
        config.private.contacts.contacts.insert(
            key.clone(),
            std::sync::Arc::new(openvtc_core::config::protected_config::Contact {
                did: key,
                alias: Some("Alice".to_string()),
            }),
        );
        assert_eq!(resolve_did_to_display(&config, did), "Alice");
    }

    /// The remove-confirm arm/cancel transitions on the agent-name overlay:
    /// `ConfirmRemove` arms the selected row (only when Ready and non-empty),
    /// `CancelRemove` clears it.
    #[test]
    fn agent_name_remove_confirm_arms_and_cancels() {
        use crate::state_handler::main_page::content::{
            AgentNameManagerPhase, AgentNameManagerState, AgentNameRow,
        };
        let mut state = State::default();
        state.main_page.agent_names = Some(AgentNameManagerState {
            phase: AgentNameManagerPhase::Ready,
            names: vec![
                AgentNameRow {
                    name: "alice".into(),
                    enabled: true,
                },
                AgentNameRow {
                    name: "alias".into(),
                    enabled: false,
                },
            ],
            selected: 1,
            ..Default::default()
        });

        assert!(handle_nav_action(
            &mut state,
            &Action::AgentNameManagerConfirmRemove
        ));
        assert_eq!(
            state.main_page.agent_names.as_ref().unwrap().confirm_remove,
            Some(1),
            "arms the selected row"
        );

        assert!(handle_nav_action(
            &mut state,
            &Action::AgentNameManagerCancelRemove
        ));
        assert_eq!(
            state.main_page.agent_names.as_ref().unwrap().confirm_remove,
            None,
            "cancel clears the arm"
        );
    }

    /// Drive `handle_nav_action` directly over a fresh `State`. Because the
    /// reducer is the single code path both the runtime loop and the degraded
    /// loop call, asserting it here proves *both* loops apply identical handling
    /// for these actions — there is no per-loop copy to drift.
    #[test]
    fn nav_reducer_handles_shared_arms_identically() {
        struct Case {
            name: &'static str,
            action: Action,
            assert_fn: fn(&State),
        }

        let cases = [
            Case {
                name: "DismissLoading reveals the main page",
                action: Action::DismissLoading,
                assert_fn: |s| {
                    assert!(
                        matches!(s.active_page, state::ActivePage::Main),
                        "expected ActivePage::Main"
                    )
                },
            },
            Case {
                name: "MainMenuSelected updates the menu selection",
                action: Action::MainMenuSelected(MainMenu::Settings),
                assert_fn: |s| assert_eq!(s.main_page.menu_panel.selected_menu, MainMenu::Settings),
            },
            Case {
                name: "MainPanelSwitch(ContentPanel) moves focus to the content panel",
                action: Action::MainPanelSwitch(MainPanel::ContentPanel),
                assert_fn: |s| {
                    assert!(!s.main_page.menu_panel.selected);
                    assert!(s.main_page.content_panel.selected);
                },
            },
            Case {
                name: "MainPanelSwitch(MainMenu) moves focus back to the menu",
                action: Action::MainPanelSwitch(MainPanel::MainMenu),
                assert_fn: |s| {
                    assert!(s.main_page.menu_panel.selected);
                    assert!(!s.main_page.content_panel.selected);
                },
            },
            Case {
                name: "CommunitySelect updates the selected index",
                action: Action::CommunitySelect(3),
                assert_fn: |s| assert_eq!(s.main_page.content_panel.communities.selected_index, 3),
            },
            Case {
                name: "CommunityConfirmDelete arms the confirmation",
                action: Action::CommunityConfirmDelete(2),
                assert_fn: |s| {
                    assert_eq!(
                        s.main_page.content_panel.communities.confirm_delete,
                        Some(2)
                    )
                },
            },
            Case {
                name: "CommunityConfirmLeave arms the leave confirmation",
                action: Action::CommunityConfirmLeave(1),
                assert_fn: |s| {
                    assert_eq!(s.main_page.content_panel.communities.confirm_leave, Some(1))
                },
            },
            Case {
                name: "DidConfirmDelete arms the persona confirmation (degraded mode used to drop this)",
                action: Action::DidConfirmDelete(1),
                assert_fn: |s| {
                    assert_eq!(
                        s.main_page.content_panel.identity.confirm,
                        main_page::content::PersonaConfirm::DeletePersona(1)
                    )
                },
            },
        ];

        for case in cases {
            let mut state = State::default();
            let handled = handle_nav_action(&mut state, &case.action);
            assert!(handled, "nav reducer should handle: {}", case.name);
            (case.assert_fn)(&state);
        }
    }

    /// Loop-local arms (terminating + async) must NOT be claimed by the shared
    /// reducer; it returns `false` so each loop falls through to its own arm.
    /// `Exit` in particular is signalled via the return value, not handled here.
    #[test]
    fn nav_reducer_defers_loop_local_arms() {
        let mut state = State::default();
        assert!(
            !handle_nav_action(&mut state, &Action::Exit),
            "Exit must be deferred to the loop (it breaks with the loop's outcome type)"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::DeleteCommunity(0)),
            "DeleteCommunity is async/loop-local"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::DeleteDid(0)),
            "DeleteDid is async/loop-local"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::StartJoin),
            "StartJoin is async/loop-local"
        );
        // The switcher's config-mutating arms resolve a community + persona and
        // must reach the loop, not the pure reducer (R-C-7).
        assert!(
            !handle_nav_action(&mut state, &Action::OpenCommunitySwitcher),
            "OpenCommunitySwitcher reads config in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::CommunitySwitcherSelect),
            "CommunitySwitcherSelect mutates config in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::ToggleFavourite(0)),
            "ToggleFavourite mutates + persists config in the loop"
        );
        // T7 community-management arms also reach the loop (network send / config
        // mutation / re-sync), not the pure reducer.
        assert!(
            !handle_nav_action(&mut state, &Action::LeaveCommunity(0)),
            "LeaveCommunity sends MEMBER_SELF_REMOVE in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::ArchiveCommunity(0)),
            "ArchiveCommunity mutates + persists config in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::ToggleShowArchived),
            "ToggleShowArchived re-syncs from config in the loop"
        );
        // The persona mint (and its clipboard copy) reach the loop, not the pure
        // reducer (network + config mutation). NB: being loop-local, these must be
        // wired in BOTH the runtime loop and `run_degraded_loop` — the State-A
        // (no-identity) account that runs the degraded loop is exactly when a user
        // creates their first persona DID.
        assert!(
            !handle_nav_action(&mut state, &Action::CreatePersonaSubmit),
            "CreatePersonaSubmit mints via the VTA in the loop"
        );
        assert!(
            !handle_nav_action(&mut state, &Action::CreatePersonaCopy),
            "CreatePersonaCopy touches the clipboard in the loop"
        );
    }

    /// The persona context choice is view state, shared by both loops: moving
    /// the highlight, naming a new context (on its row only), and going back.
    /// A community-context view action is too, while one that reaches the VTA
    /// is left to the loop.
    #[test]
    fn nav_reducer_moves_through_the_persona_context_choice() {
        use crate::state_handler::actions::CommunityContextAction;
        use crate::state_handler::main_page::content::{
            CreatePersonaPhase, CreatePersonaState, DeviceAccessView,
        };
        use openvtc_core::config::community_context::{ContextKind, ContextOption};

        let option = |id: &str, kind| ContextOption {
            context_id: id.to_string(),
            kind,
            communities: vec![],
            holds_persona_keys: false,
        };
        let mut state = State::default();
        state.main_page.create_persona = Some(CreatePersonaState {
            phase: CreatePersonaPhase::Context,
            context_options: vec![
                option("openvtc/a", ContextKind::New),
                option("openvtc", ContextKind::Top),
            ],
            context_slug: "a".to_string(),
            ..Default::default()
        });
        let overlay = |s: &State| s.main_page.create_persona.clone().unwrap();

        assert!(handle_nav_action(
            &mut state,
            &Action::CreatePersonaContextSelect(9)
        ));
        assert_eq!(overlay(&state).context_selected, 1);
        handle_nav_action(&mut state, &Action::CreatePersonaContextSlug("b".into()));
        assert_eq!(
            overlay(&state).context_slug,
            "a",
            "the top row takes no name"
        );
        handle_nav_action(&mut state, &Action::CreatePersonaContextSelect(0));
        handle_nav_action(
            &mut state,
            &Action::CreatePersonaContextSlug("laptop".into()),
        );
        assert_eq!(overlay(&state).context_slug, "laptop");
        assert!(handle_nav_action(&mut state, &Action::CreatePersonaBack));
        assert_eq!(overlay(&state).phase, CreatePersonaPhase::Label);

        state.main_page.content_panel.communities.device_access = Some(DeviceAccessView {
            community: "a".into(),
            context_id: "openvtc/a".into(),
            can_grant: true,
            selected: 0,
            form: None,
            confirm_revoke: false,
            busy: false,
            message: None,
        });
        assert!(handle_nav_action(
            &mut state,
            &Action::CommunityContext(CommunityContextAction::DevicesClose)
        ));
        assert!(
            state
                .main_page
                .content_panel
                .communities
                .device_access
                .is_none()
        );
        assert!(!handle_nav_action(
            &mut state,
            &Action::CommunityContext(CommunityContextAction::DeleteStart(0))
        ));
    }

    /// The create-persona overlay's UI-only arms (open / edit label / close) are
    /// handled by the pure reducer so both loops share them.
    #[test]
    fn nav_reducer_handles_create_persona_overlay() {
        use crate::state_handler::main_page::content::CreatePersonaPhase;
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let mut state = State::default();
        // Open the overlay on its label phase.
        assert!(handle_nav_action(&mut state, &Action::StartCreatePersona));
        let overlay = state
            .main_page
            .create_persona
            .as_ref()
            .expect("overlay open");
        assert_eq!(overlay.phase, CreatePersonaPhase::Label);

        // Editing keys append to the label.
        let key =
            |c| Action::CreatePersonaInput(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        assert!(handle_nav_action(&mut state, &key('h')));
        assert!(handle_nav_action(&mut state, &key('i')));
        assert_eq!(
            state
                .main_page
                .create_persona
                .as_ref()
                .unwrap()
                .label
                .value(),
            "hi"
        );

        // Close clears the overlay.
        assert!(handle_nav_action(&mut state, &Action::CreatePersonaClose));
        assert!(state.main_page.create_persona.is_none());
    }

    /// The switcher's UI-only arms (move highlight / close) are handled by the
    /// pure reducer so both loops share them (R-C-7).
    #[test]
    fn nav_reducer_handles_switcher_navigation() {
        use crate::state_handler::main_page::content::{CommunitySwitcherState, SwitcherItem};

        let item = |n: &str| SwitcherItem {
            vtc_did: format!("did:example:{n}"),
            persona_ref: openvtc_core::config::account::PersonaId::new(),
            display_name: n.to_string(),
            persona_label: String::new(),
            is_current: false,
        };
        let mut state = State::default();
        state.main_page.switcher = Some(CommunitySwitcherState {
            items: vec![item("a"), item("b"), item("c")],
            selected: 0,
        });

        assert!(handle_nav_action(
            &mut state,
            &Action::CommunitySwitcherMove(2)
        ));
        assert_eq!(state.main_page.switcher.as_ref().unwrap().selected, 2);

        // Out-of-range moves clamp to the last entry rather than panicking.
        assert!(handle_nav_action(
            &mut state,
            &Action::CommunitySwitcherMove(99)
        ));
        assert_eq!(state.main_page.switcher.as_ref().unwrap().selected, 2);

        assert!(handle_nav_action(
            &mut state,
            &Action::CloseCommunitySwitcher
        ));
        assert!(state.main_page.switcher.is_none());
    }

    /// The refresh guard's three outcomes.
    ///
    /// The middle one is the interesting one: a request that arrives while the
    /// vault is busy is *deferred*, not dropped. The in-flight query was issued
    /// before whatever prompted this request — a lifecycle mutation, or an `i`
    /// filter flip — so its answer is already stale, and discarding the new
    /// request would leave, say, a just-archived VIC rendered as active until
    /// someone refreshed by hand.
    #[test]
    fn vic_refresh_guard_defers_rather_than_drops() {
        let mut state = State::default();
        let mut in_flight = background_dispatch::InFlight::default();

        // No admin session: nothing to query, and the panel must not be left
        // claiming a load is under way.
        state.main_page.content_panel.vta.vic_loading = true;
        assert!(!begin_vic_refresh(&mut in_flight, &mut state, false));
        assert!(!state.main_page.content_panel.vta.vic_loading);
        assert!(!in_flight.is_busy(background_dispatch::DispatchDomain::Vic));

        // First request with a session: claims the domain and starts loading.
        assert!(begin_vic_refresh(&mut in_flight, &mut state, true));
        assert!(state.main_page.content_panel.vta.vic_loading);
        assert!(in_flight.is_busy(background_dispatch::DispatchDomain::Vic));

        // Second while that one is in flight: not started, but remembered.
        assert!(!begin_vic_refresh(&mut in_flight, &mut state, true));
        assert!(
            state.main_page.content_panel.vta.vic_refresh_queued,
            "a rejected refresh must be re-issued once the domain frees"
        );

        // Once the outcome lands the domain is free and the queued request runs.
        in_flight.finish(background_dispatch::DispatchDomain::Vic);
        state.main_page.content_panel.vta.vic_refresh_queued = false;
        assert!(begin_vic_refresh(&mut in_flight, &mut state, true));
    }
}
