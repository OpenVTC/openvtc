//! The runtime's event arms other than inbound messages and the periodic
//! sweeps: UI actions, dispatch outcomes, presence and the admin-session
//! supervisor, listener lifecycle, the TSP store, saves and VTA account sync.

use super::*;
#[allow(unused_imports)]
use crate::state_handler::state::PublishState;
use crate::state_handler::*;

impl Runtime {
    /// A UI action. Everything but leaving and the join flow's entry points is
    /// `runtime_actions::handle_action`'s — and while a join is open, every
    /// action is the join's, as the screen is.
    pub(super) async fn on_action(&mut self, action: Action) -> Flow {
        if self.join.is_active() {
            let (join, mut ctx) = self.join_parts();
            let step = join.on_action(&mut ctx, action).await;
            return match self.apply_join_step(step).await {
                Some(interrupted) => Flow::Exit(interrupted),
                None => Flow::Continue,
            };
        }
        let Runtime {
            state,
            config,
            join_entry,
            awaiting_requirements,
            awaiting_challenge,
            awaiting_wallet,
            terminator,
            ..
        } = self;
        match action {
            Action::Exit => {
                if let Err(e) = terminator.terminate(Interrupted::UserInt) {
                    debug!("Failed to send terminate signal: {e}");
                }

                return Flow::Exit(Interrupted::UserInt);
            }

            Action::StartJoin => {
                // State-B join from the live runtime: reuse the always-on
                // admin VTA session. The DIDComm service keeps running, and
                // so does this loop: the join is driven from here, and owns
                // the screen until the user returns. Entered at the loop's
                // tail, which is also where a join waiting on a community's
                // requirements is entered again.
                *join_entry = Some(join_flow::JoinEntry::Fresh);
            }
            // The same join, for a community already chosen: `j` on a
            // vetting application resumes the join that application was
            // made for, without going back for its DID.
            Action::StartJoinFor(vtc_did) => {
                *join_entry = Some(join_flow::JoinEntry::ForCommunity { vtc_did });
            }
            // A join waiting on a community's requirements keeps its screen
            // up while this loop hears the answer, so the two keys that
            // page offers land here rather than in the join flow.
            Action::JoinCancel if awaiting_requirements.is_some() => {
                if let Some(awaiting) = awaiting_requirements.take() {
                    config.private.vetting.forget_query(&awaiting.document_id);
                }
                state.active_page = state::ActivePage::Main;
            }
            Action::JoinVettingJoin if awaiting_requirements.is_some() => {
                if let Some(awaiting) = awaiting_requirements.take() {
                    config.private.vetting.forget_query(&awaiting.document_id);
                    *join_entry = Some(join_flow::JoinEntry::Resume {
                        vtc_did: awaiting.vtc_did,
                        outcome: join_flow::RequirementsOutcome::Skipped,
                    });
                }
            }
            // Leaving a join parked on its challenge. Nothing was sent
            // but the question, and the challenge it brings stands
            // unused until the community lets it lapse.
            Action::JoinCancel if awaiting_challenge.is_some() => {
                if let Some(awaiting) = awaiting_challenge.take() {
                    config.private.vetting.forget_query(&awaiting.document_id);
                }
                state.join.processing = false;
                state.join.waiting_on_challenge = false;
                state.main_page.log(
                    "Stopped waiting for the community's challenge. Nothing was sent — \
                                     join again when you are ready.",
                );
                state.active_page = state::ActivePage::Main;
            }
            // Leaving a wallet session. The session lapses on its own;
            // the page offers to try again or go on without it.
            Action::JoinCancel if awaiting_wallet.is_some() => {
                if let Some(query) = awaiting_wallet.take().and_then(|a| a.asking) {
                    config.private.vetting.forget_query(&query);
                }
                *join_entry = Some(join_flow::JoinEntry::Wallet {
                    end: join_flow::WalletEnd::Unfinished(
                        "You stopped waiting for the wallet. Nothing has been sent to \
                                         the community but the session request."
                            .to_string(),
                    ),
                });
            }
            // Everything else acts on state and the resources below,
            // and lives in `runtime_actions` where a test can call it.
            // Only the three arms above need what a loop has and a
            // handler cannot be given: the terminator, the action
            // receiver, and the ability to `break` with this loop's own
            // outcome type.
            action => {
                if matches!(
                    runtime_actions::handle_action(&mut self.action_ctx(), action).await,
                    runtime_actions::Handled::ExitUserInt
                ) {
                    // A confirmed profile wipe. The handler cannot break
                    // this loop or reach the terminator, so it says so.
                    if let Err(e) = self.terminator.terminate(Interrupted::UserInt) {
                        debug!("Failed to send terminate signal: {e}");
                    }
                    return Flow::Exit(Interrupted::UserInt);
                }
            }
        }
        Flow::Continue
    }

    /// Background-dispatch completions (R13). A network-bound action
    /// that was spawned off the loop (e.g. the mediator reconnect)
    /// delivers its result here; the outcome is applied on this thread
    /// (the single mutator) and the domain's busy-flag is cleared.
    /// Because this is just another select arm, nav actions, `q`/Exit,
    /// and inbound DIDComm events are all serviced *while* the spawned
    /// I/O is still pending.
    pub(super) async fn on_dispatch_outcome(
        &mut self,
        outcome: background_dispatch::DispatchOutcome,
    ) -> Flow {
        // The join's own jobs, before the shared applier: the driver matches
        // each to the job it is waiting for.
        let outcome = match outcome {
            background_dispatch::DispatchOutcome::Join(outcome) => {
                let (join, mut ctx) = self.join_parts();
                let step = join.on_outcome(&mut ctx, *outcome).await;
                let flow = match self.apply_join_step(step).await {
                    Some(interrupted) => Flow::Exit(interrupted),
                    None => Flow::Continue,
                };
                self.release_held_inbound().await;
                return flow;
            }
            background_dispatch::DispatchOutcome::Progress(
                background_dispatch::ProgressUpdate::Join { generation, line },
            ) => {
                self.join.on_progress(&mut self.state, generation, line);
                return Flow::Continue;
            }
            outcome => outcome,
        };
        let mut minted = None;
        let Runtime {
            state,
            config,
            tdk,
            admin_vta,
            didcomm_service,
            save,
            in_flight,
            dispatch_tx,
            session_manager,
            witness_router,
            ping_sent_at,
            handler,
            pending_replies,
            ..
        } = self;
        let after = background_dispatch::apply_outcome(
            state,
            config,
            save,
            in_flight,
            pending_replies,
            outcome,
        );
        // A VTA answer or a failed send may call for the Rooms panel's next
        // step, and frees the lane it waits on.
        rooms_actions::advance(&mut rooms_actions::Loop {
            state,
            config,
            tdk,
            vta: admin_vta.as_ref(),
            dispatch_tx,
            in_flight,
            pending_replies,
        })
        .await;
        // The same for the Elections panel.
        elections_actions::advance(&mut elections_actions::Loop {
            state,
            config,
            tdk,
            vta: admin_vta.as_ref(),
            dispatch_tx,
            in_flight,
            pending_replies,
        })
        .await;
        let settled = settle_after_apply(after, state, config, save, tdk).await;
        match settled {
            // A community we have just left still holds a messaging
            // session. The session manager lives here, not in the
            // shared apply path, so the outcome reports the teardown
            // and this arm performs it. Local work — removing a
            // listener — not a network call.
            AfterSettle::Deregister(vtc, persona) => {
                deregister_inactive_community(
                    session_manager,
                    didcomm_service,
                    config,
                    state,
                    &vtc,
                    persona,
                )
                .await;
                state.main_page.sync_from_config(config);
            }
            // A persona minted while running has no listener yet
            // (startup builds one per identity; this path does not).
            // Bring it up so it can vet/apply/join without a restart.
            // It has no community, so — like a community-less identity
            // at startup — it gets a listener but no session-manager
            // entry (that is per (persona, community)).
            AfterSettle::PersonaMinted(persona_id) => minted = Some(persona_id),
            AfterSettle::HiddenVetting(outcome) => {
                let mut ctx = runtime_actions::ActionCtx {
                    state,
                    config,
                    save,
                    in_flight,
                    dispatch_tx,
                    tdk,
                    admin_vta: admin_vta.as_ref(),
                    didcomm_service,
                    session_manager,
                    ping_sent_at,
                    state_tx: &handler.state_tx,
                    profile: handler.profile.as_str(),
                    witness_router,
                    pending_replies,
                };
                vetting_actions::apply_pcs_outcome(&mut ctx, *outcome).await;
            }
            AfterSettle::Nothing => {}
        }
        // A refresh asked for while the vault was busy is re-issued
        // here, now that the domain is free — see `vic_refresh_queued`.
        if state.main_page.content_panel.vta.vic_refresh_queued {
            state.main_page.content_panel.vta.vic_refresh_queued = false;
            spawn_vic_refresh(dispatch_tx, in_flight, state, admin_vta.as_ref());
        }
        // Same rule for the identity pane: a write that just landed
        // asked for the listing it invalidated, and could not start
        // it while its own outcome held the domain.
        if state.main_page.content_panel.identity.refresh_queued {
            state.main_page.content_panel.identity.refresh_queued = false;
            spawn_persona_effect(
                dispatch_tx,
                in_flight,
                state,
                admin_vta.as_ref(),
                persona_actions::PersonaEffect::Read,
            );
        }
        if let Some(persona_id) = minted {
            if self.join.is_active() {
                // Minted from the join's own create-persona overlay: the join
                // offers it as a way in, and brings it online itself.
                let (join, mut ctx) = self.join_parts();
                join.on_persona_minted(&mut ctx, persona_id).await;
            } else {
                install_persona_listener(
                    &self.didcomm_service,
                    &self.tdk,
                    &self.config,
                    persona_id,
                    &mut self.state,
                )
                .await;
            }
        }
        Flow::Continue
    }

    /// D13 presence: another install using this account, or a
    /// report that we could not tell. The task never touches
    /// `State` — everything lands here, in the single mutator.
    pub(super) async fn on_presence(&mut self, report: device_presence::PresenceReport) {
        let Runtime {
            state,
            admin_vta,
            vta_supervisor,
            handler,
            ..
        } = self;
        match report {
            device_presence::PresenceReport::Registered { device_id } => {
                debug!(%device_id, "this install is registered with the VTA");
                state.self_device_id = Some(device_id);
            }
            device_presence::PresenceReport::NewSiblings(siblings) => {
                if let Some(warning) = openvtc_core::devices::sibling_warning(&siblings) {
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
                let _ = handler.state_tx.publish(state);
            }
            device_presence::PresenceReport::Failing {
                what,
                reason,
                replies_not_arriving,
            } => {
                // Shown in the panel (the task has already logged it
                // at WARN), so an absence of sibling warnings is not
                // mistaken for an absence of siblings.
                // Logged once per failing spell, not every interval.
                let problem = format!("{} failed: {reason}", what.label());
                let receive = &mut state.main_page.content_panel.vta.receive;
                let first = receive.presence_problem.is_none();
                receive.presence_problem = Some(problem.clone());
                if first {
                    state.main_page.log(format!("WARNING: {problem}"));
                }
                // The session's replies have stopped: act on it now,
                // not at the next health tick.
                if replies_not_arriving {
                    vta_supervisor.check(admin_vta.as_ref(), &mut state.main_page);
                }
            }
            device_presence::PresenceReport::Recovered => {
                state.main_page.content_panel.vta.receive.presence_problem = None;
            }
        }
    }

    /// The admin session's receive leg: read its health (no I/O) for
    /// the panel, and start a rebuild when one is due.
    pub(super) async fn on_vta_health_tick(&mut self) {
        let Runtime {
            state,
            admin_vta,
            vta_supervisor,
            ..
        } = self;
        vta_supervisor.check(admin_vta.as_ref(), &mut state.main_page);
    }

    /// A rebuild of the stalled admin session landed. Swap the new
    /// client in everywhere the session is held: `admin_vta` (which
    /// every later operation borrows or clones from) and the
    /// presence task's watch.
    pub(super) async fn on_vta_rebuilt(&mut self, outcome: vta_recovery::RebuildOutcome) {
        let Runtime {
            state,
            admin_vta,
            didcomm_service,
            vta_supervisor,
            ..
        } = self;
        if let Some(client) = vta_supervisor.land(outcome, &mut state.main_page) {
            // Collection claims are made on the live session too.
            didcomm_service.set_collection_vta(Some(client.clone()));
            *admin_vta = Some(client);
        }
    }

    /// Lifecycle log messages from the Messaging
    pub(super) async fn on_lifecycle_log(&mut self, event: didcomm::LifecycleLog) {
        let Runtime { state, config, .. } = self;
        // Formatted here, not in the logger task: naming a listener
        // needs `config`, which only this thread holds.
        let line = format_lifecycle_log(config, &event);
        match line.detail {
            Some(detail) => state.main_page.log_detailed(line.summary, detail),
            None => state.main_page.log(line.summary),
        }
    }

    /// Typed listener lifecycle events → drive the connection status
    /// asynchronously (phase 2). The persona listener connecting flips
    /// the status to Connected; a disconnect drops back to Connecting
    /// while the service auto-reconnects.
    pub(super) async fn on_listener_event(
        &mut self,
        ev: Result<didcomm::ListenerStatus, tokio::sync::broadcast::error::RecvError>,
    ) {
        let Runtime {
            state,
            config,
            session_manager,
            ..
        } = self;
        if let Ok(ev) = ev {
            // Route persona-listener lifecycle through the session
            // manager (D11/D15), which holds per-session status; a
            // disconnect carrying an error is recorded as that one
            // session failing (isolated — others are untouched). The
            // SDK keeps retrying per its restart policy, so a restart
            // or clean drop is "not connected" until the next connect.
            // Events for R-DID listeners (not persona sessions) match
            // nothing and are ignored.
            // Every listener's state, session or not, for the
            // indicator's no-community reading.
            let online = &mut state.connection.online_listeners;
            let listener_changed = match &ev {
                didcomm::ListenerStatus::Connected { listener_id } => {
                    online.insert(listener_id.clone())
                }
                didcomm::ListenerStatus::Disconnected { listener_id, .. } => {
                    online.remove(listener_id)
                }
            };
            // A listener that has just come up can carry what could not be sent
            // while it was down: re-ask the communities' modes now.
            if matches!(ev, didcomm::ListenerStatus::Connected { .. }) {
                config.private.vetting.listener_connected();
            }
            let changed = listener_changed
                | match ev {
                    didcomm::ListenerStatus::Connected { listener_id } => {
                        session_manager.mark_connected(&listener_id)
                    }
                    didcomm::ListenerStatus::Disconnected { listener_id, error } => match error {
                        Some(e) => session_manager.mark_failed(&listener_id, e),
                        None => session_manager.mark_disconnected(&listener_id),
                    },
                };
            // Derive the global connection indicator from the
            // aggregate of all persona-sessions (a per-community
            // status panel is future UI work).
            if changed {
                apply_session_aggregate(session_manager, state);
            }
        }
    }

    /// The backstop for the edge-triggered listener-status stream. Returns
    /// whether a session's status changed.
    pub(super) async fn on_session_reconcile(&mut self) -> bool {
        let Runtime {
            state,
            didcomm_service,
            session_manager,
            ..
        } = self;
        // The loop tail broadcasts `state`, so a change here reaches
        // the UI without an explicit send.
        reconcile_sessions(session_manager, didcomm_service, state)
    }

    /// A background TSP relationship write (an invite recorded by the
    /// inbound dispatcher, a relationship formed by a send) changed the
    /// durable store. Snapshot it into the config and mark it dirty; the
    /// deadline arm below persists it on the same coalesced schedule as
    /// every other mutation. `Notify` holds one permit, so a write that
    /// lands between iterations is not missed, and a burst collapses to
    /// one snapshot — which is exactly the coalescing we want.
    pub(super) async fn on_tsp_dirty(&mut self) {
        let Runtime {
            state,
            config,
            didcomm_service,
            save,
            ..
        } = self;
        config.private.tsp_relationships = didcomm_service.tsp_store().snapshot().await;
        save.mark_dirty();
        // A relationship changed, so the pane's view of it is stale.
        // Recompute here — the same event that persists it also
        // refreshes what the user sees.
        let rows = compute_tsp_relationship_rows(config, &didcomm_service.tsp_store()).await;
        state.main_page.content_panel.tsp_relationships.rows = rows.into();
    }

    pub(super) async fn on_save_deadline(&mut self) {
        let Runtime {
            state,
            config,
            save,
            save_done_tx,
            ..
        } = self;
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
    }

    /// A backgrounded coalesced save finished (R11). Clear the
    /// in-flight flag and re-arm if the config was dirtied again. A
    /// failed save is surfaced exactly as the old inline `save_config`
    /// failure did (status + log) and left dirty for retry.
    pub(super) async fn on_save_done(&mut self, result: Result<(), String>) {
        let Runtime {
            state,
            save,
            vta_sync,
            ..
        } = self;
        match &result {
            // What was just saved may be news for the VTA.
            Ok(()) => vta_sync.request(),
            Err(reason) => {
                state
                    .main_page
                    .log_error("Failed to save config", &anyhow::anyhow!("{reason}"));
            }
        }
        save.finish(result.is_ok());
    }

    /// Start a VTA account-sync cycle when one is due. Returns whether one
    /// started.
    pub(super) async fn on_vta_sync_tick(&mut self) -> bool {
        let Runtime {
            config,
            admin_vta,
            vta_sync,
            vta_sync_tx,
            ..
        } = self;
        if let Some(client) = admin_vta.as_ref()
            && !config.account.top_context_id.is_empty()
            && vta_sync.should_start(tokio::time::Instant::now())
        {
            let context_id = config.account.top_context_id.clone();
            config.private.vta_sync.bind_context(&context_id);
            let view = openvtc_core::vta_sync::SyncView {
                account: &config.account,
                private: &config.private,
                key_info: &config.key_info,
            };
            let out = openvtc_core::vta_sync::outgoing(&view, &config.private.vta_sync);
            let since = config.private.vta_sync.watermark;
            let client = client.clone();
            let tx = vta_sync_tx.clone();
            tokio::spawn(async move {
                let ex = openvtc_core::vta_sync::exchange(&client, &context_id, since, out).await;
                let _ = tx.send(ex);
            });
            return true;
        }
        false
    }

    pub(super) async fn on_vta_sync_exchange(&mut self, ex: openvtc_core::vta_sync::Exchange) {
        let Runtime {
            state,
            config,
            save,
            vta_sync,
            ..
        } = self;
        let mut report = openvtc_core::vta_sync::SyncReport::default();
        let mut sync_state = std::mem::take(&mut config.private.vta_sync);
        let lost_race = {
            let mut parts = openvtc_core::vta_sync::SyncParts {
                account: &mut config.account,
                private: &mut config.private,
                key_info: &mut config.key_info,
            };
            openvtc_core::vta_sync::absorb(
                &mut parts,
                &mut sync_state,
                ex,
                openvtc_core::vta_sync::ApplyMode::Live,
                &mut report,
            )
        };
        config.private.vta_sync = sync_state;
        let error = report.error.take();
        for line in report.log_lines() {
            state.main_page.log(line);
        }
        if vta_sync.finished(tokio::time::Instant::now(), error.as_ref())
            && let Some(e) = &error
        {
            state.main_page.log(e.explain());
        }
        if lost_race {
            // The merged record goes up on the next cycle.
            vta_sync.request();
        }
        if !report.changed.is_empty() {
            state.main_page.sync_from_config(config);
        }
        if report.touched() {
            save.mark_dirty();
        }
    }
}
