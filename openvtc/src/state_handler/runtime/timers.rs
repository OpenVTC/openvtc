//! The runtime's periodic sweeps.

use super::*;
#[allow(unused_imports)]
use crate::state_handler::state::PublishState;
use crate::state_handler::*;

impl Runtime {
    /// Coalesced-save debounce (R11). Fires when the debounce window
    /// since the first dirty mark of a burst elapses. Builds an owned
    /// snapshot on this (the single mutator) thread and runs the heavy
    /// serialize+encrypt+keyring+card I/O on a blocking thread so the
    /// loop stays responsive. At most one save is in flight; a mark
    /// that lands while a save runs is re-scheduled on completion.
    /// When nothing is scheduled the arm parks forever (no busy-wait).
    pub(super) async fn on_capabilities_sweep(&mut self) {
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
            pending_replies,
            ping_sent_at,
            join_entry,
            awaiting_requirements,
            awaiting_challenge,
            awaiting_wallet,
            handler,
            ..
        } = self;
        // The Repos panel: reply windows, and polling a forge-account
        // link no faster than the spec's five seconds.
        repos_actions::tick(&mut repos_actions::Loop {
            state,
            config,
            tdk,
            vta: admin_vta.as_ref(),
            dispatch_tx,
            in_flight,
            pending_replies,
        })
        .await;
        // The Rooms panel: reply windows, and a step left on a busy lane.
        rooms_actions::tick(&mut rooms_actions::Loop {
            state,
            config,
            tdk,
            vta: admin_vta.as_ref(),
            dispatch_tx,
            in_flight,
            pending_replies,
        })
        .await;
        // The Elections panel: the same.
        elections_actions::tick(&mut elections_actions::Loop {
            state,
            config,
            tdk,
            vta: admin_vta.as_ref(),
            dispatch_tx,
            in_flight,
            pending_replies,
        })
        .await;
        // Questions to communities have a reply window too (R1.2).
        vetting_actions::expire_queries(state, config, chrono::Utc::now());
        // A ticket whose question about its community's mode went unanswered, or
        // could not be sent, ends here, saying which.
        vetting_actions::settle_pending_tickets(state, config, save, chrono::Utc::now());
        // Hidden-vetting work for the VTA — answers a community or a vetter sent,
        // an application that needs its engine — goes as soon as it arises,
        // backed off while the VTA cannot be reached (R1.4).
        if vetting_actions::pcs_work_due(config, chrono::Utc::now()) {
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
            vetting_actions::start_pcs_work(&mut ctx, Vec::new());
        }
        // A request reached the desk: re-read what its community
        // requires now, before a session opens on a stale answer.
        if std::mem::take(&mut config.private.vetting.vetter_refresh_due) {
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
            vetting_actions::dispatch(&mut ctx, actions::VettingAction::RefreshVetterSide).await;
        } else if vetting_actions::desk_open(state) {
            // While the desk is open, how each community vets is kept no older
            // than its TTL — asked at most once per re-ask interval (R1.4).
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
            vetting_actions::refresh_stale_modes(&mut ctx).await;
        }
        if awaiting_requirements
            .as_ref()
            .is_some_and(|a| a.asked_at.elapsed() >= join_flow::REQUIREMENTS_WAIT)
            && let Some(awaiting) = awaiting_requirements.take()
        {
            config.private.vetting.forget_query(&awaiting.document_id);
            *join_entry = Some(join_flow::JoinEntry::Resume {
                vtc_did: awaiting.vtc_did,
                outcome: join_flow::RequirementsOutcome::Unanswered(format!(
                    "no answer within {} seconds — its service may be offline",
                    join_flow::REQUIREMENTS_WAIT.as_secs()
                )),
            });
        }
        // R1.2 / R6.4: a challenge that never comes is the community
        // not answering — our side sent the question, so it is not
        // our mediator, and nothing refused it.
        if awaiting_challenge
            .as_ref()
            .is_some_and(|a| a.asked_at.elapsed() >= join_flow::CHALLENGE_WAIT)
            && let Some(awaiting) = awaiting_challenge.take()
        {
            config.private.vetting.forget_query(&awaiting.document_id);
            *join_entry = Some(join_flow::JoinEntry::Challenge {
                awaiting,
                outcome: join_flow::ChallengeOutcome::Unanswered(format!(
                    "the request was sent, but no answer came within {} seconds — \
                     its service may be offline or unreachable",
                    join_flow::CHALLENGE_WAIT.as_secs()
                )),
            });
        }
        // A wallet session is polled on this tick, and given up on
        // when the community stops answering (R1.2).
        if let Some(awaiting) = awaiting_wallet.as_mut()
            && let Some(entry) =
                join_flow::wallet_tick(awaiting, config, tdk, Some(didcomm_service)).await
        {
            *awaiting_wallet = None;
            *join_entry = Some(entry);
        }
        // A ping has a reply window too (#584): past it, say so in
        // the panel that sent it and expire the outbound task, so
        // the Inbox does not keep a ping nobody will answer.
        if ping_sent_at.is_some_and(|t| t.elapsed() > PING_REPLY_WINDOW) {
            *ping_sent_at = None;
            let cutoff = chrono::Utc::now()
                - chrono::Duration::from_std(PING_REPLY_WINDOW).unwrap_or_default();
            let before = config.private.tasks.tasks.len();
            config.private.tasks.tasks.retain(|_, t| {
                !(matches!(t.type_, openvtc_core::tasks::TaskType::TrustPing { .. })
                    && t.created < cutoff)
            });
            if config.private.tasks.tasks.len() != before {
                save.mark_dirty();
                state
                    .main_page
                    .sync_panels(config, crate::state_handler::main_page::Panels::FROM_TASKS);
            }
            let line = format!(
                "No reply to the ping after {} s — they may be offline, or not \
                 listening on that DID.",
                PING_REPLY_WINDOW.as_secs()
            );
            state.main_page.content_panel.relationships.status_message =
                Some(Status::warning(line.clone()));
            state.main_page.log_warning(line);
        }
        // R4.3: a capability query has a defined reply window. The
        // send was fire-and-forget; if no correlated reply arrived,
        // fail the view closed with a distinct, actionable message.
        if let Some(view) = state.main_page.content_panel.capabilities.view.as_mut()
            && view.pending_thid.is_some()
            && view
                .sent_at
                .is_some_and(|t| t.elapsed() > std::time::Duration::from_secs(30))
        {
            view.pending_thid = None;
            view.sent_at = None;
            if matches!(
                view.phase,
                crate::state_handler::main_page::content::CapabilitiesPhase::Loading
            ) {
                view.phase = crate::state_handler::main_page::content::CapabilitiesPhase::Failed(
                    "no reply within 30s — the community's governance host may be offline"
                        .to_string(),
                );
            } else {
                view.status_message = Some(Status::error(
                    "no reply to the change within 30s — refresh (r) to re-check".to_string(),
                ));
            }
        }
    }

    pub(super) async fn on_pending_expiry(&mut self) {
        let Runtime {
            state,
            config,
            didcomm_service,
            save,
            session_manager,
            handler,
            ..
        } = self;
        // The vetting book's own clock: forget cards past their
        // retention, move finished desk requests to the record of
        // who we vetted, close sessions nobody answered. Fires at
        // start-up too, so a card from a previous run does not wait
        // an hour to go.
        let mut vetting_changed = config.private.vetting.prune(chrono::Utc::now());
        // Applications whose persona this account no longer holds:
        // left by a deletion before deletions took them along, and
        // unusable — their DID is gone. Judged by the persona
        // record, not the loaded identity, which can be missing for
        // a run without the persona being gone.
        let personas = &config.account.personas;
        let applications = &mut config.private.vetting.applications;
        let before = applications.len();
        applications.retain(|a| personas.contains_key(&a.persona));
        let orphaned = before - applications.len();
        if orphaned > 0 {
            vetting_changed = true;
            state.main_page.log(format!(
                "Dropped {orphaned} vetting application{} made as an identity that no \
                 longer exists.",
                if orphaned == 1 { "" } else { "s" }
            ));
        }
        // Applications whose join is done and that hold nothing a
        // rejoin could present again (see `retire_joined`).
        let members: std::collections::HashSet<(String, openvtc_core::config::account::PersonaId)> =
            config
                .account
                .memberships()
                .filter(|m| m.status.is_active())
                .map(|m| (m.vtc_did.clone(), m.persona_ref))
                .collect();
        let retired = config.private.vetting.retire_joined(
            |a| members.contains(&(a.community.clone(), a.persona)),
            chrono::Utc::now(),
        );
        if retired > 0 {
            vetting_changed = true;
            state.main_page.log(format!(
                "Cleared {retired} finished vetting application{} — joined, and its \
                 statements have expired.",
                if retired == 1 { "" } else { "s" }
            ));
        }
        if vetting_changed {
            save.mark_dirty();
            state.main_page.sync_panels(
                config,
                crate::state_handler::main_page::Panels::FROM_VETTING_BOOK,
            );
        }
        // The vetter side runs on its own schedule — the
        // hidden-vetting tick below, at least hourly.
        // R-B-7: expire Pending joins unanswered for 7 days — or for
        // the `decisionSla` a vetting community publishes — raising
        // actions-required, and tear down each one's now-dead session
        // (R-S-3). Records are retained read-only (R-S-1).
        let vetting = &config.private.vetting;
        let default_timeout =
            chrono::TimeDelta::days(openvtc_core::config::account::PENDING_TIMEOUT_DAYS);
        let timeouts: std::collections::HashMap<_, _> = config
            .account
            .memberships()
            .filter_map(|c| {
                vetting
                    .decision_sla(&c.vtc_did, c.persona_ref)
                    .map(|sla| ((c.vtc_did.clone(), c.persona_ref), sla))
            })
            .collect();
        let expired = config
            .account
            .expire_stale_pending_with(chrono::Utc::now(), |c| {
                timeouts
                    .get(&(c.vtc_did.clone(), c.persona_ref))
                    .copied()
                    .unwrap_or(default_timeout)
            });
        if !expired.is_empty() {
            save.mark_dirty();
            for (vtc, persona) in &expired {
                deregister_inactive_community(
                    session_manager,
                    didcomm_service,
                    config,
                    state,
                    vtc,
                    *persona,
                )
                .await;
            }
            state.main_page.sync_from_config(config);
            state.main_page.log(format!(
                "{} pending join{} expired (no decision within the time allowed).",
                expired.len(),
                if expired.len() == 1 { "" } else { "s" },
            ));
            let _ = handler.state_tx.publish(state);
        }

        // The other thing that lapses by the clock: our own `vetter`
        // role credential. Nothing arrives to announce it — the first
        // sign is an applicant's request refused at their end — so
        // this sweep is where it gets noticed. Said once per grant
        // per state; see `take_grant_warnings`.
        let warnings = config
            .private
            .vetting
            .take_grant_warnings(chrono::Utc::now());
        if !warnings.is_empty() {
            for warning in &warnings {
                let community =
                    crate::state_handler::community_label(config, &warning.community, None, 64);
                state.main_page.log(if warning.expired {
                    format!(
                        "Your vetter credential from {community} expired on {}. \
                         Requests to you there are refused until it is reissued — \
                         ask for it again from your vetting desk (g).",
                        warning.valid_until.format("%Y-%m-%d"),
                    )
                } else {
                    format!(
                        "Your vetter credential from {community} expires on {}. \
                         Ask for it again from your vetting desk (g).",
                        warning.valid_until.format("%Y-%m-%d"),
                    )
                });
                let id = warning.id();
                config.private.tasks.tasks.insert(
                    id.clone().into(),
                    openvtc_core::tasks::Task {
                        id: std::sync::Arc::new(id),
                        type_: openvtc_core::tasks::TaskType::VetterGrantExpiring {
                            community: std::sync::Arc::new(community),
                            expired: warning.expired,
                            valid_until: warning.valid_until.format("%Y-%m-%d").to_string(),
                        },
                        created: chrono::Utc::now(),
                        our_persona: Some(warning.persona),
                    },
                );
            }
            save.mark_dirty();
            state
                .main_page
                .sync_panels(config, crate::state_handler::main_page::Panels::FROM_TASKS);
            let _ = handler.state_tx.publish(state);
        }
    }

    pub(super) async fn on_join_status_tick(&mut self) {
        let Runtime {
            state,
            config,
            tdk,
            didcomm_service,
            save,
            verifier,
            restore_backlog,
            seen_messages,
            pending_replies,
            join_status_pacer,
            ..
        } = self;
        // Kept messages still waiting for room (the request rate,
        // say) are tried again even if no check is running.
        if !restore_backlog.is_empty()
            && restore_kept(
                verifier,
                restore_backlog,
                config,
                state,
                tdk,
                didcomm_service,
                seen_messages,
                pending_replies,
            )
            .await
        {
            save.mark_dirty();
        }
        // Ask each community about a join it has not resolved —
        // every Pending join, including one that never got any
        // reply, which is asked id-less; see `openvtc_core::join::status_poll`.
        //
        // Spawned detached rather than through `background_dispatch`:
        // there is no outcome to apply on the loop thread (the reply
        // arrives on the persona's listener and goes through inbound
        // dispatch like any other), and the pacer already prevents
        // pile-up by marking a record polled before the send.
        let candidates = config.account.pollable_pending(chrono::Utc::now());
        if !candidates.is_empty()
            && let Some(atm) = tdk.atm.clone()
        {
            let due = join_status_pacer.due(candidates, std::time::Instant::now());
            let polls = openvtc_core::join::status_poll::build(config, tdk, due).await;
            if !polls.is_empty() {
                tokio::spawn(openvtc_core::join::status_poll::send_all(atm, polls));
            }
        }
        // A change syncs only the panels that read it, so text that turns with
        // the clock alone — a credential expiring, a join awaiting its
        // acknowledgement, a vetter grant running out — is brought up to date
        // here, at most a minute late.
        state
            .main_page
            .sync_panels(config, crate::state_handler::main_page::Panels::FROM_CLOCK);
    }

    pub(super) async fn on_hidden_vetting_tick(&mut self) {
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
            pending_replies,
            ping_sent_at,
            hidden_vetting_pacer,
            handler,
            ..
        } = self;
        let now = chrono::Utc::now();
        // A question left unanswered since the last pass is retried on its
        // backoff, not at the next scheduled pass (R1.4).
        hidden_vetting_pacer.pull_forward(&config.private.vetting, now);
        if hidden_vetting_pacer.due(now) {
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
            vetting_actions::dispatch(&mut ctx, actions::VettingAction::RefreshVetterSide).await;
            let next = hidden_vetting_pacer.schedule(
                &config.private.vetting,
                chrono::Utc::now(),
                &mut rand::thread_rng(),
            );
            debug!(%next, "next hidden-vetting pass");
        }
    }

    pub(super) async fn on_community_profile_tick(&mut self) {
        let Runtime {
            config,
            tdk,
            community_profile_pacer,
            pending_replies,
            ..
        } = self;
        // Ask each Active community, once, for its profile so the
        // new-relationship form can default to the community's
        // declared identifier form (issue #241). Spawned detached,
        // like the status poll: the reply arrives on the persona's
        // listener and folds in through inbound dispatch, and the
        // pacer marks each community asked before the send so a tick
        // never re-asks one.
        if let Some(atm) = tdk.atm.clone() {
            let mut asks = Vec::new();
            for ask in community_profile_pacer.due(config) {
                // Local key lookup; an ask whose key cannot be
                // read is dropped rather than sent unsigned.
                if let Ok(keys) = config.get_persona_keys_for(ask.persona, tdk).await {
                    asks.push(ask.with_signer(keys.authentication.secret.clone()));
                }
            }
            if !asks.is_empty() {
                tokio::spawn(community_profile_poll::send_all(atm, asks, pending_replies));
            }
        }
    }

    pub(super) async fn on_agent_name_tick(&mut self) {
        let Runtime {
            state,
            config,
            tdk,
            admin_vta,
            in_flight,
            dispatch_tx,
            contexts_checked,
            grants_swept,
            ..
        } = self;
        // Collect DIDs whose agent name is uncached or stale and, if
        // any, resolve them in one background job (read-only I/O).
        // Results are folded into the persisted cache on the loop
        // thread by `apply_outcome`. The busy-guard drops the tick if
        // a prior sweep is still running, so ticks never pile up.
        let targets = config.agent_name_refresh_targets(chrono::Utc::now());
        if !targets.is_empty() {
            let job = agent_name_refresh::AgentNameRefreshJob {
                resolver: tdk.did_resolver().clone(),
                dids: targets,
            };
            background_dispatch::dispatch(job, in_flight, dispatch_tx, |_| {});
        }

        // Ask what each persona presents. Shares this tick for the
        // same reason as the transport probe — the loop gains no
        // extra timer — and re-asks every sweep rather than on a
        // TTL, because the answer is the holder's own decision and
        // they may have changed it from `pnm` a moment ago. The
        // busy-guard keeps a slow agent from stacking sweeps.
        dispatch_binding_refresh(config, admin_vta.as_ref(), in_flight, dispatch_tx);

        // Register the contexts memberships name. Joins before
        // per-community contexts recorded an id without creating it;
        // faces worn there worked only because nothing checked.
        let top_context_id = config.account.top_context_id.clone();
        let unchecked: Vec<String> = config
            .account
            .memberships()
            .map(|c| c.sub_context_id.clone())
            .filter(|id| {
                openvtc_core::config::community_context::is_sub_context(id, &top_context_id)
                    && !contexts_checked.contains(id)
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if !unchecked.is_empty()
            && let Some(client) = admin_vta.as_ref()
        {
            let job = community_context_actions::ContextRegistrationJob {
                client: client.clone(),
                top_context_id,
                contexts: unchecked.clone(),
            };
            if background_dispatch::dispatch(job, in_flight, dispatch_tx, |_| {}) {
                contexts_checked.extend(unchecked);
            }
        }

        // Read each membership context's device grants, once a run,
        // after registration has made sure the contexts exist — a
        // grant listing for a context not yet created would read as
        // a failure.
        if !*grants_swept
            && !in_flight.is_busy(background_dispatch::DispatchDomain::CommunityContexts)
            && let Some(client) = admin_vta.as_ref()
        {
            let targets = community_context_actions::sweep_targets(config);
            if !targets.is_empty() {
                let job = community_context_actions::DeviceGrantSweepJob {
                    client: client.clone(),
                    contexts: targets,
                };
                if background_dispatch::dispatch(job, in_flight, dispatch_tx, |_| {}) {
                    *grants_swept = true;
                }
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
            && let openvtc_core::config::KeyBackend::Vta { vta_did, .. } = &config.key_backend
            && !vta_did.is_empty()
        {
            let job = vta_transports::VtaTransportsProbe {
                vta_did: vta_did.clone(),
            };
            background_dispatch::dispatch(job, in_flight, dispatch_tx, |_| {});
        }
    }
}
