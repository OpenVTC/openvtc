//! The runtime's inbound arm: a DIDComm event as it arrives, or handed
//! back with the result of its off-loop check.

use super::*;
use crate::state_handler::*;

/// The most messages held for a join being submitted; past this they are
/// processed as they arrive, as they are when no join is being submitted.
const MAX_HELD_INBOUND: usize = 64;

impl Runtime {
    /// Process messages held while a join request was being sent, once it
    /// no longer is.
    pub(super) async fn release_held_inbound(&mut self) {
        if self.join.submitting_to().is_some() || self.held_inbound.is_empty() {
            return;
        }
        for (event, pre) in std::mem::take(&mut self.held_inbound) {
            Box::pin(self.on_inbound(event, pre)).await;
        }
    }

    /// DIDComm inbound message events — as they arrive, or handed
    /// back with the result of their off-loop check.
    pub(super) async fn on_inbound(
        &mut self,
        event: didcomm::DIDCommEvent,
        pre: Option<openvtc_core::inbound::PreVerified>,
    ) {
        // While a join request to a community is being sent, its messages
        // wait: the pending record its submit-receipt or verdict is matched
        // against is written only once the submit comes back, and a fast
        // answer processed first would find nothing and be dropped. The old
        // nested join loop got this for free by not reading inbound at all.
        if let didcomm::DIDCommEvent::InboundMessage { authenticated, .. } = &event
            && let Some(vtc) = self.join.submitting_to()
            && authenticated.as_deref() == Some(vtc)
            && self.held_inbound.len() < MAX_HELD_INBOUND
        {
            self.held_inbound.push((event, pre));
            return;
        }
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
            verifier,
            restore_backlog,
            seen_messages,
            pending_replies,
            witness_router,
            ping_sent_at,
            join_entry,
            awaiting_requirements,
            awaiting_challenge,
            awaiting_wallet,
            ..
        } = self;
        match event {
            didcomm::DIDCommEvent::InboundMessage {
                message,
                transport,
                authenticated,
                ..
            } => {
                // Capture message info before processing for detailed logging
                let msg_type = message.typ.clone();
                let msg_from = message.from.clone().unwrap_or_else(|| "unknown".into());
                let msg_to = message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default();
                let msg_thid = message.thid.clone().unwrap_or_else(|| "none".into());

                // A credential that has been checked no longer
                // shows its membership as verifying.
                let returning_credential =
                    matches!(pre, Some(openvtc_core::inbound::PreVerified::Credential(_)));
                let returning = pre.is_some();
                let mut effects = openvtc_core::inbound::InboundEffects::default();
                // Only the sender the transport authenticated can be
                // waited on: a claimed `from` alone neither holds a
                // community's messages back nor jumps its queue.
                let waiting = |claimed: &str| {
                    authenticated.as_deref() == Some(claimed) && verifier.is_waiting_on(claimed)
                };
                let arrival = match pre {
                    Some(pre) => openvtc_core::inbound::Arrival::Returning(pre),
                    None => openvtc_core::inbound::Arrival::New { waiting: &waiting },
                };
                let dispatched = openvtc_core::inbound::process_inbound_message(
                    config,
                    tdk,
                    didcomm_service,
                    seen_messages,
                    pending_replies,
                    &message,
                    authenticated.as_deref(),
                    &mut effects,
                    arrival,
                )
                .await;
                // Applied (or refused): its kept copy goes.
                if returning {
                    let before = config.private.deferred_inbound.len();
                    config.private.deferred_inbound.retain(|kept| {
                        Some(kept.sender.as_str()) != authenticated.as_deref()
                            || kept.message.id != message.id
                    });
                    if config.private.deferred_inbound.len() != before {
                        save.mark_dirty();
                    }
                }
                let openvtc_core::inbound::InboundEffects {
                    inactivated,
                    capability_replies,
                    git_ns_replies,
                    rooms_replies,
                    elections_replies,
                    personhood_challenges,
                    vetting_answers,
                    vetting_grant_checks,
                    renewals,
                    witness_replies,
                    notifications,
                    deferred,
                } = effects;
                // Notifications for our personas, to the member's VTA as received,
                // and the sender answered (VTI-NTF-054).
                for mut received in notifications {
                    received.over_tsp = transport == openvtc_core::didcomm::MessagingTransport::Tsp;
                    notification_actions::hand_over(config, tdk, admin_vta.as_ref(), received)
                        .await;
                }
                // A witness's answers, to the witnessing waiting on their thread.
                for reply in witness_replies {
                    let thread = reply
                        .document
                        .get("threadId")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    if witness_router.deliver(&reply.sender, reply.document) {
                        debug!(%thread, "a witness's answer, handed to its witnessing");
                    }
                }
                if returning_credential {
                    state
                        .main_page
                        .content_panel
                        .communities
                        .verifying
                        .remove(&msg_from);
                    state.main_page.sync_from_config(config);
                }
                // Set aside for its check: the membership shows
                // "verifying…" until the result comes back.
                if let Some(deferred) = deferred {
                    let _ = queue_for_check(
                        verifier,
                        config,
                        state,
                        deferred,
                        transport,
                        authenticated.as_deref(),
                    );
                    save.mark_dirty();
                }
                // A check finished, so there may be room for a
                // message kept from before the restart.
                if returning
                    && !restore_backlog.is_empty()
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
                    let Some(persona) = config.account.persona_id_for_did(&msg_to) else {
                        warn!(
                            vtc = %msg_from,
                            to = %msg_to,
                            "personhood challenge addressed to a DID this account \
                             holds no persona for — ignoring",
                        );
                        continue;
                    };
                    state
                        .main_page
                        .content_panel
                        .communities
                        .personhood_challenge = Some(
                        crate::state_handler::main_page::content::PersonhoodChallengeView {
                            vtc_did: msg_from.clone(),
                            persona,
                            challenge_id: reply.challenge_id,
                            match_code: reply.match_code.clone(),
                            expires_at: reply.expires_at,
                        },
                    );
                    state.main_page.content_panel.communities.status_message =
                        Some(Status::info(format!(
                            "Personhood challenge received — confirm the code {} with \
                             whoever is vetting you, then assert.",
                            reply.match_code
                        )));
                }

                // How a renewal the member asked for ended: on the
                // Communities status line, where they asked, and in
                // the activity log with the community named.
                for (vtc, outcome) in renewals {
                    let line = outcome.describe();
                    match &outcome {
                        openvtc_core::renewal::RenewalOutcome::Renewed { .. } => {
                            state.main_page.log(&line)
                        }
                        _ => state
                            .main_page
                            .log_error("Membership renewal", &format!("{vtc}: {line}")),
                    }
                    let severity = match &outcome {
                        openvtc_core::renewal::RenewalOutcome::Renewed { .. } => {
                            crate::state_handler::main_page::status::Severity::Success
                        }
                        _ => crate::state_handler::main_page::status::Severity::Error,
                    };
                    state.main_page.content_panel.communities.status_message =
                        Some(Status::new(severity, line));
                }

                match dispatched {
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
                apply_capability_replies(state, capability_replies);
                // git-ns answers for the Repos panel; a change that
                // landed is followed by a fresh read of the view.
                if !git_ns_replies.is_empty()
                    && repos_actions::apply_replies(state, config, git_ns_replies)
                {
                    repos_actions::refresh(
                        &mut repos_actions::Loop {
                            state,
                            config,
                            tdk,
                            vta: admin_vta.as_ref(),
                            dispatch_tx,
                            in_flight,
                            pending_replies,
                        },
                        true,
                    )
                    .await;
                }
                // The answer names the repositories to look for
                // on this machine.
                repos_workspace::probe_if_due(state, dispatch_tx, in_flight);
                // Data-room answers for the Rooms panel; each may call for the
                // next step of a refresh or an acceptance.
                if !rooms_replies.is_empty()
                    && rooms_actions::apply_replies(state, pending_replies, rooms_replies)
                {
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
                }
                // Election answers for the Elections panel; each may call for
                // the next step of a ticket or a vote.
                if !elections_replies.is_empty()
                    && elections_actions::apply_replies(state, pending_replies, elections_replies)
                {
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
                }
                // A vetter's grant is checked for revocation off the
                // loop: the check fetches the community's status list.
                for check in vetting_grant_checks {
                    vetting_actions::spawn_grant_check(dispatch_tx, tdk, check);
                }
                // The manifest or challenge a waiting join asked for
                // resumes it; every other answer goes to the Vetting page.
                let mut answers = Vec::with_capacity(vetting_answers.len());
                for answer in vetting_answers {
                    if let Some(entry) = awaiting_requirements
                        .as_ref()
                        .and_then(|a| join_flow::resume_for(a, &answer))
                    {
                        *awaiting_requirements = None;
                        *join_entry = Some(entry);
                    } else if let Some(entry) = awaiting_challenge
                        .as_ref()
                        .and_then(|a| join_flow::challenge_resume_for(a, &answer))
                    {
                        *awaiting_challenge = None;
                        *join_entry = Some(entry);
                    } else if let Some(step) = awaiting_wallet
                        .as_mut()
                        .and_then(|a| join_flow::wallet_answer(a, &answer, state))
                    {
                        if let Some(entry) = step {
                            *awaiting_wallet = None;
                            *join_entry = Some(entry);
                        }
                    } else {
                        answers.push(answer);
                    }
                }
                vetting_actions::apply_answers(state, config, answers);
                // A manifest in is a fresh reading of how its community vets: say a
                // switch, and decide a ticket that was waiting on it.
                vetting_actions::settle_pending_tickets(state, config, save, chrono::Utc::now());
            }
            didcomm::DIDCommEvent::TrustPingReceived {
                from,
                listener_id,
                message_id,
            } => {
                // `from` is the sender the transport authenticated
                // (never the plaintext header); with none there is
                // nobody to answer.
                let sender = from.as_deref().unwrap_or("unknown");
                let sender_arc = std::sync::Arc::new(sender.to_string());

                // Only respond to pings from the mediator or established relationships
                let is_mediator = from.is_some() && sender == config.mediator_did();
                let has_relationship = from.is_some()
                    && config
                        .private
                        .relationships
                        .find_by_remote_did(&sender_arc)
                        .map(|r| {
                            r.state == openvtc_core::relationships::RelationshipState::Established
                        })
                        .unwrap_or(false);

                if is_mediator || has_relationship {
                    // Send pong to the authenticated sender, setting `from` to our
                    // listener's DID so the recipient can identify us.
                    let our_listener_did = didcomm_service
                        .listener_did(&listener_id)
                        .await
                        .unwrap_or_else(|| config.persona_did().to_string());
                    if let Ok(pong_msg) = build_trust_pong(&our_listener_did, sender, &message_id)
                        && let Err(e) = didcomm::send_message_via(
                            didcomm_service,
                            &pong_msg,
                            &listener_id,
                            sender,
                        )
                        .await
                    {
                        state.main_page.log_error("Failed to send pong", &e);
                    }
                    let ping_display = resolve_did_to_display(config, sender);
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
                            resolve_did_to_display(config, sender)
                        ),
                        format!(
                            "Trust-Ping Rejected\n\
                             ───────────────────\n\
                             From (DID):      {sender}\n\
                             Reason:          {}",
                            if from.is_some() {
                                "no established relationship"
                            } else {
                                "the transport authenticated no sender"
                            },
                        ),
                    );
                }
            }
            didcomm::DIDCommEvent::TrustPongReceived { from } => {
                debug!(from = ?from, "TrustPongReceived event");
                let sender_did = from.as_deref().unwrap_or("");
                // `from` is the sender the transport authenticated.
                // A pong with none is logged as such rather than
                // credited to whoever we pinged last: it closes no
                // ping task either (see the dispatcher).
                let sender_display = if sender_did.is_empty() {
                    "an unauthenticated sender".to_string()
                } else {
                    resolve_did_to_display(config, sender_did)
                };
                let ms = ping_sent_at
                    .take()
                    .map(|sent_at| sent_at.elapsed().as_millis());
                let latency_str = ms.map(|v| format!(" ({v}ms)")).unwrap_or_default();
                // The answer belongs where the ping was sent, not only
                // in the log (#584).
                if !sender_did.is_empty() {
                    state.main_page.content_panel.relationships.status_message =
                        Some(Status::success(format!(
                            "Pong from {sender_display}{latency_str} — they are reachable."
                        )));
                }
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
    }
}
