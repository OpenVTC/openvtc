//! Inbound DIDComm message dispatch for the TUI.
//!
//! Messages that don't need human input are auto-processed.
//! Messages requiring user decisions are queued as tasks in the inbox.
//!
//! The pure protocol logic (validators, the join-receipt / credential-issue
//! handlers, the VRC vetting + proof verification, and the replay guard) lives
//! in [`openvtc_core::messaging`] so it is testable without the TUI crate. This
//! module keeps only the async I/O orchestrator [`process_inbound_message`],
//! which imports and calls into core.

use std::sync::Arc;

use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use openvtc_core::didcomm::Messaging;
use openvtc_core::messaging::{
    SeenMessages, check_message_age, check_task_capacity, create_finalize_message,
    handle_credential_issue, handle_join_problem_report, handle_join_status_response,
    handle_join_submit_receipt, handle_join_trust_task_error, handle_join_verdict,
    is_trust_task_error_type, require_thid, validate_did, verify_vrc_proof, vet_vrc_issued,
};
use openvtc_core::personhood::{
    PERSONHOOD_ASSERT_RESPONSE_TYPE, PERSONHOOD_CHALLENGE_RESPONSE_TYPE,
};
use openvtc_core::{
    MessageType,
    config::{Config, account::VtcDid},
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
    vrc::VRCRequestReject,
};
use tracing::{debug, info, warn};
use vta_sdk::protocols::PROBLEM_REPORT_TYPE;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
    JOIN_REQUEST_SUBMIT_RESPONSE_TYPE,
};
use vta_sdk::protocols::members::{MEMBER_REQUEST_VMC_TYPE, MEMBER_VMC_RESPONSE_TYPE};

/// Maximum allowed message body size in bytes (1 MB).
const MAX_MESSAGE_BODY_SIZE: usize = 1_048_576;

/// Maximum number of relationships allowed before rejecting new requests.
const MAX_RELATIONSHIPS: usize = 5_000;

/// Build, sign, and send the reciprocal member VMC for `(vtc_did, persona_id)` —
/// resolving that persona's runtime identity (DID / profile / mediator) and
/// signing key from `config`. Shared by the manual "issue VMC" action and the
/// auto-answer to a VTC `members/request-vmc/1.0`. Returns the DIDComm message id.
pub(crate) async fn issue_member_vmc_for(
    config: &Config,
    tdk: &TDK,
    vtc_did: &str,
    persona_id: openvtc_core::config::account::PersonaId,
    closes_request: Option<uuid::Uuid>,
) -> Result<(uuid::Uuid, serde_json::Value), openvtc_core::errors::OpenVTCError> {
    use openvtc_core::errors::OpenVTCError;
    // The grant we are acknowledging, as the community sent it. Without one
    // there is nothing to acknowledge: an acknowledgement names a specific
    // grant by digest, and a community that has issued us none has no
    // membership edge for us to complete.
    let grant = config
        .account
        .membership(vtc_did, persona_id)
        .and_then(|c| {
            c.credentials
                .get(&openvtc_core::CredentialKind::Membership)
                .cloned()
        })
        .ok_or_else(|| {
            OpenVTCError::Config(
                "this community has not issued us a membership credential, so there is \
                 nothing to acknowledge"
                    .into(),
            )
        })?;
    let id = config
        .identities
        .get(&persona_id)
        .ok_or_else(|| OpenVTCError::Config("persona identity unavailable".into()))?;
    let member_did = id.persona_did().to_string();
    let profile = id.profile().clone();
    let mediator = id.mediator_did.clone().unwrap_or_default();
    let atm = tdk
        .atm
        .as_ref()
        .ok_or_else(|| OpenVTCError::Config("messaging (ATM) unavailable".into()))?;
    let keys = config.get_persona_keys_for(persona_id, tdk).await?;
    openvtc_core::members::issue_and_send_member_vmc(
        &openvtc_core::members::Delivery {
            atm,
            profile: &profile,
            member_did: &member_did,
            vtc_did,
            mediator_did: &mediator,
        },
        &keys.signing.secret,
        &grant,
        closes_request,
    )
    .await
}

/// What an inbound message asks the loop to do, beyond mutating `Config`.
///
/// These are things this function cannot do itself: tearing down a session
/// needs the session manager, and the live personhood challenge belongs to
/// `State` rather than to the account. Collected here rather than as three
/// trailing `&mut Vec` parameters — same reason the community verbs grew a
/// `Performed` enum, and it keeps the signature within clippy's argument
/// budget as more effects arrive.
#[derive(Default)]
pub struct InboundEffects {
    /// Communities that resolved to an inactive status; the loop deregisters
    /// their sessions (R-S-3).
    pub inactivated: Vec<(VtcDid, openvtc_core::config::account::PersonaId)>,
    /// Capability replies, keyed by the request id they thread on.
    pub capability_replies: Vec<(String, openvtc_core::capabilities::CapabilityReply)>,
    /// Personhood challenges the community answered with. Display state with a
    /// ten-minute life — never persisted.
    pub personhood_challenges: Vec<openvtc_core::personhood::ChallengeReply>,
}

/// Process an inbound DIDComm message.
///
/// Auto-processes messages that don't need human input (pong, accept, finalize, reject).
/// Queues interactive tasks for messages that need user decisions (inbound requests, VRCs).
///
/// Returns `true` if Config was mutated and needs saving.
pub async fn process_inbound_message(
    config: &mut Config,
    tdk: &TDK,
    service: &Messaging,
    seen: &mut SeenMessages,
    message: &Message,
    effects: &mut InboundEffects,
) -> Result<bool, anyhow::Error> {
    let InboundEffects {
        inactivated,
        capability_replies,
        personhood_challenges,
    } = effects;
    // Drop messages outside the replay / freshness window before doing
    // any state-mutating work. Saves us from acting on stale captures
    // and from clock-skew–induced retries.
    if let Err(reason) = check_message_age(message) {
        warn!(
            id = %message.id,
            typ = %message.typ,
            from = ?message.from,
            "dropping inbound message: {reason}",
        );
        return Ok(false);
    }

    // Drop messages whose ID we've already seen this session. The TDK
    // already guards against unpack-level duplicates, but the LRU is a
    // belt-and-braces defense for mediator pickup retries and replay
    // attempts.
    if seen.observe(&message.id) {
        debug!(id = %message.id, typ = %message.typ, "dropping replayed message ID");
        return Ok(false);
    }

    // Validate sender — trust-pong messages may omit `from` (the thid
    // linkage to our outbound ping is sufficient for task cleanup).
    let from_did = match &message.from {
        Some(did) => Arc::new(did.to_string()),
        None => {
            // Allow pong through for task cleanup even without `from`
            if message.typ == openvtc_core::protocol_urls::TRUST_PONG {
                if let Some(task_id) = &message.thid {
                    config.private.tasks.remove(&Arc::new(task_id.to_string()));
                }
                debug!("trust-pong (no from) — task cleaned up");
                return Ok(true);
            }
            warn!("anonymous inbound message rejected (no 'from' field)");
            return Ok(false);
        }
    };

    // The persona this message was addressed to — the DID any auto-reply must be
    // sent *from*. Resolved from the envelope's `to`, falling back to the active
    // persona when `to` is absent or not one of ours. For a single-persona
    // account `to` is always that persona, so this is identical to the previous
    // `config.persona_did()` behaviour; with multiple personas it routes the
    // reply out of the right one.
    let recipient_did: String = message
        .to
        .as_ref()
        .and_then(|tos| tos.iter().find(|t| config.is_persona_did(t)))
        .cloned()
        .unwrap_or_else(|| config.persona_did().to_string());

    // The persona this message was addressed to, for D10 attribution: inbox
    // tasks created from this message are tagged with it so they scope to the
    // right community on the main page (R-C-6).
    let recipient_persona = config.account.persona_id_for_did(&recipient_did);

    // Validate message body size to prevent DoS via oversized payloads
    let body_size = serde_json::to_string(&message.body)
        .map(|s| s.len())
        .unwrap_or(0);
    if body_size > MAX_MESSAGE_BODY_SIZE {
        warn!(
            size = body_size,
            "rejecting oversized message body ({} bytes)", body_size
        );
        return Ok(false);
    }

    // Peer identity vetting (docs/design/vetting-process.md): requests,
    // sessions, cards, statements, declines and refusals between members, and a
    // community's vetting requirements. Tried before the join and credential
    // routes below because it shares two of their types; `handle` returns
    // `None` for anything that is not vetting's, which falls through unchanged.
    if openvtc_core::vetting::inbound::may_claim(&message.typ) {
        let resolver =
            vta_sdk::trust_task_proof::TrustTaskVmResolver::new(tdk.did_resolver().clone());
        let ctx = openvtc_core::vetting::inbound::Context {
            account: &config.account,
            resolver: &resolver,
            recipient: recipient_persona.map(|p| (p, recipient_did.as_str())),
            now: chrono::Utc::now(),
        };
        if let Some(handled) = openvtc_core::vetting::inbound::handle(
            &mut config.private.vetting,
            &ctx,
            message,
            &from_did,
        )
        .await
        {
            if let Some(reply) = handled.reply
                && let Err(e) = openvtc_core::vetting::wire::sign_and_send(
                    config,
                    tdk,
                    service,
                    reply.persona,
                    reply.document,
                )
                .await
            {
                warn!(to = %from_did, error = %e, "could not send vetting reply");
            }
            let noticed = handled.notice.is_some();
            if let Some(notice) = handled.notice {
                config
                    .public
                    .logs
                    .insert(LogFamily::Community, notice.describe());
                if let Some((id, task)) = notice.task() {
                    config
                        .private
                        .tasks
                        .new_task_for(&Arc::new(id), task, recipient_persona);
                }
            }
            return Ok(handled.changed || noticed);
        }
    }

    // Trust Task envelope replies (governance/capability/*): parse the body
    // document, classify it, and hand it to the state loop keyed by the
    // document's `threadId` (== our request id). Foreign trust tasks riding
    // the same envelope type are ignored here.
    if message.typ == openvtc_core::capabilities::TRUST_TASK_ENVELOPE_TYPE {
        // trust-tasks-capability-client 0.17 folded the §4.9 correlation check
        // into the parse: `parse_envelope_reply` now takes the thread id the
        // caller is waiting on. This is a fan-in point that is waiting on
        // nothing in particular, so the document is read first and classified
        // against its own `threadId`; the correlation that matters is still
        // `apply_capability_replies` matching it to the open view's
        // `pending_thid`, and an uncorrelated reply is dropped there.
        if let Some((thid, doc)) =
            openvtc_core::capabilities::parse_envelope_document(&message.body)
            && let Some(reply) = openvtc_core::capabilities::parse_capability_reply(&doc, &thid)
        {
            capability_replies.push((thid, reply));
        }
        return Ok(false);
    }

    // VTC join-requests submit-receipt: the VTC's asynchronous reply to our
    // submit, threaded (`thid`) on our submit message id. It carries the
    // authoritative VTC `requestId`; reconcile it onto the matching Pending
    // community record (which holds our submit message id as a placeholder).
    // It is a VTC Trust-Task type, not an openvtc relationship-protocol type,
    // so handle it before the `MessageType` conversion below (which rejects it).
    if message.typ == JOIN_REQUEST_SUBMIT_RECEIPT_TYPE {
        return Ok(handle_join_submit_receipt(
            &mut config.account,
            message,
            &from_did,
        ));
    }

    // VTC credential delivery: on approve, the VTC pushes the issued VMC + role
    // VEC as separate `credential-exchange/issue` messages. Store each on the
    // community and flip Pending -> Active when the membership credential lands.
    if message.typ == CREDENTIAL_ISSUE_TYPE {
        // Snapshot before, so the log can say what *changed* rather than that a
        // message arrived. An issued membership credential is the moment a join
        // completes — the single most consequential inbound message there is,
        // and it used to be indistinguishable from any other in the log.
        let was_active = config
            .account
            .memberships_for(&from_did)
            .iter()
            .any(|m| m.status.is_active());
        let outcome = handle_credential_issue(&mut config.account, message, &from_did);
        // Admission is the moment the member owes the community its half of
        // the membership pair. Sending it here — naming the join request it
        // closes — is what `vtc/members/vmc/0.1`'s `requestId` is for; without
        // it the community's request sits `Approved` indefinitely, waiting for
        // a reciprocal that only ever arrived unlinked, if at all.
        //
        // Best-effort by nature: the credential we just received is already
        // stored and the membership is already Active. A failure to send ours
        // back is logged and leaves the join open — recoverable, either by the
        // member issuing manually or by the community asking with
        // `members/request-vmc`.
        if let Some((persona_id, request_id)) = outcome.closed_join {
            match issue_member_vmc_for(config, tdk, &from_did, persona_id, Some(request_id)).await {
                Ok((_, vmc)) => {
                    // Keep our half. The send is the only moment this document
                    // exists on this side, and a member who cannot show what
                    // they sent cannot answer whether they consented, nor
                    // re-send it without minting a different credential.
                    if let Some(record) = config.account.membership_mut(&from_did, persona_id) {
                        record.member_vmc = Some(vmc);
                    }
                    info!(
                        vtc = %from_did,
                        %request_id,
                        "sent our reciprocal membership credential, closing the join request"
                    )
                }
                Err(e) => warn!(
                    vtc = %from_did,
                    %request_id,
                    error = %e,
                    "could not send our reciprocal membership credential — the community's \
                     join request stays open"
                ),
            }
        }
        let changed = outcome.changed;
        if changed {
            let now_active = config
                .account
                .memberships_for(&from_did)
                .iter()
                .any(|m| m.status.is_active());
            config.public.logs.insert(
                LogFamily::Community,
                if now_active && !was_active {
                    format!("Admitted to community ({from_did}) — membership is now Active.")
                } else {
                    format!("Credential received from community ({from_did}).")
                },
            );
        }
        return Ok(changed);
    }

    // VTC join-requests submit `#response`: the synchronous admission verdict in
    // the trust-task join model (allow / deny / refer / request_more), threaded
    // (`thid`) on our submit message id. `allow` → Active, `deny` → Rejected; a
    // rejection inactivates the community so the loop deregisters the session.
    if message.typ == JOIN_REQUEST_SUBMIT_RESPONSE_TYPE {
        let outcome = handle_join_verdict(&mut config.account, message, &from_did);
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    // DIDComm problem-report: the framework-failure path of the trust-task join
    // (invalid/expired/malformed VIC, bad signature), threaded on our submit id.
    // `e.p.msg.forbidden` (the invitation was not accepted) → Rejected; other
    // codes are surfaced but leave the join Pending. Routed here so a rejection
    // is no longer silently dropped into a stuck `Pending`.
    if message.typ == PROBLEM_REPORT_TYPE {
        let outcome = handle_join_problem_report(&mut config.account, message, &from_did);

        // A report the join handler cannot claim refused *something else* we
        // sent. This client does not know what — it keeps no record of
        // outstanding requests by thread id — but "we don't know which" is not
        // a reason to say nothing. Every problem-report is a community telling
        // us it refused us, and the one thing worse than an unattributed
        // rejection is an invisible one.
        //
        // This is how the reciprocal-VMC exchange stayed broken for its whole
        // life: the VTC rejected every delivery and said so here, on a thread
        // no join matched, and each report went into a `warn!` naming the
        // correlation miss rather than the failure.
        if let Some((code, comment)) = outcome.unclaimed {
            warn!(
                vtc = %from_did,
                code = %code,
                comment = %comment,
                thid = message.thid.as_deref().unwrap_or("none"),
                "community refused something we sent"
            );
            config.public.logs.insert(
                LogFamily::Community,
                format!("Community ({from_did}) refused something we sent [{code}]: {comment}"),
            );
            return Ok(true);
        }

        if let Some(persona) = outcome.status.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.status.changed);
    }

    // VTC trust-task-error: the framework failure document for a Trust Task join
    // ceremony (malformed / denied / internal), threaded on our submit id. Trust
    // Tasks signal failures with these documents, NOT DIDComm problem-reports —
    // without this branch a failed ceremony was an unknown type, silently dropped
    // into a stuck `Pending`. Matched by type prefix (version-agnostic).
    if is_trust_task_error_type(&message.typ) {
        let outcome = handle_join_trust_task_error(&mut config.account, message, &from_did);
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    // VTC join-requests status-response: the authoritative lifecycle resolution
    // (approved / rejected / deferred) for a Pending join, correlated by
    // `requestId` (R-B-8). A rejection inactivates the community, so report its
    // VTC DID up so the loop deregisters the session (R-S-3).
    if message.typ == JOIN_REQUEST_STATUS_RESPONSE_TYPE {
        let outcome = handle_join_status_response(&mut config.account, message, &from_did);
        if let Some(persona) = outcome.inactivated {
            inactivated.push((from_did.to_string(), persona));
        }
        return Ok(outcome.changed);
    }

    // VTC personhood challenge reply: carries the nonce an assertion must be
    // signed over, and the match code to read aloud. Reported up rather than
    // applied here — the challenge is display state with a ten-minute life,
    // and this function owns `Config`, which is the thing that gets persisted.
    // A single-use nonce has no business surviving a restart.
    if message.typ == PERSONHOOD_CHALLENGE_RESPONSE_TYPE {
        match openvtc_core::personhood::parse_challenge_reply(&message.body) {
            Ok(reply) => {
                debug!(
                    vtc = %from_did,
                    challenge = %reply.challenge_id,
                    "personhood challenge received",
                );
                personhood_challenges.push(reply);
            }
            // Includes the match-code disagreement, which is a real finding
            // rather than a malformed message: it means this client and the
            // community derive different codes from the same challenge, so
            // the spoken confirmation would be meaningless.
            Err(e) => warn!(vtc = %from_did, "unusable personhood challenge reply: {e}"),
        }
        return Ok(false);
    }

    // VTC personhood assertion result. The re-issued VMC carrying
    // `PersonhoodCredential` arrives separately as a credential-issue message,
    // which is what actually updates the wallet — this is the decision.
    if message.typ == PERSONHOOD_ASSERT_RESPONSE_TYPE {
        match openvtc_core::personhood::parse_assert_reply(&message.body) {
            Ok(reply) => info!(
                vtc = %from_did,
                did = %reply.did,
                personhood = reply.personhood,
                "personhood asserted",
            ),
            Err(e) => warn!(vtc = %from_did, "unusable personhood assert reply: {e}"),
        }
        return Ok(false);
    }

    // VTC member-VMC receipt (`members/vmc/1.0#response`): the VTC acknowledging
    // the reciprocal VMC we sent. Informational — log and move on.
    if message.typ == MEMBER_VMC_RESPONSE_TYPE {
        info!(vtc = %from_did, "VTC acknowledged our membership credential (member VMC receipt)");
        // The send reports only that a frame was accepted locally. This is the
        // first and only evidence the community actually took the credential,
        // so it belongs where the member can see it rather than in a log file.
        config.public.logs.insert(
            LogFamily::Community,
            format!("Community ({from_did}) acknowledged your membership credential."),
        );
        return Ok(true);
    }

    // VTC → member: "please issue + send your VMC" (`members/request-vmc/1.0`).
    // Auto-answer: the sender is the community VTC and the recipient is one of our
    // personas; if we hold an Active membership there, issue + send our reciprocal
    // VMC straight back. Best-effort — a failure is logged, not surfaced as a stuck
    // state (the admin can re-request, or the member can issue manually with `m`).
    if message.typ == MEMBER_REQUEST_VMC_TYPE {
        match recipient_persona {
            Some(persona_id)
                if config
                    .account
                    .membership(&from_did, persona_id)
                    .is_some_and(|c| c.status.is_active()) =>
            {
                match issue_member_vmc_for(config, tdk, &from_did, persona_id, None).await {
                    Ok((_, vmc)) => {
                        if let Some(record) = config.account.membership_mut(&from_did, persona_id) {
                            record.member_vmc = Some(vmc);
                        }
                        info!(
                            vtc = %from_did,
                            "auto-issued our membership credential in response to the VTC's request"
                        )
                    }
                    Err(e) => warn!(
                        vtc = %from_did,
                        error = %e,
                        "failed to auto-issue our membership credential on request"
                    ),
                }
            }
            _ => warn!(
                vtc = %from_did,
                "members/request-vmc with no matching Active membership — ignoring"
            ),
        }
        return Ok(false);
    }

    let msg_type = match MessageType::try_from(message) {
        Ok(t) => t,
        Err(_) => {
            warn!(typ = %message.typ, "unknown message type — ignoring");
            return Ok(false);
        }
    };

    let thid_display = message.thid.as_deref().unwrap_or("none");
    debug!(
        msg_type = %msg_type.friendly_name(),
        from = %from_did,
        thid = %thid_display,
        id = %message.id,
        "processing inbound message"
    );

    match msg_type {
        // =====================================================================
        // Auto-processed (no user interaction needed)
        // =====================================================================
        MessageType::RelationshipRequestRejected => {
            let task_id = require_thid(message)?;
            let body: RelationshipRejectBody = serde_json::from_value(message.body.clone())?;

            // Verify sender has a relationship with us
            if config.private.relationships.get(&from_did).is_none()
                && config
                    .private
                    .relationships
                    .find_by_remote_did(&from_did)
                    .is_none()
            {
                warn!(from = %from_did, "reject from unknown party — ignoring");
                return Ok(false);
            }

            // Extract the listener's local DID before async work + before any
            // mutation, so the `&Relationship` borrow ends here.
            let our_did = config
                .private
                .relationships
                .find_by_task_id(&task_id)
                .map(|rel| Arc::clone(&rel.our_did))
                .filter(|our_did| !config.is_persona_did(our_did.as_str()));
            let listener_to_remove =
                our_did.map(|our_did| super::didcomm::listener_id_for_did(&our_did, config));
            if let Some(lid) = listener_to_remove {
                // Infallible now: dropping a transport closes its socket and
                // forgets its wire, with nothing left that can fail.
                service.remove_listener(&lid).await;
            }
            let _ = config.private.relationships.remove_by_task_id(
                &task_id,
                &mut config.private.vrcs_issued,
                &mut config.private.vrcs_received,
            );
            config.private.tasks.remove(&task_id);

            config.public.logs.insert(
                LogFamily::Relationship,
                format!(
                    "Relationship request rejected by ({}). Reason: {}",
                    from_did,
                    body.reason.as_deref().unwrap_or("none")
                ),
            );
            info!(from = %from_did, "relationship request rejected (auto-processed)");
            Ok(true)
        }

        MessageType::RelationshipRequestAccepted => {
            let task_id = require_thid(message)?;
            let body: RelationshipAcceptBody = serde_json::from_value(message.body.clone())?;

            if let Err(e) = validate_did(&body.did) {
                warn!(from = %from_did, error = %e, "rejecting accept with invalid DID in body");
                return Ok(false);
            }

            // All handshake messages use persona DIDs for from/to, so from_did
            // is the remote party's persona DID. Look up by task_id first, then
            // by persona DID. Validate sender matches the expected remote party.
            //
            // R20: with plain values we cannot hold a `&mut` across the finalize
            // `.await` below, so resolve the map key, mutate via `get_mut` (the
            // borrow ends immediately), then await. The mutation happens before
            // the await — no re-look-up is needed.
            let key = config
                .private
                .relationships
                .find_key_by_task_id(&task_id)
                .or_else(|| {
                    config
                        .private
                        .relationships
                        .get(&from_did)
                        .map(|_| Arc::clone(&from_did))
                });

            if let Some(key) = key {
                let rel = config
                    .private
                    .relationships
                    .get_mut(&key)
                    .expect("key just resolved");

                // Verify sender is the party we sent the request to
                if *rel.remote_p_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %rel.remote_p_did,
                        "accept from unexpected party"
                    );
                    return Ok(false);
                }

                rel.state = RelationshipState::Established;
                rel.remote_did = Arc::new(body.did.clone());
            } else {
                warn!(from = %from_did, task_id = %task_id, "no relationship found for accept message");
                return Ok(false);
            }

            // Send finalize using persona DIDs (same as request and accept).
            // If the send fails, still persist the Established state.
            let finalize_msg = create_finalize_message(&recipient_did, &from_did, &task_id)?;

            if let Err(e) = super::didcomm::send_message(
                service,
                config,
                &finalize_msg,
                &recipient_did,
                &from_did,
            )
            .await
            {
                warn!(to = %from_did, error = %e, "failed to send finalize — relationship established locally");
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Relationship established with ({})", from_did),
            );
            info!(from = %from_did, "relationship accepted + finalize sent (auto-processed)");
            Ok(true)
        }

        MessageType::RelationshipRequestFinalize => {
            let task_id = require_thid(message)?;

            // All handshake messages use persona DIDs, so from_did is the
            // remote persona DID which is the relationship HashMap key.
            let key = config
                .private
                .relationships
                .find_key_by_task_id(&task_id)
                .or_else(|| {
                    config
                        .private
                        .relationships
                        .get(&from_did)
                        .map(|_| Arc::clone(&from_did))
                });

            if let Some(key) = key {
                let rel = config
                    .private
                    .relationships
                    .get_mut(&key)
                    .expect("key just resolved");

                // Verify sender matches expected remote party
                if *rel.remote_p_did != *from_did {
                    warn!(
                        from = %from_did,
                        expected = %rel.remote_p_did,
                        "finalize from unexpected party"
                    );
                    return Ok(false);
                }

                rel.state = RelationshipState::Established;
            } else {
                warn!(from = %from_did, task_id = %task_id, "no relationship found for finalize message");
                return Ok(false);
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Relationship,
                format!("Relationship finalized with ({})", from_did),
            );
            info!(from = %from_did, "relationship finalized (auto-processed)");
            Ok(true)
        }

        MessageType::TrustPong => {
            if let Some(task_id) = &message.thid {
                config.private.tasks.remove(&Arc::new(task_id.to_string()));
            }
            debug!(from = %from_did, "trust-pong received (auto-processed)");
            Ok(true)
        }

        MessageType::VRCRequestRejected => {
            let task_id = require_thid(message)?;
            let body: VRCRequestReject = serde_json::from_value(message.body.clone())?;

            // Verify sender has a relationship with us
            if config.private.relationships.get(&from_did).is_none()
                && config
                    .private
                    .relationships
                    .find_by_remote_did(&from_did)
                    .is_none()
            {
                warn!(from = %from_did, "VRC reject from unknown party — ignoring");
                return Ok(false);
            }

            config.private.tasks.remove(&task_id);
            config.public.logs.insert(
                LogFamily::Task,
                format!(
                    "VRC request rejected by ({}). Reason: {}",
                    from_did,
                    body.reason.as_deref().unwrap_or("none")
                ),
            );
            info!(from = %from_did, "VRC request rejected (auto-processed)");
            Ok(true)
        }

        // =====================================================================
        // Queued as tasks (need user interaction)
        // =====================================================================
        MessageType::RelationshipRequest => {
            let task_id = Arc::new(message.id.clone());
            let body: openvtc_core::relationships::RelationshipRequestBody =
                serde_json::from_value(message.body.clone())?;

            if let Err(e) = validate_did(&body.did) {
                warn!(from = %from_did, error = %e, "rejecting request with invalid DID in body");
                return Ok(false);
            }

            let to_did = Arc::new(
                message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
            );

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            if config.private.relationships.relationships.len() >= MAX_RELATIONSHIPS {
                warn!("relationship limit reached — rejecting request");
                return Ok(false);
            }

            // Reject if we already have a relationship with this sender
            if config.private.relationships.get(&from_did).is_some()
                || config
                    .private
                    .relationships
                    .find_by_remote_did(&from_did)
                    .is_some()
            {
                warn!(from = %from_did, "relationship request from existing relationship — ignoring");
                return Ok(false);
            }

            // Reject if a pending inbound request from this sender already exists
            let has_pending = config.private.tasks.tasks.values().any(|task| {
                matches!(&task.type_, TaskType::RelationshipRequestInbound { from, .. } if *from == from_did)
            });
            if has_pending {
                warn!(from = %from_did, "duplicate pending relationship request — ignoring");
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::RelationshipRequestInbound {
                    from: from_did.clone(),
                    to: to_did,
                    request: body,
                },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound relationship request from ({})", from_did),
            );
            info!(from = %from_did, "relationship request queued in inbox");
            Ok(true)
        }

        MessageType::VRCRequest => {
            let task_id = Arc::new(message.id.clone());
            let body = serde_json::from_value(message.body.clone())?;

            let relationship = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .ok_or_else(|| {
                    anyhow::anyhow!("VRC request from ({}) but no relationship found", from_did)
                })?;

            // Only accept VRC requests from established relationships
            if relationship.state != RelationshipState::Established {
                warn!(from = %from_did, state = ?relationship.state, "VRC request from non-established relationship");
                return Ok(false);
            }
            let remote_p_did = Arc::clone(&relationship.remote_p_did);

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::VRCRequestInbound {
                    request: body,
                    remote_p_did,
                },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("Inbound VRC request from ({})", from_did),
            );
            info!(from = %from_did, "VRC request queued in inbox");
            Ok(true)
        }

        MessageType::VRCIssued => {
            let vrc: DTGCredential = serde_json::from_value(message.body.clone())?;

            // Task R2 hardening: require an established relationship, bind the
            // credential's issuer to the authenticated sender, and only let the
            // thid resolve our own pending outbound VRC request to that sender.
            let pending_request = match vet_vrc_issued(
                &config.private.relationships,
                &config.private.tasks,
                &vrc,
                &from_did,
                message.thid.as_deref(),
            ) {
                Ok(pending) => pending,
                Err(reason) => {
                    warn!(from = %from_did, issuer = %vrc.issuer(), "dropping VRC-issued message: {reason}");
                    return Ok(false);
                }
            };

            // Task R2 gate 4: the data-integrity proof must verify against the
            // issuer's resolved key before any state is touched.
            if let Err(reason) = verify_vrc_proof(tdk, &vrc).await {
                warn!(from = %from_did, issuer = %vrc.issuer(), "dropping VRC-issued message: {reason}");
                return Ok(false);
            }

            // Only a verified response may resolve our pending outbound VRC
            // request; the inbox task reuses its id so the request is replaced
            // by the issued credential. Unsolicited (or unmatched-thid) VRCs
            // are queued under the message id and leave other tasks untouched.
            let task_id = pending_request
                .clone()
                .unwrap_or_else(|| Arc::new(message.id.clone()));
            if let Some(request_id) = &pending_request {
                config.private.tasks.remove(request_id);
            }

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            config.private.tasks.new_task_for(
                &task_id,
                TaskType::VRCIssued { vrc: Box::new(vrc) },
                recipient_persona,
            );

            config.public.logs.insert(
                LogFamily::Task,
                format!("VRC issued received from ({})", from_did),
            );
            info!(from = %from_did, "VRC issued queued in inbox");
            Ok(true)
        }

        MessageType::TrustPing => {
            // Trust pings are already auto-responded to in the messaging loop.
            // Just create an informational task so the user sees it.
            let task_id = Arc::new(message.id.clone());
            let to_did = Arc::new(
                message
                    .to
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
            );

            if check_task_capacity(config, &task_id, &from_did).is_err() {
                return Ok(false);
            }

            // Find the relationship for this ping
            if let Some(remote_p_did) = config
                .private
                .relationships
                .find_by_remote_did(&from_did)
                .map(|rel| Arc::clone(&rel.remote_p_did))
            {
                config.private.tasks.new_task_for(
                    &task_id,
                    TaskType::TrustPing {
                        from: from_did.clone(),
                        to: to_did,
                        remote_p_did,
                    },
                    recipient_persona,
                );
            }
            debug!(from = %from_did, "trust-ping task created");
            Ok(true)
        }

        _ => {
            warn!(msg_type = %message.typ, "unhandled message type");
            Ok(false)
        }
    }
}
