//! Inbox task action handlers.
//!
//! These functions process user decisions on inbox tasks (accept/reject
//! relationship requests, accept VRCs, dismiss tasks). They operate on
//! `&mut Config` and `&TDK` owned by the StateHandler.

use std::sync::Arc;

use affinidi_tdk::TDK;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use anyhow::Result;
use chrono::Utc;
use openvtc_core::didcomm::Messaging;
use openvtc_core::{
    config::Config,
    logs::LogFamily,
    relationships::{RelationshipAcceptBody, RelationshipRejectBody, RelationshipState},
    tasks::TaskType,
};
use serde_json::json;
use tracing::{debug, info, warn};

// NOTE (R14): the formerly-inline `accept_relationship_request` /
// `reject_relationship_request` are now split into a loop-thread `prepare_*`
// (below, in the dispatch-wrapper section) and an I/O-only job, so the slow
// VTA round-trip + handshake send no longer park the runtime select loop.

/// Accept a received VRC — store it in vrcs_received and remove the task.
pub fn accept_vrc(config: &mut Config, task_id: &str) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());

    // Find the task and extract VRC + sender
    let (vrc, remote_p_did) = {
        let task = config
            .private
            .tasks
            .get_by_id(&task_id)
            .ok_or_else(|| anyhow::anyhow!("task not found: {}", task_id))?;
        match &task.type_ {
            TaskType::VRCIssued { vrc } => {
                // Determine issuer as remote p-did
                let issuer = Arc::new(vrc.issuer().to_string());
                (Arc::new(*vrc.clone()), issuer)
            }
            _ => anyhow::bail!("task {} is not a VRC issued task", task_id),
        }
    };

    // Store in received VRCs
    config.private.vrcs_received.insert(&remote_p_did, vrc)?;

    // Remove the task
    config.private.tasks.remove(&task_id);

    config.public.logs.insert(
        LogFamily::Task,
        format!("Accepted VRC from ({})", remote_p_did),
    );
    info!(from = %remote_p_did, "VRC accepted and stored");
    Ok(())
}

// NOTE (R14): the formerly-inline `accept_vrc_request` / `reject_vrc_request`
// are now split into a loop-thread `prepare_*` (in the dispatch-wrapper section
// below) + an I/O-only send job, so the DIDComm send no longer parks the loop.
// The VRC create + sign stays on the loop thread (local crypto, not network).

/// Clear all tasks from the inbox.
pub fn clear_all_tasks(config: &mut Config) -> Result<()> {
    config.private.tasks.clear();
    info!("all inbox tasks cleared");
    Ok(())
}

/// Dismiss (remove) a task from the inbox without any action.
pub fn dismiss_task(config: &mut Config, task_id: &str) -> Result<()> {
    let task_id = Arc::new(task_id.to_string());
    if config.private.tasks.remove(&task_id) {
        debug!(task_id = %task_id, "task dismissed");
    } else {
        warn!(task_id = %task_id, "task not found for dismissal");
    }
    Ok(())
}

// ------------------------------------------------------------------
// Message construction helpers — kept transport-agnostic so the same
// builders can be packed by the DIDComm service later.
// ------------------------------------------------------------------

/// Build a DIDComm relationship-acceptance message carrying the proofs that
/// bind `r_did` to this handshake (`thid`, the request's id).
async fn build_accept_message(
    from: &str,
    to: &str,
    r_did: &str,
    thid: &str,
    did_signer: &Secret,
    persona_signer: &Secret,
) -> Result<Message> {
    let (did_proof, persona_proof) = openvtc_core::relationships::did_binding_proofs(
        r_did,
        from,
        to,
        thid,
        did_signer,
        persona_signer,
    )
    .await?;
    super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST_ACCEPT,
        json!(RelationshipAcceptBody {
            did: r_did.to_string(),
            did_proof: Some(did_proof),
            persona_proof,
        }),
        from,
        to,
        Some(thid),
    )
}

/// Build a DIDComm relationship-rejection message.
fn build_reject_message(from: &str, to: &str, reason: Option<&str>, thid: &str) -> Result<Message> {
    super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST_REJECT,
        json!(RelationshipRejectBody {
            reason: reason.map(|r| r.to_string())
        }),
        from,
        to,
        Some(thid),
    )
}

// ============================================================
// State-handler dispatch wrappers
//
// These were inlined into state_handler/mod.rs's main_loop. They share
// nothing with the rest of the file beyond their UI-feedback shape, so
// hosting them next to the protocol-level handlers above keeps related
// code together and shrinks mod.rs.
// ============================================================

use crate::state_handler::{
    actions::InboxAction,
    dispatch_util,
    main_page::content::{ActiveTaskView, InboxConfirm, TaskKind},
    save_coalesce::SaveScheduler,
    state::State,
};

fn handle_inbox_select(state: &mut State, index: usize) {
    state.main_page.content_panel.inbox.selected_index = index;
}

fn handle_inbox_open_detail(state: &mut State, index: usize) {
    state.main_page.content_panel.inbox.selected_index = index;
    if let Some(task) = state.main_page.content_panel.inbox.tasks.get(index) {
        let view = match &task.kind {
            TaskKind::RelationshipRequestInbound {
                from_did,
                their_did,
                reason,
                name,
            } => Some(ActiveTaskView::RelationshipRequestInbound {
                task_id: task.id.clone(),
                from_did: from_did.clone(),
                // `remote_agent_name` is the verified name for the requester's
                // persona DID — i.e. `from_did`, the DID this labels. The
                // requester's R-DID (`their_did`) is a pseudonym and gets none.
                from_agent_name: task.remote_agent_name.clone(),
                their_did: their_did.clone(),
                reason: reason.clone(),
                name: name.clone(),
            }),
            TaskKind::VRCRequestInbound { reason } => Some(ActiveTaskView::VRCRequestInbound {
                task_id: task.id.clone(),
                from_did: task.remote_did.clone(),
                from_agent_name: task.remote_agent_name.clone(),
                reason: reason.clone(),
            }),
            TaskKind::VRCIssued => Some(ActiveTaskView::VRCIssued {
                task_id: task.id.clone(),
                issuer: task.remote_did.clone(),
                issuer_agent_name: task.remote_agent_name.clone(),
            }),
            TaskKind::RelationshipRequestOutbound {
                our_did,
                our_agent_name,
            } => Some(ActiveTaskView::RelationshipRequestOutbound {
                task_id: task.id.clone(),
                to_did: task.remote_did.clone(),
                to_agent_name: task.remote_agent_name.clone(),
                our_did: our_did.clone(),
                our_agent_name: our_agent_name.clone(),
                state: "Request Sent".to_string(),
            }),
            TaskKind::VRCRequestOutbound => Some(ActiveTaskView::VRCRequestOutbound {
                task_id: task.id.clone(),
                remote_did: task.remote_did.clone(),
                remote_agent_name: task.remote_agent_name.clone(),
            }),
            TaskKind::TrustPing | TaskKind::Informational(_) => Some(ActiveTaskView::Info {
                task_id: task.id.clone(),
                type_display: task.type_display.clone(),
                remote_did: task.remote_did.clone(),
                remote_agent_name: task.remote_agent_name.clone(),
            }),
        };
        state.main_page.content_panel.inbox.active_task = view;
    }
}

/// Helper: save config after an inbox action, sync UI state, and log messages.
fn save_and_sync(
    config: &Config,
    state: &mut State,
    save: &mut SaveScheduler,
    success_status: &str,
    success_log: &str,
) {
    state.main_page.content_panel.inbox.active_task = None;
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        dispatch_util::Persist::SaveAndSync,
        |mp| &mut mp.content_panel.inbox.status_message,
        success_status.to_string(),
        dispatch_util::SyncLog::Plain(success_log.to_string()),
    );
}

fn record_error(state: &mut State, context: &str, err: &anyhow::Error) {
    dispatch_util::record_error(
        &mut state.main_page,
        |mp| &mut mp.content_panel.inbox.status_message,
        context,
        err,
    );
}

fn handle_accept_vrc(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    task_id: &str,
) {
    match accept_vrc(config, task_id) {
        Ok(()) => save_and_sync(
            config,
            state,
            save,
            "VRC accepted and stored",
            "VRC accepted and stored",
        ),
        Err(e) => record_error(state, "Failed to accept VRC", &e),
    }
}

// ============================================================
// R14 backgrounded inbox network dispatch
// ============================================================

use openvtc_core::relationships::Relationship as RelRecord;

/// A backgrounded inbox network action, ready to run off the loop thread.
pub(crate) enum InboxJob {
    /// Accept a relationship request: optionally mint an R-DID + listener (VTA /
    /// BIP32, off-loop), then send the acceptance via the persona listener.
    AcceptRelationship(Box<AcceptJob>),
    /// A single DIDComm send (reject-relationship, accept/reject VRC request).
    Send(InboxSend),
}

impl InboxJob {
    pub(crate) async fn run(self) -> InboxOutcome {
        match self {
            InboxJob::AcceptRelationship(job) => job.run().await,
            InboxJob::Send(send) => send.run().await,
        }
    }
}

/// Owned inputs for a backgrounded relationship-acceptance.
pub(crate) struct AcceptJob {
    tdk: TDK,
    service: Messaging,
    /// `Some` ⇒ mint an R-DID first; `None` ⇒ use the persona DID directly.
    rdid_plan: Option<crate::state_handler::relationship_actions::RDidPlan>,
    persona_did: Arc<String>,
    /// The persona's authentication key, which signs the DID binding.
    persona_auth: Secret,
    persona_listener_id: String,
    task_id: Arc<String>,
    from_did: Arc<String>,
    their_did: String,
}

impl AcceptJob {
    async fn run(self) -> InboxOutcome {
        let AcceptJob {
            tdk,
            service,
            rdid_plan,
            persona_did,
            persona_auth,
            persona_listener_id,
            task_id,
            from_did,
            their_did,
        } = self;

        // 1. Mint the R-DID + listener off the loop (if requested).
        let (our_did, key_info) = match rdid_plan {
            Some(plan) => match plan.create_io(&tdk, &service, &from_did).await {
                Ok(created) => (Arc::new(created.r_did), created.key_info),
                Err(e) => {
                    return InboxOutcome {
                        effect: InboxEffect::AcceptRelationship {
                            task_id,
                            from_did,
                            their_did,
                            our_did: persona_did,
                            key_info: Vec::new(),
                        },
                        result: Err(format!("{e}")),
                    };
                }
            },
            None => (Arc::clone(&persona_did), Vec::new()),
        };

        // 2. Build + send the acceptance via the persona listener (handshake uses
        //    persona DIDs for routing; the R-DID is carried in the body).
        let built = async {
            let did_signer = crate::state_handler::relationship_actions::relationship_did_signer(
                &tdk,
                &our_did,
                &persona_did,
                &persona_auth,
            )
            .await?;
            build_accept_message(
                &persona_did,
                &from_did,
                &our_did,
                &task_id,
                &did_signer,
                &persona_auth,
            )
            .await
        }
        .await;
        let result = match built {
            Ok(msg) => {
                super::didcomm::send_message_via(&service, &msg, &persona_listener_id, &from_did)
                    .await
                    .map_err(|e| format!("{e}"))
            }
            Err(e) => Err(format!("{e}")),
        };

        InboxOutcome {
            effect: InboxEffect::AcceptRelationship {
                task_id,
                from_did,
                their_did,
                our_did,
                key_info,
            },
            result,
        }
    }
}

/// A single backgrounded inbox DIDComm send + the post-send effect.
pub(crate) struct InboxSend {
    service: Messaging,
    listener_id: String,
    to_did: Arc<String>,
    message: Box<Message>,
    effect: InboxEffect,
}

impl InboxSend {
    async fn run(self) -> InboxOutcome {
        let InboxSend {
            service,
            listener_id,
            to_did,
            message,
            effect,
        } = self;
        let result = super::didcomm::send_message_via(&service, &message, &listener_id, &to_did)
            .await
            .map_err(|e| format!("{e}"));
        InboxOutcome { effect, result }
    }
}

/// Post-send mutation for an inbox network action, owning the data the old
/// inline success block referenced.
pub(crate) enum InboxEffect {
    /// Accept relationship: insert relationship + remove task + log.
    AcceptRelationship {
        task_id: Arc<String>,
        from_did: Arc<String>,
        their_did: String,
        our_did: Arc<String>,
        /// R-DID `key_info` to record (empty when the persona DID was used).
        key_info: Vec<(String, openvtc_core::config::secured_config::KeyInfoConfig)>,
    },
    /// Reject relationship: remove task + log.
    RejectRelationship {
        task_id: Arc<String>,
        from_did: Arc<String>,
        reason: Option<String>,
    },
    /// Accept VRC request: store the signed issued VRC + remove task + log.
    AcceptVrcRequest {
        task_id: Arc<String>,
        their_p_did: Arc<String>,
        vrc: Box<dtg_credentials::DTGCredential>,
    },
    /// Reject VRC request: remove task + log.
    RejectVrcRequest {
        task_id: Arc<String>,
        their_p_did: Arc<String>,
        reason: Option<String>,
    },
}

/// Completed inbox network dispatch: the post-send effect + the send result.
pub(crate) struct InboxOutcome {
    effect: InboxEffect,
    result: Result<(), String>,
}

impl InboxOutcome {
    /// Apply the post-send mutation on the loop thread, reproducing the old
    /// inline success/error block. The status slot is `inbox.status_message`; on
    /// success the active task is cleared (as `save_and_sync` did before).
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        match self.effect {
            InboxEffect::AcceptRelationship {
                task_id,
                from_did,
                their_did,
                our_did,
                key_info,
            } => {
                // Record minted R-DID key metadata (success + failure, matching
                // the pre-R14 in-memory state; only success persists via save).
                for (id, info) in key_info {
                    config.key_info.insert(id, info);
                }
                match self.result {
                    Ok(()) => {
                        config.private.relationships.relationships.insert(
                            Arc::clone(&from_did),
                            RelRecord {
                                task_id: Arc::clone(&task_id),
                                remote_did: Arc::new(their_did),
                                remote_p_did: Arc::clone(&from_did),
                                our_did,
                                created: Utc::now(),
                                state: RelationshipState::RequestAccepted,
                                // The accept is built and signed under
                                // `persona_did_arc()` (the active/selected
                                // persona), so the new relationship belongs to
                                // that persona (D10). Invariant: the inbox is
                                // filtered to the active persona (R-C-6), so a
                                // selectable inbound-request task's addressed
                                // persona (`task.our_persona`) always equals the
                                // active persona — tag and signing persona agree.
                                our_persona: config.active_persona,
                                needs_reestablishment: false,
                            },
                        );
                        config.private.tasks.remove(&task_id);
                        config.public.logs.insert(
                            LogFamily::Relationship,
                            format!("Accepted relationship request from ({from_did})"),
                        );
                        info!(from = %from_did, "relationship request accepted");
                        save_and_sync(
                            config,
                            state,
                            save,
                            "Relationship request accepted",
                            "Accepted relationship request",
                        );
                    }
                    Err(e) => record_error(
                        state,
                        "Failed to accept relationship",
                        &anyhow::anyhow!("failed to send acceptance: {e}"),
                    ),
                }
            }
            InboxEffect::RejectRelationship {
                task_id,
                from_did,
                reason,
            } => match self.result {
                Ok(()) => {
                    config.private.tasks.remove(&task_id);
                    config.public.logs.insert(
                        LogFamily::Relationship,
                        format!(
                            "Rejected relationship request from ({from_did}). Reason: {}",
                            reason.as_deref().unwrap_or("none")
                        ),
                    );
                    info!(from = %from_did, "relationship request rejected");
                    save_and_sync(
                        config,
                        state,
                        save,
                        "Relationship request rejected",
                        "Rejected relationship request",
                    );
                }
                Err(e) => record_error(
                    state,
                    "Failed to reject relationship",
                    &anyhow::anyhow!("failed to send rejection: {e}"),
                ),
            },
            InboxEffect::AcceptVrcRequest {
                task_id,
                their_p_did,
                vrc,
            } => match self.result {
                Ok(()) => {
                    // Store the issued VRC (a fallible op today, surfaced as an
                    // error if it fails — matching the old inline `?`).
                    if let Err(e) = config
                        .private
                        .vrcs_issued
                        .insert(&their_p_did, Arc::new(*vrc))
                    {
                        record_error(state, "Failed to issue VRC", &anyhow::anyhow!("{e}"));
                        return;
                    }
                    config.private.tasks.remove(&task_id);
                    config.public.logs.insert(
                        LogFamily::Task,
                        format!("Issued VRC to ({their_p_did}) Task ID ({task_id})"),
                    );
                    info!(to = %their_p_did, "VRC issued and sent");
                    save_and_sync(
                        config,
                        state,
                        save,
                        "VRC issued and sent",
                        "VRC issued and sent",
                    );
                }
                Err(e) => record_error(
                    state,
                    "Failed to issue VRC",
                    &anyhow::anyhow!("failed to send VRC: {e}"),
                ),
            },
            InboxEffect::RejectVrcRequest {
                task_id,
                their_p_did,
                reason,
            } => match self.result {
                Ok(()) => {
                    config.private.tasks.remove(&task_id);
                    config.public.logs.insert(
                        LogFamily::Task,
                        format!(
                            "Rejected VRC request from ({their_p_did}). Reason: {}",
                            reason.as_deref().unwrap_or("none")
                        ),
                    );
                    info!(from = %their_p_did, "VRC request rejected");
                    save_and_sync(
                        config,
                        state,
                        save,
                        "VRC request rejected",
                        "Rejected VRC request",
                    );
                }
                Err(e) => record_error(
                    state,
                    "Failed to reject VRC request",
                    &anyhow::anyhow!("failed to send VRC rejection: {e}"),
                ),
            },
        }
    }
}

/// Loop-thread preparation for `AcceptRelationship`. Extracts the request data,
/// reserves the R-DID plan, updates the contact, and snapshots message inputs.
/// The slow VTA round-trip + handshake send run in the returned job.
async fn prepare_accept_relationship(
    config: &mut Box<Config>,
    tdk: &TDK,
    state: &mut State,
    service: &Messaging,
    task_id: &str,
    generate_r_did: bool,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<InboxJob> {
    let task_id = Arc::new(task_id.to_string());

    let (from_did, their_did, sender_name) = {
        let task = config
            .private
            .tasks
            .get_by_id(&task_id)
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        match &task.type_ {
            TaskType::RelationshipRequestInbound { from, request, .. } => {
                let sanitized_name = request
                    .name
                    .as_deref()
                    .map(|n| super::main_page::sanitize_display(n, 64));
                (Arc::clone(from), request.did.clone(), sanitized_name)
            }
            _ => anyhow::bail!("task {task_id} is not an inbound relationship request"),
        }
    };

    // Reserve the R-DID plan (BIP32 path-pointer reservation only; the key
    // creation runs in the task).
    let rdid_plan = if generate_r_did {
        let mediator = config.mediator_did().to_string();
        Some(
            crate::state_handler::relationship_actions::plan_relationship_did(
                config, &mediator, admin_vta,
            )?,
        )
    } else {
        None
    };

    // Add or update contact with sender's name as alias (done before the send).
    if let Some(existing) = config.private.contacts.find_contact(&from_did) {
        if existing.alias.is_none() && sender_name.is_some() {
            config
                .private
                .contacts
                .remove_contact(&mut config.public.logs, &from_did);
            config
                .private
                .contacts
                .add_contact(tdk, &from_did, sender_name, false, &mut config.public.logs)
                .await?;
        }
    } else {
        config
            .private
            .contacts
            .add_contact(tdk, &from_did, sender_name, false, &mut config.public.logs)
            .await?;
    }

    let persona_did = config.persona_did_arc();
    let persona_listener_id = super::didcomm::listener_id_for_did(&persona_did, config);
    // Signs the binding of our relationship DID to this accept.
    let persona_auth = config
        .get_persona_keys(tdk)
        .await
        .map_err(|e| anyhow::anyhow!("could not load the persona's authentication key: {e}"))?
        .authentication
        .secret;

    if generate_r_did {
        state.main_page.content_panel.inbox.status_message =
            Some("Accepting with R-DID — creating keys...".to_string());
        state
            .main_page
            .log("Accepting relationship request (creating R-DID)...");
    } else {
        state.main_page.content_panel.inbox.status_message =
            Some("Accepting relationship request...".to_string());
        state.main_page.log("Accepting relationship request...");
    }

    Ok(InboxJob::AcceptRelationship(Box::new(AcceptJob {
        tdk: tdk.clone(),
        service: service.clone(),
        rdid_plan,
        persona_did,
        persona_auth,
        persona_listener_id,
        task_id,
        from_did,
        their_did,
    })))
}

/// Loop-thread preparation for `RejectRelationship`: build the rejection message
/// + resolve the persona listener; the task sends it.
fn prepare_reject_relationship(
    config: &mut Box<Config>,
    service: &Messaging,
    state: &mut State,
    task_id: &str,
    reason: Option<&str>,
) -> Result<InboxJob> {
    let task_id = Arc::new(task_id.to_string());
    let from_did = {
        let task = config
            .private
            .tasks
            .get_by_id(&task_id)
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        match &task.type_ {
            TaskType::RelationshipRequestInbound { from, .. } => Arc::clone(from),
            _ => anyhow::bail!("task {task_id} is not an inbound relationship request"),
        }
    };
    let persona_did = config.persona_did_arc();
    let listener_id = super::didcomm::listener_id_for_did(&persona_did, config);
    let msg = build_reject_message(&persona_did, &from_did, reason, &task_id)?;
    state.main_page.content_panel.inbox.status_message =
        Some("Rejecting relationship request...".to_string());
    Ok(InboxJob::Send(InboxSend {
        service: service.clone(),
        listener_id,
        to_did: Arc::clone(&from_did),
        message: Box::new(msg),
        effect: InboxEffect::RejectRelationship {
            task_id,
            from_did,
            reason: reason.map(|s| s.to_string()),
        },
    }))
}

/// Loop-thread preparation for `AcceptVrcRequest`: create + sign the VRC (local
/// crypto), build the message; the task sends it and `apply` stores the issued
/// VRC on success.
async fn prepare_accept_vrc_request(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &Messaging,
    state: &mut State,
    task_id: &str,
) -> Result<InboxJob> {
    use openvtc_core::vrc::DtgCredentialMessage;

    let task_id = Arc::new(task_id.to_string());
    let remote_p_did = {
        let task = config
            .private
            .tasks
            .get_by_id(&task_id)
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        match &task.type_ {
            TaskType::VRCRequestInbound { remote_p_did, .. } => Arc::clone(remote_p_did),
            _ => anyhow::bail!("task {task_id} is not an inbound VRC request"),
        }
    };
    let (our_r_did, their_p_did, their_r_did) = {
        let relationship = config
            .private
            .relationships
            .get(&remote_p_did)
            .ok_or_else(|| anyhow::anyhow!("no relationship for {remote_p_did}"))?;
        (
            Arc::clone(&relationship.our_did),
            Arc::clone(&relationship.remote_p_did),
            Arc::clone(&relationship.remote_did),
        )
    };

    // Create + sign the VRC on the loop thread (local crypto, not network).
    //
    // The VRC is issued under **the identity this relationship uses**, not the
    // persona DID. It is the durable artifact both parties retain and may
    // publish to the community trust graph, so a persona-attributed issuer
    // correlated every relationship a persona had, indefinitely, from a
    // credential that outlives the handshake that produced it. The subject was
    // already the peer's R-DID; only the issuer half was persona-attributed,
    // which meant the pairwise channel led straight back to the persona.
    //
    // This could not be fixed here until the VTC stopped requiring it: its
    // publish path pinned the VRC issuer to the authenticated session DID, so
    // a VRC issued under a relationship DID was rejected. Lifted in
    // OpenVTC/verifiable-trust-infrastructure#1061.
    let valid_from = Utc::now();
    // The VRC carries its own identifier, set before signing.
    //
    // Same shape as the membership-credential bug: `new_vrc` leaves `id`
    // unset, and a credential with no identifier cannot be stored under one —
    // so a peer that keys relationship credentials by `id` cannot make a
    // re-issue idempotent, tell a renewal from a duplicate, or reference this
    // VRC from a witness credential. Nothing rejects a VRC for it *today*,
    // which is exactly what the reciprocal VMC looked like right up until a
    // community started keying on it.
    //
    // Before signing, necessarily: a Data Integrity proof covers every member
    // but `proof`, so an id spliced in afterwards leaves a document whose
    // proof no longer verifies.
    let mut vrc = openvtc_core::vrc::new_identified_vrc(&our_r_did, &their_r_did, valid_from, None);
    // `our_did` is the persona DID for a relationship established without a
    // dedicated R-DID, so sign as whichever identity it actually is — the same
    // discriminator `listener_id_for_did` routes sends on.
    if config.is_persona_did(&our_r_did) {
        let persona_keys = config.get_persona_keys(tdk).await?;
        vrc.sign(&persona_keys.signing.secret, None).await?;
    } else {
        let secret = openvtc_core::relationships::relationship_signing_secret(tdk, &our_r_did)
            .await
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no signing secret held for relationship DID {our_r_did} \
                         — the relationship needs re-establishing"
                )
            })?;
        vrc.sign(&secret, None).await?;
    }
    let msg = vrc.message(&our_r_did, &their_r_did, Some(&task_id))?;
    let listener_id = super::didcomm::listener_id_for_did(&our_r_did, config);

    state.main_page.content_panel.inbox.status_message = Some("Issuing VRC...".to_string());

    Ok(InboxJob::Send(InboxSend {
        service: service.clone(),
        listener_id,
        to_did: their_r_did,
        message: Box::new(msg),
        effect: InboxEffect::AcceptVrcRequest {
            task_id,
            their_p_did,
            vrc: Box::new(vrc),
        },
    }))
}

/// Loop-thread preparation for `RejectVrcRequest`: build the rejection message;
/// the task sends it.
fn prepare_reject_vrc_request(
    config: &mut Box<Config>,
    service: &Messaging,
    state: &mut State,
    task_id: &str,
    reason: Option<&str>,
) -> Result<InboxJob> {
    use openvtc_core::vrc::VRCRequestReject;

    let task_id = Arc::new(task_id.to_string());
    let remote_p_did = {
        let task = config
            .private
            .tasks
            .get_by_id(&task_id)
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        match &task.type_ {
            TaskType::VRCRequestInbound { remote_p_did, .. } => Arc::clone(remote_p_did),
            _ => anyhow::bail!("task {task_id} is not an inbound VRC request"),
        }
    };
    let (our_r_did, their_r_did, their_p_did) = {
        let relationship = config
            .private
            .relationships
            .get(&remote_p_did)
            .ok_or_else(|| anyhow::anyhow!("no relationship for {remote_p_did}"))?;
        (
            Arc::clone(&relationship.our_did),
            Arc::clone(&relationship.remote_did),
            Arc::clone(&relationship.remote_p_did),
        )
    };
    let msg = VRCRequestReject::create_message(
        &their_r_did,
        &our_r_did,
        &task_id,
        reason.map(|s| s.to_string()),
    )?;
    let listener_id = super::didcomm::listener_id_for_did(&our_r_did, config);
    state.main_page.content_panel.inbox.status_message =
        Some("Rejecting VRC request...".to_string());
    Ok(InboxJob::Send(InboxSend {
        service: service.clone(),
        listener_id,
        to_did: their_r_did,
        message: Box::new(msg),
        effect: InboxEffect::RejectVrcRequest {
            task_id,
            their_p_did,
            reason: reason.map(|s| s.to_string()),
        },
    }))
}

fn handle_dismiss_task(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    task_id: &str,
) {
    // The confirmation (if any) is now resolved.
    state.main_page.content_panel.inbox.confirm = None;
    if let Err(e) = dismiss_task(config, task_id) {
        state.main_page.log_error("Failed to dismiss task", &e);
        return;
    }
    state.main_page.content_panel.inbox.active_task = None;
    // R11: coalesced save (was inline `save_config`).
    save.mark_dirty();
    state.main_page.sync_from_config(config);
    state.main_page.log("Task dismissed");
}

fn handle_clear_all(config: &mut Box<Config>, state: &mut State, save: &mut SaveScheduler) {
    // The confirmation (if any) is now resolved.
    state.main_page.content_panel.inbox.confirm = None;
    if let Err(e) = clear_all_tasks(config) {
        state.main_page.log_error("Failed to clear inbox", &e);
        return;
    }
    state.main_page.content_panel.inbox.active_task = None;
    // R11: coalesced save (was inline `save_config`).
    save.mark_dirty();
    state.main_page.sync_from_config(config);
    state.main_page.log("All inbox tasks cleared");
}

/// Outcome of synchronously dispatching an `InboxAction` on the loop thread.
/// Local actions are `Handled`; network actions return a spawnable [`InboxJob`].
pub(crate) enum InboxDispatch {
    Handled,
    Spawn(InboxJob),
}

/// Whether an `InboxAction` is a network-bound action the loop should run
/// off-thread (claiming the `Inbox` busy-domain first). Checked *before*
/// `dispatch` does any pre-send config mutation.
pub(crate) fn is_network(action: &InboxAction) -> bool {
    matches!(
        action,
        InboxAction::AcceptRelationship { .. }
            | InboxAction::RejectRelationship { .. }
            | InboxAction::AcceptVrcRequest { .. }
            | InboxAction::RejectVrcRequest { .. }
    )
}

/// Dispatch a single `InboxAction`.
///
/// Local actions (`AcceptVrc`, dismiss, clear, nav) are `Handled` synchronously;
/// network actions do their loop-thread pre-send work and return
/// [`InboxDispatch::Spawn`] for the loop to run off-thread (post-send mutation in
/// [`InboxOutcome::apply`]). A pre-send failure is recorded as a status and
/// returns `Handled` (no job spawned → the loop releases the busy-domain).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch(
    action: InboxAction,
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &Messaging,
    state: &mut State,
    save: &mut SaveScheduler,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> InboxDispatch {
    match action {
        InboxAction::SelectTask(index) => handle_inbox_select(state, index),
        InboxAction::OpenDetail(index) => handle_inbox_open_detail(state, index),
        InboxAction::Back => {
            state.main_page.content_panel.inbox.active_task = None;
        }
        InboxAction::AcceptRelationship {
            task_id,
            generate_r_did,
        } => {
            match prepare_accept_relationship(
                config,
                tdk,
                state,
                service,
                &task_id,
                generate_r_did,
                admin_vta,
            )
            .await
            {
                Ok(job) => return InboxDispatch::Spawn(job),
                Err(e) => record_error(state, "Failed to accept relationship", &e),
            }
        }
        InboxAction::RejectRelationship { task_id, reason } => {
            match prepare_reject_relationship(config, service, state, &task_id, reason.as_deref()) {
                Ok(job) => return InboxDispatch::Spawn(job),
                Err(e) => record_error(state, "Failed to reject relationship", &e),
            }
        }
        InboxAction::AcceptVrc { task_id } => handle_accept_vrc(config, state, save, &task_id),
        InboxAction::AcceptVrcRequest { task_id } => {
            match prepare_accept_vrc_request(config, tdk, service, state, &task_id).await {
                Ok(job) => return InboxDispatch::Spawn(job),
                Err(e) => record_error(state, "Failed to issue VRC", &e),
            }
        }
        InboxAction::RejectVrcRequest { task_id, reason } => {
            match prepare_reject_vrc_request(config, service, state, &task_id, reason.as_deref()) {
                Ok(job) => return InboxDispatch::Spawn(job),
                Err(e) => record_error(state, "Failed to reject VRC request", &e),
            }
        }
        InboxAction::DismissTask { task_id } => handle_dismiss_task(config, state, save, &task_id),
        InboxAction::ClearAll => handle_clear_all(config, state, save),
        // R25 confirmation arming/cancel — pure state mutations, never network.
        InboxAction::ConfirmDismiss { task_id } => {
            state.main_page.content_panel.inbox.confirm = Some(InboxConfirm::Dismiss { task_id });
        }
        InboxAction::ConfirmClearAll => {
            state.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
        }
        InboxAction::CancelConfirm => {
            state.main_page.content_panel.inbox.confirm = None;
        }
    }
    InboxDispatch::Handled
}

#[cfg(test)]
mod r14_tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    /// Accept-relationship success inserts the relationship (RequestAccepted),
    /// removes the task, records minted R-DID key_info, and sets the status —
    /// reproducing the post-send tail of `accept_relationship_request`.
    #[test]
    fn accept_relationship_success_inserts_relationship() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let from = Arc::new("did:peer:from".to_string());
        let task_id = Arc::new("task-acc".to_string());
        config
            .private
            .tasks
            .new_task(&task_id, TaskType::RelationshipRequestRejected); // any placeholder

        let outcome = InboxOutcome {
            effect: InboxEffect::AcceptRelationship {
                task_id: Arc::clone(&task_id),
                from_did: Arc::clone(&from),
                their_did: "did:peer:their".to_string(),
                our_did: Arc::new("did:peer:our-rdid".to_string()),
                key_info: vec![(
                    "z-acc-key".to_string(),
                    openvtc_core::config::secured_config::KeyInfoConfig {
                        path: openvtc_core::config::secured_config::KeySourceMaterial::Derived {
                            path: "m/3'/1'/1'/0'".to_string(),
                        },
                        create_time: Utc::now(),
                        purpose: openvtc_core::config::KeyTypes::RelationshipVerification,
                    },
                )],
            },
            result: Ok(()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(
            config.private.relationships.get(&from).is_some(),
            "relationship inserted on accept success"
        );
        assert!(
            config.private.tasks.get_by_id(&task_id).is_none(),
            "task removed on accept success"
        );
        assert!(config.key_info.contains_key("z-acc-key"));
        assert_eq!(
            state
                .main_page
                .content_panel
                .inbox
                .status_message
                .as_deref(),
            Some("Relationship request accepted")
        );
    }

    /// Accept-relationship failure records key_info but inserts NO relationship
    /// and keeps the task; the error status is surfaced.
    #[test]
    fn accept_relationship_failure_keeps_task_and_no_relationship() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let from = Arc::new("did:peer:from".to_string());
        let task_id = Arc::new("task-acc".to_string());
        config
            .private
            .tasks
            .new_task(&task_id, TaskType::RelationshipRequestRejected);

        let outcome = InboxOutcome {
            effect: InboxEffect::AcceptRelationship {
                task_id: Arc::clone(&task_id),
                from_did: Arc::clone(&from),
                their_did: "did:peer:their".to_string(),
                our_did: Arc::new("did:peer:our-rdid".to_string()),
                key_info: Vec::new(),
            },
            result: Err("send failed".to_string()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(
            config.private.relationships.get(&from).is_none(),
            "no relationship on accept failure"
        );
        assert!(
            config.private.tasks.get_by_id(&task_id).is_some(),
            "task retained on accept failure"
        );
        let status = state
            .main_page
            .content_panel
            .inbox
            .status_message
            .clone()
            .unwrap_or_default();
        assert!(status.starts_with("Error:"), "got: {status}");
    }

    /// Reject-relationship success removes the task and sets the status.
    #[test]
    fn reject_relationship_success_removes_task() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let task_id = Arc::new("task-rej".to_string());
        config
            .private
            .tasks
            .new_task(&task_id, TaskType::RelationshipRequestRejected);

        let outcome = InboxOutcome {
            effect: InboxEffect::RejectRelationship {
                task_id: Arc::clone(&task_id),
                from_did: Arc::new("did:peer:from".to_string()),
                reason: Some("no thanks".to_string()),
            },
            result: Ok(()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(config.private.tasks.get_by_id(&task_id).is_none());
        assert_eq!(
            state
                .main_page
                .content_panel
                .inbox
                .status_message
                .as_deref(),
            Some("Relationship request rejected")
        );
    }

    /// Reject-relationship failure keeps the task and surfaces the error.
    #[test]
    fn reject_relationship_failure_keeps_task() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let task_id = Arc::new("task-rej".to_string());
        config
            .private
            .tasks
            .new_task(&task_id, TaskType::RelationshipRequestRejected);

        let outcome = InboxOutcome {
            effect: InboxEffect::RejectRelationship {
                task_id: Arc::clone(&task_id),
                from_did: Arc::new("did:peer:from".to_string()),
                reason: None,
            },
            result: Err("send failed".to_string()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(
            config.private.tasks.get_by_id(&task_id).is_some(),
            "task retained on reject failure"
        );
    }
}
