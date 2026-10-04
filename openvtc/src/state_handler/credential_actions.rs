//! Credential (VRC) action handlers for the TUI.

use std::sync::Arc;

use anyhow::Result;
use openvtc_core::didcomm::Messaging;
use openvtc_core::{config::Config, logs::LogFamily, tasks::TaskType, vrc::VrcRequest};
use tracing::{debug, info};

/// One VRC request, resolved on the loop thread.
///
/// The only credential action that touches the network. It used to be awaited
/// inline, which meant asking a peer for a credential froze the application for
/// as long as the send retried — and an unresponsive peer is a common reason for
/// the request to be slow, not a rare one.
pub(crate) struct VrcRequestJob {
    pub(crate) service: Messaging,
    /// The DIDComm message, built on the loop where `Config` is available.
    pub(crate) message: Box<affinidi_tdk::didcomm::Message>,
    /// Listener the send goes out through, resolved from our side's DID.
    pub(crate) listener_id: String,
    pub(crate) remote_did: Arc<String>,
    pub(crate) remote_p_did: Arc<String>,
    /// Message id, which becomes the tracking task's id on success.
    pub(crate) msg_id: Arc<String>,
}

impl VrcRequestJob {
    /// Send it. I/O only.
    pub(crate) async fn run(self) -> VrcRequestOutcome {
        let result = crate::state_handler::didcomm::send_message_via(
            &self.service,
            &self.message,
            &self.listener_id,
            &self.remote_did,
        )
        .await;
        VrcRequestOutcome {
            remote_p_did: self.remote_p_did,
            msg_id: self.msg_id,
            error: result.err().map(|e| format!("{e}")),
        }
    }
}

/// What the send did. Data only; applied on the loop thread.
pub(crate) struct VrcRequestOutcome {
    remote_p_did: Arc<String>,
    msg_id: Arc<String>,
    error: Option<String>,
}

impl VrcRequestOutcome {
    /// Record the tracking task and report, or say why the request never left.
    ///
    /// The task is created *after* the send, as it was inline: a task tracking
    /// a request that was never sent would sit in the inbox waiting for a reply
    /// that cannot come.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        match self.error {
            None => {
                let our_persona = config.active_persona;
                config.private.tasks.new_task_for(
                    &self.msg_id,
                    TaskType::VRCRequestOutbound {
                        remote_p_did: Arc::clone(&self.remote_p_did),
                    },
                    our_persona,
                );
                config.public.logs.insert(
                    LogFamily::Relationship,
                    format!(
                        "Requested VRC from ({}) Task ID ({})",
                        self.remote_p_did, self.msg_id
                    ),
                );
                info!(to = %self.remote_p_did, "VRC request sent");

                state.main_page.content_panel.credentials.mode = CredentialsMode::List;
                let display_name =
                    crate::state_handler::resolve_did_to_display(config, &self.remote_p_did);
                dispatch_util::save_and_sync(
                    &mut state.main_page,
                    config,
                    save,
                    dispatch_util::Persist::SaveAndSync,
                    |mp| &mut mp.content_panel.credentials.status_message,
                    format!("VRC request sent to {display_name}"),
                    dispatch_util::SyncLog::Plain(format!("VRC request sent to {display_name}")),
                );
            }
            Some(e) => {
                // `record_error` takes an `anyhow::Error`; the job hands back a
                // formatted string, because an error cannot cross the channel.
                dispatch_util::record_error(
                    &mut state.main_page,
                    |mp| &mut mp.content_panel.credentials.status_message,
                    "Failed to send VRC request",
                    &anyhow::anyhow!(e),
                );
            }
        }
    }
}

/// Resolve a VRC request on the loop: the relationship's two DIDs, the message,
/// and the listener it goes out through. `None` when the relationship is gone.
pub(crate) fn prepare_vrc_request(
    config: &Config,
    service: &Messaging,
    remote_p_did: &str,
    reason: Option<&str>,
) -> Option<VrcRequestJob> {
    let remote_key = Arc::new(remote_p_did.to_string());
    let relationship = config.private.relationships.get(&remote_key)?;
    let our_did = Arc::clone(&relationship.our_did);
    let remote_did = Arc::clone(&relationship.remote_did);

    let message = VrcRequest {
        reason: reason.map(ToString::to_string),
    }
    .create_message(&remote_did, &our_did)
    .ok()?;
    let msg_id = Arc::new(message.id.clone());

    Some(VrcRequestJob {
        service: service.clone(),
        listener_id: crate::state_handler::didcomm::listener_id_for_did(&our_did, config),
        message: Box::new(message),
        remote_did,
        remote_p_did: remote_key,
        msg_id,
    })
}

/// Remove a VRC by its ID from both received and issued collections.
pub fn remove_vrc(config: &mut Config, vrc_id: &str) -> Result<()> {
    let vrc_id = Arc::new(vrc_id.to_string());
    config.private.vrcs_received.remove_vrc(&vrc_id);
    config.private.vrcs_issued.remove_vrc(&vrc_id);

    config
        .public
        .logs
        .insert(LogFamily::Task, format!("Removed VRC ({})", vrc_id));

    debug!(vrc_id = %vrc_id, "VRC removed");
    Ok(())
}

// ============================================================
// State-handler dispatch wrappers
// ============================================================

use crate::state_handler::{
    actions::CredentialAction,
    dispatch_util,
    main_page::content::{CredentialTab, CredentialsMode},
    save_coalesce::SaveScheduler,
    state::State,
};

fn handle_switch_tab(state: &mut State) {
    state.main_page.content_panel.credentials.selected_tab =
        match state.main_page.content_panel.credentials.selected_tab {
            CredentialTab::Received => CredentialTab::Issued,
            CredentialTab::Issued => CredentialTab::Membership,
            CredentialTab::Membership => CredentialTab::Vetting,
            CredentialTab::Vetting => CredentialTab::Received,
        };
    state.main_page.content_panel.credentials.selected_index = 0;
}

fn handle_open_detail(state: &mut State, index: usize) {
    state.main_page.content_panel.credentials.selected_index = index;
    state.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index };
}

fn handle_back(state: &mut State) {
    state.main_page.content_panel.credentials.mode = CredentialsMode::List;
    state.main_page.content_panel.credentials.selected_index = 0;
}

fn handle_start_new_request(state: &mut State) {
    state.main_page.content_panel.credentials.mode = CredentialsMode::NewRequest {
        relationship_index: 0,
        reason_input: String::new(),
    };
}

fn handle_select_relationship(state: &mut State, index: usize) {
    if let CredentialsMode::NewRequest {
        ref mut relationship_index,
        ..
    } = state.main_page.content_panel.credentials.mode
    {
        let established_count = state
            .main_page
            .content_panel
            .relationships
            .relationships
            .iter()
            .filter(|r| r.state == "Established")
            .count();
        if index < established_count {
            *relationship_index = index;
        }
    }
}

fn handle_reason_update(state: &mut State, value: String) {
    if let CredentialsMode::NewRequest {
        ref mut reason_input,
        ..
    } = state.main_page.content_panel.credentials.mode
    {
        *reason_input = value;
    }
}

fn handle_remove(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    vrc_id: &str,
) {
    // The confirmation is now resolved.
    state.main_page.content_panel.credentials.confirm_delete = None;
    if let Err(e) = remove_vrc(config, vrc_id) {
        state.main_page.log_error("Failed to remove VRC", &e);
        return;
    }
    state.main_page.content_panel.credentials.mode = CredentialsMode::List;
    state.main_page.content_panel.credentials.selected_index = 0;
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        dispatch_util::Persist::SaveAndSync,
        |mp| &mut mp.content_panel.credentials.status_message,
        "VRC removed",
        dispatch_util::SyncLog::Plain("VRC removed".to_string()),
    );
}

/// Dispatch a single `CredentialAction`.
///
/// Takes neither the TDK nor the messaging service any more: the one action that
/// used them — requesting a VRC from a peer — is dispatched off the loop, so
/// everything reaching here is state or config. Not `async` either, for the same
/// reason.
pub(crate) fn dispatch(
    action: CredentialAction,
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
) {
    match action {
        CredentialAction::SwitchTab => handle_switch_tab(state),
        CredentialAction::Select(index) => {
            state.main_page.content_panel.credentials.selected_index = index;
        }
        CredentialAction::OpenDetail(index) => handle_open_detail(state, index),
        CredentialAction::Back | CredentialAction::CancelNewRequest => handle_back(state),
        CredentialAction::StartNewRequest => handle_start_new_request(state),
        CredentialAction::SelectRelationship(index) => handle_select_relationship(state, index),
        CredentialAction::ReasonUpdate(value) => handle_reason_update(state, value),
        // `SubmitRequest` is not handled here: it is the one credential action
        // that goes to the network, so the loop resolves it into a
        // `VrcRequestJob` and dispatches it. Everything else in this module is
        // state or config, which is why the dispatcher stayed on the loop.
        CredentialAction::SubmitRequest { .. } => {
            debug_assert!(false, "SubmitRequest is dispatched by the loop");
        }
        CredentialAction::Remove { vrc_id } => handle_remove(config, state, save, &vrc_id),
        // R25 confirmation arming/cancel — pure state mutations.
        CredentialAction::ConfirmRemove { vrc_id } => {
            state.main_page.content_panel.credentials.confirm_delete = Some(vrc_id);
        }
        CredentialAction::CancelRemove => {
            state.main_page.content_panel.credentials.confirm_delete = None;
        }
    }
}

#[cfg(test)]
mod tests {
    //! Table-driven tests for the pure mode-transition handlers in this module.
    //! Each is a pure function of `&mut State`; the tables drive the handler from
    //! a starting `State` and assert on the resulting credentials-panel mode/tab.
    //! Mirrors the table-test style in `ui/pages/setup_flow/navigation.rs`.
    use super::*;

    /// `handle_switch_tab` cycles Received → Issued → Membership → Vetting →
    /// Received and
    /// resets the selection index each time.
    #[test]
    fn switch_tab_cycles_and_resets_index() {
        // (starting tab, expected next tab)
        let cases: &[(CredentialTab, CredentialTab)] = &[
            (CredentialTab::Received, CredentialTab::Issued),
            (CredentialTab::Issued, CredentialTab::Membership),
            (CredentialTab::Membership, CredentialTab::Vetting),
            (CredentialTab::Vetting, CredentialTab::Received),
        ];
        for (start, expected) in cases {
            let mut state = State::default();
            state.main_page.content_panel.credentials.selected_tab = *start;
            state.main_page.content_panel.credentials.selected_index = 5;
            handle_switch_tab(&mut state);
            assert_eq!(
                state.main_page.content_panel.credentials.selected_tab, *expected,
                "from {start:?}"
            );
            assert_eq!(
                state.main_page.content_panel.credentials.selected_index, 0,
                "index reset on tab switch from {start:?}"
            );
        }
    }

    /// `handle_open_detail` enters `Detail { index }` and tracks the index;
    /// `handle_back` returns to `List` resetting the index.
    #[test]
    fn open_detail_and_back_transitions() {
        for index in [0usize, 3, 42] {
            let mut state = State::default();
            handle_open_detail(&mut state, index);
            assert!(
                matches!(
                    state.main_page.content_panel.credentials.mode,
                    CredentialsMode::Detail { index: i } if i == index
                ),
                "open_detail({index}) enters Detail"
            );
            assert_eq!(
                state.main_page.content_panel.credentials.selected_index,
                index
            );

            handle_back(&mut state);
            assert!(
                matches!(
                    state.main_page.content_panel.credentials.mode,
                    CredentialsMode::List
                ),
                "back returns to List"
            );
            assert_eq!(state.main_page.content_panel.credentials.selected_index, 0);
        }
    }

    /// `handle_start_new_request` enters the `NewRequest` form with a zeroed
    /// relationship index and an empty reason.
    #[test]
    fn start_new_request_enters_form() {
        let mut state = State::default();
        handle_start_new_request(&mut state);
        match &state.main_page.content_panel.credentials.mode {
            CredentialsMode::NewRequest {
                relationship_index,
                reason_input,
            } => {
                assert_eq!(*relationship_index, 0);
                assert!(reason_input.is_empty());
            }
            other => panic!("expected NewRequest, got {other:?}"),
        }
    }

    /// `handle_reason_update` writes the reason only while in `NewRequest`, and is
    /// a no-op in other modes. Table-driven over the starting mode.
    #[test]
    fn reason_update_only_in_new_request() {
        // In NewRequest: the reason is written.
        let mut state = State::default();
        handle_start_new_request(&mut state);
        handle_reason_update(&mut state, "because".to_string());
        assert!(matches!(
            &state.main_page.content_panel.credentials.mode,
            CredentialsMode::NewRequest { reason_input, .. } if reason_input == "because"
        ));

        // In List / Detail: a no-op (mode unchanged).
        for mode in [CredentialsMode::List, CredentialsMode::Detail { index: 1 }] {
            let mut state = State::default();
            state.main_page.content_panel.credentials.mode = mode.clone();
            handle_reason_update(&mut state, "ignored".to_string());
            assert_eq!(
                std::mem::discriminant(&state.main_page.content_panel.credentials.mode),
                std::mem::discriminant(&mode),
                "reason_update is a no-op outside NewRequest"
            );
        }
    }
}

#[cfg(test)]
mod vrc_request_tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    fn outcome(error: Option<&str>) -> VrcRequestOutcome {
        VrcRequestOutcome {
            remote_p_did: Arc::new("did:webvh:QmScidPeer:example.com:bob".to_string()),
            msg_id: Arc::new("msg-1".to_string()),
            error: error.map(ToString::to_string),
        }
    }

    /// A sent request creates the task that will match the reply. It is created
    /// on the outcome, not before the send, so a request that never left cannot
    /// leave a task waiting for a reply that cannot come.
    #[test]
    fn a_sent_request_creates_the_tracking_task() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        outcome(None).apply(&mut state, &mut config, &mut save);

        assert_eq!(config.private.tasks.tasks.len(), 1, "one tracking task");
        assert!(save.is_pending());
    }

    /// A failed send creates none, and says why.
    #[test]
    fn a_failed_request_creates_no_task() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        outcome(Some("peer unreachable")).apply(&mut state, &mut config, &mut save);

        assert_eq!(
            config.private.tasks.tasks.len(),
            0,
            "no task for a failed send"
        );
        assert!(
            state
                .main_page
                .content_panel
                .credentials
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("unreachable")),
        );
    }
}
