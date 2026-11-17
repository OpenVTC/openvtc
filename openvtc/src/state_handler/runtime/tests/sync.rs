//! Runtime-harness tests driving the handlers that sync only some panels: each
//! leaves the whole page as a full `sync_from_config` would, so a handler that
//! changes more than its `Panels` set covers is caught (#612).

use std::sync::Arc;

use super::*;
use crate::state_handler::actions::{InboxAction, SettingsAction, VettingAction};
use crate::state_handler::main_page::content::{SettingsMode, VettingMode};
use crate::state_handler::main_page::test_clock;
use crate::state_handler::main_page::tests::{
    BOB_DID, JOINING_VTC, REJECTED_VTC, SECOND_VTC, assert_fully_synced, blank_page, busy_config,
    signed_vrc,
};
use crate::state_handler::vetting_actions::{Sent, VettingOutcome};
use openvtc_core::tasks::TaskType;

/// A runtime over the account that fills every panel, its page fully synced.
async fn busy_runtime() -> (Runtime, Handles) {
    let (mut rt, h) = runtime().await;
    rt.config = Box::new(busy_config());
    rt.state.main_page = blank_page();
    rt.state.main_page.sync_from_config(&rt.config);
    (rt, h)
}

/// Where `vtc` is in the Communities overview's display order.
fn display_index(rt: &Runtime, vtc: &str) -> usize {
    rt.config
        .account
        .communities_for_display(rt.state.main_page.content_panel.communities.show_archived)
        .iter()
        .position(|c| c.vtc_did == vtc)
        .expect("listed")
}

fn task(rt: &mut Runtime, id: &str, type_: TaskType) {
    let persona = rt.config.active_persona;
    rt.config
        .private
        .tasks
        .new_task_for(&Arc::new(id.to_string()), type_, persona);
    rt.state.main_page.sync_from_config(&rt.config);
}

#[tokio::test]
async fn accepting_a_vrc_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    rt.config
        .private
        .vrcs_received
        .remove_relationship(&Arc::new(BOB_DID.to_string()));
    let vrc = signed_vrc(BOB_DID, "did:key:zSomeoneElse");
    task(
        &mut rt,
        "task-vrc",
        TaskType::VRCIssued {
            vrc: Box::new((*vrc).clone()),
        },
    );

    rt.on_action(Action::Inbox(InboxAction::AcceptVrc {
        task_id: "task-vrc".into(),
    }))
    .await;

    assert!(rt.save.is_pending(), "the VRC was stored");
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

#[tokio::test]
async fn dismissing_a_task_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;

    rt.on_action(Action::Inbox(InboxAction::DismissTask {
        task_id: "task-accepted".into(),
    }))
    .await;

    assert!(rt.save.is_pending());
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

/// A sent session clears the inbox task it answered, prunes the book and
/// saves (`outcome::sent_result`, then `Persist`).
#[tokio::test]
async fn a_vetting_send_outcome_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    task(
        &mut rt,
        "vetting-request-r1",
        TaskType::RelationshipRequestAccepted,
    );

    rt.on_dispatch_outcome(background_dispatch::DispatchOutcome::Vetting(
        VettingOutcome::Sent {
            sent: Box::new(Sent::Session {
                request_id: "r1".into(),
            }),
            error: None,
        },
    ))
    .await;

    assert!(
        !rt.config
            .private
            .tasks
            .tasks
            .contains_key(&Arc::new("vetting-request-r1".to_string()))
    );
    assert!(rt.save.is_pending());
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

/// Abandoning an application: the plan's own sync, then its save.
#[tokio::test]
async fn abandoning_an_application_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    let application_id = rt
        .config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.community == JOINING_VTC)
        .unwrap()
        .id
        .clone();
    rt.state.main_page.content_panel.vetting.mode = VettingMode::ConfirmAbandon { application_id };

    rt.on_action(Action::Vetting(VettingAction::Submit)).await;

    assert_eq!(rt.config.private.vetting.applications.len(), 1);
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

#[tokio::test]
async fn a_favourite_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    let header = rt.state.main_page.config.community.clone();
    let i = display_index(&rt, SECOND_VTC);

    rt.on_action(Action::ToggleFavourite(i)).await;

    assert_ne!(
        rt.state.main_page.config.community, header,
        "the favourite is named in the header now"
    );
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

#[tokio::test]
async fn archiving_an_inactive_membership_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    let i = display_index(&rt, REJECTED_VTC);

    rt.on_action(Action::ArchiveCommunity(i)).await;

    assert!(rt.config.account.communities[REJECTED_VTC][0].archived);
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

#[tokio::test]
async fn acknowledging_an_outcome_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    let before = rt
        .state
        .main_page
        .content_panel
        .communities
        .actions_required;
    let i = display_index(&rt, REJECTED_VTC);

    rt.on_action(Action::AcknowledgeCommunity(i)).await;

    assert_eq!(
        rt.state
            .main_page
            .content_panel
            .communities
            .actions_required,
        before - 1
    );
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

#[tokio::test]
async fn showing_archived_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    let rows = rt.state.main_page.content_panel.communities.items.len();

    rt.on_action(Action::ToggleShowArchived).await;

    assert_eq!(
        rt.state.main_page.content_panel.communities.items.len(),
        rows + 1,
        "the archived membership is listed"
    );
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

#[tokio::test]
async fn a_friendly_name_syncs_as_a_full_sync_would() {
    let _clock = test_clock::freeze(chrono::Utc::now());
    let (mut rt, _h) = busy_runtime().await;
    let settings = &mut rt.state.main_page.content_panel.settings;
    settings.selected_index = crate::ui::pages::main::components::settings_panel::FRIENDLY_NAME_ROW;
    settings.mode = SettingsMode::EditFriendlyName {
        input: "Someone Else".into(),
    };

    rt.on_action(Action::Settings(SettingsAction::SubmitEdit {
        value: "Someone Else".into(),
    }))
    .await;

    assert_eq!(rt.config.public.friendly_name, "Someone Else");
    assert_fully_synced(&rt.state.main_page, &rt.config);
}

/// The loop's minute tick brings time-dependent text up to date: after a
/// long gap, the page is what a full sync gives.
#[tokio::test]
async fn the_minute_tick_catches_up_with_the_clock() {
    let now = chrono::Utc::now();
    let (mut rt, _h) = {
        let _clock = test_clock::freeze(now);
        busy_runtime().await
    };

    let _clock = test_clock::freeze(now + chrono::Duration::days(400));
    rt.on_join_status_tick().await;

    assert_fully_synced(&rt.state.main_page, &rt.config);
}
