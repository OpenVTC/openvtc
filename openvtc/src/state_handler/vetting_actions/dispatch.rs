//! Maps each `VettingAction` onto the page: the action dispatcher, form
//! navigation, and form submission.
//!
//! An action is first offered to [`reduce`], which makes the view-only
//! changes — moving through a form, opening one, reading a pasted link — on
//! the state, reading the book but never changing it. An action that changes
//! the book or sends is planned by [`plan`], which is pure: it decides, makes
//! the state and book changes the action makes before anything is saved or
//! signed, and returns a [`VettingEffect`] that [`run`] carries out. What
//! follows an action whatever became of it — reading requirements again asks
//! for the hidden-vetting challenge and runs the vetter pass even after a
//! refusal — is a step the runner runs regardless ([`Step::Always`]).

use crate::state_handler::main_page::status::Status;
use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::vetting::vetter::DeskState;
use vta_sdk::protocols::vetting::VettingMethod;

use super::answers::focus_application;
use super::applicant::{
    ask_listed_vetter, open_directory, paste_ticket, plan_abandon_application, plan_directory_page,
    plan_refresh_requirements, plan_request_vetter, plan_search_directory, plan_start_application,
    plan_started, plan_switch_vetting_path, refresh_application_contexts,
};
use super::desk::{
    Attesting, HiddenAttest, plan_ask_binding, plan_ask_manifest, plan_attest, plan_decline_submit,
    plan_open_session, plan_session_kept, plan_switch_tab, plan_withdraw,
};
use super::effect::{Followup, Step, VettingEffect, run, warned_since};
use super::faces::{
    plan_choose_face, plan_create_face, plan_open_new_face, plan_send_card, plan_wear_face,
};
use super::hidden::{
    plan_ask_for_challenge, plan_attest_hidden, plan_check_hidden_key, plan_draw_now,
    plan_hidden_view_submit,
};
use super::tickets::{plan_delete_ticket, plan_issue_ticket};
use super::vetter::{
    open_profile, plan_ask_event_mode, plan_ask_resend, plan_profile_submit, profile_form,
};
use super::view_sync::sync_journey;
use crate::state_handler::actions::VettingAction;
use crate::state_handler::background_dispatch::DispatchDomain;
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::main_page::content::{
    AttestForm, DECLINE_REASONS, DIRECTORY_METHODS, DeskStage, DeskView, EVENT_FIELDS,
    JourneyTarget, VETTING_METHODS, VETTING_RELATIONSHIPS, VETTING_TICKET_USES,
    VETTING_WITHDRAWAL_REASONS, VettingMode, VettingState, VettingTab,
};
use crate::state_handler::main_page::sync_clock;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

// ============================================================================
// Actions
// ============================================================================

/// The vetting page's state.
pub(super) fn panel(state: &mut State) -> &mut VettingState {
    &mut state.main_page.content_panel.vetting
}

/// Set the vetting page's status line, with the severity the caller knows.
pub(super) fn show(state: &mut State, message: Status) {
    panel(state).status_message = Some(message);
}

/// Persist the book and show `message`.
pub(super) fn persist(ctx: &mut ActionCtx<'_>, message: impl Into<String>) {
    let message = message.into();
    dispatch_util::save_and_sync(
        &mut ctx.state.main_page,
        ctx.config,
        ctx.save,
        Persist::SaveAndSync(crate::state_handler::main_page::Panels::FROM_VETTING_BOOK),
        |mp| &mut mp.content_panel.vetting.status_message,
        message.clone(),
        SyncLog::Plain(message),
    );
}

/// Handle one Vetting-page action: [`plan`] it and [`run`] the effect.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: VettingAction) {
    let busy = ctx.in_flight.is_busy(DispatchDomain::Vetting);
    let has_vta = ctx.admin_vta.is_some();
    let effect = plan(ctx.state, ctx.config, busy, has_vta, action);
    run(ctx, effect).await;
}

/// Apply a view-only action: one that changes the page and at most reads the
/// book. Returns `false` for the actions that change the book, send, or are
/// handled on the loop.
pub(super) fn reduce(state: &mut State, config: &Config, action: &VettingAction) -> bool {
    match action {
        VettingAction::OpenJourney => {
            let v = panel(state);
            let target = match (v.tab, v.desk_view) {
                (VettingTab::Applications, _) => v
                    .applications
                    .get(v.selected)
                    .map(|r| JourneyTarget::Application(r.id.clone())),
                (VettingTab::Desk, DeskView::Requests) => v
                    .desk
                    .get(v.selected)
                    .map(|r| JourneyTarget::Desk(r.request_id.clone())),
                _ => None,
            };
            if let Some(target) = target {
                v.journey_target = Some(target);
                v.mode = VettingMode::List;
                v.status_message = None;
                sync_journey(panel(state), config, sync_clock());
            }
        }
        VettingAction::OpenApplication(application_id) => {
            if config
                .private
                .vetting
                .applications
                .iter()
                .any(|a| a.id == *application_id)
            {
                focus_application(
                    state,
                    config,
                    application_id,
                    "Where your application stands, and what happens next.".to_string(),
                );
            } else {
                // Finished or abandoned between the panel drawing it and the
                // key arriving: say so where the holder is looking.
                state.main_page.content_panel.communities.status_message = Some(Status::warning(
                    "That application is no longer in progress.".to_string(),
                ));
            }
        }
        VettingAction::CloseJourney => {
            let v = panel(state);
            v.journey_target = None;
            v.journey = None;
            v.mode = VettingMode::List;
        }
        VettingAction::ShowTicket => {
            let v = panel(state);
            // Only a ticket that can still be redeemed is worth holding up to a
            // camera; a spent one would scan and then be refused.
            if v.tickets.get(v.selected).is_some_and(|t| t.live) {
                v.mode = VettingMode::ShowTicket { index: v.selected };
                v.status_message = None;
            }
        }
        VettingAction::SwitchDeskView(forward) => {
            let v = panel(state);
            // The desk view is remembered across a tab switch, so this only
            // has to reset the cursor — the lists are different lengths and a
            // carried index would point at a different row, or at none.
            v.desk_view = v.desk_view.shifted(*forward);
            v.selected = 0;
            v.status_message = None;
        }
        VettingAction::Select(i) => {
            let v = panel(state);
            v.selected = (*i).min(v.tab_len().saturating_sub(1));
        }
        VettingAction::Back => back(panel(state)),
        VettingAction::PasteTicket(text) => paste_ticket(state, config, text),
        VettingAction::FindVetters => open_directory(state),
        VettingAction::AskListedVetter => ask_listed_vetter(state),
        VettingAction::EditProfile => open_profile(state, config),
        VettingAction::RemoveEvent => {
            if let VettingMode::Profile(form) = &mut panel(state).mode
                && form.event.is_none()
                && let Some(i) = form.event_index()
            {
                form.draft.events.remove(i);
                form.field = form.field.min(form.rows() - 1);
                form.error = None;
            }
        }
        VettingAction::AskResend => {
            if panel(state).resend_candidates.is_empty() {
                show(
                    state,
                    Status::warning(
                        "Every community you are an active member of has already sent you a live \
                     vetter credential — or you are not an active member of any.",
                    ),
                );
            } else {
                panel(state).mode = VettingMode::Resend { index: 0 };
            }
        }
        VettingAction::AskEventMode => {
            if panel(state).event_offers.is_empty() {
                show(
                    state,
                    Status::warning(
                        "No community you vet for is running an event. Event mode is the exception, \
                     not the setting — an ordinary week is the slow drip.",
                    ),
                );
            } else {
                panel(state).mode = VettingMode::EventMode { index: 0 };
            }
        }
        VettingAction::Status(message) => show(state, message.clone()),
        VettingAction::Input(text) => {
            input(&mut panel(state).mode, text.clone());
            refresh_application_contexts(state, config);
        }
        VettingAction::NextField => move_field(panel(state), true),
        VettingAction::PrevField => move_field(panel(state), false),
        VettingAction::Cycle(forward) => {
            let before = profile_membership(panel(state));
            cycle(panel(state), *forward);
            let after = profile_membership(panel(state));
            if let Some(index) = after
                && before != after
            {
                // Each community has its own profile: show the one for this one.
                let form = profile_form(panel(state), &config.private.vetting, index, 0);
                panel(state).mode = VettingMode::Profile(Box::new(form));
            }
            refresh_application_contexts(state, config);
        }
        VettingAction::Toggle => match &mut panel(state).mode {
            VettingMode::NewFace(form) => form.toggle(),
            VettingMode::Attest { form, .. } => match form.field {
                3 => form.liveness_confirmed = !form.liveness_confirmed,
                4 => form.attested = !form.attested,
                _ => {}
            },
            VettingMode::Profile(form) if form.event.is_none() => {
                match form.field {
                    1 => form.draft.listed = !form.draft.listed,
                    7 => form.draft.toggle_method(VettingMethod::InPerson),
                    8 => form.draft.toggle_method(VettingMethod::Video),
                    9 => form.draft.toggle_method(VettingMethod::PriorAcquaintance),
                    _ => {}
                }
                form.error = None;
            }
            _ => {}
        },
        VettingAction::StartApplication => {
            if panel(state).personas.is_empty() {
                show(
                    state,
                    Status::warning(
                        "Create a persona under My Identity first — it is the DID you join with.",
                    ),
                );
            } else {
                panel(state).mode = VettingMode::NewApplication {
                    community: String::new(),
                    persona_index: 0,
                    context_options: Vec::new(),
                    context_index: 0,
                    field: 0,
                };
                refresh_application_contexts(state, config);
            }
        }
        VettingAction::RequestVetter => {
            let v = panel(state);
            if let Some(row) = v.applications.get(v.selected).cloned() {
                v.mode = VettingMode::RequestVetter {
                    application_id: row.id,
                    entry: String::new(),
                    vetter: String::new(),
                    ticket: None,
                    note: None,
                };
            }
        }
        VettingAction::OpenHiddenVetting => {
            if panel(state).hidden.is_empty() {
                show(
                    state,
                    Status::warning(
                        "None of the communities you vet for hides its vetters, so there is no \
                     hidden vetting to show.",
                    ),
                );
            } else {
                panel(state).mode = VettingMode::HiddenVetting { index: 0 };
            }
        }
        VettingAction::ReviewCard => {
            let v = panel(state);
            let Some(row) = v.applications.get(v.selected).cloned() else {
                return true;
            };
            match row.requests.iter().find_map(|r| r.card_session.clone()) {
                Some(session_id) => {
                    v.mode = VettingMode::SendCard {
                        application_id: row.id,
                        session_id,
                        preview: None,
                    };
                }
                None => show(
                    state,
                    Status::warning("No vetter is waiting for your card."),
                ),
            }
        }
        VettingAction::NewTicket => {
            if panel(state).memberships.is_empty() {
                show(
                    state,
                    Status::warning(
                        "You can hand out tickets once a community you belong to has named you a \
                     vetter — ask its admins for the vetter role.",
                    ),
                );
            } else {
                panel(state).mode = VettingMode::NewTicket {
                    membership_index: 0,
                    uses_index: 0,
                    field: 0,
                };
            }
        }
        VettingAction::DeleteTicket => {
            let v = panel(state);
            match v.tickets.get(v.selected).cloned() {
                Some(row) => v.mode = VettingMode::ConfirmDeleteTicket { ticket_id: row.id },
                None => show(state, Status::warning("Highlight a ticket to delete.")),
            }
        }
        VettingAction::OpenSession => {
            let v = panel(state);
            match v.desk.get(v.selected).cloned() {
                Some(row) if matches!(row.stage, DeskStage::Accepted | DeskStage::Session) => {
                    v.mode = VettingMode::OpenSession {
                        request_id: row.request_id,
                        method_index: 0,
                    };
                }
                Some(_) => show(
                    state,
                    Status::warning("That request has moved past opening a session."),
                ),
                None => {}
            }
        }
        VettingAction::StartAttest => {
            // The form opens on the method the session was opened with: the
            // statement says how the person was checked, and a default of "in
            // person" after a video call is a false statement one Enter away.
            let selected = {
                let v = panel(state);
                v.desk.get(v.selected).cloned()
            };
            match selected {
                Some(row) if row.stage == DeskStage::Card => {
                    let method_index = match config
                        .private
                        .vetting
                        .desk_entry(&row.request_id)
                        .map(|e| &e.state)
                    {
                        Some(DeskState::CardReceived { session, .. }) => VETTING_METHODS
                            .iter()
                            .position(|m| *m == session.method)
                            .unwrap_or(0),
                        _ => 0,
                    };
                    panel(state).mode = VettingMode::Attest {
                        request_id: row.request_id,
                        form: AttestForm {
                            method_index,
                            ..AttestForm::default()
                        },
                    };
                }
                Some(_) => show(
                    state,
                    Status::warning("You can attest once their card has arrived."),
                ),
                None => {}
            }
        }
        VettingAction::ArmDecline => {
            let v = panel(state);
            match v.desk.get(v.selected).cloned() {
                Some(row) if row.stage != DeskStage::Closed => {
                    v.mode = VettingMode::ConfirmDecline {
                        request_id: row.request_id,
                        reason_index: 0,
                        message: String::new(),
                        field: 0,
                    };
                }
                Some(_) => show(state, Status::warning("That request is already closed.")),
                None => {}
            }
        }
        VettingAction::ArmAbandon => {
            let v = panel(state);
            match v.applications.get(v.selected).cloned() {
                Some(row) => {
                    v.mode = VettingMode::ConfirmAbandon {
                        application_id: row.id,
                    };
                }
                None => show(
                    state,
                    Status::warning("Highlight an application to abandon."),
                ),
            }
        }
        VettingAction::ArmWithdraw => {
            let v = panel(state);
            match v.issued.get(v.selected).cloned() {
                // Sent but not recorded is not withdrawn: the community may
                // have refused it, or never heard it, and the core allows the
                // notice again until it is recorded. Refusing here left a
                // refused withdrawal with no way forward.
                Some(row) if !row.withdrawal_recorded => {
                    v.mode = VettingMode::Withdraw {
                        statement_id: row.id,
                        reason_index: 0,
                    };
                }
                Some(_) => show(
                    state,
                    Status::warning(
                        "That statement is already withdrawn — the community recorded it.",
                    ),
                ),
                None => {}
            }
        }
        VettingAction::SwitchTab
        | VettingAction::DirectoryPage(_)
        | VettingAction::ChooseFace
        | VettingAction::RefreshRequirements
        | VettingAction::SwitchVettingPath
        | VettingAction::RefreshVetterSide
        | VettingAction::CheckHiddenKey
        | VettingAction::DrawNow
        | VettingAction::Submit => return false,
    }
    true
}

/// Plan an action. Pure: no awaits, no spawning, no saving. It makes the
/// state and book changes the action makes before anything is saved or
/// signed, and returns what is left. `busy` is whether a vetting job holds
/// the domain, decided before any preparation, as the job that would claim it
/// finds it. `has_vta` is whether the loop holds a VTA session, which a face
/// or card job runs against.
pub(super) fn plan(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    has_vta: bool,
    action: VettingAction,
) -> VettingEffect {
    if reduce(state, config, &action) {
        return VettingEffect::none();
    }
    match action {
        VettingAction::DirectoryPage(forward) => plan_directory_page(state, config, busy, forward),
        VettingAction::SwitchVettingPath => plan_switch_vetting_path(state, config),
        VettingAction::SwitchTab => plan_switch_tab(state, config),
        VettingAction::Submit => plan_submit(state, config, busy, has_vta),
        VettingAction::CheckHiddenKey => plan_check_hidden_key(state, config, Utc::now()),
        VettingAction::DrawNow => plan_draw_now(config, Utc::now()),
        VettingAction::ChooseFace => plan_choose_face(state, config, busy, has_vta),
        VettingAction::RefreshVetterSide => VettingEffect(vec![Step::RefreshVetterSide]),
        VettingAction::RefreshRequirements => plan_refresh(state, config, busy),
        // View-only: `reduce` handled these.
        VettingAction::OpenJourney
        | VettingAction::OpenApplication(_)
        | VettingAction::CloseJourney
        | VettingAction::ShowTicket
        | VettingAction::SwitchDeskView(_)
        | VettingAction::Select(_)
        | VettingAction::Back
        | VettingAction::PasteTicket(_)
        | VettingAction::FindVetters
        | VettingAction::AskListedVetter
        | VettingAction::EditProfile
        | VettingAction::RemoveEvent
        | VettingAction::AskResend
        | VettingAction::AskEventMode
        | VettingAction::Status(_)
        | VettingAction::Input(_)
        | VettingAction::NextField
        | VettingAction::PrevField
        | VettingAction::Cycle(_)
        | VettingAction::Toggle
        | VettingAction::StartApplication
        | VettingAction::RequestVetter
        | VettingAction::OpenHiddenVetting
        | VettingAction::ReviewCard
        | VettingAction::NewTicket
        | VettingAction::DeleteTicket
        | VettingAction::OpenSession
        | VettingAction::StartAttest
        | VettingAction::ArmDecline
        | VettingAction::ArmAbandon
        | VettingAction::ArmWithdraw => VettingEffect::none(),
    }
}

/// Plan reading the selected application's requirements again, then — however
/// that went — asking its community for a hidden-vetting challenge and running
/// the vetter pass.
///
/// The challenge is asked even when the refresh is refused or gives up: the
/// community keeps one per applicant, so asking again replaces it. It asks
/// quietly when the refresh said why it did not happen, so that stays on the
/// status line. The vetter pass runs with or without an application: a vetter
/// has none, and nothing else would fetch the manifest of a community it vets
/// for — which is where a community says it hides its vetters.
fn plan_refresh(state: &mut State, config: &mut Config, busy: bool) -> VettingEffect {
    let v = panel(state);
    let mut steps = Vec::new();
    if let Some(row) = v.applications.get(v.selected).cloned() {
        let said_before = panel(state).status_message.clone();
        let VettingEffect(refresh) = plan_refresh_requirements(state, config, busy, &row.id);
        steps.extend(refresh);
        steps.push(Step::always(Step::Then(Followup::AskChallenge {
            application_id: row.id,
            said_before,
        })));
    }
    steps.push(Step::always(Step::RefreshVetterSide));
    VettingEffect(steps)
}

/// Plan Enter on the open view.
fn plan_submit(state: &mut State, config: &mut Config, busy: bool, has_vta: bool) -> VettingEffect {
    match panel(state).mode.clone() {
        VettingMode::List => VettingEffect::none(),
        // Nothing to submit — it is a code being held up to a phone. Enter
        // closes it, the same as Esc, because both are what a hand reaches for
        // when the scan is done.
        VettingMode::ShowTicket { .. } => {
            back(panel(state));
            VettingEffect::none()
        }
        // Nor here: it says what to run somewhere else. Enter closes it like
        // Esc, rather than being the one view where Enter does nothing.
        VettingMode::HolderGrant { .. } => {
            back(panel(state));
            VettingEffect::none()
        }
        VettingMode::NewApplication {
            community,
            persona_index,
            context_options,
            context_index,
            ..
        } => {
            let context = context_options
                .get(context_index)
                .map(|o| o.context_id.clone());
            plan_start_application(state, config, community.trim(), persona_index, context)
        }
        VettingMode::ConfirmAbandon { .. } => plan_abandon_application(state, config),
        VettingMode::RequestVetter {
            application_id,
            entry,
            vetter,
            ticket,
            ..
        } => plan_request_vetter(
            state,
            config,
            busy,
            &application_id,
            entry.trim(),
            vetter.trim(),
            ticket,
        ),
        VettingMode::Directory(view) => match view.result_index() {
            Some(_) => {
                ask_listed_vetter(state);
                VettingEffect::none()
            }
            None => plan_search_directory(state, config, busy, vec![None]),
        },
        VettingMode::Profile(form) => plan_profile_submit(state, config, busy, *form),
        VettingMode::Resend { index } => plan_ask_resend(state, config, busy, index),
        VettingMode::EventMode { index } => plan_ask_event_mode(state, config, busy, index),
        VettingMode::ConfirmDeleteTicket { ticket_id } => {
            plan_delete_ticket(state, config, &ticket_id)
        }
        VettingMode::NewTicket {
            membership_index,
            uses_index,
            ..
        } => plan_issue_ticket(state, config, busy, membership_index, uses_index),
        VettingMode::OpenSession {
            request_id,
            method_index,
        } => plan_open_session(state, config, busy, &request_id, method_index),
        VettingMode::ConfirmDecline {
            request_id,
            reason_index,
            message,
            ..
        } => {
            let code = DECLINE_REASONS.get(reason_index).and_then(|(c, _)| *c);
            plan_decline_submit(state, config, busy, &request_id, code, &message)
        }
        VettingMode::Withdraw {
            statement_id,
            reason_index,
        } => plan_withdraw(state, config, busy, &statement_id, reason_index),
        VettingMode::HiddenVetting { .. } => plan_hidden_view_submit(state),
        VettingMode::ChooseFace {
            application_id,
            faces,
            index,
            required,
        } => {
            if index == faces.len() {
                plan_open_new_face(state, busy, has_vta, &application_id, required)
            } else {
                plan_wear_face(
                    state,
                    config,
                    busy,
                    has_vta,
                    &application_id,
                    faces.get(index).cloned(),
                )
            }
        }
        VettingMode::NewFace(form) => plan_create_face(state, config, busy, has_vta, *form),
        VettingMode::SendCard {
            application_id,
            session_id,
            preview,
        } => plan_send_card(
            state,
            config,
            busy,
            has_vta,
            &application_id,
            &session_id,
            preview,
        ),
        VettingMode::Attest { request_id, form } => {
            match plan_attest(state, config, busy, &request_id, &form) {
                Attesting::Effect(effect) => effect,
                Attesting::Hidden(hidden) => {
                    let HiddenAttest {
                        request_id,
                        entry,
                        vetter_did,
                        attestation,
                        now,
                    } = *hidden;
                    plan_attest_hidden(
                        state,
                        config,
                        has_vta,
                        &request_id,
                        &entry,
                        &vetter_did,
                        attestation,
                        now,
                    )
                }
                Attesting::Enrol => VettingEffect(vec![Step::RefreshVetterSide]),
            }
        }
    }
}

/// Plan a [`Followup`], on the state and book the steps before it left.
pub(super) fn plan_followup(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    followup: Followup,
) -> VettingEffect {
    match followup {
        Followup::AskChallenge {
            application_id,
            said_before,
        } => {
            let refused = warned_since(state, said_before.as_ref());
            plan_ask_for_challenge(state, config, &application_id, !refused)
        }
        Followup::Started {
            application_id,
            started,
        } => plan_started(state, config, busy, &application_id, &started),
        // desk and tickets
        Followup::SessionKept {
            request_id,
            known,
            previous,
        } => plan_session_kept(state, config, &request_id, known, previous),
        Followup::AskManifest { community, persona } => {
            plan_ask_manifest(config, &community, persona)
        }
        Followup::AskBinding {
            community,
            persona,
            now,
        } => plan_ask_binding(config, &community, persona, now),
    }
}

pub(super) fn input(mode: &mut VettingMode, text: String) {
    // Editing the field discards what the last link was read as: the vetter and
    // the ticket both come out of that text, and leaving either behind would
    // send the request to whoever the *previous* link named.
    if let VettingMode::RequestVetter { ticket, vetter, .. } = mode {
        *ticket = None;
        vetter.clear();
    }
    if let Some(focused) = mode.focused_text_mut() {
        *focused = text;
    }
    match mode {
        VettingMode::Directory(view) => view.error = None,
        VettingMode::Profile(form) => {
            form.error = None;
            if let Some(event) = &mut form.event {
                event.error = None;
            }
        }
        _ => {}
    }
}

/// Esc: an open event form returns to its profile; anything else to the list.
pub(super) fn back(v: &mut VettingState) {
    if let VettingMode::Profile(form) = &mut v.mode
        && form.event.is_some()
    {
        form.event = None;
        return;
    }
    // Backing out of choosing a face that a card asked for goes back to that
    // card: it is still open, and still the thing the holder was doing.
    if matches!(
        v.mode,
        VettingMode::ChooseFace { .. } | VettingMode::NewFace(_) | VettingMode::HolderGrant { .. }
    ) && let Some(card) = v.card_after_face.take()
    {
        v.mode = card_mode(card);
        return;
    }
    v.card_after_face = None;
    v.mode = VettingMode::List;
}

/// The card page for `(application_id, session_id)`, before its preview.
pub(super) fn card_mode((application_id, session_id): (String, String)) -> VettingMode {
    VettingMode::SendCard {
        application_id,
        session_id,
        preview: None,
    }
}

fn profile_membership(v: &VettingState) -> Option<usize> {
    match &v.mode {
        VettingMode::Profile(form) => Some(form.membership_index),
        _ => None,
    }
}

fn move_field(v: &mut VettingState, forward: bool) {
    let step = |field: &mut usize, count: usize| {
        if count == 0 {
            return;
        }
        *field = if forward {
            (*field + 1) % count
        } else {
            (*field + count - 1) % count
        };
    };
    match &mut v.mode {
        // Two fields, not three: which context the application lives in is
        // taken rather than asked (a sub-context of its own).
        VettingMode::NewApplication { field, .. } => step(field, 2),
        VettingMode::NewTicket { field, .. } => step(field, 2),
        VettingMode::Directory(view) => {
            let rows = view.rows();
            step(&mut view.field, rows);
        }
        VettingMode::Profile(form) => match &mut form.event {
            Some(event) => step(&mut event.field, EVENT_FIELDS),
            None => {
                let rows = form.rows();
                step(&mut form.field, rows);
            }
        },
        // One past the faces is "make a new one" — a row, not a key, so that
        // every way out of this screen is in the list the eye is already on.
        VettingMode::ChooseFace { faces, index, .. } => step(index, faces.len() + 1),
        VettingMode::NewFace(form) => form.move_focus(forward),
        VettingMode::Attest { form, .. } => step(&mut form.field, AttestForm::FIELDS),
        VettingMode::ConfirmDecline { field, .. } => step(field, 2),
        _ => {}
    }
}

pub(super) fn cycle(v: &mut VettingState, forward: bool) {
    let turn = |index: &mut usize, count: usize| {
        if count == 0 {
            return;
        }
        *index = if forward {
            (*index + 1) % count
        } else {
            (*index + count - 1) % count
        };
    };
    let (personas, memberships, documentation) =
        (v.personas.len(), v.memberships.len(), v.documentation.len());
    let (communities, resend) = (v.directory_communities.len(), v.resend_candidates.len());
    let offers = v.event_offers.len();
    let hidden = v.hidden.len();
    match &mut v.mode {
        VettingMode::HiddenVetting { index } => turn(index, hidden),
        VettingMode::Directory(view) => match view.field {
            0 => turn(&mut view.community_index, communities),
            5 => turn(&mut view.method_index, DIRECTORY_METHODS.len()),
            _ => {}
        },
        VettingMode::Profile(form) if form.event.is_none() && form.field == 0 => {
            turn(&mut form.membership_index, memberships);
        }
        VettingMode::Resend { index } => turn(index, resend),
        VettingMode::EventMode { index } => turn(index, offers),
        VettingMode::NewApplication {
            persona_index,
            field: 1,
            ..
        } => turn(persona_index, personas),
        VettingMode::NewTicket {
            membership_index,
            field: 0,
            ..
        } => turn(membership_index, memberships),
        VettingMode::NewTicket {
            uses_index,
            field: 1,
            ..
        } => turn(uses_index, VETTING_TICKET_USES.len()),
        VettingMode::OpenSession { method_index, .. } => {
            turn(method_index, VETTING_METHODS.len());
        }
        VettingMode::Attest { form, .. } => match form.field {
            0 => turn(&mut form.method_index, VETTING_METHODS.len()),
            1 => turn(&mut form.documentation_index, documentation),
            2 => turn(&mut form.relationship_index, VETTING_RELATIONSHIPS.len()),
            _ => {}
        },
        VettingMode::Withdraw { reason_index, .. } => {
            turn(reason_index, VETTING_WITHDRAWAL_REASONS.len());
        }
        VettingMode::ConfirmDecline {
            reason_index,
            field: 0,
            ..
        } => turn(reason_index, DECLINE_REASONS.len()),
        VettingMode::ChooseFace { faces, index, .. } => turn(index, faces.len() + 1),
        // Which of several attributes of one claim type the face shows.
        VettingMode::NewFace(form) => form.pick(forward),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{VettingMode, VettingState};
    use crate::state_handler::state::State;

    /// Backing out of the picker a card opened returns to that card; from the
    /// list it returns to the list.
    #[test]
    fn backing_out_of_the_picker_returns_where_it_came_from() {
        let picker = || VettingMode::ChooseFace {
            application_id: "a".into(),
            faces: Vec::new(),
            index: 0,
            required: Vec::new(),
        };
        let mut v = VettingState {
            mode: picker(),
            card_after_face: Some(("a".into(), "s".into())),
            ..VettingState::default()
        };
        back(&mut v);
        assert!(matches!(&v.mode, VettingMode::SendCard { session_id, .. } if session_id == "s"));

        let mut v = VettingState {
            mode: picker(),
            ..VettingState::default()
        };
        back(&mut v);
        assert!(matches!(v.mode, VettingMode::List));
    }

    /// View-only actions are reduced and owe nothing; every other action,
    /// Enter on the attest form among them, is planned.
    #[test]
    fn plan_reduces_or_plans() {
        use crate::state_handler::dispatch_util::test_config;
        let mut config = test_config();
        let mut state = State::default();

        let VettingEffect(steps) = plan(
            &mut state,
            &mut config,
            false,
            false,
            VettingAction::FindVetters,
        );
        assert!(steps.is_empty());
        assert!(
            panel(&mut state).status_message.is_some(),
            "reduced: the empty directory is explained"
        );

        panel(&mut state).mode = VettingMode::ShowTicket { index: 0 };
        let VettingEffect(steps) =
            plan(&mut state, &mut config, false, false, VettingAction::Submit);
        assert!(steps.is_empty());
        assert!(matches!(panel(&mut state).mode, VettingMode::List));

        // Unticked, the attestation says so and owes nothing.
        panel(&mut state).mode = VettingMode::Attest {
            request_id: "r".into(),
            form: AttestForm {
                attested: false,
                ..AttestForm::default()
            },
        };
        let VettingEffect(steps) =
            plan(&mut state, &mut config, true, false, VettingAction::Submit);
        assert!(steps.is_empty());
        assert!(matches!(panel(&mut state).mode, VettingMode::Attest { .. }));
        assert_eq!(
            panel(&mut state).status_message.as_ref().unwrap().severity,
            crate::state_handler::main_page::status::Severity::Warning
        );
    }

    /// With no application selected, reading requirements again still owes
    /// the vetter pass, run whatever came before it.
    #[test]
    fn a_refresh_with_no_application_owes_the_vetter_pass() {
        use crate::state_handler::dispatch_util::test_config;
        let mut config = test_config();
        let mut state = State::default();

        let VettingEffect(steps) = plan(
            &mut state,
            &mut config,
            false,
            false,
            VettingAction::RefreshRequirements,
        );
        let [Step::Always(pass)] = steps.as_slice() else {
            panic!("the pass alone");
        };
        assert!(matches!(**pass, Step::RefreshVetterSide));
    }

    /// A refresh refused while busy owes nothing of its own, and still owes
    /// the challenge — told what the status said before the refusal, so it
    /// asks quietly — and the vetter pass, both run regardless.
    #[test]
    fn a_refused_refresh_still_owes_the_challenge_and_the_pass() {
        use crate::state_handler::dispatch_util::test_config;
        use openvtc_core::config::account::PersonaId;
        let mut config = test_config();
        let mut state = State::default();
        let id = config
            .private
            .vetting
            .start_application(
                "did:web:vtc.example",
                PersonaId::new(),
                "did:key:zApplicant",
                Utc::now(),
            )
            .unwrap()
            .id
            .clone();
        state.main_page.sync_from_config(&config);
        let before = Some(Status::info("from before"));
        panel(&mut state).status_message = before.clone();

        let VettingEffect(steps) = plan(
            &mut state,
            &mut config,
            true,
            false,
            VettingAction::RefreshRequirements,
        );
        let [Step::Always(challenge), Step::Always(pass)] = steps.as_slice() else {
            panic!("the challenge, then the pass");
        };
        let Step::Then(Followup::AskChallenge {
            application_id,
            said_before,
        }) = &**challenge
        else {
            panic!("the challenge, planned once the refresh ran");
        };
        assert_eq!(application_id, &id);
        assert_eq!(said_before, &before);
        assert!(matches!(**pass, Step::RefreshVetterSide));
        assert!(
            warned_since(&mut state, said_before.as_ref()),
            "the refusal is news the challenge must not cover"
        );

        // Not busy: the refresh's own sign and send come first.
        let VettingEffect(steps) = plan(
            &mut state,
            &mut config,
            false,
            false,
            VettingAction::RefreshRequirements,
        );
        assert!(matches!(
            steps.as_slice(),
            [
                Step::Sign { .. },
                Step::Send { .. },
                Step::Always(_),
                Step::Always(_)
            ]
        ));
    }
}
