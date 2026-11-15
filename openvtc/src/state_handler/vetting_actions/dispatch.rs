//! Maps each `VettingAction` onto the page: the action dispatcher, form
//! navigation, and form submission.

use chrono::Utc;
use openvtc_core::vetting::vetter::DeskState;
use vta_sdk::protocols::vetting::VettingMethod;

use super::answers::focus_application;
use super::applicant::{
    abandon_application, ask_listed_vetter, directory_page, open_directory, paste_ticket,
    refresh_application_contexts, refresh_requirements, request_vetter, search_directory,
    start_application, switch_vetting_path,
};
use super::desk::{
    attest, decline, open_session, refresh_stale_modes, refresh_vetter_side, withdraw,
};
use super::faces::{create_face, list_faces, open_new_face, send_card, wear_face};
use super::hidden::ask_for_challenge;
use super::tickets::{delete_ticket, issue_ticket};
use super::vetter::{ask_event_mode, ask_resend, open_profile, profile_form, profile_submit};
use super::view_sync::sync_journey;
use super::words::{clause, community_display, get_tokens_words, hides_vetters};
use crate::state_handler::actions::VettingAction;
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::main_page::content::{
    AttestForm, DECLINE_MESSAGE_MAX, DECLINE_REASONS, DIRECTORY_METHODS, DeskStage, DeskView,
    EVENT_FIELDS, JourneyTarget, VETTING_METHODS, VETTING_RELATIONSHIPS, VETTING_TICKET_USES,
    VETTING_WITHDRAWAL_REASONS, VettingMode, VettingState, VettingTab,
};
use crate::state_handler::runtime_actions::ActionCtx;

// ============================================================================
// Actions
// ============================================================================

pub(super) fn page<'a>(ctx: &'a mut ActionCtx<'_>) -> &'a mut VettingState {
    &mut ctx.state.main_page.content_panel.vetting
}

pub(super) fn status(ctx: &mut ActionCtx<'_>, message: impl Into<String>) {
    page(ctx).status_message = Some(message.into());
}

/// Persist the book and show `message`.
pub(super) fn persist(ctx: &mut ActionCtx<'_>, message: impl Into<String>) {
    let message = message.into();
    dispatch_util::save_and_sync(
        &mut ctx.state.main_page,
        ctx.config,
        ctx.save,
        Persist::SaveAndSync,
        |mp| &mut mp.content_panel.vetting.status_message,
        message.clone(),
        SyncLog::Plain(message),
    );
}

/// Handle one Vetting-page action.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: VettingAction) {
    match action {
        VettingAction::OpenJourney => {
            let v = page(ctx);
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
                sync_journey(
                    &mut ctx.state.main_page.content_panel.vetting,
                    ctx.config,
                    Utc::now(),
                );
            }
        }
        VettingAction::OpenApplication(application_id) => {
            if ctx
                .config
                .private
                .vetting
                .applications
                .iter()
                .any(|a| a.id == application_id)
            {
                focus_application(
                    ctx.state,
                    ctx.config,
                    &application_id,
                    "Where your application stands, and what happens next.".to_string(),
                );
            } else {
                // Finished or abandoned between the panel drawing it and the
                // key arriving: say so where the holder is looking.
                ctx.state.main_page.content_panel.communities.status_message =
                    Some("That application is no longer in progress.".to_string());
            }
        }
        VettingAction::CloseJourney => {
            let v = page(ctx);
            v.journey_target = None;
            v.journey = None;
            v.mode = VettingMode::List;
        }
        VettingAction::SwitchTab => {
            let v = page(ctx);
            v.tab = v.tab.next();
            v.selected = 0;
            v.mode = VettingMode::List;
            v.status_message = None;
            // Opening the desk: how each community vets is read again where the last reading
            // is stale, so the badges and the ticket gate are not shown from an old answer.
            if v.tab == VettingTab::Desk {
                refresh_stale_modes(ctx).await;
            }
        }
        VettingAction::ShowTicket => {
            let v = page(ctx);
            // Only a ticket that can still be redeemed is worth holding up to a
            // camera; a spent one would scan and then be refused.
            if v.tickets.get(v.selected).is_some_and(|t| t.live) {
                v.mode = VettingMode::ShowTicket { index: v.selected };
                v.status_message = None;
            }
        }
        VettingAction::SwitchDeskView(forward) => {
            let v = page(ctx);
            // The desk view is remembered across a tab switch, so this only
            // has to reset the cursor — the lists are different lengths and a
            // carried index would point at a different row, or at none.
            v.desk_view = v.desk_view.shifted(forward);
            v.selected = 0;
            v.status_message = None;
        }
        VettingAction::Select(i) => {
            let v = page(ctx);
            v.selected = i.min(v.tab_len().saturating_sub(1));
        }
        VettingAction::Back => back(page(ctx)),
        VettingAction::PasteTicket(text) => paste_ticket(ctx, &text),
        VettingAction::FindVetters => open_directory(ctx),
        VettingAction::DirectoryPage(forward) => directory_page(ctx, forward).await,
        VettingAction::AskListedVetter => ask_listed_vetter(ctx),
        VettingAction::EditProfile => open_profile(ctx),
        VettingAction::RemoveEvent => {
            if let VettingMode::Profile(form) = &mut page(ctx).mode
                && form.event.is_none()
                && let Some(i) = form.event_index()
            {
                form.draft.events.remove(i);
                form.field = form.field.min(form.rows() - 1);
                form.error = None;
            }
        }
        VettingAction::AskResend => {
            if page(ctx).resend_candidates.is_empty() {
                status(
                    ctx,
                    "Every community you are an active member of has already sent you a live \
                     vetter credential — or you are not an active member of any.",
                );
            } else {
                page(ctx).mode = VettingMode::Resend { index: 0 };
            }
        }
        VettingAction::AskEventMode => {
            if page(ctx).event_offers.is_empty() {
                status(
                    ctx,
                    "No community you vet for is running an event. Event mode is the exception, \
                     not the setting — an ordinary week is the slow drip.",
                );
            } else {
                page(ctx).mode = VettingMode::EventMode { index: 0 };
            }
        }
        VettingAction::Status(message) => status(ctx, message),
        VettingAction::Input(text) => {
            input(&mut page(ctx).mode, text);
            refresh_application_contexts(ctx);
        }
        VettingAction::NextField => move_field(page(ctx), true),
        VettingAction::PrevField => move_field(page(ctx), false),
        VettingAction::Cycle(forward) => {
            let before = profile_membership(page(ctx));
            cycle(page(ctx), forward);
            let after = profile_membership(page(ctx));
            if let Some(index) = after
                && before != after
            {
                // Each community has its own profile: show the one for this one.
                let form = profile_form(
                    &ctx.state.main_page.content_panel.vetting,
                    &ctx.config.private.vetting,
                    index,
                    0,
                );
                page(ctx).mode = VettingMode::Profile(Box::new(form));
            }
            refresh_application_contexts(ctx);
        }
        VettingAction::Toggle => match &mut page(ctx).mode {
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
            if page(ctx).personas.is_empty() {
                status(
                    ctx,
                    "Create a persona under My Identity first — it is the DID you join with.",
                );
            } else {
                page(ctx).mode = VettingMode::NewApplication {
                    community: String::new(),
                    persona_index: 0,
                    context_options: Vec::new(),
                    context_index: 0,
                    field: 0,
                };
                refresh_application_contexts(ctx);
            }
        }
        VettingAction::ChooseFace => {
            let v = page(ctx);
            // From a card, the card's application — not whichever row the list
            // behind it last had selected — and the card is where it returns.
            let id = match &v.mode {
                VettingMode::SendCard {
                    application_id,
                    session_id,
                    ..
                } => {
                    v.card_after_face = Some((application_id.clone(), session_id.clone()));
                    Some(application_id.clone())
                }
                // A retry after granting access keeps whichever card sent it.
                VettingMode::HolderGrant { .. } => v
                    .card_after_face
                    .as_ref()
                    .map(|(application_id, _)| application_id.clone())
                    .or_else(|| v.applications.get(v.selected).map(|row| row.id.clone())),
                _ => {
                    v.card_after_face = None;
                    v.applications.get(v.selected).map(|row| row.id.clone())
                }
            };
            if let Some(id) = id {
                list_faces(ctx, &id);
            }
        }
        VettingAction::RequestVetter => {
            let v = page(ctx);
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
        VettingAction::RefreshRequirements => {
            let v = page(ctx);
            if let Some(row) = v.applications.get(v.selected).cloned() {
                refresh_requirements(ctx, &row.id).await;
                // A hidden application also needs the community's challenge, and asking early
                // is free: the community keeps one per applicant, and asking again replaces it.
                ask_for_challenge(ctx, &row.id).await;
            }
            // A vetter has no application, so nothing else would ever fetch the manifest of a
            // community it vets for — and the manifest is where a community says it hides its
            // vetters. Asking here is what lets a vetter-only member reach the mode at all.
            refresh_vetter_side(ctx).await;
        }
        VettingAction::SwitchVettingPath => switch_vetting_path(ctx),
        VettingAction::RefreshVetterSide => refresh_vetter_side(ctx).await,
        VettingAction::OpenHiddenVetting => {
            if page(ctx).hidden.is_empty() {
                status(
                    ctx,
                    "None of the communities you vet for hides its vetters, so there is no \
                     hidden vetting to show.",
                );
            } else {
                page(ctx).mode = VettingMode::HiddenVetting { index: 0 };
            }
        }
        VettingAction::CheckHiddenKey => {
            let now = Utc::now();
            let index = match page(ctx).mode {
                VettingMode::HiddenVetting { index } => index,
                _ => 0,
            };
            let Some(held) = ctx.config.private.vetting.hidden_vetter.get_mut(index) else {
                return;
            };
            let community = held.community.clone();
            let started = held.recheck_key(now);
            let name = community_display(ctx.config, &community);
            if started {
                ctx.save.mark_dirty();
                status(
                    ctx,
                    format!(
                        "Asking {name} which hidden-vetting key it holds for you, to restore it \
                         at your VTA…"
                    ),
                );
                refresh_vetter_side(ctx).await;
            } else {
                status(
                    ctx,
                    format!(
                        "Nothing to check at {name}: your hidden-vetting key is not in question, \
                         or a check is already running."
                    ),
                );
            }
        }
        VettingAction::DrawNow => {
            // Get tokens, in one key: whatever the schedule owes, in order — enrol where not
            // enrolled, then draw every window that has begun — and, per community, exactly
            // what is happening or what blocks it and until when. Said from the book as it was
            // before the pass, which is what the pass acts on.
            let now = Utc::now();
            // Asked by hand: a lost enrolment is worth one more ask — the community may now
            // re-issue it to the same identifier, and it bounds how many times it will.
            for held in &mut ctx.config.private.vetting.hidden_vetter {
                held.lost_reasked = false;
            }
            let words: Vec<String> = {
                let book = &ctx.config.private.vetting;
                book.vetter_standing(now)
                    .into_iter()
                    .filter(|s| s.live && hides_vetters(book, &s.community))
                    .map(|s| {
                        let name = community_display(ctx.config, &s.community);
                        let why = get_tokens_words(book, &s.community, s.persona, &name, now);
                        format!("{name}: {}.", clause(&why))
                    })
                    .collect()
            };
            refresh_vetter_side(ctx).await;
            status(
                ctx,
                if words.is_empty() {
                    "None of the communities you vet for proves vetting with PCS ZKP, so there \
                     are no tokens to get — hand out tickets with t."
                        .to_string()
                } else {
                    format!("Getting tokens — {}", words.join(" "))
                },
            );
        }
        VettingAction::ReviewCard => {
            let v = page(ctx);
            let Some(row) = v.applications.get(v.selected).cloned() else {
                return;
            };
            match row.requests.iter().find_map(|r| r.card_session.clone()) {
                Some(session_id) => {
                    v.mode = VettingMode::SendCard {
                        application_id: row.id,
                        session_id,
                        preview: None,
                    };
                }
                None => status(ctx, "No vetter is waiting for your card."),
            }
        }
        VettingAction::NewTicket => {
            if page(ctx).memberships.is_empty() {
                status(
                    ctx,
                    "You can hand out tickets once a community you belong to has named you a \
                     vetter — ask its admins for the vetter role.",
                );
            } else {
                page(ctx).mode = VettingMode::NewTicket {
                    membership_index: 0,
                    uses_index: 0,
                    field: 0,
                };
            }
        }
        VettingAction::DeleteTicket => {
            let v = page(ctx);
            match v.tickets.get(v.selected).cloned() {
                Some(row) => v.mode = VettingMode::ConfirmDeleteTicket { ticket_id: row.id },
                None => status(ctx, "Highlight a ticket to delete."),
            }
        }
        VettingAction::OpenSession => {
            let v = page(ctx);
            match v.desk.get(v.selected).cloned() {
                Some(row) if matches!(row.stage, DeskStage::Accepted | DeskStage::Session) => {
                    v.mode = VettingMode::OpenSession {
                        request_id: row.request_id,
                        method_index: 0,
                    };
                }
                Some(_) => status(ctx, "That request has moved past opening a session."),
                None => {}
            }
        }
        VettingAction::StartAttest => {
            // The form opens on the method the session was opened with: the
            // statement says how the person was checked, and a default of "in
            // person" after a video call is a false statement one Enter away.
            let selected = {
                let v = page(ctx);
                v.desk.get(v.selected).cloned()
            };
            match selected {
                Some(row) if row.stage == DeskStage::Card => {
                    let method_index = match ctx
                        .config
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
                    page(ctx).mode = VettingMode::Attest {
                        request_id: row.request_id,
                        form: AttestForm {
                            method_index,
                            ..AttestForm::default()
                        },
                    };
                }
                Some(_) => status(ctx, "You can attest once their card has arrived."),
                None => {}
            }
        }
        VettingAction::ArmDecline => {
            let v = page(ctx);
            match v.desk.get(v.selected).cloned() {
                Some(row) if row.stage != DeskStage::Closed => {
                    v.mode = VettingMode::ConfirmDecline {
                        request_id: row.request_id,
                        reason_index: 0,
                        message: String::new(),
                        field: 0,
                    };
                }
                Some(_) => status(ctx, "That request is already closed."),
                None => {}
            }
        }
        VettingAction::ArmAbandon => {
            let v = page(ctx);
            match v.applications.get(v.selected).cloned() {
                Some(row) => {
                    v.mode = VettingMode::ConfirmAbandon {
                        application_id: row.id,
                    };
                }
                None => status(ctx, "Highlight an application to abandon."),
            }
        }
        VettingAction::ArmWithdraw => {
            let v = page(ctx);
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
                Some(_) => status(
                    ctx,
                    "That statement is already withdrawn — the community recorded it.",
                ),
                None => {}
            }
        }
        VettingAction::Submit => submit(ctx).await,
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

async fn submit(ctx: &mut ActionCtx<'_>) {
    match page(ctx).mode.clone() {
        VettingMode::List => {}
        // Nothing to submit — it is a code being held up to a phone. Enter
        // closes it, the same as Esc, because both are what a hand reaches for
        // when the scan is done.
        VettingMode::ShowTicket { .. } => back(page(ctx)),
        // Nor here: it says what to run somewhere else. Enter closes it like
        // Esc, rather than being the one view where Enter does nothing.
        VettingMode::HolderGrant { .. } => back(page(ctx)),
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
            start_application(ctx, community.trim(), persona_index, context).await;
        }
        VettingMode::ConfirmAbandon { .. } => abandon_application(ctx),
        VettingMode::ConfirmDeleteTicket { ticket_id } => delete_ticket(ctx, &ticket_id),
        VettingMode::ChooseFace {
            application_id,
            faces,
            index,
            required,
        } => {
            if index == faces.len() {
                open_new_face(ctx, &application_id, required);
            } else {
                wear_face(ctx, &application_id, faces.get(index).cloned());
            }
        }
        VettingMode::NewFace(form) => create_face(ctx, *form),
        VettingMode::RequestVetter {
            application_id,
            entry,
            vetter,
            ticket,
            ..
        } => request_vetter(ctx, &application_id, entry.trim(), vetter.trim(), ticket).await,
        VettingMode::Directory(view) => match view.result_index() {
            Some(_) => ask_listed_vetter(ctx),
            None => search_directory(ctx, vec![None]).await,
        },
        VettingMode::Profile(form) => profile_submit(ctx, *form).await,
        VettingMode::Resend { index } => ask_resend(ctx, index).await,
        VettingMode::EventMode { index } => ask_event_mode(ctx, index).await,
        // Enter is "draw now", as `d` is: the view's one verb.
        VettingMode::HiddenVetting { .. } => {
            status(
                ctx,
                "Reading each community's requirements again and drawing what the schedule owes…",
            );
            refresh_vetter_side(ctx).await;
        }
        VettingMode::SendCard {
            application_id,
            session_id,
            preview,
        } => send_card(ctx, &application_id, &session_id, preview).await,
        VettingMode::NewTicket {
            membership_index,
            uses_index,
            ..
        } => issue_ticket(ctx, membership_index, uses_index).await,
        VettingMode::OpenSession {
            request_id,
            method_index,
        } => open_session(ctx, &request_id, method_index).await,
        VettingMode::Attest { request_id, form } => attest(ctx, &request_id, &form).await,
        VettingMode::ConfirmDecline {
            request_id,
            reason_index,
            message,
            ..
        } => {
            let code = DECLINE_REASONS.get(reason_index).and_then(|(c, _)| *c);
            let message = message.trim();
            if message.chars().count() > DECLINE_MESSAGE_MAX {
                return status(
                    ctx,
                    format!(
                        "The note is {} characters; a decline carries at most \
                         {DECLINE_MESSAGE_MAX}.",
                        message.chars().count()
                    ),
                );
            }
            let message = (!message.is_empty()).then(|| message.to_string());
            decline(ctx, &request_id, code, message).await
        }
        VettingMode::Withdraw {
            statement_id,
            reason_index,
        } => withdraw(ctx, &statement_id, reason_index).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{VettingMode, VettingState};

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
}
