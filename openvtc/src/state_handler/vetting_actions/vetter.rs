//! The vetter's own standing with its communities: the directory profile,
//! event-mode requests, and credential resends.

use crate::state_handler::main_page::status::Status;
use chrono::Utc;
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::registry::{
    EventDraft, ProfileDraft, ProfileState, VetterProfileRecord,
};
use openvtc_core::vetting::wire;

use super::dispatch::{page, persist, status};
use super::jobs::Sent;
use super::send::{Claim, abandon, begin, persona_did, sign_and_send};
use crate::state_handler::main_page::content::{
    EVENT_LABELS, EventForm, LineTone, PROFILE_FIELDS, PROFILE_LABELS, VetterProfileForm,
    VettingMode, VettingState, VettingTab, row_of,
};
use crate::state_handler::main_page::sanitize_display;
use crate::state_handler::runtime_actions::ActionCtx;

/// The profile form for membership `membership_index`, from what was last sent
/// there — or a first profile from this vetter's own policy.
pub(crate) fn profile_form(
    v: &VettingState,
    book: &VettingBook,
    membership_index: usize,
    field: usize,
) -> VetterProfileForm {
    let record = v
        .memberships
        .get(membership_index)
        .and_then(|m| book.vetter_profile(&m.community, m.persona));
    VetterProfileForm {
        membership_index,
        draft: record.map_or_else(
            || ProfileDraft::new(&book.policy),
            |r| r.draft(&book.policy),
        ),
        field,
        event: None,
        error: None,
        state_line: record.map(profile_state_line),
    }
}

fn profile_state_line(record: &VetterProfileRecord) -> (LineTone, String) {
    let day = |at: &chrono::DateTime<Utc>| at.format("%Y-%m-%d").to_string();
    match &record.state {
        ProfileState::Sent { sent_at } => (
            LineTone::Caution,
            format!(
                "Sent {} — the community has not answered yet.",
                day(sent_at)
            ),
        ),
        ProfileState::Stored {
            listed: true,
            updated_at,
        } => (
            LineTone::Good,
            format!("Published {} and listed in the directory.", day(updated_at)),
        ),
        ProfileState::Stored { updated_at, .. } => (
            LineTone::Good,
            format!("Published {}, not listed.", day(updated_at)),
        ),
        ProfileState::Refused { code, at } => (
            LineTone::Bad,
            format!(
                "Refused {} ({}) — the community did not count you as a vetter then.",
                day(at),
                sanitize_display(code, 80)
            ),
        ),
    }
}

pub(super) fn open_profile(ctx: &mut ActionCtx<'_>) {
    let v = &ctx.state.main_page.content_panel.vetting;
    if v.memberships.is_empty() {
        let hint = if v.resend_candidates.is_empty() {
            ""
        } else {
            " If one did and the credential never arrived, g asks it to send it again."
        };
        return status(
            ctx,
            Status::warning(format!(
                "A profile is published to a community that named you a vetter, and none has.{hint}"
            )),
        );
    }
    let form = profile_form(v, &ctx.config.private.vetting, 0, 0);
    page(ctx).mode = VettingMode::Profile(Box::new(form));
}

/// Enter on the profile form: keep an open event, open one, or publish.
pub(super) async fn profile_submit(ctx: &mut ActionCtx<'_>, form: VetterProfileForm) {
    if let Some(event) = &form.event {
        let result = event.draft.to_event();
        if let VettingMode::Profile(open) = &mut page(ctx).mode {
            match result {
                Ok(_) => {
                    let kept = match event.index {
                        Some(i) if i < open.draft.events.len() => {
                            open.draft.events[i] = event.draft.clone();
                            i
                        }
                        _ => {
                            open.draft.events.push(event.draft.clone());
                            open.draft.events.len() - 1
                        }
                    };
                    open.event = None;
                    open.error = None;
                    open.field = PROFILE_FIELDS + kept;
                }
                Err(e) => {
                    if let Some(open_event) = &mut open.event {
                        if let Some(row) = e.row().and_then(|l| row_of(&EVENT_LABELS, l)) {
                            open_event.field = row;
                        }
                        open_event.error = Some(e.to_string());
                    }
                }
            }
        }
        return;
    }
    if let Some(i) = form.event_index() {
        if let VettingMode::Profile(open) = &mut page(ctx).mode {
            open.event = Some(EventForm {
                index: Some(i),
                draft: form.draft.events[i].clone(),
                field: 0,
                error: None,
            });
        }
        return;
    }
    if form.on_add_event() {
        if let VettingMode::Profile(open) = &mut page(ctx).mode {
            open.event = Some(EventForm {
                index: None,
                draft: EventDraft::default(),
                field: 0,
                error: None,
            });
        }
        return;
    }
    publish_profile(ctx, &form).await;
}

async fn publish_profile(ctx: &mut ActionCtx<'_>, form: &VetterProfileForm) {
    let Some(membership) = page(ctx).memberships.get(form.membership_index).cloned() else {
        return;
    };
    let body = match form.draft.to_body() {
        Ok(body) => body,
        Err(e) => {
            if let VettingMode::Profile(open) = &mut page(ctx).mode {
                // Put the cursor on the row the message names, so a refusal
                // read at the bottom of thirteen rows says where to go and
                // then goes there. An event's rows are the event form's, so a
                // refusal from one lands on the event's row here instead.
                if let Some(index) = e.event() {
                    open.field = PROFILE_FIELDS + index;
                } else if let Some(row) = e.row().and_then(|l| row_of(&PROFILE_LABELS, l)) {
                    open.field = row;
                }
                open.error = Some(e.to_string());
            }
            return;
        }
    };
    let Some(vetter_did) = persona_did(ctx.config, membership.persona) else {
        return status(
            ctx,
            Status::error("The persona this community named a vetter is not available."),
        );
    };
    if !begin(ctx) {
        return;
    }
    let document = match wire::vetter_profile_request(&vetter_did, &membership.community, &body) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not publish your profile", e),
    };
    let document_id = document.id.clone();
    let now = Utc::now();
    let book = &mut ctx.config.private.vetting;
    let previous = book.record_profile_sent(&membership.community, membership.persona, &body, now);
    book.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: membership.community.clone(),
        persona: membership.persona,
        kind: QueryKind::VetterProfile,
        sent_at: now,
    });
    {
        let v = page(ctx);
        v.mode = VettingMode::List;
        // Back to the desk, on whichever view it was left on: what happened to
        // the profile shows in the desk header, which every view carries.
        v.tab = VettingTab::Desk;
    }
    persist(ctx, format!("Sending your profile to {}…", membership.name));
    let sent = Sent::Profile {
        document_id: document_id.clone(),
        community: membership.community.clone(),
        persona: membership.persona,
        previous: previous.clone().map(Box::new),
    };
    if let Err(e) = sign_and_send(ctx, membership.persona, document, sent, Claim::Held).await {
        let book = &mut ctx.config.private.vetting;
        book.restore_profile(&membership.community, membership.persona, previous);
        book.forget_query(&document_id);
        abandon(ctx, "Could not publish your profile", e);
    }
}

/// Ask a community to let us vet at one of its events, at one of its published tiers.
///
/// The window we ask for is the event's own. A vetter naming their own days would say which
/// days of a conference they expect to be at the desk, and a community that had to compare two
/// vetters' windows would learn more from the difference than from either.
///
/// What comes back is never a grant — approval is somebody else's act — so the answer is
/// recorded and the label opens later, or not at all.
pub(super) async fn ask_event_mode(ctx: &mut ActionCtx<'_>, index: usize) {
    let Some(offer) = page(ctx).event_offers.get(index).cloned() else {
        return;
    };
    let Some(did) = persona_did(ctx.config, offer.persona) else {
        return status(
            ctx,
            Status::error("The persona that belongs to this community is not available."),
        );
    };
    if !begin(ctx) {
        return;
    }
    let body = openvtc_core::vetting::wire::pcs::EventModeRequest {
        event_id: offer.event_id.clone(),
        tier: offer.tier.clone(),
        window: openvtc_core::vetting::wire::pcs::EventWindow {
            start_date: offer.start_date,
            end_date: offer.end_date,
        },
    };
    let document = match wire::pcs_event_mode_request(&did, &offer.community, &body) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask to vet at the event", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: offer.community.clone(),
        persona: offer.persona,
        kind: QueryKind::PcsEventMode,
        sent_at: Utc::now(),
    });
    page(ctx).mode = VettingMode::List;
    status(
        ctx,
        Status::progress(format!(
            "Asking {} to vet at {} ({})…",
            offer.community_name, offer.event_id, offer.tier
        )),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: offer.community.clone(),
        kind: QueryKind::PcsEventMode,
    };
    if let Err(e) = sign_and_send(ctx, offer.persona, document, sent, Claim::Held).await {
        ctx.config.private.vetting.forget_query(&document_id);
        abandon(ctx, "Could not ask to vet at the event", e);
    }
}

pub(super) async fn ask_resend(ctx: &mut ActionCtx<'_>, index: usize) {
    let Some(target) = page(ctx).resend_candidates.get(index).cloned() else {
        return;
    };
    let Some(did) = persona_did(ctx.config, target.persona) else {
        return status(
            ctx,
            Status::error("The persona that belongs to this community is not available."),
        );
    };
    if !begin(ctx) {
        return;
    }
    let document = match wire::vetter_resend_request(&did, &target.community) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask for your vetter credential", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: target.community.clone(),
        persona: target.persona,
        kind: QueryKind::VetterResend,
        sent_at: Utc::now(),
    });
    page(ctx).mode = VettingMode::List;
    status(
        ctx,
        Status::progress(format!(
            "Asking {} to send your vetter credential again…",
            target.name
        )),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: target.community.clone(),
        kind: QueryKind::VetterResend,
    };
    if let Err(e) = sign_and_send(ctx, target.persona, document, sent, Claim::Held).await {
        ctx.config.private.vetting.forget_query(&document_id);
        abandon(ctx, "Could not ask for your vetter credential", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{LineTone, VettingMembership, VettingState};
    use chrono::Utc;
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::VettingBook;
    use openvtc_core::vetting::registry::ProfileDraft;

    /// The form opens on what was last sent to that community.
    #[test]
    fn the_profile_form_opens_on_what_was_last_sent() {
        let mut book = VettingBook::default();
        let persona = PersonaId::new();
        let mut draft = ProfileDraft::new(&book.policy);
        draft.display_name = "Carol".into();
        book.record_profile_sent(
            "did:web:vtc",
            persona,
            &draft.to_body().unwrap(),
            Utc::now(),
        );
        let v = VettingState {
            memberships: vec![VettingMembership {
                community: "did:web:vtc".into(),
                name: "VTC".into(),
                persona,
                accent: None,
            }]
            .into(),
            ..VettingState::default()
        };
        let form = profile_form(&v, &book, 0, 0);
        assert_eq!(form.draft.display_name, "Carol");
        assert!(matches!(form.state_line, Some((LineTone::Caution, _))));
        let fresh = profile_form(&VettingState::default(), &book, 0, 0);
        assert!(!fresh.draft.listed, "a first profile is unlisted");
    }
}
