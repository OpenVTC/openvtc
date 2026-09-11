//! A membership's VTA context, from the communities panel.
//!
//! Two things a holder does with a community's own context:
//!
//! - **Delete it** once the membership is over. The VTA is asked what the
//!   delete would remove — every key, DID, access entry and DID template, in
//!   the context and in each sub-context the delete cascades to — and all of
//!   it is shown; the holder types `DELETE`; then the subtree is deleted. A
//!   context another membership, a persona's keys, or a vetting application
//!   still uses is refused before the VTA is asked, naming what uses it
//!   ([`community_context::deletable_context`]). The check runs again before
//!   the delete itself, because a preview can sit on screen for as long as
//!   the holder likes.
//! - **Give a device access** to it: a `did:key` granted the VTA's
//!   `application` role in that context alone, with an expiry, listed and
//!   revocable per community ([`openvtc_core::community_access`]).
//!
//! Every VTA call is a background job in [`DispatchDomain::CommunityAccess`],
//! applied back on the loop thread by [`ContextOutcome::apply`]. View-only
//! changes — typing, moving the highlight, opening the grant form — go through
//! [`reduce`], which both loops share.

use std::future::Future;

use chrono::Utc;
use openvtc_core::community_access::{self, DeviceGrant, EXPIRY_CHOICES, Revoked};
use openvtc_core::config::Config;
use openvtc_core::config::account::{CommunityRecord, PersonaId};
use openvtc_core::config::community_context::{self, ContextDeletionPreview, DELETE_CONFIRMATION};
use openvtc_core::errors::OpenVTCError;
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::CommunityContextAction as Act;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::content::{
    CommunitiesState, ContextDeletePhase, ContextDeleteView, DeviceAccessView, GrantForm,
    GrantListing,
};
use crate::state_handler::main_page::shorten_did;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

const DOMAIN: DispatchDomain = DispatchDomain::CommunityAccess;

/// Longest confirmation kept. Well past the word, so an over-long paste reads
/// as wrong rather than being trimmed into a match.
const MAX_TYPED: usize = 32;
/// Longest `did:key` input kept.
const MAX_DID_INPUT: usize = 512;
/// Longest device name kept.
const MAX_NAME_INPUT: usize = 64;

fn panel(state: &mut State) -> &mut CommunitiesState {
    &mut state.main_page.content_panel.communities
}

/// An error's message without the kind prefix its `Display` adds — the
/// surrounding sentence already says what failed.
fn reason(e: &OpenVTCError) -> String {
    match e {
        OpenVTCError::Config(m) | OpenVTCError::Vta(m) | OpenVTCError::Auth(m) => m.clone(),
        other => other.to_string(),
    }
}

// ****************************************************************************
// View-only changes (shared nav reducer)
// ****************************************************************************

/// Apply a view-only action. Returns `false` for the actions that read the
/// config or reach the VTA, which the loop services through [`dispatch`].
pub(crate) fn reduce(state: &mut State, action: &Act) -> bool {
    let CommunitiesState {
        context_delete,
        device_access,
        device_grants,
        ..
    } = panel(state);
    let grant_count = |view: &DeviceAccessView| {
        device_grants
            .get(&view.context_id)
            .map_or(0, |l| l.grants().len())
    };
    match action {
        Act::DeleteInput(typed) => {
            if let Some(view) = context_delete.as_mut()
                && matches!(view.phase, ContextDeletePhase::Ready(_))
            {
                view.typed = typed.chars().take(MAX_TYPED).collect();
            }
        }
        Act::DeleteCancel => {
            // A running delete cannot be called back; closing the view would
            // only hide it.
            if context_delete
                .as_ref()
                .is_some_and(|v| !matches!(v.phase, ContextDeletePhase::Deleting))
            {
                *context_delete = None;
            }
        }
        Act::DevicesClose => *device_access = None,
        Act::DevicesSelect(i) => {
            if let Some(view) = device_access.as_mut() {
                view.selected = (*i).min(grant_count(view).saturating_sub(1));
                view.confirm_revoke = false;
            }
        }
        Act::GrantStart => {
            if let Some(view) = device_access.as_mut()
                && view.can_grant
                && !view.busy
            {
                view.form = Some(GrantForm::default());
                view.confirm_revoke = false;
                view.message = None;
            }
        }
        Act::GrantField(field) => {
            if let Some(form) = idle_form(device_access) {
                form.field = field % GrantForm::FIELDS;
            }
        }
        Act::GrantInput { field, value } => {
            if let Some(form) = idle_form(device_access) {
                match field {
                    0 => form.did = value.chars().take(MAX_DID_INPUT).collect(),
                    1 => form.name = value.chars().take(MAX_NAME_INPUT).collect(),
                    _ => {}
                }
            }
        }
        Act::GrantExpiry(i) => {
            if let Some(form) = idle_form(device_access) {
                form.expiry = (*i).min(EXPIRY_CHOICES.len() - 1);
            }
        }
        Act::GrantCancel => {
            if let Some(view) = device_access.as_mut()
                && !view.busy
            {
                view.form = None;
            }
        }
        Act::RevokeArm => {
            if let Some(view) = device_access.as_mut()
                && !view.busy
                && view.form.is_none()
            {
                view.confirm_revoke = view.selected < grant_count(view);
            }
        }
        Act::RevokeCancel => {
            if let Some(view) = device_access.as_mut() {
                view.confirm_revoke = false;
            }
        }
        Act::DeleteStart(_)
        | Act::DeleteConfirm
        | Act::DevicesOpen(_)
        | Act::DevicesRefresh
        | Act::GrantSubmit
        | Act::RevokeConfirm => return false,
    }
    true
}

/// The grant form, when it is open and nothing is running.
fn idle_form(view: &mut Option<DeviceAccessView>) -> Option<&mut GrantForm> {
    view.as_mut()
        .filter(|v| !v.busy)
        .and_then(|v| v.form.as_mut())
}

// ****************************************************************************
// Loop-side actions
// ****************************************************************************

/// Service an action that reads the config or reaches the VTA.
pub(crate) fn dispatch(ctx: &mut ActionCtx<'_>, action: Act) {
    match action {
        Act::DeleteStart(index) => start_deletion(ctx, index),
        Act::DeleteConfirm => confirm_deletion(ctx),
        Act::DevicesOpen(index) => open_devices(ctx, index),
        Act::DevicesRefresh => {
            if let Some(context_id) = panel(ctx.state)
                .device_access
                .as_ref()
                .filter(|v| !v.busy)
                .map(|v| v.context_id.clone())
            {
                read_grants(ctx, context_id);
            }
        }
        Act::GrantSubmit => submit_grant(ctx),
        Act::RevokeConfirm => confirm_revoke(ctx),
        // View-only: the shared reducer handled these before the loop saw them.
        Act::DeleteInput(_)
        | Act::DeleteCancel
        | Act::DevicesClose
        | Act::DevicesSelect(_)
        | Act::GrantStart
        | Act::GrantField(_)
        | Act::GrantInput { .. }
        | Act::GrantExpiry(_)
        | Act::GrantCancel
        | Act::RevokeArm
        | Act::RevokeCancel => {}
    }
}

/// The membership at a Communities display index.
fn membership_at<'c>(
    state: &State,
    config: &'c Config,
    index: usize,
) -> Option<&'c CommunityRecord> {
    config
        .account
        .communities_for_display(state.main_page.content_panel.communities.show_archived)
        .get(index)
        .copied()
}

fn community_name(config: &Config, membership: &CommunityRecord) -> String {
    crate::state_handler::community_label(
        config,
        &membership.vtc_did,
        membership.display_name.as_deref(),
        60,
    )
}

/// Claim the domain and the VTA session for a job, or say why not.
fn claim(ctx: &mut ActionCtx<'_>, what: &str) -> Result<VtaClient, String> {
    let Some(client) = ctx.admin_vta else {
        return Err(format!(
            "VTA session unavailable — cannot {what} right now."
        ));
    };
    if !ctx.in_flight.try_begin(DOMAIN) {
        return Err(InFlight::busy_message(DOMAIN));
    }
    Ok(client.clone())
}

fn spawn(ctx: &ActionCtx<'_>, job: impl Future<Output = ContextOutcome> + Send + 'static) {
    background_dispatch::spawn_dispatch(ctx.dispatch_tx.clone(), DOMAIN, async move {
        DispatchOutcome::CommunityContext(job.await)
    });
}

fn set_view_message(state: &mut State, message: String) {
    if let Some(view) = panel(state).device_access.as_mut() {
        view.message = Some(message);
    }
}

fn start_deletion(ctx: &mut ActionCtx<'_>, index: usize) {
    let config: &Config = ctx.config;
    let Some(membership) = membership_at(ctx.state, config, index) else {
        return;
    };
    let context_id = match community_context::deletable_context(
        &config.account,
        &config.private.vetting.applications,
        membership,
    ) {
        Ok(id) => id,
        Err(refusal) => {
            panel(ctx.state).status_message = Some(refusal.describe());
            return;
        }
    };
    let view = ContextDeleteView {
        vtc_did: membership.vtc_did.clone(),
        persona: membership.persona_ref,
        community: community_name(config, membership),
        context_id: context_id.clone(),
        phase: ContextDeletePhase::Previewing,
        typed: String::new(),
    };
    let top = config.account.top_context_id.clone();
    let client = match claim(ctx, "delete a context") {
        Ok(client) => client,
        Err(message) => {
            panel(ctx.state).status_message = Some(message);
            return;
        }
    };
    let communities = panel(ctx.state);
    communities.device_access = None;
    communities.status_message = None;
    communities.context_delete = Some(view);
    spawn(ctx, async move {
        let result = community_context::preview_context_deletion(&client, &top, &context_id)
            .await
            .map_err(|e| reason(&e));
        ContextOutcome::Previewed { context_id, result }
    });
}

fn confirm_deletion(ctx: &mut ActionCtx<'_>) {
    let Some(view) = panel(ctx.state).context_delete.clone() else {
        return;
    };
    if !matches!(view.phase, ContextDeletePhase::Ready(_)) {
        return;
    }
    if !community_context::confirms_deletion(&view.typed) {
        panel(ctx.state).status_message = Some(format!(
            "Type {DELETE_CONFIRMATION} in capitals to delete {}.",
            view.context_id
        ));
        return;
    }
    // Checked again, against the config as it is now: the preview may have
    // been on screen while a join or an application started using the context.
    let config: &Config = ctx.config;
    let problem = match config
        .account
        .memberships()
        .find(|m| m.vtc_did == view.vtc_did && m.persona_ref == view.persona)
        .map(|m| {
            community_context::deletable_context(
                &config.account,
                &config.private.vetting.applications,
                m,
            )
        }) {
        Some(Ok(id)) if id == view.context_id => None,
        Some(Ok(_)) | None => {
            Some("The membership changed since the preview — start the deletion again.".to_string())
        }
        Some(Err(refusal)) => Some(refusal.describe()),
    };
    if let Some(problem) = problem {
        let communities = panel(ctx.state);
        communities.context_delete = None;
        communities.status_message = Some(problem);
        return;
    }
    let top = config.account.top_context_id.clone();
    let client = match claim(ctx, "delete a context") {
        Ok(client) => client,
        Err(message) => {
            panel(ctx.state).status_message = Some(message);
            return;
        }
    };
    if let Some(open) = panel(ctx.state).context_delete.as_mut() {
        open.phase = ContextDeletePhase::Deleting;
    }
    let ContextDeleteView {
        vtc_did,
        persona,
        context_id,
        ..
    } = view;
    spawn(ctx, async move {
        let result = community_context::delete_context(&client, &top, &context_id)
            .await
            .map_err(|e| reason(&e));
        ContextOutcome::Deleted {
            vtc_did,
            persona,
            context_id,
            result,
        }
    });
}

fn open_devices(ctx: &mut ActionCtx<'_>, index: usize) {
    let config: &Config = ctx.config;
    let Some(membership) = membership_at(ctx.state, config, index) else {
        return;
    };
    if !community_context::is_sub_context(
        &membership.sub_context_id,
        &config.account.top_context_id,
    ) {
        panel(ctx.state).status_message = Some(
            "This community lives in your top context. Device access is scoped to a \
             community's own context, and access to the top context would reach every community."
                .to_string(),
        );
        return;
    }
    let view = DeviceAccessView {
        community: community_name(config, membership),
        context_id: membership.sub_context_id.clone(),
        can_grant: membership.status.is_active(),
        selected: 0,
        form: None,
        confirm_revoke: false,
        busy: false,
        message: None,
    };
    let context_id = view.context_id.clone();
    let communities = panel(ctx.state);
    communities.context_delete = None;
    communities.device_access = Some(view);
    read_grants(ctx, context_id);
}

fn read_grants(ctx: &mut ActionCtx<'_>, context_id: String) {
    let client = match claim(ctx, "read device access") {
        Ok(client) => client,
        Err(message) => return set_view_message(ctx.state, message),
    };
    let communities = panel(ctx.state);
    communities
        .device_grants
        .entry(context_id.clone())
        .or_insert(GrantListing::Loading);
    if let Some(view) = communities.device_access.as_mut() {
        view.busy = true;
    }
    spawn(ctx, async move {
        let result = community_access::list_device_grants(&client, &context_id)
            .await
            .map_err(|e| reason(&e));
        ContextOutcome::Listed { context_id, result }
    });
}

fn submit_grant(ctx: &mut ActionCtx<'_>) {
    let Some(view) = panel(ctx.state).device_access.clone() else {
        return;
    };
    let Some(form) = view.form.as_ref() else {
        return;
    };
    if view.busy || !view.can_grant {
        return;
    }
    let own_did = ctx.admin_vta.and_then(VtaClient::caller_did);
    let did = match community_access::parse_device_did(&form.did, own_did) {
        Ok(did) => did,
        Err(e) => return set_view_message(ctx.state, reason(&e)),
    };
    let expires = community_access::expires_at(Utc::now(), form.expiry);
    let label = community_access::grant_label(&form.name, &view.community);
    let top = ctx.config.account.top_context_id.clone();
    let client = match claim(ctx, "grant device access") {
        Ok(client) => client,
        Err(message) => return set_view_message(ctx.state, message),
    };
    if let Some(open) = panel(ctx.state).device_access.as_mut() {
        open.busy = true;
        open.message = Some(format!("Granting {}…", shorten_did(&did, 40)));
    }
    let context_id = view.context_id;
    spawn(ctx, async move {
        let result =
            community_access::grant_device(&client, &top, &context_id, &did, &label, expires)
                .await
                .map_err(|e| reason(&e));
        // Re-read whatever the grant did, so the list is the VTA's answer.
        let listing = community_access::list_device_grants(&client, &context_id)
            .await
            .map_err(|e| reason(&e));
        ContextOutcome::Granted {
            context_id,
            did,
            result,
            listing,
        }
    });
}

fn confirm_revoke(ctx: &mut ActionCtx<'_>) {
    let communities = panel(ctx.state);
    let Some(view) = communities.device_access.as_mut() else {
        return;
    };
    let armed = std::mem::take(&mut view.confirm_revoke);
    if !armed || view.busy {
        return;
    }
    let context_id = view.context_id.clone();
    let Some(grant) = communities
        .device_grants
        .get(&context_id)
        .and_then(|l| l.grants().get(view.selected))
        .cloned()
    else {
        return;
    };
    let client = match claim(ctx, "revoke device access") {
        Ok(client) => client,
        Err(message) => return set_view_message(ctx.state, message),
    };
    if let Some(open) = panel(ctx.state).device_access.as_mut() {
        open.busy = true;
        open.message = Some(format!("Revoking {}…", shorten_did(&grant.did, 40)));
    }
    spawn(ctx, async move {
        let result = community_access::revoke_device_grant(&client, &context_id, &grant.did)
            .await
            .map_err(|e| reason(&e));
        let listing = community_access::list_device_grants(&client, &context_id)
            .await
            .map_err(|e| reason(&e));
        ContextOutcome::Revoked {
            context_id,
            did: grant.did,
            result,
            listing,
        }
    });
}

// ****************************************************************************
// Outcomes
// ****************************************************************************

/// What a context job did. Data only; applied on the loop thread.
pub(crate) enum ContextOutcome {
    /// The VTA said what deleting the context would remove.
    Previewed {
        context_id: String,
        result: Result<ContextDeletionPreview, String>,
    },
    /// The context was deleted, or was not.
    Deleted {
        vtc_did: String,
        persona: PersonaId,
        context_id: String,
        result: Result<(), String>,
    },
    /// The context's device grants were read.
    Listed {
        context_id: String,
        result: Result<Vec<DeviceGrant>, String>,
    },
    /// A device was granted access (or was not), and the grants re-read.
    Granted {
        context_id: String,
        did: String,
        result: Result<DeviceGrant, String>,
        listing: Result<Vec<DeviceGrant>, String>,
    },
    /// A device's access was revoked (or was not), and the grants re-read.
    Revoked {
        context_id: String,
        did: String,
        result: Result<Revoked, String>,
        listing: Result<Vec<DeviceGrant>, String>,
    },
}

impl ContextOutcome {
    /// Apply the result to the panel, the account and the activity log.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        match self {
            ContextOutcome::Previewed { context_id, result } => {
                let communities = panel(state);
                // The holder may have closed the view, or opened another, while
                // the VTA was answering.
                let Some(view) = communities
                    .context_delete
                    .as_mut()
                    .filter(|v| v.context_id == context_id)
                else {
                    return;
                };
                match result {
                    Ok(preview) => view.phase = ContextDeletePhase::Ready(preview),
                    Err(e) => {
                        communities.context_delete = None;
                        communities.status_message = Some(format!(
                            "Couldn't ask your VTA what deleting {context_id} would remove: {e}"
                        ));
                        state
                            .main_page
                            .log_error("Context deletion preview failed", e.as_str());
                    }
                }
            }
            ContextOutcome::Deleted {
                vtc_did,
                persona,
                context_id,
                result,
            } => {
                let communities = panel(state);
                if communities
                    .context_delete
                    .as_ref()
                    .is_some_and(|v| v.context_id == context_id)
                {
                    communities.context_delete = None;
                }
                match result {
                    Ok(()) => {
                        // The context is gone at the VTA. A record still naming
                        // it would have the registration job create an empty one
                        // on the next launch, so the records let go of it.
                        for membership in config
                            .account
                            .memberships_mut()
                            .filter(|m| m.sub_context_id == context_id)
                        {
                            membership.sub_context_id.clear();
                        }
                        for application in config
                            .private
                            .vetting
                            .applications
                            .iter_mut()
                            .filter(|a| a.context_id.as_deref() == Some(context_id.as_str()))
                        {
                            application.context_id = None;
                        }
                        communities.device_grants.remove(&context_id);
                        communities.status_message = Some(format!(
                            "Deleted context {context_id} and everything in it."
                        ));
                        save.mark_dirty();
                        state.main_page.sync_from_config(config);
                        state.main_page.log(format!(
                            "Deleted community context {context_id} (community {vtc_did}, persona {persona})"
                        ));
                    }
                    Err(e) => {
                        communities.status_message =
                            Some(format!("Couldn't delete {context_id}: {e}"));
                        state
                            .main_page
                            .log_error("Context deletion failed", e.as_str());
                    }
                }
            }
            ContextOutcome::Listed { context_id, result } => {
                store_listing(state, &context_id, result);
            }
            ContextOutcome::Granted {
                context_id,
                did,
                result,
                listing,
            } => {
                let message = match &result {
                    Ok(grant) => {
                        state.main_page.log(format!(
                            "Granted {did} the {} role in {context_id}",
                            grant.role
                        ));
                        format!(
                            "Granted {} {} in this context{}.",
                            shorten_did(&did, 40),
                            grant.role,
                            grant
                                .expires_at
                                .map(|at| format!(" until {}", at.format("%Y-%m-%d %H:%M UTC")))
                                .unwrap_or_default()
                        )
                    }
                    Err(e) => {
                        state
                            .main_page
                            .log_error("Device access grant failed", e.as_str());
                        format!("Couldn't grant access: {e}")
                    }
                };
                store_listing(state, &context_id, listing);
                if let Some(view) = open_view(state, &context_id) {
                    view.message = Some(message);
                    if result.is_ok() {
                        view.form = None;
                    }
                }
            }
            ContextOutcome::Revoked {
                context_id,
                did,
                result,
                listing,
            } => {
                let short = shorten_did(&did, 40);
                let message = match &result {
                    Ok(revoked) => {
                        state
                            .main_page
                            .log(format!("Revoked {did}'s access in {context_id}"));
                        match revoked {
                            Revoked::Deleted => format!("Revoked {short}'s access."),
                            Revoked::Narrowed(rest) => format!(
                                "Removed {short} from this community; it keeps access in {}.",
                                rest.join(", ")
                            ),
                            Revoked::AlreadyGone => {
                                format!("{short} had no access left at your VTA.")
                            }
                        }
                    }
                    Err(e) => {
                        state
                            .main_page
                            .log_error("Device access revocation failed", e.as_str());
                        format!("Couldn't revoke access: {e}")
                    }
                };
                store_listing(state, &context_id, listing);
                if let Some(view) = open_view(state, &context_id) {
                    view.message = Some(message);
                }
            }
        }
    }
}

/// The device-access view, if it is open on `context_id`.
fn open_view<'s>(state: &'s mut State, context_id: &str) -> Option<&'s mut DeviceAccessView> {
    panel(state)
        .device_access
        .as_mut()
        .filter(|v| v.context_id == context_id)
}

/// Record a grant listing and release the view it was read for.
fn store_listing(state: &mut State, context_id: &str, listing: Result<Vec<DeviceGrant>, String>) {
    let count = listing.as_ref().map_or(0, Vec::len);
    panel(state).device_grants.insert(
        context_id.to_string(),
        match listing {
            Ok(grants) => GrantListing::Loaded(grants),
            Err(e) => GrantListing::Failed(e),
        },
    );
    if let Some(view) = open_view(state, context_id) {
        view.busy = false;
        view.confirm_revoke = false;
        view.selected = view.selected.min(count.saturating_sub(1));
    }
}

// ****************************************************************************
// Once-a-run sweep
// ****************************************************************************

/// The contexts a sweep reads: every membership's own context, once each.
pub(crate) fn sweep_targets(config: &Config) -> Vec<String> {
    let top = config.account.top_context_id.as_str();
    config
        .account
        .memberships()
        .map(|m| m.sub_context_id.clone())
        .filter(|id| community_context::is_sub_context(id, top))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Read the device grants of every context in `contexts`.
pub(crate) async fn sweep(client: VtaClient, contexts: Vec<String>) -> DispatchOutcome {
    let mut results = Vec::with_capacity(contexts.len());
    for context_id in contexts {
        let result = community_access::list_device_grants(&client, &context_id)
            .await
            .map_err(|e| reason(&e));
        results.push((context_id, result));
    }
    DispatchOutcome::DeviceGrantSweep(results)
}

/// Fold a sweep into the panel. A listing already read — by the holder, after
/// the sweep started — is newer, and kept.
pub(crate) fn apply_sweep(
    state: &mut State,
    results: Vec<(String, Result<Vec<DeviceGrant>, String>)>,
) {
    let grants = &mut panel(state).device_grants;
    for (context_id, result) in results {
        if matches!(grants.get(&context_id), Some(GrantListing::Loaded(_))) {
            continue;
        }
        grants.insert(
            context_id,
            match result {
                Ok(listed) => GrantListing::Loaded(listed),
                Err(e) => GrantListing::Failed(e),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use openvtc_core::community_access::Revoked;
    use openvtc_core::config::account::CommunityRecord;
    use vta_sdk::protocols::context_management::delete::DeleteContextPreviewResultBody;

    const CTX: &str = "openvtc/acme";
    const VTC: &str = "did:webvh:QmScid:example.com:acme";

    fn grant(did: &str) -> DeviceGrant {
        DeviceGrant {
            did: did.to_string(),
            role: "application".to_string(),
            label: None,
            contexts: vec![CTX.to_string()],
            elsewhere: vec![],
            expires_at: None,
        }
    }

    fn device_view() -> DeviceAccessView {
        DeviceAccessView {
            community: "Acme".to_string(),
            context_id: CTX.to_string(),
            can_grant: true,
            selected: 0,
            form: None,
            confirm_revoke: false,
            busy: false,
            message: None,
        }
    }

    fn delete_view(phase: ContextDeletePhase) -> ContextDeleteView {
        ContextDeleteView {
            vtc_did: VTC.to_string(),
            persona: PersonaId::new(),
            community: "Acme".to_string(),
            context_id: CTX.to_string(),
            phase,
            typed: String::new(),
        }
    }

    fn ready() -> ContextDeletePhase {
        ContextDeletePhase::Ready(ContextDeletionPreview {
            context_id: CTX.to_string(),
            contexts: vec![DeleteContextPreviewResultBody {
                id: CTX.to_string(),
                ..Default::default()
            }],
        })
    }

    #[test]
    fn the_confirmation_is_typed_only_once_the_preview_is_shown() {
        let mut state = State::default();
        panel(&mut state).context_delete = Some(delete_view(ContextDeletePhase::Previewing));
        assert!(reduce(&mut state, &Act::DeleteInput("D".into())));
        assert_eq!(panel(&mut state).context_delete.as_ref().unwrap().typed, "");

        panel(&mut state).context_delete = Some(delete_view(ready()));
        reduce(&mut state, &Act::DeleteInput("DELETE".into()));
        assert_eq!(
            panel(&mut state).context_delete.as_ref().unwrap().typed,
            "DELETE"
        );
        reduce(&mut state, &Act::DeleteInput("x".repeat(100)));
        assert_eq!(
            panel(&mut state)
                .context_delete
                .as_ref()
                .unwrap()
                .typed
                .len(),
            MAX_TYPED
        );
    }

    #[test]
    fn a_running_delete_cannot_be_dismissed() {
        let mut state = State::default();
        panel(&mut state).context_delete = Some(delete_view(ContextDeletePhase::Deleting));
        reduce(&mut state, &Act::DeleteCancel);
        assert!(panel(&mut state).context_delete.is_some());
        panel(&mut state).context_delete = Some(delete_view(ready()));
        reduce(&mut state, &Act::DeleteCancel);
        assert!(panel(&mut state).context_delete.is_none());
    }

    #[test]
    fn the_grant_form_edits_its_fields_and_clamps_the_expiry() {
        let mut state = State::default();
        panel(&mut state).device_access = Some(device_view());
        reduce(&mut state, &Act::GrantStart);
        reduce(
            &mut state,
            &Act::GrantInput {
                field: 0,
                value: "did:key:z6Mk".into(),
            },
        );
        reduce(
            &mut state,
            &Act::GrantInput {
                field: 1,
                value: "laptop".into(),
            },
        );
        reduce(&mut state, &Act::GrantField(4));
        reduce(&mut state, &Act::GrantExpiry(99));
        let form = panel(&mut state)
            .device_access
            .as_ref()
            .unwrap()
            .form
            .clone()
            .unwrap();
        assert_eq!(form.did, "did:key:z6Mk");
        assert_eq!(form.name, "laptop");
        assert_eq!(form.field, 1);
        assert_eq!(form.expiry, EXPIRY_CHOICES.len() - 1);
    }

    /// A finished membership's grants can be read and revoked, but no device is
    /// added to it.
    #[test]
    fn a_finished_membership_takes_no_new_grant() {
        let mut state = State::default();
        panel(&mut state).device_access = Some(DeviceAccessView {
            can_grant: false,
            ..device_view()
        });
        reduce(&mut state, &Act::GrantStart);
        assert!(
            panel(&mut state)
                .device_access
                .as_ref()
                .unwrap()
                .form
                .is_none()
        );
    }

    #[test]
    fn revocation_is_armed_only_on_a_grant() {
        let mut state = State::default();
        panel(&mut state).device_access = Some(device_view());
        reduce(&mut state, &Act::RevokeArm);
        assert!(
            !panel(&mut state)
                .device_access
                .as_ref()
                .unwrap()
                .confirm_revoke
        );
        panel(&mut state)
            .device_grants
            .insert(CTX.into(), GrantListing::Loaded(vec![grant("did:key:zA")]));
        reduce(&mut state, &Act::RevokeArm);
        assert!(
            panel(&mut state)
                .device_access
                .as_ref()
                .unwrap()
                .confirm_revoke
        );
    }

    #[test]
    fn actions_that_reach_the_vta_are_left_to_the_loop() {
        let mut state = State::default();
        for action in [
            Act::DeleteStart(0),
            Act::DeleteConfirm,
            Act::DevicesOpen(0),
            Act::DevicesRefresh,
            Act::GrantSubmit,
            Act::RevokeConfirm,
        ] {
            assert!(!reduce(&mut state, &action));
        }
    }

    #[test]
    fn a_preview_readies_the_confirmation_and_a_stale_one_is_dropped() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        panel(&mut state).context_delete = Some(delete_view(ContextDeletePhase::Previewing));

        ContextOutcome::Previewed {
            context_id: "openvtc/other".into(),
            result: Ok(ContextDeletionPreview::default()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            panel(&mut state).context_delete.as_ref().unwrap().phase,
            ContextDeletePhase::Previewing
        ));

        ContextOutcome::Previewed {
            context_id: CTX.into(),
            result: Ok(ContextDeletionPreview::default()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            panel(&mut state).context_delete.as_ref().unwrap().phase,
            ContextDeletePhase::Ready(_)
        ));
    }

    #[test]
    fn a_failed_preview_closes_the_view_and_says_why() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        panel(&mut state).context_delete = Some(delete_view(ContextDeletePhase::Previewing));
        ContextOutcome::Previewed {
            context_id: CTX.into(),
            result: Err("could not reach your VTA".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        let communities = panel(&mut state);
        assert!(communities.context_delete.is_none());
        assert!(
            communities
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("could not reach"))
        );
    }

    /// After a delete the records let go of the context, so nothing recreates
    /// it, and the change is saved.
    #[test]
    fn a_deleted_context_is_forgotten_by_the_records() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let persona = PersonaId::new();
        config.account.top_context_id = "openvtc".into();
        let mut record = CommunityRecord::new_pending(
            VTC.into(),
            None,
            CTX.into(),
            persona,
            uuid::Uuid::new_v4(),
            Utc::now(),
        );
        record.status = openvtc_core::config::account::CommunityStatus::Left;
        config.account.add_membership(record);
        config
            .private
            .vetting
            .start_application(VTC, persona, "did:webvh:join", Utc::now())
            .unwrap()
            .context_id = Some(CTX.into());
        panel(&mut state)
            .device_grants
            .insert(CTX.into(), GrantListing::Loaded(vec![]));
        panel(&mut state).context_delete = Some(delete_view(ContextDeletePhase::Deleting));

        ContextOutcome::Deleted {
            vtc_did: VTC.into(),
            persona,
            context_id: CTX.into(),
            result: Ok(()),
        }
        .apply(&mut state, &mut config, &mut save);

        assert!(
            config
                .account
                .memberships()
                .all(|m| m.sub_context_id.is_empty())
        );
        assert!(config.private.vetting.applications[0].context_id.is_none());
        assert!(save.is_pending());
        let communities = panel(&mut state);
        assert!(communities.context_delete.is_none());
        assert!(!communities.device_grants.contains_key(CTX));
        assert!(
            communities
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("Deleted context"))
        );
    }

    #[test]
    fn a_failed_delete_changes_no_record() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        ContextOutcome::Deleted {
            vtc_did: VTC.into(),
            persona: PersonaId::new(),
            context_id: CTX.into(),
            result: Err("your VTA refused".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(!save.is_pending());
        assert!(
            panel(&mut state)
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("Couldn't delete"))
        );
    }

    #[test]
    fn a_grant_closes_the_form_and_refreshes_the_list() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        panel(&mut state).device_access = Some(DeviceAccessView {
            busy: true,
            form: Some(GrantForm::default()),
            ..device_view()
        });
        ContextOutcome::Granted {
            context_id: CTX.into(),
            did: "did:key:zA".into(),
            result: Ok(grant("did:key:zA")),
            listing: Ok(vec![grant("did:key:zA")]),
        }
        .apply(&mut state, &mut config, &mut save);
        let communities = panel(&mut state);
        let view = communities.device_access.as_ref().unwrap();
        assert!(!view.busy && view.form.is_none());
        assert!(
            view.message
                .as_deref()
                .is_some_and(|m| m.contains("Granted"))
        );
        assert_eq!(communities.device_grants[CTX].grants().len(), 1);
    }

    /// A refused grant keeps the form, so the holder can fix what they typed.
    #[test]
    fn a_refused_grant_keeps_the_form() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        panel(&mut state).device_access = Some(DeviceAccessView {
            busy: true,
            form: Some(GrantForm::default()),
            ..device_view()
        });
        ContextOutcome::Granted {
            context_id: CTX.into(),
            did: "did:key:zA".into(),
            result: Err("did:key:zA already has access".into()),
            listing: Ok(vec![]),
        }
        .apply(&mut state, &mut config, &mut save);
        let view = panel(&mut state).device_access.clone().unwrap();
        assert!(view.form.is_some());
        assert!(view.message.unwrap().contains("already has access"));
    }

    #[test]
    fn a_narrowed_revocation_says_what_the_device_keeps() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        panel(&mut state).device_access = Some(DeviceAccessView {
            busy: true,
            selected: 3,
            ..device_view()
        });
        ContextOutcome::Revoked {
            context_id: CTX.into(),
            did: "did:key:zA".into(),
            result: Ok(Revoked::Narrowed(vec!["openvtc/work".into()])),
            listing: Ok(vec![grant("did:key:zB")]),
        }
        .apply(&mut state, &mut config, &mut save);
        let view = panel(&mut state).device_access.clone().unwrap();
        assert!(!view.busy);
        assert_eq!(view.selected, 0, "the highlight stays on the list");
        assert!(view.message.unwrap().contains("openvtc/work"));
    }

    #[test]
    fn a_sweep_never_overwrites_a_newer_listing() {
        let mut state = State::default();
        panel(&mut state).device_grants.insert(
            CTX.into(),
            GrantListing::Loaded(vec![grant("did:key:zNew")]),
        );
        apply_sweep(
            &mut state,
            vec![
                (CTX.into(), Ok(vec![])),
                ("openvtc/other".into(), Err("unreachable".into())),
            ],
        );
        let grants = &panel(&mut state).device_grants;
        assert_eq!(grants[CTX].grants()[0].did, "did:key:zNew");
        assert!(matches!(grants["openvtc/other"], GrantListing::Failed(_)));
    }

    #[test]
    fn a_sweep_reads_each_own_context_once() {
        let mut config = test_config();
        config.account.top_context_id = "openvtc".into();
        for (vtc, context) in [("did:a", CTX), ("did:b", CTX), ("did:c", "openvtc")] {
            config.account.add_membership(CommunityRecord::new_pending(
                vtc.into(),
                None,
                context.into(),
                PersonaId::new(),
                uuid::Uuid::new_v4(),
                Utc::now(),
            ));
        }
        assert_eq!(sweep_targets(&config), [CTX]);
    }
}
