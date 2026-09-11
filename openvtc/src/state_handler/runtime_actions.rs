//! The runtime loop's action handling, lifted out of the loop (R14 follow-up).
//!
//! `main_loop` was ~1,600 lines, 900 of them one `match` over `Action`, and
//! nothing in it could be called by a test: every fix this file's history
//! records was verified by reading it, by a live log, or by a unit test on some
//! piece extracted from it. That is also how a change whose entire purpose was
//! compile-time exhaustiveness shipped broken across feature sets.
//!
//! What made the lift possible is the R14 sweep: the arms are now uniformly
//! *resolve owned inputs -> claim a domain -> spawn -> apply on the outcome*, so
//! they need a fixed set of resources and no longer interleave network work with
//! loop-local state. [`ActionCtx`] is that set.
//!
//! Three arms stay in the loop, because they are not about acting on state:
//! `Exit` and `UXError` signal the terminator and `break` with the loop's own
//! outcome type, and `StartJoin` drives the join flow's own action loop with the
//! receiver this one is selecting on.

use tokio::sync::{mpsc::UnboundedSender, watch};

use crate::state_handler::actions::Action;
use crate::state_handler::background_dispatch::{self, DispatchOutcome, InFlight};
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::session_manager::SessionManager;
use crate::state_handler::state::State;
use crate::state_handler::*;
use openvtc_core::config::Config;
use openvtc_core::didcomm::Messaging;

/// Everything an action can act on.
///
/// Deliberately a struct of borrows rather than an owned context: the loop keeps
/// ownership, so nothing here changes who may mutate what — the single-mutator
/// invariant is that all of this is touched from the loop thread, and a
/// borrowed context cannot escape it.
///
/// Every field is constructible in a test. `TDK` builds offline
/// (`with_load_environment(false)`), `Messaging` has `start_empty_service`, and
/// `admin_vta` is already an `Option` because a State-A account may have no
/// session — so a test that passes `None` is exercising a real path, not a
/// stub.
pub(crate) struct ActionCtx<'a> {
    pub(crate) state: &'a mut State,
    /// `Box<Config>` rather than `Config`, matching what the loop holds: the
    /// dispatchers this delegates to take `&mut Box<Config>`, and deref
    /// coercion covers the ones that want a plain `&mut Config`.
    pub(crate) config: &'a mut Box<Config>,
    pub(crate) save: &'a mut SaveScheduler,
    pub(crate) in_flight: &'a mut InFlight,
    pub(crate) dispatch_tx: &'a UnboundedSender<DispatchOutcome>,
    pub(crate) tdk: &'a TDK,
    pub(crate) admin_vta: Option<&'a vta_sdk::client::VtaClient>,
    pub(crate) didcomm_service: &'a Messaging,
    pub(crate) session_manager: &'a mut SessionManager,
    /// When a manual trust-ping went out, so the reply can be timed. Loop
    /// state rather than `State`: it is a stopwatch, not something the UI
    /// renders, and it is read by the inbound arm that stays in the loop.
    pub(crate) ping_sent_at: &'a mut Option<std::time::Instant>,
    pub(crate) state_tx: &'a watch::Sender<State>,
    pub(crate) profile: &'a str,
}

/// What the loop must do after an action was handled.
pub(crate) enum Handled {
    /// Carry on.
    Continue,
    /// The operator confirmed a profile wipe. Only the loop can honour this —
    /// it owns the terminator and the outcome type — so the handler says so and
    /// the loop acts.
    ExitUserInt,
}

/// Handle one action.
///
/// The match is exhaustive with no `_` arm, which is the guarantee #236 added
/// and this move carries over intact: a new `Action` variant cannot be added
/// without deciding here what the runtime loop does with it.
pub(crate) async fn handle_action(ctx: &mut ActionCtx<'_>, action: Action) -> Handled {
    match action {
        // Shared nav reducer first: pure-ctx.state nav arms live in exactly
        // one place (`handle_nav_action`). It returns true when it
        // handled the action; the loop-specific arms below run only when
        // it didn't.
        _ if handle_nav_action(ctx.state, &action) => {}
        Action::DeleteCommunity(i) => {
            // Capture the deleted community + its persona BEFORE the
            // delete so we can deregister its session and tear down
            // *its* listener (not the active one) if its persona ends
            // up with no live community.
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            remove_community(ctx.state, ctx.config, ctx.save, i);
            // A deleted community must not leave its persona's mediator
            // connection running. Deregister it from the session
            // manager (D15/R-S-3); if that persona no longer has any
            // live community, stop and remove its listener so the
            // connection is torn down with the community, not left
            // dangling.
            if let Some((vtc, pid)) = target {
                let removed = ctx.session_manager.deregister(pid, &vtc);
                let still_live = ctx
                    .config
                    .account
                    .memberships()
                    .any(|c| c.persona_ref == pid && c.is_live());
                if !still_live
                    && let Some(did) = ctx.config.identities.get(&pid).map(|id| id.did.clone())
                {
                    // Prefer the listener id the manager recorded for
                    // the torn-down session; fall back to deriving it.
                    let listener_id = removed
                        .map(|s| s.listener_id)
                        .unwrap_or_else(|| didcomm::persona_listener_id(&did));
                    ctx.didcomm_service.remove_listener(&listener_id).await;
                    ctx.state
                        .main_page
                        .log("Community removed — persona listener stopped.");
                }
            }
            // Drop the global messaging status only when NO persona
            // has a live community left.
            if !ctx.config.account.memberships().any(|c| c.is_live()) {
                ctx.state.connection.status = state::MediatorStatus::NoActiveCommunity;
                ctx.state.connection.messaging_active = false;
            }
        }
        Action::SetActiveCommunity(i) => {
            // Switch the working context to the Active community at
            // display index `i` (R-C-6 / D10). Extract owned values to
            // end the immutable account borrow before mutating ctx.config.
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .filter(|c| c.status.is_active())
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona)) = target {
                ctx.state.selected_community = Some((vtc, persona));
                ctx.config.set_active_persona(Some(persona));
                // Refilter the community-scoped panels immediately so
                // the switch is reflected this frame.
                ctx.state.main_page.sync_from_config(ctx.config);
            }
        }
        Action::ToggleFavourite(i) => {
            // R-C-4: flip the star on the community at display index
            // `i`, persist (coalesced), then keep the highlight on it
            // as the list re-sorts (favourites float to the top).
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona)) = target {
                if let Some(c) = ctx.config.account.membership_mut(&vtc, persona) {
                    c.toggle_favourite();
                }
                ctx.save.mark_dirty();
                ctx.state.main_page.sync_from_config(ctx.config);
                if let Some(new_idx) = ctx
                    .config
                    .account
                    .communities_for_display(
                        ctx.state.main_page.content_panel.communities.show_archived,
                    )
                    .iter()
                    .position(|c| c.vtc_did == vtc && c.persona_ref == persona)
                {
                    ctx.state.main_page.content_panel.communities.selected_index = new_idx;
                }
            }
        }
        Action::AcknowledgeCommunity(i) => {
            // R-S-2: clear the actions-required badge on a terminal
            // outcome (Rejected / Expired) the user has now seen.
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona)) = target
                && let Some(c) = ctx.config.account.membership_mut(&vtc, persona)
            {
                c.acknowledge();
                ctx.save.mark_dirty();
                ctx.state.main_page.sync_from_config(ctx.config);
            }
        }
        Action::LeaveCommunity(i) => {
            // R-L-1: send MEMBER_SELF_REMOVE, then set Left +
            // deregister the session once it lands (the community's
            // receipt is advisory). Both halves are in
            // `community_actions`; the session teardown is reported
            // back to this loop, which owns the session manager.
            ctx.state.main_page.content_panel.communities.confirm_leave = None;
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .filter(|c| c.status.is_active())
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona_id)) = target {
                match capability_sender(ctx.config, ctx.tdk, persona_id) {
                    Some((atm, profile, member_did, mediator)) => {
                        spawn_community_job(
                            ctx.dispatch_tx,
                            ctx.in_flight,
                            ctx.state,
                            community_actions::CommunityJob {
                                atm,
                                profile,
                                member_did,
                                mediator,
                                vtc_did: vtc,
                                persona: persona_id,
                                verb: community_actions::Verb::Leave,
                            },
                        );
                    }
                    None => {
                        ctx.state.main_page.content_panel.communities.status_message =
                            Some("Messaging unavailable — cannot leave right now.".to_string());
                    }
                }
            }
        }
        Action::CapabilitiesOpen(i) => {
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .filter(|c| c.status.is_active())
                .map(|c| {
                    (
                        c.vtc_did.clone(),
                        c.persona_ref,
                        community_label(ctx.config, &c.vtc_did, c.display_name.as_deref(), 256),
                    )
                });
            if let Some((vtc, persona_id, name)) = target {
                capability_actions::open_view(ctx.state, vtc.clone(), persona_id, name);
                match capability_sender(ctx.config, ctx.tdk, persona_id) {
                    Some((atm, profile, persona_did, mediator)) => {
                        spawn_capability_job(
                            ctx.dispatch_tx,
                            ctx.in_flight,
                            ctx.state,
                            capability_actions::CapabilityJob {
                                atm,
                                profile,
                                persona_did,
                                mediator,
                                vtc_did: vtc,
                                persona: persona_id,
                                verb: capability_actions::Verb::List,
                            },
                        );
                    }
                    None => capability_actions::send_unavailable(ctx.state),
                }
            }
        }
        Action::CapabilitiesRefresh => {
            let target = ctx
                .state
                .main_page
                .content_panel
                .capabilities
                .view
                .as_ref()
                .map(|v| (v.vtc_did.clone(), v.persona));
            if let Some((vtc, persona_id)) = target {
                if let Some(view) = ctx.state.main_page.content_panel.capabilities.view.as_mut() {
                    view.phase =
                        crate::state_handler::main_page::content::CapabilitiesPhase::Loading;
                    view.status_message = None;
                }
                match capability_sender(ctx.config, ctx.tdk, persona_id) {
                    Some((atm, profile, persona_did, mediator)) => {
                        spawn_capability_job(
                            ctx.dispatch_tx,
                            ctx.in_flight,
                            ctx.state,
                            capability_actions::CapabilityJob {
                                atm,
                                profile,
                                persona_did,
                                mediator,
                                vtc_did: vtc,
                                persona: persona_id,
                                verb: capability_actions::Verb::List,
                            },
                        );
                    }
                    None => capability_actions::send_unavailable(ctx.state),
                }
            }
        }
        Action::CapabilitiesToggleCommit => {
            let target = ctx
                .state
                .main_page
                .content_panel
                .capabilities
                .view
                .as_ref()
                .and_then(|v| {
                    let i = v.confirm_toggle?;
                    let item = v.items.get(i)?;
                    Some((
                        v.vtc_did.clone(),
                        v.persona,
                        item.slug.clone(),
                        item.version.clone(),
                        !item.enabled,
                    ))
                });
            if let Some((vtc, persona_id, slug, version, enable)) = target {
                if let Some(view) = ctx.state.main_page.content_panel.capabilities.view.as_mut() {
                    view.confirm_toggle = None;
                }
                // The signing key is read here, not in the job: it
                // comes from the TDK secrets resolver (in memory,
                // populated at startup), so it is not I/O — and
                // reading it here is what lets the job own a
                // `Secret` rather than borrow `Config`.
                let signed = match (
                    capability_sender(ctx.config, ctx.tdk, persona_id),
                    ctx.config.get_persona_keys_for(persona_id, ctx.tdk).await,
                ) {
                    (Some(sender), Ok(keys)) => Some((sender, keys)),
                    (_, Err(e)) => {
                        if let Some(view) =
                            ctx.state.main_page.content_panel.capabilities.view.as_mut()
                        {
                            view.status_message = Some(format!("couldn't sign the change: {e}"));
                        }
                        None
                    }
                    (None, _) => {
                        capability_actions::send_unavailable(ctx.state);
                        None
                    }
                };
                if let Some(((atm, profile, persona_did, mediator), keys)) = signed {
                    spawn_capability_job(
                        ctx.dispatch_tx,
                        ctx.in_flight,
                        ctx.state,
                        capability_actions::CapabilityJob {
                            atm,
                            profile,
                            persona_did,
                            mediator,
                            vtc_did: vtc,
                            persona: persona_id,
                            verb: capability_actions::Verb::Toggle {
                                slug,
                                version,
                                enable,
                                signing_secret: Box::new(keys.signing.secret.clone()),
                            },
                        },
                    );
                }
            }
        }
        Action::IssueMemberVmc(i) => {
            // Issue this membership's reciprocal VMC (member -> community)
            // and send it to the VTC over DIDComm (members/vmc/1.0).
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .filter(|c| c.status.is_active())
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona_id)) = target {
                // The grant we are acknowledging, as the community sent it.
                // Read here with the key, for the same reason: the job owns its
                // inputs rather than borrowing `Config`. Without a grant there
                // is nothing to acknowledge — an acknowledgement names one
                // specific grant by digest.
                let Some(grant) = ctx
                    .config
                    .account
                    .membership(&vtc, persona_id)
                    .and_then(|c| c.credentials.get(&openvtc_core::CredentialKind::Membership))
                    .cloned()
                else {
                    ctx.state.main_page.content_panel.communities.status_message = Some(
                        "This community hasn't issued you a membership credential yet — \
                         there is nothing to acknowledge."
                            .to_string(),
                    );
                    return Handled::Continue;
                };
                // The signing key is read here for the same reason as
                // the capability toggle: it comes from the in-memory
                // secrets resolver, not the network, and reading it
                // here lets the job own a `Secret` rather than borrow
                // `Config`.
                let ready = match (
                    capability_sender(ctx.config, ctx.tdk, persona_id),
                    ctx.config.get_persona_keys_for(persona_id, ctx.tdk).await,
                ) {
                    (Some(sender), Ok(keys)) => Some((sender, keys)),
                    (_, Err(e)) => {
                        ctx.state.main_page.content_panel.communities.status_message =
                            Some(format!("Couldn't sign the membership credential: {e}"));
                        None
                    }
                    (None, _) => {
                        ctx.state.main_page.content_panel.communities.status_message =
                            Some("Messaging unavailable — cannot issue right now.".to_string());
                        None
                    }
                };
                if let Some(((atm, profile, member_did, mediator), keys)) = ready {
                    spawn_community_job(
                        ctx.dispatch_tx,
                        ctx.in_flight,
                        ctx.state,
                        community_actions::CommunityJob {
                            atm,
                            profile,
                            member_did,
                            mediator,
                            vtc_did: vtc,
                            persona: persona_id,
                            verb: community_actions::Verb::IssueVmc {
                                signing_secret: Box::new(keys.signing.secret.clone()),
                                grant: Box::new(grant),
                            },
                        },
                    );
                }
            }
        }
        Action::RequestPersonhoodChallenge(i) => {
            // Ask the community for the nonce an assertion must carry. No key
            // is needed yet — nothing is signed until the challenge comes back.
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .filter(|c| c.status.is_active())
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona_id)) = target {
                match capability_sender(ctx.config, ctx.tdk, persona_id) {
                    Some((atm, profile, member_did, mediator)) => spawn_community_job(
                        ctx.dispatch_tx,
                        ctx.in_flight,
                        ctx.state,
                        community_actions::CommunityJob {
                            atm,
                            profile,
                            member_did,
                            mediator,
                            vtc_did: vtc,
                            persona: persona_id,
                            verb: community_actions::Verb::RequestPersonhoodChallenge,
                        },
                    ),
                    None => {
                        ctx.state.main_page.content_panel.communities.status_message = Some(
                            "Messaging unavailable — cannot ask for a challenge right now."
                                .to_string(),
                        );
                    }
                }
            }
        }
        Action::AssertPersonhood => {
            // The challenge names its own membership, so the target comes from
            // the challenge rather than from whichever row is highlighted.
            let challenge = ctx
                .state
                .main_page
                .content_panel
                .communities
                .personhood_challenge
                .clone();
            let Some(challenge) = challenge else {
                ctx.state.main_page.content_panel.communities.status_message =
                    Some("No personhood challenge in hand — ask for one first.".to_string());
                return Handled::Continue;
            };
            if !challenge.is_live(chrono::Utc::now()) {
                // Drop it rather than send: the community would refuse it, and
                // leaving a dead challenge on screen invites a second attempt
                // that fails the same way.
                ctx.state
                    .main_page
                    .content_panel
                    .communities
                    .personhood_challenge = None;
                ctx.state.main_page.content_panel.communities.status_message =
                    Some("That personhood challenge expired — ask for a fresh one.".to_string());
                return Handled::Continue;
            }

            // Present the credentials this community itself issued to this
            // membership and let its policy choose among them. A client-side
            // filter would have to guess at a policy it cannot read, and
            // guessing wrong means withholding the very credential that would
            // have satisfied it — the identity-verification endorsement an
            // administrator issued after vetting the member in person.
            //
            // Scoped to this membership rather than the whole wallet: another
            // community's credentials are not evidence here, and sending them
            // would disclose one community's membership to another.
            let credentials: Vec<serde_json::Value> = ctx
                .config
                .account
                .membership(&challenge.vtc_did, challenge.persona)
                .map(|m| m.credentials.values().cloned().collect())
                .unwrap_or_default();

            match (
                capability_sender(ctx.config, ctx.tdk, challenge.persona),
                ctx.config
                    .get_persona_keys_for(challenge.persona, ctx.tdk)
                    .await,
            ) {
                (Some((atm, profile, member_did, mediator)), Ok(keys)) => spawn_community_job(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    community_actions::CommunityJob {
                        atm,
                        profile,
                        member_did,
                        mediator,
                        vtc_did: challenge.vtc_did.clone(),
                        persona: challenge.persona,
                        verb: community_actions::Verb::AssertPersonhood {
                            signing_secret: Box::new(keys.signing.secret.clone()),
                            challenge_id: challenge.challenge_id,
                            credentials,
                        },
                    },
                ),
                (_, Err(e)) => {
                    ctx.state.main_page.content_panel.communities.status_message =
                        Some(format!("Couldn't sign the personhood presentation: {e}"));
                }
                (None, _) => {
                    ctx.state.main_page.content_panel.communities.status_message =
                        Some("Messaging unavailable — cannot assert right now.".to_string());
                }
            }
        }
        Action::WithdrawJoin(i) => {
            // Cancel a Pending join: best-effort notify the VTC, set
            // the record `Withdrawn`, and tear down its now-dead
            // session (R-S-3) so it can be deleted or re-joined.
            ctx.state
                .main_page
                .content_panel
                .communities
                .confirm_withdraw = None;
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .filter(|c| {
                    matches!(
                        c.status,
                        openvtc_core::config::account::CommunityStatus::Pending { .. }
                    )
                })
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona)) = target {
                // Best-effort VTC notification. The applicant-side
                // withdraw DIDComm message does not exist in vta-sdk
                // yet (only the `withdrawn` *status* the VTC reports),
                // so there is nothing to send. The cancel is otherwise
                // fully local; the request will also lapse to the VTC's
                // own timeout. TODO(VTI): once vta-sdk gains a
                // `join-requests/withdraw/1.0` message, send it here.
                debug!(
                    vtc = %vtc,
                    "cancel pending join: VTC notify pending protocol support (vta-sdk withdraw message)"
                );
                if ctx
                    .config
                    .account
                    .membership_mut(&vtc, persona)
                    .is_some_and(|c| c.withdraw())
                {
                    ctx.save.mark_dirty();
                    deregister_inactive_community(
                        ctx.session_manager,
                        ctx.didcomm_service,
                        ctx.config,
                        ctx.state,
                        &vtc,
                        persona,
                    )
                    .await;
                    ctx.state.main_page.sync_from_config(ctx.config);
                    ctx.state.main_page.content_panel.communities.status_message =
                        Some("Join cancelled — request withdrawn.".to_string());
                }
            }
        }
        Action::ArchiveCommunity(i) => {
            // R-C-8: archive an inactive community (hide it, retain the
            // record). Guarded inactive-only by `archive_community`.
            let target = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .get(i)
                .map(|c| (c.vtc_did.clone(), c.persona_ref));
            if let Some((vtc, persona)) = target {
                match ctx.config.account.archive_membership(&vtc, persona) {
                    Ok(()) => {
                        ctx.save.mark_dirty();
                        ctx.state.main_page.sync_from_config(ctx.config);
                        ctx.state.main_page.content_panel.communities.status_message =
                            Some("Community archived.".to_string());
                    }
                    Err(e) => {
                        ctx.state.main_page.content_panel.communities.status_message =
                            Some(format!("Couldn't archive: {e}"));
                    }
                }
            }
        }
        Action::ToggleShowArchived => {
            // R-C-8: flip archived visibility and rebuild the list so
            // archived records stay discoverable.
            let comms = &mut ctx.state.main_page.content_panel.communities;
            comms.show_archived = !comms.show_archived;
            ctx.state.main_page.sync_from_config(ctx.config);
        }
        Action::OpenCommunitySwitcher => {
            // R-C-7: list the Active communities (the only switchable
            // ones) in display order and preselect the current one.
            let current = ctx.state.selected_community.clone();
            let items: Vec<_> = ctx
                .config
                .account
                .communities_for_display(
                    ctx.state.main_page.content_panel.communities.show_archived,
                )
                .into_iter()
                .filter(|c| c.status.is_active())
                .map(|c| {
                    // Same precedence as the communities panel:
                    // user label, then verified agent name, then
                    // the truncated DID.
                    let persona = ctx.config.account.personas.get(&c.persona_ref);
                    let persona_label = persona
                        .and_then(|p| p.label.clone())
                        .or_else(|| {
                            persona
                                .and_then(|p| ctx.config.agent_name_for(&p.did).map(str::to_owned))
                        })
                        .unwrap_or_default();
                    main_page::content::SwitcherItem {
                        vtc_did: c.vtc_did.clone(),
                        persona_ref: c.persona_ref,
                        display_name: c
                            .display_name
                            .clone()
                            .or_else(|| ctx.config.agent_name_for(&c.vtc_did).map(str::to_owned))
                            .unwrap_or_else(|| main_page::shorten_did(&c.vtc_did, 40)),
                        persona_label,
                        is_current: current.as_ref() == Some(&(c.vtc_did.clone(), c.persona_ref)),
                    }
                })
                .collect();
            // Don't pop an empty overlay when there's nothing to switch.
            if !items.is_empty() {
                let selected = items.iter().position(|it| it.is_current).unwrap_or(0);
                ctx.state.main_page.switcher =
                    Some(main_page::content::CommunitySwitcherState { items, selected });
            }
        }
        Action::CommunitySwitcherSelect => {
            // Switch the working context to the highlighted Active
            // community, then close the overlay (R-C-6 / R-C-7).
            let target = ctx.state.main_page.switcher.as_ref().and_then(|sw| {
                sw.items
                    .get(sw.selected)
                    .map(|it| (it.vtc_did.clone(), it.persona_ref))
            });
            if let Some((vtc, persona)) = target
                && ctx
                    .config
                    .account
                    .membership(&vtc, persona)
                    .is_some_and(|c| c.status.is_active())
            {
                ctx.state.selected_community = Some((vtc, persona));
                ctx.config.set_active_persona(Some(persona));
                ctx.state.main_page.sync_from_config(ctx.config);
            }
            ctx.state.main_page.switcher = None;
        }
        Action::DeleteDid(i) => {
            // Identity deletion does a VTA `delete_did_webvh` + listener
            // teardown (R14): claim the Did domain, run the guards +
            // extraction on-thread, then spawn the I/O; local ctx.config
            // cleanup + ctx.save apply on the outcome. Guard failures (DID
            // bound to a community, not found) are surfaced inline and
            // spawn nothing.
            let domain = background_dispatch::DispatchDomain::Did;
            if !ctx.in_flight.try_begin(domain) {
                let msg = background_dispatch::InFlight::busy_message(domain);
                ctx.state.main_page.log(msg);
            } else if let Some(job) = prepare_delete_context_did(
                ctx.state,
                ctx.config,
                ctx.admin_vta,
                ctx.didcomm_service,
                i,
            ) {
                background_dispatch::spawn_dispatch(ctx.dispatch_tx.clone(), domain, async move {
                    background_dispatch::DispatchOutcome::Did(job.run().await)
                });
            } else {
                // Guard rejected the delete (logged inline); release.
                ctx.in_flight.finish(domain);
            }
        }
        Action::CreatePersonaSubmit => {
            // Mint a standalone persona DID using the always-on admin
            // VTA session; the overlay shows progress and, on success,
            // the new DID (copied to the clipboard). The mint runs off
            // this loop and streams its steps back as progress.
            spawn_persona_mint(
                ctx.dispatch_tx,
                ctx.in_flight,
                ctx.state,
                ctx.config,
                ctx.tdk,
                ctx.admin_vta,
            );
        }
        Action::StartAgentNameManager(index) => {
            if let Some(did) = open_agent_name_overlay(ctx.state, index) {
                spawn_agent_name_job(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.admin_vta,
                    did,
                    agent_name_actions::Verb::Open,
                );
            }
        }
        Action::AgentNameManagerClaim => {
            if let Some((did, name)) = agent_name_to_claim(ctx.state) {
                spawn_agent_name_job(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.admin_vta,
                    did,
                    agent_name_actions::Verb::Claim(name),
                );
            }
        }
        Action::AgentNameManagerToggle => {
            if let Some((did, name, enabled)) = selected_agent_name(ctx.state) {
                let verb = if enabled {
                    agent_name_actions::Verb::Park(name)
                } else {
                    agent_name_actions::Verb::Resume(name)
                };
                spawn_agent_name_job(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.admin_vta,
                    did,
                    verb,
                );
            }
        }
        Action::AgentNameManagerRemove => {
            if let Some((did, name, _)) = selected_agent_name(ctx.state) {
                spawn_agent_name_job(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.admin_vta,
                    did,
                    agent_name_actions::Verb::Remove(name),
                );
            }
        }
        Action::Persona(persona_action) => {
            // The pane's own reducer decides what changed and what it still
            // owes the agent; the loop only spawns what it names.
            let effect = persona_actions::apply(ctx.state, &persona_action);
            spawn_persona_effect(
                ctx.dispatch_tx,
                ctx.in_flight,
                ctx.state,
                ctx.admin_vta,
                effect,
            );
        }
        Action::VicRefresh => {
            // Off the loop: this is Tab into the VIC list, and the
            // focus change queued behind it must not wait on a vault
            // round-trip.
            spawn_vic_refresh(ctx.dispatch_tx, ctx.in_flight, ctx.state, ctx.admin_vta);
        }
        Action::VicToggleInactive => {
            ctx.state.main_page.content_panel.vta.vic_show_inactive =
                !ctx.state.main_page.content_panel.vta.vic_show_inactive;
            spawn_vic_refresh(ctx.dispatch_tx, ctx.in_flight, ctx.state, ctx.admin_vta);
        }
        Action::AddVicSubmit => {
            if let Some(vic) = vic_to_import(ctx.state) {
                spawn_vic_mutation(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.admin_vta,
                    vic::VicVerb::Add(vic),
                );
            }
        }
        Action::VicArchive(i)
        | Action::VicUnarchive(i)
        | Action::VicRestore(i)
        | Action::DeleteVic(i)
        | Action::PurgeVic(i) => {
            if let Some(verb) = vic_lifecycle_verb(ctx.state, &action, i) {
                spawn_vic_mutation(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.admin_vta,
                    verb,
                );
            }
        }
        Action::CreatePersonaCopy => {
            if let Some(did) = ctx
                .state
                .main_page
                .create_persona
                .as_ref()
                .and_then(|o| o.did.clone())
            {
                let copied = crate::clipboard::copy_to_clipboard(&did).is_ok();
                if let Some(overlay) = ctx.state.main_page.create_persona.as_mut() {
                    overlay.copied = copied;
                }
                let _ = ctx.state_tx.send(ctx.state.clone());
            }
        }
        Action::Inbox(ia) => {
            // Network inbox actions (accept/reject relationship or VRC
            // request) run off the loop (R14): claim the Inbox domain,
            // do the loop-thread pre-send work, then spawn the send;
            // the outcome arm applies the post-send mutation. A second
            // inbox network action while one is in flight is rejected
            // with a status. Local actions run inline as before.
            if inbox_actions::is_network(&ia) {
                let domain = background_dispatch::DispatchDomain::Inbox;
                if !ctx.in_flight.try_begin(domain) {
                    let msg = background_dispatch::InFlight::busy_message(domain);
                    ctx.state.main_page.content_panel.inbox.status_message = Some(msg.clone());
                    ctx.state.main_page.log(msg);
                } else {
                    match inbox_actions::dispatch(
                        ia,
                        ctx.config,
                        ctx.tdk,
                        ctx.didcomm_service,
                        ctx.state,
                        ctx.save,
                        ctx.admin_vta,
                    )
                    .await
                    {
                        inbox_actions::InboxDispatch::Spawn(job) => {
                            background_dispatch::spawn_dispatch(
                                ctx.dispatch_tx.clone(),
                                domain,
                                async move {
                                    background_dispatch::DispatchOutcome::Inbox(job.run().await)
                                },
                            );
                        }
                        // Pre-send failure recorded a status; nothing
                        // was spawned, so release the domain now.
                        inbox_actions::InboxDispatch::Handled => {
                            ctx.in_flight.finish(domain);
                        }
                    }
                }
            } else {
                let _ = inbox_actions::dispatch(
                    ia,
                    ctx.config,
                    ctx.tdk,
                    ctx.didcomm_service,
                    ctx.state,
                    ctx.save,
                    ctx.admin_vta,
                )
                .await;
            }
        }
        Action::Relationship(ra) => {
            // Network relationship actions (create/ping/remove/request
            // VRC) run off the loop (R14). Same pattern as Inbox: claim
            // the Relationship domain, prepare on-thread, spawn the I/O,
            // apply the outcome later. `is_ping` stamps `ping_sent_at`
            // for pong-latency display.
            if relationship_actions::is_network(&ra) {
                let domain = background_dispatch::DispatchDomain::Relationship;
                if !ctx.in_flight.try_begin(domain) {
                    let msg = background_dispatch::InFlight::busy_message(domain);
                    ctx.state
                        .main_page
                        .content_panel
                        .relationships
                        .status_message = Some(msg.clone());
                    ctx.state.main_page.log(msg);
                } else {
                    match relationship_actions::dispatch(
                        ra,
                        ctx.config,
                        ctx.tdk,
                        ctx.didcomm_service,
                        ctx.state,
                        ctx.save,
                        ctx.admin_vta,
                    )
                    .await
                    {
                        relationship_actions::RelationshipDispatch::Spawn { job, is_ping } => {
                            if is_ping {
                                *ctx.ping_sent_at = Some(std::time::Instant::now());
                            }
                            background_dispatch::spawn_dispatch(
                                ctx.dispatch_tx.clone(),
                                domain,
                                async move {
                                    background_dispatch::DispatchOutcome::Relationship(
                                        job.run().await,
                                    )
                                },
                            );
                        }
                        relationship_actions::RelationshipDispatch::Handled => {
                            ctx.in_flight.finish(domain);
                        }
                    }
                }
            } else {
                let _ = relationship_actions::dispatch(
                    ra,
                    ctx.config,
                    ctx.tdk,
                    ctx.didcomm_service,
                    ctx.state,
                    ctx.save,
                    ctx.admin_vta,
                )
                .await;
            }
        }
        Action::Credential(ca) => {
            // One of the twelve credential actions goes to the
            // network — requesting a VRC from a peer — so it is
            // resolved here and dispatched. The other eleven are
            // ctx.state or ctx.config, and the dispatcher handles them
            // inline as before.
            if let actions::CredentialAction::SubmitRequest {
                relationship_p_did,
                reason,
            } = &ca
            {
                let domain = background_dispatch::DispatchDomain::Credential;
                if !ctx.in_flight.try_begin(domain) {
                    ctx.state.main_page.content_panel.credentials.status_message =
                        Some(background_dispatch::InFlight::busy_message(domain));
                } else if let Some(job) = credential_actions::prepare_vrc_request(
                    ctx.config,
                    ctx.didcomm_service,
                    relationship_p_did,
                    reason.as_deref(),
                ) {
                    background_dispatch::spawn_dispatch(
                        ctx.dispatch_tx.clone(),
                        domain,
                        async move { background_dispatch::DispatchOutcome::Credential(job.run().await) },
                    );
                } else {
                    ctx.in_flight.finish(domain);
                    ctx.state.main_page.content_panel.credentials.status_message =
                        Some("That relationship is no longer available.".to_string());
                }
            } else {
                credential_actions::dispatch(ca, ctx.config, ctx.state, ctx.save);
            }
        }
        Action::Vetting(va) => vetting_actions::dispatch(ctx, va).await,
        Action::Settings(sa) => {
            match settings_actions::dispatch(
                sa,
                ctx.config,
                ctx.state,
                ctx.state_tx,
                ctx.save,
                ctx.profile,
            )
            .await
            {
                settings_actions::SettingsOutcome::Continue => {}
                settings_actions::SettingsOutcome::ExitUserInt => {
                    return Handled::ExitUserInt;
                }
                settings_actions::SettingsOutcome::ReconnectMediator => {
                    // R13 proving case: the up-to-30s mediator
                    // reconnect ran inline here before, freezing the
                    // UI (queued keys, dropped inbound events, dead
                    // `q`). Now it runs as a background task and the
                    // loop stays live.
                    //
                    // The busy-guard rejects a second reconnect while
                    // one is in flight (matching the old effectively
                    // serialised behaviour) with a visible status.
                    if !ctx
                        .in_flight
                        .try_begin(background_dispatch::DispatchDomain::Mediator)
                    {
                        let msg = background_dispatch::InFlight::busy_message(
                            background_dispatch::DispatchDomain::Mediator,
                        );
                        ctx.state.connection.status = state::MediatorStatus::Connecting;
                        ctx.state.main_page.log(msg);
                    } else {
                        // Build the new listener ctx.config on the loop
                        // thread (cheap, local: reads secrets from the
                        // TDK resolver, no network), then hand only the
                        // slow connect I/O to a background task.
                        let listener_id = didcomm::persona_listener_id(ctx.config.persona_did());
                        let new_listener_config =
                            didcomm::persona_listener_config(ctx.config, ctx.tdk).await;
                        let service = ctx.didcomm_service.clone();
                        background_dispatch::spawn_dispatch(
                            ctx.dispatch_tx.clone(),
                            background_dispatch::DispatchDomain::Mediator,
                            async move {
                                let outcome = didcomm::reconnect_persona_listener_io(
                                    &service,
                                    listener_id,
                                    new_listener_config,
                                )
                                .await;
                                background_dispatch::DispatchOutcome::MediatorReconnect(outcome)
                            },
                        );
                    }
                }
            }
        }
        // ---- Listed so this match stays EXHAUSTIVE; no `_` arm ----
        //
        // The mirror of the degraded loop's listing. A silent
        // catch-all here would hide the same class of defect in the
        // other direction: an action wired into State A, or sent by
        // a screen, that this loop never services.

        // Serviced by `handle_nav_action` in the guard arm above.
        Action::MainMenuSelected(..)
        | Action::MainPanelSwitch(..)
        | Action::DismissLoading
        | Action::CapabilitiesClose
        | Action::CapabilitiesUp
        | Action::CapabilitiesDown
        | Action::CapabilitiesDetail
        | Action::CapabilitiesToggleArm
        | Action::CapabilitiesToggleCancel
        | Action::CommunitySelect(..)
        | Action::CommunityConfirmDelete(..)
        | Action::CommunityCancelDelete
        | Action::CommunityConfirmLeave(..)
        | Action::CommunityCancelLeave
        | Action::CommunityConfirmWithdraw(..)
        | Action::CommunityCancelWithdraw
        | Action::CommunitySwitcherMove(..)
        | Action::CloseCommunitySwitcher
        | Action::DidSelect(..)
        | Action::DidConfirmDelete(..)
        | Action::DidCancelDelete
        | Action::StartCreatePersona
        | Action::CreatePersonaInput(..)
        | Action::CreatePersonaClose
        | Action::AgentNameManagerInput(..)
        | Action::AgentNameManagerSelect(..)
        | Action::AgentNameManagerConfirmRemove
        | Action::AgentNameManagerCancelRemove
        | Action::AgentNameManagerClose
        | Action::VicSelect(..)
        | Action::VicConfirmDelete(..)
        | Action::VicCancelDelete
        | Action::VicConfirmPurge(..)
        | Action::VicCancelPurge
        | Action::StartAddVic
        | Action::AddVicInput(..)
        | Action::AddVicPaste(..)
        | Action::AddVicClose => {}

        // Owned by the join-flow and setup-wizard sub-loops.
        Action::ActivateMainMenu
        | Action::JoinSubmitVtc(..)
        | Action::JoinIdentitySelect(..)
        | Action::JoinIdentityChoose
        | Action::JoinReuseConfirm
        | Action::JoinReuseCancel
        | Action::JoinInvitationSelect(..)
        | Action::JoinInvitationChoose
        | Action::JoinContextSelect(..)
        | Action::JoinContextSlug(..)
        | Action::JoinContextChoose
        | Action::JoinCancel
        | Action::JoinPasteVic(..)
        | Action::JoinPasteFromClipboard
        | Action::JoinClearVic
        | Action::ImportConfig(..)
        | Action::SetProtection(..)
        | Action::VtaSubmitDid(..)
        | Action::VtaStartProvision(..)
        | Action::RecoverPlanContext
        | Action::SetupCompleted(..) => {}
        #[cfg(feature = "openpgp-card")]
        Action::GetTokens
        | Action::SetAdminPin(..)
        | Action::SetTouchPolicy(..)
        | Action::SetTokenName(..)
        | Action::FactoryReset(..)
        | Action::TokenWriteKeys(..) => {}

        // Owned by the loop: `Exit` and `UXError` signal the terminator and
        // break with its outcome type, and `StartJoin` drives the join flow's
        // own action loop using the receiver this one selects on. Listed so the
        // match stays exhaustive — the guarantee is that a NEW variant cannot be
        // added without a decision here, and these three already have one.
        Action::Exit | Action::UXError(..) | Action::StartJoin => {
            debug_assert!(false, "handled by the loop, not the handler");
        }
    }
    Handled::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::{test_config, test_tdk};
    use crate::state_handler::main_page::content::ManagedDid;
    use tokio::sync::mpsc;

    /// Everything the handler needs, owned by the test so it can be borrowed
    /// into an `ActionCtx` per call.
    struct Harness {
        state: State,
        config: Box<Config>,
        save: SaveScheduler,
        in_flight: InFlight,
        dispatch_tx: mpsc::UnboundedSender<DispatchOutcome>,
        dispatch_rx: mpsc::UnboundedReceiver<DispatchOutcome>,
        tdk: TDK,
        admin_vta: Option<vta_sdk::client::VtaClient>,
        didcomm_service: Messaging,
        session_manager: SessionManager,
        ping_sent_at: Option<std::time::Instant>,
        state_tx: watch::Sender<State>,
    }

    impl Harness {
        /// `with_session` decides whether the account has a live admin VTA
        /// session. The client points at an address nothing is listening on:
        /// these tests assert what the handler *dispatches*, not what a VTA
        /// answers, and a job that fails against a dead URL asserts the same
        /// thing as one that succeeds.
        async fn new(with_session: bool) -> Self {
            let (dispatch_tx, dispatch_rx) = mpsc::unbounded_channel();
            let (state_tx, _state_rx) = watch::channel(State::default());
            let (event_tx, _event_rx) = mpsc::unbounded_channel();
            Self {
                state: State::default(),
                config: Box::new(test_config()),
                save: SaveScheduler::new("test"),
                in_flight: InFlight::default(),
                dispatch_tx,
                dispatch_rx,
                tdk: test_tdk().await,
                admin_vta: with_session
                    .then(|| vta_sdk::client::VtaClient::new("http://127.0.0.1:1")),
                didcomm_service: openvtc_core::didcomm::start_empty_service(
                    event_tx,
                    tokio_util::sync::CancellationToken::new(),
                ),
                session_manager: SessionManager::default(),
                ping_sent_at: None,
                state_tx,
            }
        }

        async fn handle(&mut self, action: Action) -> Handled {
            let mut ctx = ActionCtx {
                state: &mut self.state,
                config: &mut self.config,
                save: &mut self.save,
                in_flight: &mut self.in_flight,
                dispatch_tx: &self.dispatch_tx,
                tdk: &self.tdk,
                admin_vta: self.admin_vta.as_ref(),
                didcomm_service: &self.didcomm_service,
                session_manager: &mut self.session_manager,
                ping_sent_at: &mut self.ping_sent_at,
                state_tx: &self.state_tx,
                profile: "test",
            };
            handle_action(&mut ctx, action).await
        }

        fn with_persona(&mut self) {
            self.state.main_page.content_panel.identity.personas = vec![ManagedDid {
                did: "did:webvh:QmScidPersona:example.com:alice".into(),
                agent_name: None,
                label: "Alice".into(),
                bound_communities: 0,
                is_active: true,
            }]
            .into();
        }
    }

    /// `g` on a selected persona must actually dispatch.
    ///
    /// This is the test that did not exist when three surfaces were found to be
    /// silently dropping actions (#235). It asserts the property that was
    /// violated: the action claimed its domain, so something is running — not
    /// that a VTA answered.
    #[tokio::test]
    async fn opening_the_agent_name_manager_dispatches() {
        let mut h = Harness::new(true).await;
        h.with_persona();

        h.handle(Action::StartAgentNameManager(0)).await;

        assert!(
            h.in_flight
                .is_busy(background_dispatch::DispatchDomain::AgentNameManage),
            "the verb must be in flight, not silently dropped"
        );
        assert!(
            h.state.main_page.agent_names.is_some(),
            "the overlay opened"
        );
    }

    /// The same key with nothing selected says so instead of doing nothing.
    #[tokio::test]
    async fn opening_it_with_no_persona_explains_itself() {
        let mut h = Harness::new(true).await;

        h.handle(Action::StartAgentNameManager(0)).await;

        assert!(
            !h.in_flight
                .is_busy(background_dispatch::DispatchDomain::AgentNameManage),
            "nothing to act on, so nothing dispatched"
        );
        assert!(
            h.state
                .main_page
                .activity_log
                .iter()
                .any(|e| e.summary.contains("No persona selected")),
            "a key that does nothing must say why"
        );
    }

    /// Without an admin session the overlay reports it rather than spinning on
    /// a query that was never sent.
    #[tokio::test]
    async fn opening_it_without_a_session_reports_that() {
        let mut h = Harness::new(false).await;
        h.with_persona();

        h.handle(Action::StartAgentNameManager(0)).await;

        let overlay = h.state.main_page.agent_names.as_ref().expect("overlay");
        assert!(
            overlay
                .message
                .as_deref()
                .is_some_and(|m| m.contains("VTA session unavailable")),
            "{:?}",
            overlay.message
        );
        assert!(
            !h.in_flight
                .is_busy(background_dispatch::DispatchDomain::AgentNameManage)
        );
    }

    /// A second verb while one is in flight is refused with a message, not
    /// queued blind and not silently dropped.
    #[tokio::test]
    async fn a_second_verb_while_one_runs_is_refused_out_loud() {
        let mut h = Harness::new(true).await;
        h.with_persona();

        h.handle(Action::StartAgentNameManager(0)).await;
        // Whatever the first one did to the overlay, clear the status so the
        // assertion below cannot pass on a leftover.
        if let Some(o) = h.state.main_page.agent_names.as_mut() {
            o.message = None;
        }
        h.handle(Action::StartAgentNameManager(0)).await;

        let overlay = h.state.main_page.agent_names.as_ref().expect("overlay");
        assert!(
            overlay
                .message
                .as_deref()
                .is_some_and(|m| m.contains("already in progress")),
            "{:?}",
            overlay.message
        );
    }

    /// Tab into the VIC list with no session must not leave the panel claiming
    /// a query is running.
    #[tokio::test]
    async fn refreshing_vics_without_a_session_clears_the_loading_flag() {
        let mut h = Harness::new(false).await;
        h.state.main_page.content_panel.vta.vic_loading = true;

        h.handle(Action::VicRefresh).await;

        assert!(!h.state.main_page.content_panel.vta.vic_loading);
        assert!(
            !h.in_flight
                .is_busy(background_dispatch::DispatchDomain::Vic)
        );
    }

    /// …and with one, it dispatches.
    #[tokio::test]
    async fn refreshing_vics_dispatches() {
        let mut h = Harness::new(true).await;

        h.handle(Action::VicRefresh).await;

        assert!(
            h.in_flight
                .is_busy(background_dispatch::DispatchDomain::Vic)
        );
        assert!(h.state.main_page.content_panel.vta.vic_loading);
    }

    /// Pure navigation still routes through the shared reducer from here.
    #[tokio::test]
    async fn navigation_still_goes_through_the_shared_reducer() {
        let mut h = Harness::new(false).await;

        h.handle(Action::DismissLoading).await;

        assert!(matches!(h.state.active_page, state::ActivePage::Main));
    }

    /// The handler never breaks the loop itself; a wipe confirmation is
    /// reported so the loop can terminate. Ordinary actions report `Continue`.
    #[tokio::test]
    async fn an_ordinary_action_continues() {
        let mut h = Harness::new(false).await;
        assert!(matches!(
            h.handle(Action::VicToggleInactive).await,
            Handled::Continue
        ));
    }

    /// Nothing is dispatched without being claimed: a domain that is busy has a
    /// job behind it, so the channel is the audit trail.
    #[tokio::test]
    async fn a_claimed_domain_has_a_job_behind_it() {
        let mut h = Harness::new(true).await;
        h.handle(Action::VicRefresh).await;

        assert!(
            h.in_flight
                .is_busy(background_dispatch::DispatchDomain::Vic)
        );
        // The job runs against a dead address, so it completes with an error —
        // what matters is that an outcome arrives at all, which is what proves
        // the spawn happened rather than the arm returning quietly.
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(30), h.dispatch_rx.recv()).await;
        assert!(outcome.is_ok(), "a spawned job must deliver an outcome");
    }
}
