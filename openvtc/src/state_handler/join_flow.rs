//! State-B "join a community" orchestration (R-A-5 Stage 4).
//!
//! [`StateHandler::join_flow`] is a nested `tokio::select!` loop modelled on
//! [`setup_wizard`](crate::state_handler::setup_wizard): it owns the screen
//! while [`ActivePage::Join`] is
//! active, processes the join actions, renders via `state_tx`, and returns to
//! the main page when the user cancels or the sequence finishes.
//!
//! The actual work runs in [`run_join_sequence`]: mint a fresh persona (reusing
//! the setup VTA helpers), derive + register the per-community sub-context,
//! submit the join, and persist a `Pending` [`CommunityRecord`]. Every failure
//! is surfaced into the join log as a [`MessageType::Error`] — the loop never
//! `?`-bubbles a sequence error in a way that would kill the app.

use std::time::Duration;

use affinidi_tdk::TDK;
use anyhow::Result;
use chrono::Utc;
use openvtc_core::config::{
    Config,
    account::{CommunityRecord, PersonaId, VtcDid},
    context_path::build_sub_context_id,
};
use openvtc_core::didcomm::Messaging;
use openvtc_core::logs::LogFamily;
use tokio::sync::{broadcast, mpsc::UnboundedReceiver};
use tracing::debug;
use vta_sdk::{client::VtaClient, protocols::did_management::create::WebvhPathMode};

use crate::{
    Interrupted,
    state_handler::{
        StateHandler,
        actions::Action,
        join::{AvailableVic, JoinPage, JoinState, PersonaOption, PresentedInvitation},
        main_page::content::{VicLifecycle, VicSummary},
        main_page::{sanitize_display, shorten_did},
        setup_sequence::{Completion, MessageType, config::ConfigExtension, vta},
        state::{ActivePage, State},
    },
};

/// Which identity to present to the community being joined (R-B-3 / D1).
#[derive(Clone, Debug)]
enum JoinIdentityChoice {
    /// Mint a fresh, self-contained `did:webvh` persona (D6).
    Mint,
    /// Reuse an existing account persona (links the user across communities).
    Reuse(PersonaId),
}

/// The persona + community of a just-completed join, handed back to the runtime
/// loop so it can bring a live session up immediately (R-B-5 / D11) rather than
/// only on the next launch.
pub(crate) struct JoinedSession {
    pub persona_id: PersonaId,
    pub persona_did: String,
    pub vtc_did: VtcDid,
}

/// Extract the [`JoinedSession`] from a finished join's state — `Some` only when
/// the sequence persisted a community (i.e. the join succeeded).
fn joined_session(js: &JoinState) -> Option<JoinedSession> {
    let record = js.created_community.as_ref()?;
    Some(JoinedSession {
        persona_id: record.persona_ref,
        persona_did: js.created_persona_did.clone().unwrap_or_default(),
        vtc_did: record.vtc_did.clone(),
    })
}

impl StateHandler {
    /// Run the join flow until the user cancels or the sequence finishes.
    ///
    /// Mirrors `setup_wizard`'s loop shape. `admin_vta` is the always-on admin
    /// VTA session (threaded in from the caller); `config` is mutated in place
    /// and persisted by the sequence on success.
    ///
    /// `messaging` is the live DIDComm service when there is one, so the
    /// sequence can bring the applicant persona's mediator socket up *before*
    /// it submits (see [`start_persona_listener`]). The State-A degraded loop has
    /// no service and passes `None`; the join still works there, it just cannot
    /// receive the community's reply until the process restarts into the full
    /// pipeline — which is what that path does anyway.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn join_flow(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
        tdk: &TDK,
        config: &mut Config,
        admin_vta: Option<&VtaClient>,
        profile: &str,
        messaging: Option<&Messaging>,
    ) -> Result<JoinExit> {
        // Enter the flow on a fresh EnterDid page.
        state.join.reset();
        // Surface the launch-supplied invitation on the entry page (reset clears
        // the transient join sub-state, so mirror the flag back in afterwards).
        state.join.has_invitation = state.invitation_credential.is_some();
        state.active_page = ActivePage::Join;
        let _ = self.state_tx.send(state.clone());

        loop {
            tokio::select! {
                maybe_action = action_rx.recv() => {
                    let Some(action) = maybe_action else {
                        // Channel closed — treat as a user-initiated exit.
                        return Ok(JoinExit::Exit(Interrupted::UserInt));
                    };
                    match action {
                        Action::Exit => return Ok(JoinExit::Exit(Interrupted::UserInt)),
                        Action::UXError(interrupted) => {
                            return Ok(JoinExit::Exit(interrupted));
                        }
                        Action::JoinCancel => {
                            // Leave the flow; the caller restores the main page.
                            // Hand back the joined session (if any) so the runtime
                            // loop can bring its live session up (R-B-5).
                            state.active_page = ActivePage::Main;
                            return Ok(JoinExit::Returned(joined_session(&state.join)));
                        }
                        Action::JoinPasteVic(text) => {
                            // #3: a pasted invitation credential — validate it is a
                            // VIC and stash it so the join presents it (mirrors the
                            // `--invitation <file>` launch flag). On the entry page
                            // the community isn't chosen yet, so only the credential
                            // shape is checked; on the invitation step it is, so the
                            // paste is also matched against it.
                            let vtc = if state.join.page == JoinPage::InvitationChoice {
                                state.join.pending_vtc.clone()
                            } else {
                                None
                            };
                            state.join.messages.clear();
                            load_pasted_vic(state, &text, vtc.as_deref());
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinPasteFromClipboard => {
                            // The `[Ctrl+V]` affordance on the entry page: same
                            // validation as a bracketed paste, just sourced from
                            // the OS clipboard. Kept to the entry page, where the
                            // community is not yet chosen, so no match is done.
                            state.join.messages.clear();
                            match crate::clipboard::read_clipboard() {
                                Ok(text) => load_pasted_vic(state, &text, None),
                                Err(why) => {
                                    state.join.messages.push(MessageType::Error(format!(
                                        "Could not read the clipboard ({why}). Paste the \
                                         invitation JSON directly into this screen instead \
                                         — that works over SSH, where reading the \
                                         clipboard cannot."
                                    )));
                                }
                            }
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinClearVic => {
                            // Explicit "proceed without a VIC": drop the loaded
                            // invitation so it isn't presented, and flag the clear so
                            // the entry page shows "joining without an invitation".
                            state.invitation_credential = None;
                            state.join.has_invitation = false;
                            state.join.invitation_issuer = None;
                            state.join.vic_cleared = true;
                            state.join.messages.clear();
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinSubmitVtc(vtc_did) => {
                            let Some(vtc_did) = validate_join_input(&vtc_did) else {
                                // Say why nothing happened. A keypress that
                                // cannot proceed must not be a silent no-op —
                                // that reads as a frozen screen (issue #29).
                                state.join.messages.push(MessageType::Error(
                                    "Enter the community's DID or agent name \
                                     first — or paste an invitation credential \
                                     (VIC) to fill it in."
                                        .to_string(),
                                ));
                                let _ = self.state_tx.send(state.clone());
                                continue;
                            };
                            // Accept an agent name (`example.com/@acme`) in place
                            // of the VTC DID. Only resolve when the input actually
                            // looks like a name, so pasting a DID keeps its
                            // existing (no-extra-round-trip) path; the resolved
                            // DID is what everything downstream persists.
                            let vtc_did = if openvtc_core::agent_name::looks_like_agent_name(
                                &vtc_did,
                            ) {
                                match openvtc_core::agent_name::resolve_identifier(
                                    tdk.did_resolver(),
                                    &vtc_did,
                                )
                                .await
                                {
                                    Ok(did) => did,
                                    Err(e) => {
                                        state.join.fail(e.to_string());
                                        let _ = self.state_tx.send(state.clone());
                                        continue;
                                    }
                                }
                            } else {
                                vtc_did
                            };
                            // Idempotency is now per-persona (R-B-9): a community may
                            // be joined as more than one persona, so the duplicate
                            // check happens once the identity is chosen (in the
                            // sequence) rather than at the community level here.
                            // Identity first: collect the invitations available for
                            // this community so each persona can be badged with its
                            // usable-invitation count, then let the operator pick the
                            // identity to present (the invitation choice, if any,
                            // follows for the chosen persona).
                            state.join.available_vics =
                                collect_available_vics(state, admin_vta, &vtc_did).await;
                            let options =
                                build_persona_options(config, &state.join.available_vics);
                            if options.is_empty() {
                                // First join — nothing to reuse; mint a fresh identity.
                                // A new persona can't hold an existing invitation.
                                state.invitation_credential = None;
                                state.join.present_invitation = false;
                                if let Some(interrupted) = self
                                    .launch_join_sequence(
                                        JoinIdentityChoice::Mint,
                                        vtc_did,
                                        interrupt_rx,
                                        state,
                                        tdk,
                                        config,
                                        admin_vta,
                                        profile,
                                        messaging,
                                    )
                                    .await
                                {
                                    return Ok(JoinExit::Exit(interrupted));
                                }
                            } else {
                                state.join.pending_vtc = Some(vtc_did);
                                state.join.persona_options = options;
                                state.join.identity_selected = 0;
                                state.join.reuse_confirm = None;
                                state.join.page = JoinPage::IdentityChoice;
                                let _ = self.state_tx.send(state.clone());
                            }
                        }
                        Action::JoinIdentitySelect(i) => {
                            // Clamp to the reuse rows plus the trailing "mint" row.
                            state.join.identity_selected = i.min(state.join.mint_row());
                            // Moving the highlight dismisses any armed warning.
                            state.join.reuse_confirm = None;
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinIdentityChoose => {
                            if state.join.mint_row_selected() {
                                let Some(vtc_did) = state.join.pending_vtc.clone() else {
                                    continue;
                                };
                                // A freshly minted persona holds no invitation.
                                state.invitation_credential = None;
                                state.join.present_invitation = false;
                                if let Some(interrupted) = self
                                    .launch_join_sequence(
                                        JoinIdentityChoice::Mint,
                                        vtc_did,
                                        interrupt_rx,
                                        state,
                                        tdk,
                                        config,
                                        admin_vta,
                                        profile,
                                        messaging,
                                    )
                                    .await
                                {
                                    return Ok(JoinExit::Exit(interrupted));
                                }
                            } else if let Some(opt) =
                                state.join.persona_options.get(state.join.identity_selected)
                            {
                                // Arm the cross-community linkage warning (D1).
                                state.join.reuse_confirm = Some(opt.id);
                                let _ = self.state_tx.send(state.clone());
                            }
                        }
                        Action::JoinReuseConfirm => {
                            let Some(persona_id) = state.join.reuse_confirm else {
                                continue;
                            };
                            // The community DID stays parked in `pending_vtc`; the
                            // invitation step is what launches the join now.
                            if state.join.pending_vtc.is_none() {
                                continue;
                            }
                            state.join.reuse_confirm = None;
                            // Invitations already known for the chosen persona:
                            // this community's valid VICs whose subject is that
                            // persona's DID.
                            let persona_did = config
                                .account
                                .personas
                                .get(&persona_id)
                                .map(|p| p.did.clone());
                            // …plus one the operator loaded for this join by hand
                            // (`--invitation` / a paste on the entry page) whatever
                            // its subject. Filtering that by subject too was how a
                            // deliberately supplied invitation could disappear
                            // between the entry page and the submit; a subject that
                            // is not the presenting persona is what
                            // `build_linkage_proof` exists for, not a reason to
                            // drop it.
                            let loaded = state
                                .invitation_credential
                                .as_ref()
                                .and_then(|v| openvtc_core::join::invitation_id(v))
                                .map(str::to_string);
                            let invitations: Vec<AvailableVic> = state
                                .join
                                .available_vics
                                .iter()
                                .filter(|v| {
                                    (persona_did.is_some() && v.subject == persona_did)
                                        || loaded.as_deref() == Some(v.id.as_str())
                                })
                                .cloned()
                                .collect();
                            // Always offer the choice, including with none found.
                            // The step carries a paste row, so an empty list is a
                            // question ("do you have one?") rather than a reason
                            // to skip. It used to launch straight into an open
                            // request here, which is why an operator holding an
                            // invitation was never asked for it.
                            state.join.invitation_options = invitations;
                            state.join.invitation_for_persona = Some(persona_id);
                            state.join.invitation_persona_did = persona_did;
                            state.join.invitation_use_selected = 0;
                            state.join.messages.clear();
                            state.join.page = JoinPage::InvitationChoice;
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinReuseCancel => {
                            state.join.reuse_confirm = None;
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinInvitationSelect(i) => {
                            // Rows: 0..len an invitation, len = paste, len+1 = without.
                            let max = state.join.invitation_without_row();
                            state.join.invitation_use_selected = i.min(max);
                            let _ = self.state_tx.send(state.clone());
                        }
                        Action::JoinInvitationChoose => {
                            let Some(vtc_did) = state.join.pending_vtc.clone() else {
                                continue;
                            };
                            let Some(persona_id) = state.join.invitation_for_persona else {
                                continue;
                            };
                            // The paste row loads a VIC instead of launching: it is
                            // the answer to "I have one, it just isn't in the
                            // vault". Read the OS clipboard as a convenience; the
                            // portable path is the terminal's own bracketed paste,
                            // which arrives as `JoinPasteVic` from anywhere on this
                            // page. Either way we stay on the step so the operator
                            // sees the loaded invitation before committing to it.
                            if state.join.invitation_use_selected
                                == state.join.invitation_paste_row()
                            {
                                state.join.messages.clear();
                                match crate::clipboard::read_clipboard() {
                                    Ok(text) => {
                                        load_pasted_vic(state, &text, Some(&vtc_did));
                                    }
                                    Err(why) => {
                                        state.join.messages.push(MessageType::Error(format!(
                                            "Could not read the clipboard ({why}). Paste the \
                                             invitation JSON directly into this screen instead."
                                        )));
                                    }
                                }
                                let _ = self.state_tx.send(state.clone());
                                continue;
                            }
                            // A selected invitation row presents that VIC; the
                            // trailing row joins without one.
                            let sel = state.join.invitation_use_selected;
                            if let Some(av) = state.join.invitation_options.get(sel) {
                                state.invitation_credential = Some(av.body.clone());
                                state.join.present_invitation = true;
                            } else {
                                state.invitation_credential = None;
                                state.join.present_invitation = false;
                            }
                            if let Some(interrupted) = self
                                .launch_join_sequence(
                                    JoinIdentityChoice::Reuse(persona_id),
                                    vtc_did,
                                    interrupt_rx,
                                    state,
                                    tdk,
                                    config,
                                    admin_vta,
                                    profile,
                                    messaging,
                                )
                                .await
                            {
                                return Ok(JoinExit::Exit(interrupted));
                            }
                        }
                        _ => {}
                    }
                }
                Ok(interrupted) = interrupt_rx.recv() => {
                    return Ok(JoinExit::Exit(interrupted));
                }
            }
            let _ = self.state_tx.send(state.clone());
        }
    }

    /// Move to the progress page and run [`run_join_sequence`] for the chosen
    /// identity, raced against the interrupt (R15). Returns `Some(interrupted)`
    /// when the user cancelled mid-sequence (the caller then exits the flow);
    /// `None` when the sequence ran to its own success/failure terminal.
    #[allow(clippy::too_many_arguments)]
    async fn launch_join_sequence(
        &self,
        choice: JoinIdentityChoice,
        vtc_did: String,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
        tdk: &TDK,
        config: &mut Config,
        admin_vta: Option<&VtaClient>,
        profile: &str,
        messaging: Option<&Messaging>,
    ) -> Option<Interrupted> {
        // Move to the progress page and lock input.
        state.join.page = JoinPage::Progress;
        state.join.processing = true;
        state.join.completed = Completion::NotFinished;
        state.join.messages.clear();
        state.join.info(format!("Joining {vtc_did}…"));
        let _ = self.state_tx.send(state.clone());

        // R15: race the multi-step VTA sequence against the interrupt so Ctrl-C /
        // Exit stay live for its whole (network-bound) duration. On interrupt the
        // sequence future is DROPPED — cancelled at whatever `.await` it parked
        // on. `minted_persona` is the only handle to mid-sequence persisted state
        // (`mint_persona_into` writes a persona before the receipt), so a cancel
        // after that point rolls it back. It lives outside the future so it stays
        // readable after the drop. A *reused* persona is never set here, so it is
        // never rolled back.
        let mut minted_persona: Option<PersonaId> = None;
        // The listener [`start_persona_listener`] installed, for the same reason
        // and by the same discipline as `minted_persona`: it is state the
        // sequence created before the join was committed, and a cancel drops
        // the future at whatever await it parked on, so the only place that can
        // still tear it down is out here. Left behind, it is a mediator socket
        // held open for a persona that was just rolled back.
        let mut started_listener: Option<String> = None;
        // Captured before the mint so a rollback (cancel or failure) can restore
        // it — `mint_persona_into` overwrites `public.friendly_name` with the
        // attempted community's persona name.
        let prior_friendly_name = config.public.friendly_name.clone();
        let sequence = run_join_sequence(
            self,
            state,
            tdk,
            config,
            admin_vta,
            profile,
            vtc_did,
            choice,
            &mut minted_persona,
            &prior_friendly_name,
            messaging,
            &mut started_listener,
        );
        let interrupted = race_against_interrupt(sequence, interrupt_rx).await;

        if let Some(interrupted) = interrupted {
            if let (Some(service), Some(listener_id)) = (messaging, started_listener.as_deref()) {
                service.remove_listener(listener_id).await;
            }
            if let Some(persona_id) = minted_persona
                && !config.account.persona_referenced(&persona_id)
            {
                rollback_minted_persona(config, persona_id, state, profile, &prior_friendly_name);
            }
            state.join.processing = false;
            state.join.completed = Completion::CompletedFail;
            state.join.info(
                "Join cancelled. Any partially-minted persona was rolled back; a sub-context may remain at the VTA.",
            );
            state.main_page.log("Join cancelled by user.");
            let _ = self.state_tx.send(state.clone());
            return Some(interrupted);
        }

        state.join.processing = false;
        let _ = self.state_tx.send(state.clone());
        None
    }
}

/// Build the reuse options for the identity-choice page (R-B-3): every existing
/// persona, labelled, with the communities it is already presented to (the
/// linkage-warning detail) and the count of `vics` bound to it (the available
/// invitations for the community being joined). Sorted by label for a stable
/// list.
fn build_persona_options(config: &Config, vics: &[AvailableVic]) -> Vec<PersonaOption> {
    let mut options: Vec<PersonaOption> = config
        .account
        .personas
        .values()
        .map(|p| {
            let mut linked_communities: Vec<String> = config
                .account
                .memberships()
                .filter(|c| c.persona_ref == p.persona_id)
                .map(|c| {
                    crate::state_handler::community_label(
                        config,
                        &c.vtc_did,
                        c.display_name.as_deref(),
                        40,
                    )
                })
                .collect();
            linked_communities.sort();
            let valid_vic_count = vics
                .iter()
                .filter(|v| v.subject.as_deref() == Some(p.did.as_str()))
                .count();
            PersonaOption {
                id: p.persona_id,
                // Explicit label, then the persona's verified agent name, then
                // the DID — matching what the communities panel already does
                // for the same personas.
                label: p
                    .label
                    .clone()
                    .or_else(|| config.agent_name_for(&p.did).map(str::to_owned))
                    .unwrap_or_else(|| shorten_did(&p.did, 32)),
                did: p.did.clone(),
                linked_communities,
                valid_vic_count,
            }
        })
        .collect();
    options.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.did.cmp(&b.did)));
    options
}

/// Collect the valid invitations (VICs) available for the community `vtc_did`,
/// across all personas: a loaded `--invitation`/pasted VIC that matches, plus the
/// community-matched, valid, active VICs the vault holds. Each is validated
/// (complete + unexpired) so the identity badges and the invitation list only
/// ever show usable invitations. Best-effort: with no admin VTA only a loaded VIC
/// is considered.
async fn collect_available_vics(
    state: &State,
    admin_vta: Option<&VtaClient>,
    vtc_did: &str,
) -> Vec<AvailableVic> {
    let now = Utc::now();
    let usable = |vic: &serde_json::Value| {
        openvtc_core::join::invitation_matches_community(vic, vtc_did)
            && !openvtc_core::join::invitation_is_expired(vic, now)
            && openvtc_core::join::validate_invitation_credential(vic).is_ok()
    };
    let mut out: Vec<AvailableVic> = Vec::new();

    // Vault: only fetch bodies for this community's active, valid descriptors.
    if let Some(vta) = admin_vta
        && let Ok(listing) = vta
            .cred_vault_query(serde_json::json!({ "purpose": "invite" }))
            .await
        && let Some(arr) = listing.get("credentials").and_then(|c| c.as_array())
    {
        for d in arr {
            let summ = VicSummary::from_descriptor(d);
            if summ.issuer != vtc_did
                || summ.status != "valid"
                || summ.lifecycle != VicLifecycle::Active
            {
                continue;
            }
            if let Ok(got) = vta.cred_vault_get(&summ.id).await
                && let Some(body) = got.get("credential").cloned()
                && usable(&body)
                && let Some(av) = to_available_vic(&body)
            {
                out.push(av);
            }
        }
    }

    // A loaded VIC (--invitation / paste) that matches this community, if not
    // already surfaced from the vault.
    if let Some(vic) = state.invitation_credential.as_ref()
        && usable(vic)
        && let Some(av) = to_available_vic(vic)
        && !out.iter().any(|o| o.id == av.id)
    {
        out.push(av);
    }
    out
}

/// Map a signed VIC body to the display+present record. `None` if it lacks an id.
fn to_available_vic(body: &serde_json::Value) -> Option<AvailableVic> {
    Some(AvailableVic {
        id: openvtc_core::join::invitation_id(body)?.to_string(),
        subject: openvtc_core::join::invitation_subject(body).map(str::to_string),
        valid_from: openvtc_core::join::invitation_valid_from(body)
            .unwrap_or_default()
            .to_string(),
        valid_until: openvtc_core::join::invitation_valid_until(body)
            .unwrap_or_default()
            .to_string(),
        body: body.clone(),
    })
}

/// Outcome of a `join_flow` invocation.
pub(crate) enum JoinExit {
    /// User cancelled / finished — return to the main page and resume the
    /// caller's loop. Carries the just-joined session when a join succeeded, so
    /// the runtime loop can register it + start its listener live (R-B-5).
    Returned(Option<JoinedSession>),
    /// Application is exiting (Exit / UXError / interrupt).
    Exit(Interrupted),
}

/// Accept a pasted / clipboard-read invitation credential (VIC).
///
/// `vtc_did` is `Some` only on the invitation step, where the community is
/// already chosen: there the paste is additionally required to be *for* that
/// community and unexpired, and lands as a new row on the step (selected, so the
/// next Enter presents it). On the entry page the community is still unknown, so
/// only the credential shape is checked and the VIC is stashed for
/// [`collect_available_vics`] to match once a DID is entered.
///
/// Every rejection is reported into `join.messages` with its reason. An
/// invitation that silently fails to load reads exactly like one that was never
/// pasted, and the operator then submits an open request believing they
/// presented a credential — which is the same failure, in miniature, as skipping
/// the step altogether.
fn load_pasted_vic(state: &mut State, text: &str, vtc_did: Option<&str>) {
    let vic = match serde_json::from_str::<serde_json::Value>(text.trim()) {
        Ok(v) => v,
        Err(e) => {
            state.join.messages.push(MessageType::Error(format!(
                "Pasted text is not valid JSON: {e}"
            )));
            return;
        }
    };
    if let Err(why) = openvtc_core::join::validate_invitation_credential(&vic) {
        state.join.messages.push(MessageType::Error(format!(
            "Pasted invitation is not usable: {why}"
        )));
        return;
    }
    let Some(vtc_did) = vtc_did else {
        // Entry page: no community to match against yet. The VIC's issuer *is*
        // the community, and `validate_invitation_credential` has already
        // guaranteed one is extractable, so record it — the page shows it and
        // prefills the DID input from it instead of asking for a DID the
        // credential already carries.
        state.join.invitation_issuer =
            openvtc_core::join::invitation_issuer(&vic).map(str::to_string);
        state.invitation_credential = Some(vic);
        state.join.has_invitation = true;
        state.join.vic_cleared = false;
        return;
    };
    if !openvtc_core::join::invitation_matches_community(&vic, vtc_did) {
        state.join.messages.push(MessageType::Error(
            "That invitation was issued by a different community, so this one will \
             not accept it."
                .to_string(),
        ));
        return;
    }
    if openvtc_core::join::invitation_is_expired(&vic, Utc::now()) {
        state.join.messages.push(MessageType::Error(
            "That invitation has expired. Ask the community for a new one, or join \
             without it."
                .to_string(),
        ));
        return;
    }
    let Some(av) = to_available_vic(&vic) else {
        state.join.messages.push(MessageType::Error(
            "That invitation has no `id`, so it cannot be presented.".to_string(),
        ));
        return;
    };
    // Re-pasting one already listed re-selects it rather than duplicating it.
    let row = match state
        .join
        .invitation_options
        .iter()
        .position(|o| o.id == av.id)
    {
        Some(existing) => existing,
        None => {
            state.join.invitation_options.push(av);
            state.join.invitation_options.len() - 1
        }
    };
    state.join.invitation_use_selected = row;
    state.join.has_invitation = true;
    state.join.vic_cleared = false;
}

/// Validate the raw VTC DID the operator submitted on the EnterDid page.
///
/// Pure decision peeled out of the `JoinSubmitVtc` arm: trims surrounding
/// whitespace and rejects an empty input (the loop `continue`s, staying on the
/// EnterDid page). Returns the cleaned DID to drive the sequence with, or `None`
/// when there is nothing to submit.
fn validate_join_input(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// #2: load a *presentable* invitation the VTA already holds for the community
/// being joined (`vtc_did`). Queries the credential vault for `purpose = invite`
/// and selects an active, vault-valid (not expired / revoked) VIC whose issuer is
/// this community — preferring the one that stays valid longest — then fetches
/// its body. The first-match grab this replaced could present a VIC for the wrong
/// community (or an expired one), which the VTC then rejected. Best-effort: any
/// error / no match yields `None`, and the join proceeds as an open request.
async fn load_invitation_from_vault(
    admin_vta: &VtaClient,
    vtc_did: &str,
) -> Option<serde_json::Value> {
    let listing = admin_vta
        .cred_vault_query(serde_json::json!({ "purpose": "invite" }))
        .await
        .ok()?;
    let descriptors = listing.get("credentials").and_then(|c| c.as_array())?;
    // Community-matched, active, vault-valid candidates; prefer the latest
    // `validUntil` (longest-lived). RFC 3339 timestamps sort lexicographically.
    let best = descriptors
        .iter()
        .map(VicSummary::from_descriptor)
        .filter(|v| {
            v.issuer == vtc_did && v.status == "valid" && v.lifecycle == VicLifecycle::Active
        })
        .max_by(|a, b| a.valid_until.cmp(&b.valid_until))?;
    let got = admin_vta.cred_vault_get(&best.id).await.ok()?;
    got.get("credential").cloned()
}

/// #1b: build a subject-linkage proof when the presenting DID differs from the
/// loaded VIC's subject — the invited persona authorizes the presenter. Returns
/// `None` on the join-as-subject path (presenter == subject), when no invitation
/// is loaded, or when the subject isn't one of our personas (we can't sign for a
/// key we don't hold; the VTC then refuses the mismatched binding). Best-effort:
/// a signing failure is logged and yields `None`.
async fn build_linkage_proof(
    config: &Config,
    admin_vta: &VtaClient,
    state: &State,
    presenter_did: &str,
) -> Option<openvtc_core::join::SubjectLinkage> {
    let vic = state.invitation_credential.as_ref()?;
    let subject = openvtc_core::join::invitation_subject(vic)?;
    if subject == presenter_did {
        return None; // join-as-subject — no linkage needed
    }
    let vic_id = openvtc_core::join::invitation_id(vic)?;
    match config
        .build_subject_linkage(subject, Some(admin_vta), vic_id, presenter_did)
        .await
    {
        Ok(linkage) => Some(linkage),
        Err(e) => {
            debug!(subject = %subject, error = %e, "subject-linkage proof unavailable");
            None
        }
    }
}

/// Idempotency decision (R-B-9): is there already a *live* (Active/Pending)
/// membership for this VTC?
///
/// Whether a *live* (Active/Pending) membership already exists for this community
/// **as this persona** — the per-persona join idempotency gate (R-B-9). A
/// community may be joined more than once, but not twice as the same persona, so
/// the check is keyed on `(vtc, persona)` and only blocks the reuse path (a
/// freshly minted persona can never collide).
fn is_duplicate_membership(config: &Config, vtc_did: &str, persona: PersonaId) -> bool {
    config.account.has_live_membership(vtc_did, persona)
}

/// Build the `Pending` [`CommunityRecord`] recorded on a successful submit.
///
/// Pure decision peeled out of step 9 of [`run_join_sequence`]; delegates to
/// [`CommunityRecord::new_pending`] so the record shape stays defined in core.
fn build_pending_record(
    vtc_did: String,
    display_name: Option<String>,
    sub_context_id: String,
    persona_id: PersonaId,
    request_id: uuid::Uuid,
    now: chrono::DateTime<Utc>,
    submit_transport: openvtc_core::didcomm::MessagingTransport,
) -> CommunityRecord {
    let mut record = CommunityRecord::new_pending(
        vtc_did,
        display_name,
        sub_context_id,
        persona_id,
        request_id,
        now,
    );
    // Which transport carried the submit, so an unacknowledged join can name it
    // rather than leaving every cause looking alike.
    record.submit_transport = Some(submit_transport);
    record
}

/// Run the automated mint → sub-context → join-submit → persist sequence.
///
/// All progress and errors land in `state.join`. On success
/// `state.join.completed` is `CompletedOK` and `created_community` holds the new
/// pending record; on any failure it is `CompletedFail` with the error logged.
///
/// `minted_persona` is written as soon as the persona is minted-and-persisted so
/// the caller can roll it back if the whole future is cancelled (R15) before the
/// persona is bound to a community.
#[allow(clippy::too_many_arguments)]
async fn run_join_sequence(
    handler: &StateHandler,
    state: &mut State,
    tdk: &TDK,
    config: &mut Config,
    admin_vta: Option<&VtaClient>,
    profile: &str,
    vtc_did: String,
    choice: JoinIdentityChoice,
    minted_persona: &mut Option<PersonaId>,
    prior_friendly_name: &str,
    messaging: Option<&Messaging>,
    started_listener: &mut Option<String>,
) {
    // Idempotency (R-B-9) was already enforced at submit, before the identity
    // choice — no re-check here.

    // The mint + join sequence needs the admin VTA session.
    let Some(admin_vta) = admin_vta else {
        state
            .join
            .fail("VTA session unavailable — cannot join right now.");
        return;
    };

    // 2. Resolve the community's verified agent name for display (best-effort).
    // A verified name (`example.com/@acme`) is the community's human-readable
    // handle; `None` when it has no verifiable name, so the sub-context
    // derivation falls back to the DID-derived token (D9). The lookup is also
    // seeded into the persisted cache so the communities list shows it without
    // waiting for the background sweep.
    let display_name =
        openvtc_core::agent_name::resolve_verified_name(tdk.did_resolver(), &vtc_did).await;
    config.set_cached_agent_name(&vtc_did, display_name.clone(), chrono::Utc::now());
    state.join.display_name = display_name.clone();

    // 3. Preflight the community's transports, before anything is minted.
    //
    // A peer that advertises no messaging service cannot be joined at all, and
    // discovering that after the persona mint leaves an orphaned identity
    // attached to a request nobody could receive. This is a check on what the
    // document *offers* — not on whether the peer can actually serve it, which
    // no client can know before sending, and which is the peer's defect to fix
    // rather than ours to route around.
    let transports = openvtc_core::config::peer_messaging_transports(&vtc_did).await;
    let Some(peer_preferred) = transports.preferred() else {
        state.join.fail(format!(
            "This community advertises no messaging transport ({}). Its DID \
             document offers neither a TSP nor a DIDComm service, so a join \
             request cannot reach it. Nothing was created.",
            state.join.display_name.as_deref().unwrap_or(&vtc_did)
        ));
        return;
    };
    // What the community *offers* — not yet the wire the submit goes out on.
    // That needs our own leg too, and is settled at step 8 once the persona (and
    // so the mediator we post through) is known.
    state
        .join
        .info(format!("Community reachable over {peer_preferred}."));
    let _ = handler.state_tx.send(state.clone());

    let top_context_id = config.account.top_context_id.clone();

    // Resolve the persona to present: reuse an existing account persona (R-B-3)
    // or mint a fresh, self-contained one (D6). Only a *minted* persona is
    // recorded in `minted_persona` for rollback — a reused persona pre-exists and
    // must never be rolled back.
    let (persona_id, persona_did) = match choice {
        JoinIdentityChoice::Reuse(persona_id) => match config.identities.get(&persona_id) {
            Some(ident) => {
                // Per-persona idempotency (R-B-9): block a second live membership
                // as the *same* persona, while still allowing other personas.
                if is_duplicate_membership(config, &vtc_did, persona_id) {
                    state.join.fail(
                        "Already a member of (or have a pending request for) this community as this persona.",
                    );
                    return;
                }
                let did = ident.persona_did().to_string();
                state.join.info(format!("Reusing persona {did}…"));
                let _ = handler.state_tx.send(state.clone());
                (persona_id, did)
            }
            None => {
                state
                    .join
                    .fail("Selected persona is unavailable — cannot reuse it.");
                return;
            }
        },
        JoinIdentityChoice::Mint => {
            // 4. Mint a fresh persona into `state.setup` (reusing the setup helpers).
            // Persona signing/auth/encryption keys.
            state
                .join
                .info("Creating persona keys (signing, authentication, encryption)…");
            let _ = handler.state_tx.send(state.clone());
            match vta::create_persona_keys(admin_vta, Some(&top_context_id)).await {
                Ok(keys) => state.setup.did_keys = Some(keys),
                Err(e) => {
                    state
                        .join
                        .fail(format!("Failed to create persona keys: {e}"));
                    return;
                }
            }
            // WebVH update keys.
            state.join.info("Creating DID update keys…");
            let _ = handler.state_tx.send(state.clone());
            match vta::create_update_keys(admin_vta, Some(&top_context_id)).await {
                Ok((update, next_update)) => {
                    state.setup.vta.update_secret = Some(update);
                    state.setup.vta.next_update_secret = Some(next_update);
                }
                Err(e) => {
                    state
                        .join
                        .fail(format!("Failed to create update keys: {e}"));
                    return;
                }
            }

            // Pick the first WebVH server. Serverless mint is a deliberate follow-up.
            state.join.info("Finding a DID hosting server…");
            let _ = handler.state_tx.send(state.clone());
            let server_id = match vta::list_webvh_servers(admin_vta).await {
                Ok(servers) => match servers.into_iter().next() {
                    Some(s) => s.id,
                    None => {
                        state.join.fail(
                    "No WebVH server available from the VTA (serverless mint not yet supported).",
                );
                        return;
                    }
                },
                Err(e) => {
                    state
                        .join
                        .fail(format!("Failed to list WebVH servers: {e}"));
                    return;
                }
            };

            // Create the persona did:webvh via the server (auto-assigned path).
            state
                .join
                .info(format!("Creating persona DID via {server_id}…"));
            let _ = handler.state_tx.send(state.clone());
            match vta::create_did_via_server(
                admin_vta,
                tdk,
                &top_context_id,
                &server_id,
                WebvhPathMode::AutoAssign,
            )
            .await
            {
                Ok((keys, did, document, _mnemonic)) => {
                    // A persona the VTA minted without `#tsp` can never reach a
                    // TSP-only community — and this join may be to one. Say so
                    // here rather than letting it surface later as a request
                    // that goes out and is never answered.
                    if let Some(warning) =
                        openvtc_core::config::did::tsp_advertisement_warning(&document)
                    {
                        state.join.info(warning);
                    }
                    state.setup.did_keys = Some(keys);
                    state.setup.webvh_address.did = did;
                    state.setup.webvh_address.document = document;
                }
                Err(e) => {
                    state
                        .join
                        .fail(format!("Failed to create persona DID: {e}"));
                    return;
                }
            }

            // The persona's mediator is the account's VTA mediator: the DID minted via
            // the VTA's webvh server advertises that mediator in its DIDComm service, so
            // the persona listener must use the same one. Hardcoding `None` (the public
            // default) left the persona with no usable mediator — the listener then
            // failed with "No Mediator is configured" and retried forever.
            state.setup.custom_mediator = match &config.key_backend {
                openvtc_core::config::KeyBackend::Vta { mediator_did, .. } => mediator_did.clone(),
                _ => None,
            };
            // A join mints the persona *unlabelled*. `display_name` here is the
            // COMMUNITY's name — naming the persona after it (or, with no
            // verified name, after a DID-derived rendering of the VTC DID) put a
            // community identifier in the persona's own label, and
            // `mint_persona_into` copied that on into `public.friendly_name`, so
            // the header announced the community twice and the DID manager
            // listed a persona labelled with a community DID. The persona's
            // community binding is recorded on the membership record and shown
            // beside it; the label is for a name the operator chose.
            state.setup.username = String::new();

            // 5. Persist the persona into the account. `mint_persona_into` writes the
            // persona record + runtime identity + key info to disk *immediately* (a
            // synchronous `Config::save`), so from here until the community record is
            // persisted (step 9) the on-disk config holds a persona with no community.
            // Record its id so a cancel (R15) or later failure can roll it back.
            let persona_id =
                match Config::mint_persona_into(config, &state.setup, tdk, profile).await {
                    Ok(id) => id,
                    Err(e) => {
                        state.join.fail(format!("Failed to save persona: {e}"));
                        return;
                    }
                };
            *minted_persona = Some(persona_id);
            let persona_did = state.setup.webvh_address.did.clone();
            state.join.info(format!("Persona created: {persona_did}"));
            let _ = handler.state_tx.send(state.clone());
            (persona_id, persona_did)
        }
    };
    // Only a freshly-minted persona is rolled back on a later failure; a reused
    // persona pre-existed and is left intact.
    let minted = minted_persona.is_some();

    // 6. Derive the per-community sub-context id (D9, collision-safe).
    let sub_context_id =
        match build_sub_context_id(&top_context_id, display_name.as_deref(), &vtc_did, |id| {
            config.account.memberships().any(|c| c.sub_context_id == id)
        }) {
            Ok(id) => id,
            Err(e) => {
                state
                    .join
                    .fail(format!("Failed to derive sub-context id: {e}"));
                if minted {
                    rollback_minted_persona(
                        config,
                        persona_id,
                        state,
                        profile,
                        prior_friendly_name,
                    );
                }
                return;
            }
        };

    // 7. Register the sub-context at the VTA.
    state
        .join
        .info(format!("Creating sub-context {sub_context_id}…"));
    let _ = handler.state_tx.send(state.clone());
    if let Err(e) = vta::create_sub_context(admin_vta, &top_context_id, &sub_context_id).await {
        state
            .join
            .fail(format!("Failed to create sub-context: {e}"));
        if minted {
            rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
        }
        return;
    }

    // 8. Submit the join request to the VTC over DIDComm. The persona is
    // the authcrypt sender (the VTC reads the applicant from the
    // envelope — no holder-binding signature, and a did:webvh persona
    // can't use the VTC's did:key-only REST signature path). The minted
    // persona's runtime identity (ATM profile + mediator) was built into
    // `config.identities` by `mint_persona_into`. The VTC's
    // submit-receipt (with the authoritative requestId) returns
    // asynchronously to the persona's mediator; until that receipt
    // handler lands, the request message id is the correlation handle
    // stored on the Pending record.
    state.join.info("Submitting join request…");
    let _ = handler.state_tx.send(state.clone());

    let Some(atm) = tdk.atm.as_ref() else {
        state
            .join
            .fail("Messaging (ATM) unavailable — cannot submit the join request.");
        if minted {
            rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
        }
        return;
    };
    let (applicant_did, persona_profile, persona_mediator) = match config
        .identities
        .get(&persona_id)
    {
        Some(ident) => (
            ident.persona_did().to_string(),
            ident.profile().clone(),
            ident.mediator_did.clone().unwrap_or_default(),
        ),
        None => {
            state
                .join
                .fail("Persona identity unavailable after mint — cannot submit.");
            if minted {
                rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
            }
            return;
        }
    };

    // Open the applicant's mailbox before knocking on the door. The VTC decides
    // a well-formed invited join in under a second and pushes the VMC + role VEC
    // straight back, so the reply is in flight while this sequence is still
    // running — and a mediator only *live-streams* a message whose recipient is
    // connected at the instant it lands. Bringing the socket up after the
    // sequence returned (which is what `register_joined_session` did alone) left
    // a window as long as the operator's own reading speed, and a community
    // reply that landed inside it was stored and never pushed: the VTC's outbox
    // read "sent", the mediator held two messages, and the membership sat
    // Pending with nothing in any log to say why. Connecting first closes the
    // window at the only end we control.
    //
    // Started here, waited for at the submit ([`await_persona_online`]): the
    // connect is I/O the invitation resolution and VP build below do not depend
    // on, so overlapping them spends the connect out of work already being done
    // rather than out of the operator's time.
    *started_listener = start_persona_listener(
        handler,
        state,
        messaging,
        config,
        tdk,
        persona_id,
        &applicant_did,
    )
    .await;
    // #2: resolve the VIC to present for THIS community. A VIC's issuer is the
    // community's VTC DID, so a presentable invitation must match `vtc_did` and
    // be unexpired — presenting a mismatched or expired one only earns a VTC
    // rejection (and reads as a failed invitation rather than an open request).
    // An explicitly loaded VIC (--invitation / paste) is still stored in the
    // vault regardless (its durable home), but only *presented* when it matches;
    // otherwise we fall back to a community-matched VIC the vault already holds,
    // else submit as an open request. Setting `state.invitation_credential` to
    // the resolved VIC keeps the VP, the linkage proof, and the summary all
    // consistent with what is actually presented. All vault calls are
    // best-effort — the join proceeds regardless.
    let loaded = state.invitation_credential.take();
    let mut presentable: Option<serde_json::Value> = None;
    if state.join.present_invitation {
        // The operator chose to present an invitation (or one was available and
        // they accepted the default). Resolve the one to present.
        if let Some(vic) = loaded {
            if let Err(e) = admin_vta.cred_vault_receive(vic.clone(), None).await {
                debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
            }
            if !openvtc_core::join::invitation_matches_community(&vic, &vtc_did) {
                state.join.info(
                    "Loaded invitation is for a different community — \
                     looking for one that matches…",
                );
            } else if openvtc_core::join::invitation_is_expired(&vic, Utc::now()) {
                state
                    .join
                    .info("Loaded invitation has expired — looking for a valid one…");
            } else {
                presentable = Some(vic);
            }
        }
        if presentable.is_none() {
            presentable = load_invitation_from_vault(admin_vta, &vtc_did).await;
        }
    } else if let Some(vic) = loaded {
        // The operator chose to join *without* an invitation. Still store a
        // loaded VIC in the vault (its durable home) but present nothing — this
        // is what honours the choice over the vault fallback above.
        if let Err(e) = admin_vta.cred_vault_receive(vic, None).await {
            debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
        }
        state.join.info(
            "Joining without an invitation — submitting an open request (awaiting approval).",
        );
    }
    // Completeness gate before presenting: a VIC resolved from the vault may
    // predate the ingest-time validation (or have lost fields in storage). An
    // incomplete VIC is unusable — the VTC can't extract it and silently refers
    // the join to a moderator — so drop it here and fall to an open request with
    // a clear reason, rather than presenting junk.
    if let Some(vic) = &presentable
        && let Err(why) = openvtc_core::join::validate_invitation_credential(vic)
    {
        state.join.info(format!(
            "Resolved invitation is incomplete ({why}) — submitting as an open request instead."
        ));
        presentable = None;
    }
    state.invitation_credential = presentable;
    state.join.has_invitation = state.invitation_credential.is_some();
    state.join.presented_invitation = state.invitation_credential.as_ref().map(|vic| {
        let subject = openvtc_core::join::invitation_subject(vic).map(str::to_string);
        PresentedInvitation {
            id: openvtc_core::join::invitation_id(vic)
                .unwrap_or_default()
                .to_string(),
            // Verified-only, from the persisted cache: the subject is one
            // of our own personas, so the sweep normally has a name for it.
            subject_agent_name: subject
                .as_deref()
                .and_then(|s| config.agent_name_for(s))
                .map(|n| sanitize_display(n, 256)),
            subject,
        }
    });

    // Present the holder VP. When a matching, unexpired invitation (VIC) is
    // resolved it rides in the VP's `verifiableCredential` array; the VTC
    // verifies it and auto-admits on a valid, trusted, unconsumed invitation (no
    // manual approval). With no presentable invitation the join is an open
    // request the community reviews and approves manually.
    if state.invitation_credential.is_some() {
        state
            .join
            .info("Presenting your invitation credential to the community…");
    } else if state.join.present_invitation {
        // Wanted to present one, but none resolved to a usable VIC.
        state.join.info(
            "No valid invitation for this community — \
             submitting as an open request (awaiting approval).",
        );
    }
    // (When the operator chose to join without an invitation, the note was
    // already surfaced above where the VIC was suppressed.)
    let _ = handler.state_tx.send(state.clone());
    // Subject-linkage (#1b): when the presenting DID differs from the VIC
    // subject, prove the subject authorized this presenter (signed with the
    // subject persona's key). On the join-as-subject path (#1a) this is `None`.
    let linkage = build_linkage_proof(config, admin_vta, state, &applicant_did).await;
    let mut vp = openvtc_core::join::build_join_vp(
        &applicant_did,
        state.invitation_credential.as_ref(),
        linkage.as_ref(),
    );
    // Peer identity vetting: present the statements gathered for this community
    // under this persona, and name the requirements they were gathered against
    // so the community applies the same criterion (vetting-process.md §10.1).
    let presentation = match config.private.vetting.application(&vtc_did, persona_id) {
        Some(application) if application.join_did == applicant_did => {
            let statements = application.presentable_statements(chrono::Utc::now());
            if !statements.is_empty() {
                state.join.info(format!(
                    "Presenting {} vetting statement(s) to the community…",
                    statements.len()
                ));
            }
            openvtc_core::join::attach_credentials(&mut vp, statements);
            openvtc_core::join::JoinPresentation {
                vp,
                extensions: application.join_extensions(),
            }
        }
        _ => vp.into(),
    };
    // Settle the wire. TSP needs **both** legs, which is the workspace rule that
    // the protocol is the highest-preference one present in *both* parties'
    // documents — and here it is not a formality. A TSP send posts the raw CESR
    // frame to *our* mediator's `/inbound`; the community's advertised mediator
    // is only the hop the routing layer is sealed to and never sees the request.
    // A mediator without its `tsp` feature therefore rejects the frame as an
    // unparseable DIDComm envelope, and does so while the error names the *other*
    // mediator — an hour of debugging for a question answerable up front.
    //
    // `None` at either end sends over DIDComm exactly as before, so a community
    // that has not been flipped is unaffected.
    let vtc_tsp_mediator = match openvtc_core::config::peer_tsp_mediator(&vtc_did).await {
        None => None,
        Some(peer_mediator) => {
            match openvtc_core::config::our_mediator_carries_tsp(&persona_mediator).await {
                Some(true) => Some(peer_mediator),
                // Our mediator does not carry TSP. Prefer DIDComm where the
                // community offers it — a working join beats a correct-looking
                // one. With TSP the community's *only* transport there is
                // nothing to fall back to, so send it and let the mediator
                // answer; refusing here would only replace one failure with
                // another, minus the evidence.
                Some(false) if transports.didcomm_mediator.is_some() => {
                    state.join.info(
                        "Your mediator does not carry TSP — submitting over DIDComm instead.",
                    );
                    let _ = handler.state_tx.send(state.clone());
                    None
                }
                Some(false) => {
                    state.join.info(
                        "This community offers TSP only, and your mediator does not \
                         advertise it — attempting the submit over TSP anyway.",
                    );
                    let _ = handler.state_tx.send(state.clone());
                    Some(peer_mediator)
                }
                // Could not ask. Unknown is not "no": take the community's
                // preference where it has an alternative, since DIDComm is the
                // transport that worked before TSP existed.
                None if transports.didcomm_mediator.is_some() => None,
                None => Some(peer_mediator),
            }
        }
    };
    let submit_transport = if vtc_tsp_mediator.is_some() {
        openvtc_core::didcomm::MessagingTransport::Tsp
    } else {
        openvtc_core::didcomm::MessagingTransport::DidComm
    };
    // Last gate before the request goes out: the socket started above has had
    // the invitation + VP work to come up, so this is normally already true.
    let applicant_online = await_persona_online(handler, state, messaging, &applicant_did).await;

    let request_id = match openvtc_core::join::submit_join_request(
        atm,
        &persona_profile,
        &applicant_did,
        &vtc_did,
        &persona_mediator,
        presentation,
        vtc_tsp_mediator.as_deref(),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            state
                .join
                .fail(format!("Failed to submit join request: {e}"));
            // Nothing was submitted, so nothing will reply — release the socket
            // we opened for this attempt before the persona is rolled back, or
            // it outlives the identity it speaks for.
            if let (Some(service), Some(listener_id)) = (messaging, started_listener.take()) {
                service.remove_listener(&listener_id).await;
            }
            rollback_minted_persona(config, persona_id, state, profile, prior_friendly_name);
            return;
        }
    };

    // 9. Record the pending membership and persist.
    let record = build_pending_record(
        vtc_did.clone(),
        display_name,
        sub_context_id,
        persona_id,
        request_id,
        Utc::now(),
        submit_transport,
    );
    config.account.add_membership(record.clone());
    if let Err(e) = save_config(config, profile) {
        state
            .join
            .fail(format!("Failed to save community record: {e}"));
        return;
    }

    // 10. Sent — refresh the communities panel and surface the relaunch prompt.
    //
    // "Sent", not "delivered". Every word below is deliberately about what this
    // client actually witnessed: `submit_join_request` resolves `Ok` when *our
    // own mediator* accepts the frame, which says nothing about whether the
    // community's mediator received it or the community ever read it. Claiming
    // otherwise is R1.1 — a send `Ok` is not a delivery — and it is the reason a
    // join that died two hops away read here as an unqualified success while the
    // community's log showed no trace of it.
    //
    // The acknowledgement is asynchronous and cannot be waited for here: the
    // join flow's `select!` loop reads UI actions only, so the inbound dispatch
    // that reconciles a receipt (`CommunityRecord::receipt_at`) does not run
    // until this sequence returns. `pending_unacknowledged` flags the record in
    // the communities panel if nothing arrives within `PENDING_ACK_GRACE_SECS`,
    // so the honest thing to do here is name what is still outstanding and point
    // at where the answer will show up.
    //
    // What the pre-submit connect changed is *where* an early reply waits, not
    // when it is read: the persona's socket is up, so a reply that arrives
    // during this window is streamed and queued on the DIDComm event channel for
    // the runtime loop to drain, rather than sitting unstreamed in a mailbox
    // whose owner never connected.
    state.main_page.sync_from_config(config);
    // Durable, unlike the ceremony commentary in `state.join`, which is
    // transient UI and gone on the next launch. A submitted join is the thing
    // you most want a record of when it does not complete.
    //
    // Whether the applicant was connected is part of that record. A join
    // submitted from an unconnected persona is still valid — the community
    // admits, and `Messaging::pickup_stored` collects the reply when the socket
    // comes up — but it is the one that takes the slow path, and an operator
    // reading this log later cannot otherwise tell that from a community that
    // never answered.
    config.public.logs.insert(
        LogFamily::Community,
        format!(
            "Join request sent to ({}) as persona ({}) over {} — Pending, not yet acknowledged.{}",
            state.join.display_name.as_deref().unwrap_or(&vtc_did),
            persona_did,
            submit_transport,
            if applicant_online {
                ""
            } else {
                " The applicant was not connected at submit; a reply that arrives before it \
                 connects is collected from the mediator rather than streamed."
            }
        ),
    );
    state.main_page.log(format!(
        "Join request sent over {submit_transport} — Pending in your Communities list, awaiting \
         the community's acknowledgement."
    ));
    state.join.created_community = Some(record);
    state.join.created_persona_did = Some(persona_did.clone());
    state.join.completed = Completion::CompletedOK;
    state.join.info(format!(
        "Join request sent over {submit_transport}. Waiting for the community to acknowledge it — \
         it's Pending in your Communities list, which will flag it if no response arrives."
    ));
}

/// How long the join sequence waits for the applicant persona's mediator socket
/// before submitting anyway (R1.2: the wait is finite).
///
/// The connect is an authenticate + websocket upgrade + live-delivery toggle
/// against a mediator that is, by definition, reachable — the same mediator this
/// process is already talking to for the admin session. Ten seconds is generous
/// for that and short enough that a mediator having a bad minute costs the
/// operator a pause, not the join: the submit goes out either way.
const PERSONA_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Install the applicant persona's mediator listener so its socket is coming up
/// while the rest of the sequence runs. Paired with [`await_persona_online`],
/// which does the waiting at the submit.
///
/// Returns the listener id **only when this call installed one** — that is the
/// caller's handle for tearing it down if the join then fails or is cancelled.
/// `None` covers every case where there is nothing to undo: no messaging service
/// (State-A), a reused persona that is already live, or an install that failed.
///
/// Failure is never fatal. A join whose applicant could not connect is still a
/// valid join: it is submitted, the community still admits, and the reply waits
/// in the mailbox for the persona's listener to pick up — on the mediator's
/// redelivery when the socket does come up, or on the next launch. So the
/// outcome is reported and the sequence continues (R6.4: the operator is told
/// what happened, not handed one generic hint).
async fn start_persona_listener(
    handler: &StateHandler,
    state: &mut State,
    messaging: Option<&Messaging>,
    config: &Config,
    tdk: &TDK,
    persona_id: PersonaId,
    applicant_did: &str,
) -> Option<String> {
    // State-A has no service to install into. The degraded loop restarts into
    // the full pipeline after a first join, and startup registration brings the
    // persona up there.
    let service = messaging?;
    let listener_id = openvtc_core::didcomm::persona_listener_id(applicant_did);

    // A reused persona already serving another community has its socket — the
    // one identity, one listener rule (D1/D11). Re-adding would error on the
    // duplicate id, and it is not ours to claim: tearing it down on a cancelled
    // join would take the other community's session with it.
    if service.has_listener(&listener_id).await {
        return None;
    }

    let Some(spec) =
        openvtc_core::didcomm::persona_listener_config_for(config, tdk, persona_id).await
    else {
        // The mint wrote this identity moments ago, so this is unexpected — but
        // it costs the join nothing, so log it and carry on.
        debug!(
            persona = %applicant_did,
            "no listener config for the applicant persona; submitting without a live session"
        );
        return None;
    };
    if let Err(e) = openvtc_core::didcomm::add_listener(service, &spec).await {
        state.join.info(format!(
            "Couldn't open this persona's mediator session ({e}) — submitting anyway; the \
             community's reply will be collected when it connects."
        ));
        let _ = handler.state_tx.send(state.clone());
        return None;
    }

    state
        .join
        .info("Connecting the new persona to its mediator…");
    let _ = handler.state_tx.send(state.clone());
    Some(listener_id)
}

/// Wait — bounded — for the applicant persona's socket to be live, immediately
/// before the join request goes out.
///
/// Split from [`start_persona_listener`] so the connect overlaps the invitation
/// resolution and VP build rather than adding to them; by the time this runs the
/// answer is normally already `Connected` and it returns at once. A persona with
/// no listener at all (State-A, or an install that failed) is nothing to wait
/// for, and the submit proceeds either way.
/// Returns whether the applicant was live at the moment of the submit — which
/// the durable join record then states, because "sent while offline" is the one
/// fact that explains a join taking the slow (collect-on-connect) path, and it
/// has to survive the relaunch you make to go looking.
async fn await_persona_online(
    handler: &StateHandler,
    state: &mut State,
    messaging: Option<&Messaging>,
    applicant_did: &str,
) -> bool {
    let Some(service) = messaging else {
        return false;
    };
    let listener_id = openvtc_core::didcomm::persona_listener_id(applicant_did);
    if !service.has_listener(&listener_id).await {
        return false;
    }

    let online = match service
        .wait_connected(&listener_id, PERSONA_CONNECT_TIMEOUT)
        .await
    {
        Ok(()) => {
            state
                .join
                .info("Persona connected — ready to receive the community's reply.");
            true
        }
        Err(e) => {
            // Installed but not up yet. The listener's own restart policy keeps
            // working on it, so this is a slow connect, not a dead one.
            debug!(listener = %listener_id, error = %e, "applicant persona not connected before submit");
            state.join.info(
                "The persona's mediator session is still connecting — submitting now; the \
                 community's reply will be collected once it is up.",
            );
            false
        }
    };
    let _ = handler.state_tx.send(state.clone());
    online
}

/// Persist the config, abstracting over the openpgp-card touch prompt.
/// Roll back a just-minted persona when a later join step fails before the
/// persona is bound to a community. The mint (`mint_persona_into`) persists the
/// persona record + runtime identity + key info *before* the submit; without
/// this, a failed join (e.g. a submit error) leaves an orphan persona in the
/// account — a spurious identity with no membership, which then confuses the
/// active-identity display. Best-effort re-save; the VTA-side keys are cleaned
/// separately via the DID manager.
fn rollback_minted_persona(
    config: &mut Config,
    persona_id: PersonaId,
    state: &State,
    profile: &str,
    prior_friendly_name: &str,
) {
    config.account.personas.remove(&persona_id);
    config.identities.remove(&persona_id);
    if let Some(keys) = &state.setup.did_keys {
        config.key_info.remove(&keys.signing.secret.id);
        config.key_info.remove(&keys.authentication.secret.id);
        config.key_info.remove(&keys.decryption.secret.id);
    }
    // `mint_persona_into` set `public.friendly_name` to the attempted community's
    // persona name; restore the pre-mint value so a failed/cancelled join doesn't
    // leave the self-display name pointing at a community we never joined.
    config.public.friendly_name = prior_friendly_name.to_string();
    if let Err(e) = save_config(config, profile) {
        debug!("persona rollback re-save failed after a failed join: {e}");
    }
}

fn save_config(config: &Config, profile: &str) -> Result<(), openvtc_core::errors::OpenVTCError> {
    config.save(
        profile,
        #[cfg(feature = "openpgp-card")]
        &|| {
            eprintln!("Touch confirmation needed for decryption");
        },
    )
}

/// Race a sequence future against the interrupt channel (R15).
///
/// Returns `None` if `sequence` completed first, or `Some(interrupted)` if an
/// interrupt arrived while it was still running — in which case `sequence` is
/// DROPPED (cancelled at its current `.await` point) by the `select!`. Dropping
/// the future is what makes Ctrl-C / Exit take effect within ~1 s even while a
/// network await is parked; the caller is responsible for any state cleanup the
/// dropped future may have left behind (e.g. a persisted-but-unbound persona).
async fn race_against_interrupt<F>(
    sequence: F,
    interrupt_rx: &mut broadcast::Receiver<Interrupted>,
) -> Option<Interrupted>
where
    F: std::future::Future<Output = ()>,
{
    tokio::select! {
        () = sequence => None,
        Ok(interrupted) = interrupt_rx.recv() => Some(interrupted),
    }
}

#[cfg(test)]
mod tests {
    //! R15: these tests cover the *select-against-interrupt wiring* in
    //! isolation — i.e. that an interrupt delivered while the join sequence is
    //! still running wins the race, drops the sequence future, and surfaces the
    //! interrupt. The full end-to-end cancel-safety property (a Ctrl-C against a
    //! live/unreachable VTA leaves no persisted-but-unbound persona) needs a real
    //! `StateHandler` + `TDK` + VTA session and is NOT unit-testable here; it is
    //! covered by manual verification and the in-code rollback at the cancel site
    //! (`join_flow` → `rollback_minted_persona` when `!persona_referenced`).

    use super::race_against_interrupt;
    use super::{
        build_pending_record, is_duplicate_membership, joined_session, load_pasted_vic,
        start_persona_listener, validate_join_input,
    };
    use crate::Interrupted;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::join::JoinState;
    use crate::state_handler::setup_sequence::MessageType;
    use crate::state_handler::state::State;
    use crate::state_handler::{StartingMode, StateHandler};
    use affinidi_tdk::{TDK, common::config::TDKConfig};
    use openvtc_core::config::account::{CommunityRecord, CommunityStatus, PersonaId};
    use openvtc_core::didcomm::Messaging;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::broadcast;

    // ---- Pure-decision tests (peeled out of the join sequence) ----

    /// `validate_join_input` trims and rejects empties; otherwise returns the
    /// cleaned DID. Table-driven over (raw input, expected).
    #[test]
    fn validate_join_input_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("", None),
            ("   ", None),
            ("\t\n", None),
            ("did:webvh:example", Some("did:webvh:example")),
            ("  did:webvh:example  ", Some("did:webvh:example")),
            ("\tdid:peer:abc\n", Some("did:peer:abc")),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                validate_join_input(raw).as_deref(),
                *expected,
                "validate_join_input({raw:?})"
            );
        }
    }

    /// `is_duplicate_membership` mirrors `Account::live_community`: live
    /// (Active/Pending) memberships are duplicates; inactive ones and unknown
    /// DIDs are not. Table-driven over the membership status.
    #[test]
    fn is_duplicate_membership_table() {
        // (status to register for "did:vtc:known", is_duplicate?)
        let cases: &[(Option<CommunityStatus>, bool)] = &[
            (None, false),
            (
                Some(CommunityStatus::Pending {
                    request_id: uuid::Uuid::new_v4(),
                }),
                true,
            ),
            (Some(CommunityStatus::Active), true),
            (Some(CommunityStatus::Left), false),
            (Some(CommunityStatus::Rejected), false),
            (Some(CommunityStatus::Removed), false),
            (Some(CommunityStatus::Expired), false),
        ];
        let vtc = "did:vtc:known";
        let persona = PersonaId::new();
        for (status, expected) in cases {
            let mut config = test_config();
            if let Some(status) = status {
                let mut rec = CommunityRecord::new_pending(
                    vtc.to_string(),
                    None,
                    "ctx/slug".to_string(),
                    persona,
                    uuid::Uuid::new_v4(),
                    chrono::Utc::now(),
                );
                rec.status = status.clone();
                config.account.add_membership(rec);
            }
            assert_eq!(
                is_duplicate_membership(&config, vtc, persona),
                *expected,
                "is_duplicate_membership for status {status:?}"
            );
            // An unrelated DID is never a duplicate regardless of registered state.
            assert!(
                !is_duplicate_membership(&config, "did:vtc:other", persona),
                "unknown DID is not a duplicate (status {status:?})"
            );
            // The same community as a *different* persona is not a duplicate.
            assert!(
                !is_duplicate_membership(&config, vtc, PersonaId::new()),
                "different persona is not a duplicate (status {status:?})"
            );
        }
    }

    /// `build_pending_record` produces a `Pending` record carrying the submit
    /// inputs (vtc/display name/sub-context/persona/request id/requested_at).
    #[test]
    fn build_pending_record_carries_inputs() {
        let persona = PersonaId::new();
        let request_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let rec = build_pending_record(
            "did:vtc:c".to_string(),
            Some("Community".to_string()),
            "top/slug".to_string(),
            persona,
            request_id,
            now,
            openvtc_core::didcomm::MessagingTransport::Tsp,
        );
        assert_eq!(rec.vtc_did, "did:vtc:c");
        assert_eq!(rec.display_name.as_deref(), Some("Community"));
        assert_eq!(rec.sub_context_id, "top/slug");
        assert_eq!(rec.persona_ref, persona);
        assert_eq!(rec.requested_at, Some(now));
        assert_eq!(
            rec.submit_transport,
            Some(openvtc_core::didcomm::MessagingTransport::Tsp),
            "the record remembers which transport carried the submit"
        );
        assert!(rec.is_live(), "a fresh Pending record is live");
        match rec.status {
            CommunityStatus::Pending { request_id: got } => {
                assert_eq!(got, request_id, "request id is carried into the status");
            }
            other => panic!("expected Pending status, got {other:?}"),
        }
    }

    #[test]
    fn joined_session_extracted_only_on_success() {
        // No persisted community → nothing for the runtime loop to register (R-B-5).
        let mut js = JoinState::default();
        assert!(joined_session(&js).is_none());

        // A successful sequence leaves the record + persona did → a session.
        let persona = PersonaId::new();
        let rec = build_pending_record(
            "did:vtc:c".to_string(),
            None,
            "top/slug".to_string(),
            persona,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            openvtc_core::didcomm::MessagingTransport::DidComm,
        );
        js.created_community = Some(rec);
        js.created_persona_did = Some("did:webvh:persona".to_string());

        let joined = joined_session(&js).expect("a persisted community yields a session");
        assert_eq!(joined.persona_id, persona);
        assert_eq!(joined.persona_did, "did:webvh:persona");
        assert_eq!(joined.vtc_did, "did:vtc:c");
    }

    #[tokio::test]
    async fn completes_when_no_interrupt() {
        let (_tx, mut rx) = broadcast::channel::<Interrupted>(4);
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = ran.clone();
        let outcome = race_against_interrupt(
            async move {
                ran2.store(true, Ordering::SeqCst);
            },
            &mut rx,
        )
        .await;
        assert!(outcome.is_none(), "no interrupt → sequence wins the race");
        assert!(
            ran.load(Ordering::SeqCst),
            "sequence future ran to completion"
        );
    }

    #[tokio::test]
    async fn interrupt_cancels_pending_sequence() {
        let (tx, mut rx) = broadcast::channel::<Interrupted>(4);
        // Deliver the interrupt before the race so the recv arm is immediately
        // ready; the sequence is a never-completing future, so the only way to
        // return is via the interrupt arm dropping it.
        tx.send(Interrupted::UserInt).expect("send interrupt");
        let completed = Arc::new(AtomicBool::new(false));
        let completed2 = completed.clone();
        let outcome = race_against_interrupt(
            async move {
                std::future::pending::<()>().await;
                // Unreachable: the future is dropped at the await above.
                completed2.store(true, Ordering::SeqCst);
            },
            &mut rx,
        )
        .await;
        assert!(
            matches!(outcome, Some(Interrupted::UserInt)),
            "interrupt wins and is surfaced: {outcome:?}"
        );
        assert!(
            !completed.load(Ordering::SeqCst),
            "pending sequence future was dropped, not run to completion"
        );
    }

    #[tokio::test]
    async fn surfaces_os_sigint_variant() {
        let (tx, mut rx) = broadcast::channel::<Interrupted>(4);
        tx.send(Interrupted::OsSigInt).expect("send interrupt");
        let outcome = race_against_interrupt(std::future::pending::<()>(), &mut rx).await;
        assert!(
            matches!(outcome, Some(Interrupted::OsSigInt)),
            "the specific interrupt variant propagates: {outcome:?}"
        );
    }

    // ---- `load_pasted_vic`: the paste row on the invitation step ----

    const COMMUNITY: &str = "did:webvh:example.com:community";

    /// A complete, presentable VIC — every field `validate_invitation_credential`
    /// requires, issued by [`COMMUNITY`] and not yet expired.
    fn pasteable_vic(id: &str) -> serde_json::Value {
        json!({
            // The DTG wire form, as `dtg-credentials` mints it — both required
            // contexts and the `DTGCredential` base type. A fixture that omits
            // them is not a VIC a community could have issued.
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://firstperson.network/credentials/dtg/v1"
            ],
            "id": id,
            "type": ["VerifiableCredential", "DTGCredential", "InvitationCredential"],
            "issuer": COMMUNITY,
            "credentialSubject": { "id": "did:webvh:example.com:alice" },
            "validUntil": "2099-01-01T00:00:00Z",
            "credentialStatus": { "type": "BitstringStatusListEntry" },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    fn first_error(state: &State) -> Option<&str> {
        state.join.messages.iter().find_map(|m| match m {
            MessageType::Error(e) => Some(e.as_str()),
            _ => None,
        })
    }

    #[test]
    fn a_matching_paste_becomes_the_selected_invitation() {
        let mut state = State::default();
        load_pasted_vic(
            &mut state,
            &pasteable_vic("urn:uuid:one").to_string(),
            Some(COMMUNITY),
        );
        assert_eq!(state.join.invitation_options.len(), 1);
        assert_eq!(state.join.invitation_options[0].id, "urn:uuid:one");
        // Selected, so the next Enter presents it rather than needing an arrow.
        assert_eq!(state.join.invitation_use_selected, 0);
        assert!(state.join.has_invitation);
        assert_eq!(first_error(&state), None);
    }

    #[test]
    fn re_pasting_the_same_invitation_reselects_rather_than_duplicates() {
        let mut state = State::default();
        let vic = pasteable_vic("urn:uuid:one").to_string();
        load_pasted_vic(&mut state, &vic, Some(COMMUNITY));
        load_pasted_vic(&mut state, &vic, Some(COMMUNITY));
        assert_eq!(state.join.invitation_options.len(), 1);
        assert_eq!(state.join.invitation_use_selected, 0);
    }

    /// Each rejection has to say *why*. A paste that silently fails to load is
    /// indistinguishable from one that was never made, and the operator then
    /// sends an open request believing they presented a credential.
    #[test]
    fn every_rejection_reports_its_reason() {
        // Wrong community.
        let mut other = pasteable_vic("urn:uuid:one");
        other["issuer"] = json!("did:webvh:example.com:elsewhere");
        // Expired.
        let mut expired = pasteable_vic("urn:uuid:one");
        expired["validUntil"] = json!("2000-01-01T00:00:00Z");
        // Right shape, wrong document — not an InvitationCredential.
        let not_a_vic = json!({ "id": "urn:uuid:one", "type": ["VerifiableCredential"] });

        let cases: &[(&str, String, &str)] = &[
            ("not JSON", "}{ not json".to_string(), "not valid JSON"),
            ("not a VIC", not_a_vic.to_string(), "not usable"),
            ("wrong community", other.to_string(), "different community"),
            ("expired", expired.to_string(), "expired"),
        ];
        for (name, text, expect) in cases {
            let mut state = State::default();
            load_pasted_vic(&mut state, text, Some(COMMUNITY));
            let err =
                first_error(&state).unwrap_or_else(|| panic!("{name}: expected a reported reason"));
            assert!(
                err.contains(expect),
                "{name}: reason should mention {expect:?}, got {err:?}"
            );
            assert!(
                state.join.invitation_options.is_empty(),
                "{name}: a rejected paste must not become a presentable row"
            );
        }
    }

    /// On the entry page the community is not chosen yet, so the paste is only
    /// shape-checked and stashed — `collect_available_vics` matches it later.
    #[test]
    fn an_entry_page_paste_is_stashed_without_a_community_check() {
        let mut state = State::default();
        let mut elsewhere = pasteable_vic("urn:uuid:one");
        elsewhere["issuer"] = json!("did:webvh:example.com:elsewhere");
        load_pasted_vic(&mut state, &elsewhere.to_string(), None);
        assert!(state.invitation_credential.is_some());
        assert!(state.join.has_invitation);
        assert!(!state.join.vic_cleared);
        // No row is added: the invitation step has not been reached.
        assert!(state.join.invitation_options.is_empty());
        assert_eq!(first_error(&state), None);
    }

    /// The entry-page paste records the VIC's issuer, which *is* the community
    /// being joined. The entry page prefills its DID input from this, so an
    /// operator holding an invitation never has to find and retype a DID the
    /// credential already carries (issue #29).
    #[test]
    fn an_entry_page_paste_records_the_issuing_community() {
        let mut state = State::default();
        load_pasted_vic(&mut state, &pasteable_vic("urn:uuid:one").to_string(), None);
        assert_eq!(state.join.invitation_issuer.as_deref(), Some(COMMUNITY));
    }

    /// `issuer` also has an object form; both must yield the community DID, or
    /// the prefill silently stops working for half the issuers out there.
    #[test]
    fn an_object_form_issuer_is_recorded_too() {
        let mut state = State::default();
        let mut vic = pasteable_vic("urn:uuid:one");
        vic["issuer"] = json!({ "id": COMMUNITY, "name": "Example Community" });
        load_pasted_vic(&mut state, &vic.to_string(), None);
        assert_eq!(state.join.invitation_issuer.as_deref(), Some(COMMUNITY));
    }

    /// A rejected paste must not leave an issuer behind: the entry page would
    /// prefill a community DID from a credential it refused to load, and the
    /// operator would join without the invitation they thought they presented.
    #[test]
    fn a_rejected_entry_page_paste_records_no_issuer() {
        let not_a_vic = json!({ "id": "urn:uuid:one", "type": ["VerifiableCredential"] });
        for text in ["}{ not json", &not_a_vic.to_string()] {
            let mut state = State::default();
            load_pasted_vic(&mut state, text, None);
            assert_eq!(state.join.invitation_issuer, None, "for paste {text:?}");
            assert!(!state.join.has_invitation);
        }
    }

    // ---- Pre-submit persona connect ----
    //
    // What `start_persona_listener` returns is an *ownership claim*: the cancel
    // and submit-failure paths remove whatever id they are handed, so handing
    // back one this call did not install would tear down a socket serving
    // something else. Both no-op paths are covered here; the install-and-connect
    // path needs a live mediator and is covered by the messaging e2e suite.

    /// Offline TDK — no environment load, no network.
    async fn test_tdk() -> TDK {
        TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .expect("TDK config builds"),
            None,
        )
        .await
        .expect("TDK builds")
    }

    /// State-A runs with no messaging service at all. Nothing is installed, so
    /// nothing is claimed — and a cancel has nothing to remove.
    #[tokio::test]
    async fn without_a_messaging_service_nothing_is_claimed() {
        let (handler, _state_rx) = StateHandler::new("test", StartingMode::NotSet);
        let mut state = State::default();
        let config = test_config();
        let tdk = test_tdk().await;

        let claimed = start_persona_listener(
            &handler,
            &mut state,
            None,
            &config,
            &tdk,
            PersonaId::new(),
            "did:webvh:example.com:applicant",
        )
        .await;

        assert!(claimed.is_none(), "no service means no listener to own");
    }

    /// A persona the config cannot resolve to an identity yields no listener
    /// config, so no listener is installed and none is claimed. The join carries
    /// on regardless — an applicant that cannot connect still gets admitted.
    #[tokio::test]
    async fn an_unresolvable_persona_is_not_claimed() {
        let (handler, _state_rx) = StateHandler::new("test", StartingMode::NotSet);
        let mut state = State::default();
        // `test_config` has no identities, so any persona id is unresolvable.
        let config = test_config();
        let tdk = test_tdk().await;
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = Messaging::start(event_tx);

        let claimed = start_persona_listener(
            &handler,
            &mut state,
            Some(&service),
            &config,
            &tdk,
            PersonaId::new(),
            "did:webvh:example.com:applicant",
        )
        .await;

        assert!(
            claimed.is_none(),
            "an uninstalled listener must never be claimed"
        );
        service.shutdown().await;
    }
}
