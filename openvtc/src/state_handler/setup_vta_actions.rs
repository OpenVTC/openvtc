use crate::env_overrides::WizardUrlOverride;
use crate::state_handler::{
    setup_sequence::{Completion, MessageType, RebuildOutcome, SetupPage},
    state::State,
};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use vta_sdk::client::{ClientIdentity, VtaClient};
use vta_sdk::provision_client::{
    DiagStatus, EphemeralSetupKey, Protocol, ProvisionAsk, VtaEvent, VtaIntent, VtaReply,
    apply_update, pending_list, provision_admin_rotated_via_rest, run_connection_test,
};

/// Env var that pins the VTA's REST base URL, bypassing `did:webvh`/DIDComm
/// resolution. Honoured only by a `dev-overrides` build: set it (e.g.
/// `http://127.0.0.1:8080`) to point the bootstrap at a local/loopback VTA whose
/// DID does not resolve back to that URL — the integration-test seam. When
/// honoured, bootstrap talks plain REST to this URL and provisions URL-direct
/// via `provision_admin_rotated_via_rest` (which never re-resolves the VTA DID).
/// A release build ignores it and says so on the enter-DID page.
const VTA_URL_OVERRIDE_ENV: &str = crate::env_overrides::VTA_URL_VAR;

/// [`VTA_URL_OVERRIDE_ENV`] after trimming (blank reads as unset) and the
/// `dev-overrides` gate.
fn vta_url_override() -> WizardUrlOverride {
    crate::env_overrides::wizard_vta_url_override(normalize_url_override(
        std::env::var(VTA_URL_OVERRIDE_ENV).ok(),
    ))
}

/// How the post-bootstrap `VtaClient` must authenticate, given the transport
/// the bootstrap actually completed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostBootstrapAuth {
    /// Reopen the mediator-backed session (TSP or DIDComm) as the rotated admin
    /// DID. The session's proven sender identity *is* the authentication.
    Session(Protocol),
    /// REST challenge-response against the advertised base URL.
    Rest,
    /// REST with nothing to talk to — the VTA advertises no `#vta-rest`
    /// service, so there is no base URL to authenticate against.
    RestWithoutUrl,
}

/// Pure core of the post-bootstrap transport decision.
///
/// Deliberately matches `Protocol` exhaustively, with no wildcard arm: a
/// wildcard is what silently routed the TSP bootstrap into REST auth, where the
/// empty base URL became reqwest's opaque "builder error". Adding a transport
/// upstream should break this build, not quietly fall back to REST.
fn post_bootstrap_auth(protocol: Option<Protocol>, has_rest_url: bool) -> PostBootstrapAuth {
    match protocol {
        Some(Protocol::Tsp) => PostBootstrapAuth::Session(Protocol::Tsp),
        Some(Protocol::DidComm) => PostBootstrapAuth::Session(Protocol::DidComm),
        // `None` means provisioning never reported a transport. It only reaches
        // here on the URL-direct override path, which is REST by construction.
        Some(Protocol::Rest) | None => {
            if has_rest_url {
                PostBootstrapAuth::Rest
            } else {
                PostBootstrapAuth::RestWithoutUrl
            }
        }
    }
}

/// Pure core of [`vta_url_override`]: trim and drop blank/whitespace-only
/// values so an exported-but-empty env var reads as unset.
fn normalize_url_override(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Handle the `VtaSubmitDid` action: resolve the VTA service URL from the
/// supplied DID and mint an ephemeral did:key the operator will authorise via
/// PNM in the next step. On success we transition to `VtaAclInstructions`; on
/// failure we stay on `VtaEnterDid` so the operator can edit and resubmit.
pub(crate) async fn handle_vta_submit_did(
    state: &mut State,
    state_tx: &watch::Sender<State>,
    vta_did: String,
) -> anyhow::Result<()> {
    // The transition from StartAsk → VtaEnterDid is a UI-only navigation
    // (handle_nav_result doesn't round-trip through the backend), so the
    // backend's active_page is still StartAsk at this point. Pin it to
    // VtaEnterDid before pushing the first state update so the UI doesn't
    // momentarily re-render StartAsk while we resolve the URL.
    state.setup.active_page = SetupPage::VtaEnterDid;
    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    state.setup.vta.vta_did = vta_did.clone();

    // OPENVTC_VTA_URL override (dev-overrides builds only): skip DID resolution
    // and talk plain REST to the pinned URL. Lets bootstrap target a
    // loopback/dev VTA whose DID can't be resolved back to its URL (the
    // integration-test seam). DIDComm is not used on this path — provisioning
    // goes URL-direct in `handle_vta_start_provision`. A release build ignores
    // the variable, says so here, and resolves the DID as normal.
    let url_override = vta_url_override();
    if let WizardUrlOverride::Ignored(message) = &url_override {
        state
            .setup
            .vta
            .messages
            .push(MessageType::Info(format!("Warning: {message}")));
    }
    if let WizardUrlOverride::Active(url) = url_override {
        state.setup.vta.messages.push(MessageType::Info(format!(
            "DEV OVERRIDE: {VTA_URL_OVERRIDE_ENV} set — using REST endpoint {url} \
             (skipping DID resolution)."
        )));
        let _ = state_tx.send(state.clone());
        state.setup.vta.vta_url = url;
        state.setup.vta.mediator_did = None;
    } else {
        state.setup.vta.messages.push(MessageType::Info(
            "Resolving VTA service endpoint…".to_string(),
        ));
        let _ = state_tx.send(state.clone());

        // Use `resolve_vta` (not `resolve_vta_url`) so we get an honest answer:
        // `rest_url` is `Some` only when the DID document advertises a `#vta-rest`
        // service, and `mediator_did` is `Some` only when it advertises a DIDComm
        // mediator. `resolve_vta_url` synthesizes a fake URL from the DID's
        // domain on the assumption REST exists — which lies on DIDComm-only VTAs.
        let resolved = match vta_sdk::provision_client::resolve_vta(&vta_did).await {
            Ok(r) => r,
            Err(e) => {
                state.setup.vta.messages.push(MessageType::Error(format!(
                    "Could not resolve {vta_did}: {e}"
                )));
                state.setup.vta.completed = Completion::CompletedFail;
                return Ok(());
            }
        };

        if resolved.rest_url.is_none() && resolved.mediator_did.is_none() {
            state.setup.vta.messages.push(MessageType::Error(format!(
                "{vta_did} advertises neither a REST endpoint nor a DIDComm mediator. \
                 The VTA cannot be reached online."
            )));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(());
        }

        state.setup.vta.vta_url = resolved.rest_url.clone().unwrap_or_default();
        state.setup.vta.mediator_did = resolved.mediator_did.clone();
        match (&resolved.rest_url, &resolved.mediator_did) {
            (Some(url), Some(med)) => {
                state
                    .setup
                    .vta
                    .messages
                    .push(MessageType::Info(format!("REST: {url}")));
                state
                    .setup
                    .vta
                    .messages
                    .push(MessageType::Info(format!("DIDComm mediator: {med}")));
            }
            (Some(url), None) => state.setup.vta.messages.push(MessageType::Info(format!(
                "REST: {url} (DIDComm not advertised)"
            ))),
            (None, Some(med)) => state.setup.vta.messages.push(MessageType::Info(format!(
                "DIDComm-only VTA — mediator: {med}"
            ))),
            (None, None) => unreachable!("guarded above"),
        }
    }

    // Mint the ephemeral admin did:key. Held in memory only — a fresh key is
    // generated if the wizard restarts, and the operator must re-run the PNM
    // ACL step for the new DID.
    let setup_key = match EphemeralSetupKey::generate() {
        Ok(k) => Arc::new(k),
        Err(e) => {
            state.setup.vta.messages.push(MessageType::Error(format!(
                "Could not generate setup did:key: {e}"
            )));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(());
        }
    };
    state.setup.vta.messages.push(MessageType::Info(format!(
        "Setup DID minted: {}",
        setup_key.did
    )));
    state.setup.vta.setup_key = Some(setup_key);
    state.setup.vta.completed = Completion::CompletedOK;
    state.setup.active_page = SetupPage::VtaAclInstructions;
    let _ = state_tx.send(state.clone());

    Ok(())
}

/// Handle the `VtaStartProvision` action: spawn `run_connection_test` against
/// the VTA, drain its `VtaEvent` stream into the diagnostics list, and on
/// success store the issued admin VC + access token. The provisioning page
/// itself emits `VtaAuthCompleted` once the operator confirms, which routes
/// into the keys-fetch / webvh-server pick flow.
///
/// On success it returns the live admin [`VtaClient`] (DIDComm session opened as
/// the rotated admin DID, or a REST client). The caller (the setup wizard) holds
/// this **single** session and reuses it for the key/DID-creation steps, then
/// shuts it down once when setup ends — so the admin DID keeps **one** mediator
/// connection for the whole flow instead of opening a fresh WebSocket per VTA
/// call (which churns the mediator's one-socket-per-DID policy and drops
/// in-flight responses). Returns `Ok(None)` if provisioning did not complete.
pub(crate) async fn handle_vta_start_provision(
    state: &mut State,
    state_tx: &watch::Sender<State>,
    context_id: String,
) -> anyhow::Result<Option<VtaClient>> {
    use crate::state_handler::setup_sequence::vta;

    let setup_key = match state.setup.vta.setup_key.clone() {
        Some(k) => k,
        None => {
            state.setup.vta.messages.push(MessageType::Error(
                "Setup DID not generated yet — restart the setup wizard.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            return Ok(None);
        }
    };
    let vta_did = state.setup.vta.vta_did.clone();
    // Persist the operator's chosen context id so downstream config writes use
    // the same value.
    state.setup.vta.context_id = Some(context_id.clone());

    state.setup.active_page = SetupPage::VtaProvisioning;
    state.setup.vta.messages.clear();
    state.setup.vta.completed = Completion::NotFinished;
    let _ = state_tx.send(state.clone());

    // AdminRotated mints a fresh long-term admin DID on the VTA side; the
    // ephemeral setup did:key only authenticates the bootstrap call. The reply
    // arrives as `VtaReply::AdminOnly` on both transports.
    let ask = ProvisionAsk::vta_admin_rotated(context_id.clone()).with_label("openvtc");
    let setup_did = setup_key.did.clone();
    let setup_priv = setup_key.private_key_multibase().to_string();

    let mut admin_reply: Option<vta_sdk::provision_client::AdminCredentialReply> = None;
    let mut connect_rest_url: Option<String> = None;
    let mut connect_mediator_did: Option<String> = None;
    let mut connect_protocol: Option<Protocol> = None;

    if let WizardUrlOverride::Active(url) = vta_url_override() {
        // URL-direct: one REST round-trip to the pinned URL via the SDK's
        // URL-direct AdminRotated entry — no DID resolution, no DIDComm, no
        // diagnostics stream (it never re-resolves the VTA DID). The REST
        // branch below then authenticates + builds the client against `url`.
        match provision_admin_rotated_via_rest(&url, &vta_did, setup_did, setup_priv, ask).await {
            Ok(adm) => {
                admin_reply = Some(adm);
                connect_protocol = Some(Protocol::Rest);
                connect_rest_url = Some(url);
            }
            Err(e) => {
                state.setup.vta.messages.push(MessageType::Error(format!(
                    "URL-direct provisioning failed: {e}"
                )));
                state.setup.vta.completed = Completion::CompletedFail;
                let _ = state_tx.send(state.clone());
            }
        }
    } else {
        state.setup.vta.diagnostics = pending_list();
        let _ = state_tx.send(state.clone());

        let (tx, mut rx) = mpsc::unbounded_channel::<VtaEvent>();
        let runner_vta_did = vta_did.clone();
        tokio::spawn(async move {
            run_connection_test(
                VtaIntent::AdminRotated,
                runner_vta_did,
                setup_did,
                setup_priv,
                ask,
                None,
                tx,
            )
            .await;
        });

        while let Some(ev) = rx.recv().await {
            match ev {
                VtaEvent::CheckStart(check) => {
                    apply_update(&mut state.setup.vta.diagnostics, check, DiagStatus::Running);
                }
                VtaEvent::CheckDone(check, status) => {
                    apply_update(&mut state.setup.vta.diagnostics, check, status);
                }
                VtaEvent::Resolved(resolved) => {
                    if let Some(rest) = resolved.rest_url.clone() {
                        state.setup.vta.vta_url = rest;
                    }
                }
                VtaEvent::AttemptCompleted { .. } => {
                    // Per-transport telemetry; the diagnostics list already shows
                    // the operator-relevant outcome on the matching DiagCheck row.
                }
                VtaEvent::PreflightDone { .. } => {
                    // AdminOnly intent never reaches preflight — FullSetup-only.
                }
                VtaEvent::Connected {
                    protocol,
                    rest_url,
                    mediator_did,
                    reply,
                } => {
                    connect_protocol = Some(protocol);
                    connect_rest_url = rest_url;
                    connect_mediator_did = mediator_did;
                    if let VtaReply::AdminOnly(adm) = reply {
                        admin_reply = Some(adm);
                    }
                }
                VtaEvent::Failed(reason) => {
                    state
                        .setup
                        .vta
                        .messages
                        .push(MessageType::Error(reason.clone()));
                    state.setup.vta.completed = Completion::CompletedFail;
                    let _ = state_tx.send(state.clone());
                }
            }
            let _ = state_tx.send(state.clone());
        }
    }

    let Some(admin) = admin_reply else {
        if matches!(state.setup.vta.completed, Completion::NotFinished) {
            state.setup.vta.messages.push(MessageType::Error(
                "Provisioning ended without an admin credential.".to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            let _ = state_tx.send(state.clone());
        }
        return Ok(None);
    };

    // Adopt the admin credential as the authenticated identity for the rest
    // of setup. Mirrors what the legacy paste-bundle flow used to do.
    state.setup.vta.credential_did = admin.admin_did.clone();
    if let Some(rest) = connect_rest_url {
        state.setup.vta.vta_url = rest;
    }
    if let Some(ref mediator) = connect_mediator_did
        && state.setup.custom_mediator.is_none()
    {
        state.setup.custom_mediator = Some(mediator.clone());
    }
    state.setup.vta.protocol = connect_protocol;
    state.setup.vta.mediator_did = connect_mediator_did;

    // Build the post-bootstrap VtaClient on the same transport the bootstrap
    // chose. TSP and DIDComm → open a fresh session as the rotated admin DID;
    // the session itself is the auth (both carry a proven sender identity the
    // VTA resolves straight to its ACL grant), so no separate token round-trip
    // is needed. REST → challenge-response auth + bearer token.
    //
    // Both mediator-backed transports MUST be handled explicitly. Falling
    // through to the REST arm on a VTA that advertises no `#vta-rest` service
    // leaves `vta_url` empty, and the SDK's `format!("{base_url}/auth/challenge")`
    // then yields the relative `/auth/challenge`, which reqwest rejects as an
    // opaque "builder error" — the bootstrap succeeds and the very next step
    // fails with no hint that the transport was the problem.
    let client = match post_bootstrap_auth(connect_protocol, !state.setup.vta.vta_url.is_empty()) {
        PostBootstrapAuth::Session(transport) => {
            let label = transport.label();
            let mediator = match state.setup.vta.mediator_did.clone() {
                Some(m) => m,
                None => {
                    state.setup.vta.messages.push(MessageType::Error(format!(
                        "{label} transport selected but no mediator DID was advertised."
                    )));
                    state.setup.vta.completed = Completion::CompletedFail;
                    let _ = state_tx.send(state.clone());
                    return Ok(None);
                }
            };
            state.setup.vta.messages.push(MessageType::Info(format!(
                "Opening {label} session as rotated admin DID…"
            )));
            let _ = state_tx.send(state.clone());

            let rest_fallback = if state.setup.vta.vta_url.is_empty() {
                None
            } else {
                Some(state.setup.vta.vta_url.clone())
            };
            let opened = if transport == Protocol::Tsp {
                VtaClient::connect_tsp(
                    &admin.admin_did,
                    &admin.admin_private_key_mb,
                    &vta_did,
                    &mediator,
                    rest_fallback,
                )
                .await
            } else {
                VtaClient::connect_didcomm(
                    &admin.admin_did,
                    &admin.admin_private_key_mb,
                    &vta_did,
                    &mediator,
                    rest_fallback,
                )
                .await
            };
            match opened {
                Ok(c) => {
                    state.setup.vta.authenticated = true;
                    state.setup.vta.admin_credential = Some(admin.clone());
                    state.setup.vta.messages.push(MessageType::Info(format!(
                        "{label} session established with VTA."
                    )));
                    c
                }
                Err(e) => {
                    state.setup.vta.messages.push(MessageType::Error(format!(
                        "{label} session open failed: {e}"
                    )));
                    state.setup.vta.completed = Completion::CompletedFail;
                    let _ = state_tx.send(state.clone());
                    return Ok(None);
                }
            }
        }
        PostBootstrapAuth::RestWithoutUrl => {
            // Say this plainly rather than letting the SDK build a relative
            // `/auth/challenge` and surface reqwest's "builder error", which
            // names neither the URL nor the transport.
            state.setup.vta.messages.push(MessageType::Error(
                "REST transport selected but the VTA DID document advertises no \
                 `#vta-rest` service, so there is no URL to authenticate against."
                    .to_string(),
            ));
            state.setup.vta.completed = Completion::CompletedFail;
            let _ = state_tx.send(state.clone());
            return Ok(None);
        }
        PostBootstrapAuth::Rest => {
            state
                .setup
                .vta
                .messages
                .push(MessageType::Info("Authenticating with VTA…".to_string()));
            let _ = state_tx.send(state.clone());

            let vta_url = state.setup.vta.vta_url.clone();
            match vta::authenticate(
                &vta_url,
                &admin.admin_did,
                &admin.admin_private_key_mb,
                &vta_did,
            )
            .await
            {
                Ok(token_result) => {
                    state.setup.vta.access_token = Some(token_result.access_token.clone());
                    state.setup.vta.authenticated = true;
                    state.setup.vta.admin_credential = Some(admin.clone());
                    state.setup.vta.messages.push(MessageType::Info(
                        "VTA authentication successful.".to_string(),
                    ));
                    // `new` + `set_token` is the shape vta-sdk 0.31 stopped
                    // accepting: a bearer token authenticates the connection,
                    // but SPEC §7.2 items 5b/7a want an in-band `recipient` and
                    // a document `proof`, which the client can only produce
                    // from the identity it signs as. Without it the very next
                    // Trust-Task dispatch on this client — the context probe
                    // below — fails with "authenticated but carries no
                    // ClientIdentity". `connect_auto`'s REST arm builds exactly
                    // this; this branch is hand-rolled only because the wizard
                    // needs the token itself to cache.
                    //
                    // `did_key`, not a struct literal: vta-sdk 0.32 lifted
                    // Trust-Task signing off `did:key` (VTI #1193), so an
                    // identity now says which verification method its proof
                    // names — `None` meaning "derive it", which only a
                    // `did:key` can. Provisioning mints the admin as a
                    // `did:key` (the bootstrap e2e asserts it), so this is the
                    // constructor that fits, and it puts that assumption in the
                    // call rather than leaving it implicit in an absent field.
                    VtaClient::authenticated(
                        &vta_url,
                        ClientIdentity::did_key(
                            admin.admin_did.clone(),
                            admin.admin_private_key_mb.clone(),
                            vta_did.clone(),
                        ),
                        token_result.access_token,
                    )
                    .await
                }
                Err(e) => {
                    state
                        .setup
                        .vta
                        .messages
                        .push(MessageType::Error(format!("Authentication failed: {e}")));
                    state.setup.vta.completed = Completion::CompletedFail;
                    let _ = state_tx.send(state.clone());
                    return Ok(None);
                }
            }
        }
    };

    // D5–D7: now that the session is authenticated, ask the context what it
    // already contains, *before* setup writes anything into it. Read-only, three
    // list calls, and the answer is ready by the time the operator presses
    // Enter — so the wizard can route through the "already in use" warning
    // without a pause the operator would experience as a hang.
    //
    // Deliberately not fatal: an outcome of `Unknown` means the wizard proceeds
    // exactly as it always has. Failing to inform the decision must not prevent
    // making it.
    let probe = openvtc_core::context_probe::probe(&client, &context_id).await;
    match &probe {
        openvtc_core::context_probe::ProbeOutcome::Occupied(contents) => {
            state.setup.vta.messages.push(MessageType::Info(format!(
                "This Trust Context already contains {}.",
                contents.summary()
            )));
        }
        openvtc_core::context_probe::ProbeOutcome::Unknown(reason) => {
            tracing::debug!("context probe inconclusive: {reason}");
        }
        openvtc_core::context_probe::ProbeOutcome::Empty => {}
    }
    state.setup.vta.context_probe = Some(probe);

    state.setup.vta.completed = Completion::CompletedOK;
    // Stay on VtaProvisioning so the operator can see the admin DID rotation
    // result (ephemeral setup DID → long-term admin DID) before advancing on
    // Enter.
    let _ = state_tx.send(state.clone());

    // Hand the live admin session back to the wizard. It is kept open and reused
    // for the key/DID-creation steps (one mediator connection for the whole
    // flow), then shut down once when setup ends.
    Ok(Some(client))
}

/// Handle [`RecoverPlanContext`](crate::state_handler::actions::Action::RecoverPlanContext):
/// work out what recovering this
/// Trust Context would restore, and show it.
///
/// Strictly read-only — `rebuild::plan` lists and verifies, `rebuild_apply`
/// is pure. Nothing reaches disk until the operator confirms on
/// [`SetupPage::RecoverConfirm`] (D5).
///
/// A failure here is recorded rather than propagated: the operator can still
/// go back and choose a different context, and losing the whole wizard because
/// a listing failed would be a worse outcome than a page that explains itself.
pub(crate) async fn handle_recover_plan_context(
    state: &mut State,
    state_tx: &watch::Sender<State>,
    client: &vta_sdk::client::VtaClient,
) {
    let context_id = state.setup.vta.context_id.clone().unwrap_or_default();
    let now = chrono::Utc::now();

    state.setup.active_page = SetupPage::RecoverConfirm;
    state.setup.vta.rebuild = None;
    let _ = state_tx.send(state.clone());

    let outcome = match openvtc_core::rebuild::plan(client, &context_id, now).await {
        Ok(plan) => {
            // Narrow the SDK key records to what the mapping needs. Only
            // active keys: a revoked key cannot back a working persona.
            let keys = match client
                .list_keys(0, 500, Some("active"), Some(&context_id))
                .await
            {
                Ok(resp) => resp
                    .keys
                    .into_iter()
                    .filter_map(|k| {
                        let key_type = match k.key_type {
                            vta_sdk::keys::KeyType::Ed25519 => {
                                openvtc_core::rebuild_apply::KeyPurposeHint::Signing
                            }
                            vta_sdk::keys::KeyType::X25519 => {
                                openvtc_core::rebuild_apply::KeyPurposeHint::Encryption
                            }
                            // A key type OpenVTC has no slot for is not an
                            // error — it simply backs no verification method
                            // this build knows how to use.
                            _ => return None,
                        };
                        Some(openvtc_core::rebuild_apply::KeyCandidate {
                            key_id: k.key_id,
                            label: k.label,
                            key_type,
                            created_at: k.created_at,
                        })
                    })
                    .collect::<Vec<_>>(),
                Err(e) => {
                    state.setup.vta.rebuild =
                        Some(Err(format!("could not list this context's keys: {e}")));
                    let _ = state_tx.send(state.clone());
                    return;
                }
            };

            let account = openvtc_core::rebuild_apply::apply(&plan, &keys, now);
            Ok(RebuildOutcome { plan, account })
        }
        Err(e) => Err(e.to_string()),
    };

    state.setup.vta.rebuild = Some(outcome);
    let _ = state_tx.send(state.clone());
}

#[cfg(test)]
mod tests {
    use super::{PostBootstrapAuth, Protocol, normalize_url_override, post_bootstrap_auth};

    /// The regression: a TSP bootstrap must reopen a TSP session, never fall
    /// back to REST auth. It used to land in the REST arm, and on a VTA with no
    /// `#vta-rest` service the empty base URL produced reqwest's "builder
    /// error" at `/auth/challenge` immediately after provisioning succeeded.
    #[test]
    fn tsp_bootstrap_reopens_a_tsp_session() {
        assert_eq!(
            post_bootstrap_auth(Some(Protocol::Tsp), false),
            PostBootstrapAuth::Session(Protocol::Tsp)
        );
    }

    /// A mediator-backed transport is authenticated by the session itself, so
    /// the presence of a REST URL must not divert it — the URL is only ever a
    /// fallback handed to the client, never a reason to switch transports.
    #[test]
    fn an_advertised_rest_url_does_not_divert_a_session_transport() {
        assert_eq!(
            post_bootstrap_auth(Some(Protocol::Tsp), true),
            PostBootstrapAuth::Session(Protocol::Tsp)
        );
        assert_eq!(
            post_bootstrap_auth(Some(Protocol::DidComm), true),
            PostBootstrapAuth::Session(Protocol::DidComm)
        );
    }

    #[test]
    fn didcomm_bootstrap_reopens_a_didcomm_session() {
        assert_eq!(
            post_bootstrap_auth(Some(Protocol::DidComm), false),
            PostBootstrapAuth::Session(Protocol::DidComm)
        );
    }

    #[test]
    fn rest_uses_challenge_response_when_a_url_was_advertised() {
        assert_eq!(
            post_bootstrap_auth(Some(Protocol::Rest), true),
            PostBootstrapAuth::Rest
        );
        // `None` is the URL-direct override path, REST by construction.
        assert_eq!(post_bootstrap_auth(None, true), PostBootstrapAuth::Rest);
    }

    /// REST with no advertised URL is a distinct, nameable failure rather than
    /// an attempt that dies inside reqwest.
    #[test]
    fn rest_without_a_url_is_its_own_outcome() {
        assert_eq!(
            post_bootstrap_auth(Some(Protocol::Rest), false),
            PostBootstrapAuth::RestWithoutUrl
        );
        assert_eq!(
            post_bootstrap_auth(None, false),
            PostBootstrapAuth::RestWithoutUrl
        );
    }

    #[test]
    fn override_unset_is_none() {
        assert_eq!(normalize_url_override(None), None);
    }

    #[test]
    fn override_blank_or_whitespace_is_none() {
        assert_eq!(normalize_url_override(Some(String::new())), None);
        assert_eq!(normalize_url_override(Some("   ".to_string())), None);
        assert_eq!(normalize_url_override(Some("\t\n".to_string())), None);
    }

    #[test]
    fn override_value_is_trimmed() {
        assert_eq!(
            normalize_url_override(Some("  http://127.0.0.1:8080  ".to_string())),
            Some("http://127.0.0.1:8080".to_string())
        );
    }
}
