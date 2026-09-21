/*! VTA client wrapper functions for the setup flow */

use affinidi_tdk::TDK;
use affinidi_tdk::did_common::Document;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use anyhow::Result;
use chrono::Utc;
use openvtc_core::config::{KeyInfo, PersonaDIDKeys, secured_config::KeySourceMaterial};
use std::future::Future;
use std::time::Duration;
use tracing::warn;
use vta_sdk::{
    client::{CreateDidWebvhRequest, CreateKeyRequest, VtaClient},
    error::VtaError,
    keys::KeyType,
    protocols::did_management::create::WebvhPathMode,
    session::{TokenResult, challenge_response},
    webvh::WebvhServerRecord,
};

/// Max attempts for a single VTA round-trip before giving up (1 try + 2 retries).
const VTA_MAX_ATTEMPTS: usize = 3;

/// Base back-off between retries; doubles each attempt (0.5s, then 1s). Short,
/// because the dominant retryable fault is a stale DIDComm socket that ATM
/// re-establishes almost immediately — we just need a beat before re-sending.
const VTA_RETRY_BASE: Duration = Duration::from_millis(500);

/// True for errors a retry might clear: transport/timeout faults where the
/// request most likely never reached the VTA (or its reply never came back).
///
/// The motivating case is a stale always-on DIDComm session — the mediator
/// dropped the idle WebSocket, the first `send_and_wait` packed into a dead
/// socket and timed out, but ATM auto-reconnects underneath, so the *next* send
/// lands on a live socket and succeeds. REST `Network` and 5xx `Server` errors
/// are transient the same way. Deterministic faults (validation, conflict,
/// not-found, auth, gone) are never retried — re-sending can't change them.
fn vta_retryable(e: &VtaError) -> bool {
    matches!(
        e,
        VtaError::DidcommTransport(_) | VtaError::Network(_) | VtaError::Server { .. }
    )
}

/// Run a single VTA round-trip with bounded retry on transient transport faults
/// (see [`vta_retryable`]). `op` is re-invoked from scratch each attempt, so it
/// must rebuild any by-value request — and the caller must be content with a
/// possible duplicate on the rare "VTA processed it but the reply was lost"
/// timeout. That's a non-issue for reads (`get_key_secret`, `list_*`) and cheap
/// for `create_key` (at worst an orphan key); the join flow already rolls back a
/// half-minted persona. `label` names the op for the retry log line.
pub(crate) async fn vta_retry<T, F, Fut>(label: &str, mut op: F) -> Result<T, VtaError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, VtaError>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < VTA_MAX_ATTEMPTS && vta_retryable(&e) => {
                let backoff = VTA_RETRY_BASE * (1 << (attempt - 1));
                warn!(
                    "VTA '{label}' failed (attempt {attempt}/{VTA_MAX_ATTEMPTS}): {e} — \
                     retrying in {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The message prefix every TSP reply-timeout carries, from the SDK's own
/// `TSP_REPLY_TIMEOUT_PREFIX`. Matched as a literal because the SDK keeps both
/// that constant and `VtaError::is_tsp_reply_timeout` `pub(crate)`, so there is
/// no public predicate to ask — the prefix is documented as the stable shared
/// signature between its producers, which makes it the least-bad handle. If the
/// SDK ever exports the predicate, use it instead.
const TSP_REPLY_TIMEOUT_PREFIX: &str = "timed out waiting for the TSP reply";

/// How the SDK renders a Trust Task rejected with the framework's
/// `internalError` code: `trust task failed [internalError]: …`. Matched as a
/// literal because that rejection has no typed variant — it arrives as
/// [`VtaError::Protocol`].
const INTERNAL_ERROR_MARKER: &str = "[internalError]";

/// Render a [`VtaError`] with what an operator can act on (R6.4).
///
/// The raw `Display` is written for a developer reading a stack of SDK errors,
/// not for someone watching a join fail: `tsp transport error: timed out waiting
/// for the TSP reply to request 'urn:uuid:…'` names a transport and a UUID and
/// nothing an operator can do. R6.4 asks that the text let them tell
/// network-unreachable from auth-rejected from contract-mismatch, so this
/// appends the SDK's own [`VtaError::suggested_fix`] — which exists for exactly
/// this, non-CLI consumers that would otherwise fork the CLI's dispatch.
///
/// A TSP reply-timeout gets a line of its own, because it is the one failure
/// whose plain reading is actively misleading. It looks like "the VTA is
/// unreachable", and the VTA is almost always fine: a trust task that the VTA
/// has to relay onward (minting a DID means calling the hosting server) reports
/// *its* leg's silence in the same words as our own. Observed live: the VTA
/// accepted the task, called the hosting server, the hosting server answered
/// promptly and the VTA refused every answer as malformed — an hour of the
/// operator's time went on a message that said "timed out". Whose leg it is
/// decides which log to open, so say so here.
fn explain(e: &VtaError) -> String {
    let mut out = e.to_string();
    if matches!(e, VtaError::TspTransport(msg) if msg.starts_with(TSP_REPLY_TIMEOUT_PREFIX)) {
        out.push_str(
            "\nThe request reached the VTA; what went unanswered is a TSP leg. \
             Check the VTA's log for the peer it was waiting on — if the task \
             is one the VTA relays onward (minting a DID calls the hosting \
             server), the silent leg is that peer's, not ours.",
        );
    }
    // An upstream peer failing is not the VTA failing. A VTA new enough to
    // say so answers `taskFailed` / `upstream_unavailable`, which the SDK
    // recovers as the same `Server { status: 502 }` a REST call produces.
    if matches!(
        e,
        VtaError::Server {
            status: 502 | 504,
            ..
        }
    ) {
        out.push_str(
            "\nA service the VTA had to call did not answer or refused — minting \
             a DID calls the DID hosting server. Neither this request nor the \
             VTA is at fault; the VTA's log names the service and why.",
        );
    }
    // An `internalError` carries fixed text on purpose — the cause stays in the
    // VTA's log — and its "the request itself was accepted" reads, on a join
    // screen, like a partial success. It is not: nothing was created.
    if matches!(e, VtaError::Protocol(msg) if msg.contains(INTERNAL_ERROR_MARKER)) {
        out.push_str(
            "\nNothing was created. \"Accepted\" only means the request was \
             well-formed; the VTA failed while carrying it out and kept the cause \
             in its own log — look for \"trust task failed\" at this time. An \
             older VTA reports a DID hosting server that did not answer this way \
             too.",
        );
    }
    if let Some(fix) = e.suggested_fix() {
        out.push('\n');
        out.push_str(fix);
    }
    out
}

/// Authenticate with VTA using REST challenge-response. Only valid for the
/// REST transport — DIDComm-only VTAs authenticate implicitly when the
/// session opens.
pub async fn authenticate(
    vta_url: &str,
    credential_did: &str,
    private_key_multibase: &str,
    vta_did: &str,
) -> Result<TokenResult> {
    challenge_response(vta_url, credential_did, private_key_multibase, vta_did)
        .await
        .map_err(|e| anyhow::anyhow!("VTA authentication failed: {e}"))
}

/// Create persona keys via VTA service
/// Creates 3 keys: Ed25519 signing, Ed25519 auth, X25519 encryption
/// Returns PersonaDIDKeys with VtaManaged source
pub async fn create_persona_keys(
    client: &VtaClient,
    context_id: Option<&str>,
) -> Result<PersonaDIDKeys> {
    let created = Utc::now();

    // Signing key (Ed25519)
    let sign_resp = vta_retry("create persona signing key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona-signing".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create signing key: {e}"))?;

    let sign_secret_resp = vta_retry("get persona signing key secret", || {
        client.get_key_secret(&sign_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get signing key secret: {e}"))?;

    let mut sign_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    sign_secret.id = sign_secret.get_public_keymultibase()?;

    let signing = KeyInfo {
        secret: sign_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: sign_resp.key_id,
        },
        expiry: None,
        created,
    };

    // Authentication key (Ed25519)
    let auth_resp = vta_retry("create persona authentication key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona-authentication".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create authentication key: {e}"))?;

    let auth_secret_resp = vta_retry("get persona authentication key secret", || {
        client.get_key_secret(&auth_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get authentication key secret: {e}"))?;

    let mut auth_secret = vta_sdk::did_key::secret_from_key_response(&auth_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    auth_secret.id = auth_secret.get_public_keymultibase()?;

    let authentication = KeyInfo {
        secret: auth_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: auth_resp.key_id,
        },
        expiry: None,
        created,
    };

    // Encryption key (X25519)
    let enc_resp = vta_retry("create persona encryption key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::X25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona-encryption".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create encryption key: {e}"))?;

    let enc_secret_resp = vta_retry("get persona encryption key secret", || {
        client.get_key_secret(&enc_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get encryption key secret: {e}"))?;

    let mut enc_secret = vta_sdk::did_key::secret_from_key_response(&enc_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    enc_secret.id = enc_secret.get_public_keymultibase()?;

    let decryption = KeyInfo {
        secret: enc_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: enc_resp.key_id,
        },
        expiry: None,
        created,
    };

    Ok(PersonaDIDKeys {
        signing,
        authentication,
        decryption,
    })
}

/// Create WebVH update keys via VTA service
/// Returns (update_secret, next_update_secret)
pub async fn create_update_keys(
    client: &VtaClient,
    context_id: Option<&str>,
) -> Result<(Secret, Secret)> {
    // Update key (Ed25519)
    let update_resp = vta_retry("create WebVH update key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("webvh-update".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create WebVH update key: {e}"))?;

    let update_secret_resp = vta_retry("get WebVH update key secret", || {
        client.get_key_secret(&update_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get WebVH update key secret: {e}"))?;

    let update_secret = vta_sdk::did_key::secret_from_key_response(&update_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Next update key (Ed25519)
    let next_update_resp = vta_retry("create WebVH next-update key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("webvh-next-update".to_string()),
            context_id: context_id.map(|s| s.to_string()),
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create WebVH next update key: {e}"))?;

    let next_update_secret_resp = vta_retry("get WebVH next-update key secret", || {
        client.get_key_secret(&next_update_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get WebVH next update key secret: {e}"))?;

    let next_update_secret = vta_sdk::did_key::secret_from_key_response(&next_update_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    Ok((update_secret, next_update_secret))
}

/// List WebVH servers available from the VTA
pub async fn list_webvh_servers(client: &VtaClient) -> Result<Vec<WebvhServerRecord>> {
    let result = vta_retry("list WebVH servers", || client.list_webvh_servers())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list WebVH servers: {}", explain(&e)))?;
    Ok(result.servers)
}

/// Create a DID via a WebVH server
/// Returns (PersonaDIDKeys, did, Document, mnemonic)
///
/// # Callers must surface the TSP warning
///
/// This requests `#tsp` unconditionally, but the VTA drops it unless it has
/// `[services] tsp` configured with a mediator — silently, and the resulting
/// persona looks entirely healthy while being unable to reach a TSP-only
/// community. A `warn!` is emitted here so the log always carries it, but the
/// operator is looking at a TUI, not a log. Pass the returned `Document` to
/// [`tsp_advertisement_warning`] and show what it returns.
///
/// [`tsp_advertisement_warning`]: openvtc_core::config::did::tsp_advertisement_warning
pub async fn create_did_via_server(
    client: &VtaClient,
    tdk: &TDK,
    context_id: &str,
    server_id: &str,
    path_mode: WebvhPathMode,
) -> Result<(PersonaDIDKeys, String, Document, String)> {
    let created = Utc::now();

    // `path_mode` is the authoritative path selector (WellKnown / Explicit /
    // AutoAssign). The legacy `path` field carries the same answer, from
    // `to_request_path()` — which is `None` for auto-assign, so the field is
    // still omitted there (the server rejects a present-but-empty path with
    // `e.p.did.path-invalid`, and an omitted one *is* the auto-assign
    // contract).
    //
    // Sending both is not belt-and-braces for its own sake: a VTA that predates
    // `path_mode` ignores the field it does not know, and silently auto-assigns
    // a mnemonic — so an operator who typed a path would get a random one and
    // no error. With the legacy field carrying it too, such a VTA honours the
    // path instead. A VTA that does know `path_mode` prefers it (see
    // `WebvhPathMode::resolve`), and the two never disagree because both come
    // from the same value.
    let legacy_path = path_mode.to_request_path().map(str::to_string);

    // Use the VTA's built-in mediator service rather than additional_services,
    // because the VTA formats the service ID as a full DID URL (e.g. "did:...#vta-didcomm")
    // which the TDK resolver requires. A relative fragment like "#public-didcomm" is rejected.
    // Built fresh on each attempt inside the retry closure: `create_did_webvh`
    // consumes the request by value and `CreateDidWebvhRequest` is not `Clone`.
    let result = vta_retry("create DID via WebVH server", || {
        let req = CreateDidWebvhRequest {
            context_id: context_id.to_string(),
            server_id: Some(server_id.to_string()),
            url: None,
            path: legacy_path.clone(),
            path_mode: Some(path_mode.clone()),
            // No explicit hosting-domain override: the server determines the
            // domain from the selected `server_id`.
            domain: None,
            label: None,
            portable: true,
            add_mediator_service: true,
            // Advertise `#tsp` at the same mediator, so a peer's both-ends
            // transport match can actually resolve to TSP for this persona.
            // Without it the document carries one `DIDCommMessaging` entry and
            // the intersection is DIDComm however much TSP the rest of the
            // stack speaks — which is what #211 diagnosed and could only work
            // around by degrading.
            //
            // Safe to assert unconditionally from here, from both sides:
            // ours, because a persona's inbound TSP arrives on the mediator
            // socket `DidCommTransport` already owns and surfaces by protocol
            // (see `openvtc_core::tsp`) — we can read what we advertise; and
            // the VTA's, because it drops the entry unless it has `[services]
            // tsp` on with a mediator configured, so a DIDComm-only VTA still
            // mints exactly the document it minted before.
            add_tsp_service: true,
            additional_services: None,
            pre_rotation_count: 1,
            did_document: None,
            did_log: None,
            set_primary: false,
            signing_key_id: None,
            ka_key_id: None,
            template: None,
            template_context: None,
            template_vars: std::collections::HashMap::new(),
        };
        client.create_did_webvh(req)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create DID via WebVH server: {}", explain(&e)))?;

    let did = result.did.clone();
    let mnemonic = result.mnemonic.clone().unwrap_or_default();

    // Fetch signing key secret (#key-0 = Ed25519)
    let sign_secret_resp = vta_retry("get WebVH DID signing key secret", || {
        client.get_key_secret(&result.signing_key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get signing key secret: {e}"))?;

    let mut sign_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    // Set the secret ID to the DID verification method ID
    sign_secret.id = format!("{}#key-0", did);

    let signing = KeyInfo {
        secret: sign_secret.clone(),
        source: KeySourceMaterial::VtaManaged {
            key_id: result.signing_key_id.clone(),
        },
        expiry: None,
        created,
    };

    // Authentication uses the same Ed25519 key (#key-0)
    let authentication = KeyInfo {
        secret: sign_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: result.signing_key_id,
        },
        expiry: None,
        created,
    };

    // Fetch KA key secret (#key-1 = X25519)
    let ka_secret_resp = vta_retry("get WebVH DID KA key secret", || {
        client.get_key_secret(&result.ka_key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get KA key secret: {e}"))?;

    let mut ka_secret = vta_sdk::did_key::secret_from_key_response(&ka_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    ka_secret.id = format!("{}#key-1", did);

    let decryption = KeyInfo {
        secret: ka_secret,
        source: KeySourceMaterial::VtaManaged {
            key_id: result.ka_key_id,
        },
        expiry: None,
        created,
    };

    let persona_keys = PersonaDIDKeys {
        signing,
        authentication,
        decryption,
    };

    // Resolve the DID to get the document
    let resolved = tdk
        .did_resolver()
        .resolve(&did)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve created DID: {e}"))?;

    // We asked for `#tsp` above; the VTA is entitled to refuse (it drops the
    // entry unless it has `[services] tsp` on with a mediator). Record here,
    // once, whether it actually granted it — this is the only place every mint
    // passes through, so a caller cannot forget to look. The user-facing half is
    // each caller's activity log, via `tsp_advertisement_warning`.
    if openvtc_core::config::did::advertises_tsp(&resolved.doc) {
        tracing::debug!(%did, "minted persona advertises #tsp");
    } else {
        tracing::warn!(
            %did,
            "minted persona has no #tsp service — the VTA did not grant the one we \
             requested (needs `[services] tsp` with a mediator). This persona cannot \
             reach a TSP-only community and the document will not gain the service later."
        );
    }

    Ok((persona_keys, did, resolved.doc, mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn retryable_covers_transport_and_5xx_only() {
        // Transient transport / server faults — retry may clear them.
        assert!(vta_retryable(&VtaError::DidcommTransport("timeout".into())));
        assert!(vta_retryable(&VtaError::Server {
            status: 503,
            body: String::new(),
        }));
        // Deterministic faults — re-sending can't change the outcome.
        assert!(!vta_retryable(&VtaError::Validation("bad".into())));
        assert!(!vta_retryable(&VtaError::Conflict("dup".into())));
        assert!(!vta_retryable(&VtaError::NotFound("gone".into())));
        assert!(!vta_retryable(&VtaError::Auth("expired".into())));
    }

    #[tokio::test(start_paused = true)]
    async fn returns_immediately_on_success() {
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = vta_retry("ok", || {
            calls.set(calls.get() + 1);
            async { Ok(7) }
        })
        .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.get(), 1, "no retry when the first attempt succeeds");
    }

    #[tokio::test(start_paused = true)]
    async fn retries_transient_then_succeeds() {
        // Models a stale socket: first send times out, ATM reconnects, second
        // send lands. The op should be retried and ultimately succeed.
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = vta_retry("stale-then-ok", || {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < 2 {
                    Err(VtaError::DidcommTransport("stale socket".into()))
                } else {
                    Ok(9)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 9);
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_attempts() {
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = vta_retry("always-down", || {
            calls.set(calls.get() + 1);
            async { Err(VtaError::DidcommTransport("down".into())) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), VTA_MAX_ATTEMPTS as u32);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_deterministic_error() {
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = vta_retry("validation", || {
            calls.set(calls.get() + 1);
            async { Err(VtaError::Validation("nope".into())) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), 1, "deterministic faults are not retried");
    }

    /// The failure that cost an hour of log-reading: the VTA relayed the
    /// mint onward to the DID hosting server, the hosting server answered
    /// but in a dialect the VTA refused, and all the operator saw was
    /// "timed out". The plain reading — "the VTA is unreachable" — sends
    /// them to the wrong log, so the text has to name the leg.
    #[test]
    fn a_tsp_reply_timeout_says_which_leg_went_quiet() {
        let out = explain(&VtaError::TspTransport(
            "timed out waiting for the TSP reply to request 'urn:uuid:fa7c223d'".into(),
        ));
        // The original is kept — the request id is what ties the TUI line to
        // the VTA's own log entry for the same task.
        assert!(out.contains("urn:uuid:fa7c223d"), "{out}");
        assert!(out.contains("reached the VTA"), "{out}");
        assert!(out.contains("hosting"), "{out}");
        // And the SDK's own hint, rather than a second one forked here.
        assert_eq!(
            out.lines().last(),
            VtaError::TspTransport(String::new())
                .suggested_fix()
                .map(str::trim),
            "the closing line is the SDK hint verbatim: {out}"
        );
    }

    /// REGRESSION (2026-09-21): a join failed because the DID hosting server
    /// never answered the VTA, and the screen said only "internal error: the
    /// consumer could not complete this task; the request itself was
    /// accepted" — which reads as a fault in the user's own VTA, and as though
    /// something had half-happened.
    #[test]
    fn an_internal_error_says_nothing_was_created_and_where_the_cause_is() {
        let out = explain(&VtaError::Protocol(
            "trust task failed [internalError]: internal error: the consumer could not \
             complete this task; the request itself was accepted"
                .into(),
        ));
        assert!(out.contains("request itself was accepted"), "{out}");
        assert!(out.contains("Nothing was created"), "{out}");
        assert!(out.contains("VTA") && out.contains("log"), "{out}");
    }

    /// A VTA that names an upstream failure (a `502`) points at that service,
    /// not at the VTA or the request.
    #[test]
    fn an_upstream_failure_points_at_the_service_the_vta_called() {
        let out = explain(&VtaError::Server {
            status: 502,
            body: "task failed: a service this VTA depends on did not answer".into(),
        });
        assert!(out.contains("hosting server"), "{out}");
        assert!(!out.contains("Nothing was created. \"Accepted\""), "{out}");
    }

    /// Any other protocol error is not an `internalError` and must not be told
    /// that nothing was created — it may be a caller fault with its own fix.
    #[test]
    fn a_plain_protocol_error_gets_no_internal_error_note() {
        let out = explain(&VtaError::Protocol(
            "trust task failed [malformedRequest]: payload parse".into(),
        ));
        assert!(!out.contains("Nothing was created"), "{out}");
    }

    /// Every other TSP transport fault — a seal or socket failure — is a
    /// genuinely local one, so it must *not* be told it reached the VTA.
    #[test]
    fn a_non_timeout_tsp_fault_is_not_blamed_on_a_far_leg() {
        let out = explain(&VtaError::TspTransport("failed to seal frame".into()));
        assert!(!out.contains("reached the VTA"), "{out}");
        assert!(out.contains("failed to seal frame"), "{out}");
    }
}
