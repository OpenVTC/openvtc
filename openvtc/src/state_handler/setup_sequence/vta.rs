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
        .map_err(|e| anyhow::anyhow!("Failed to list WebVH servers: {e}"))?;
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
    // AutoAssign). The legacy `path` field is left `None` — the server rejects a
    // present-but-empty path with `e.p.did.path-invalid`.

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
            path: None,
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
    .map_err(|e| anyhow::anyhow!("Failed to create DID via WebVH server: {e}"))?;

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
}
