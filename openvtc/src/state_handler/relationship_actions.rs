//! Relationship action handlers for the TUI.

use std::sync::Arc;

use crate::state_handler::setup_sequence::vta;
use affinidi_tdk::{
    TDK,
    affinidi_crypto::ed25519::ed25519_private_to_x25519,
    didcomm::Message,
    dids::{DID, PeerKeyRole},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use anyhow::Result;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek_bip32::DerivationPath;
use openvtc_core::didcomm::Messaging;
use openvtc_core::{
    config::{
        Config, KeyBackend, KeyTypes,
        account::RelationshipIdentifierDefault,
        secured_config::{KeyInfoConfig, KeySourceMaterial},
    },
    logs::LogFamily,
    relationships::{RelationshipRequestBody, RelationshipState, did_binding_proofs},
    tasks::TaskType,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

/// Build a trust-ping DIDComm message (used by the backgrounded ping path).
fn build_ping_message(from: &str, to: &str) -> Result<Message> {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    Ok(affinidi_tdk::didcomm::Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/trust-ping/2.0/ping".to_string(),
        serde_json::json!({"response_requested": true}),
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now)
    .expires_time(now + 60 * 5)
    .finalize())
}

/// Loop-thread plan for creating a relationship DID, plus everything the
/// *I/O-only* [`RDidPlan::create_io`] needs to run off the loop without touching
/// `Config`. Building this is the only step that reads/mutates `Config` (the
/// BIP32 path-pointer reservation); the actual key creation (VTA round-trip or
/// BIP32 derivation), did:peer build, and resolver insert all run in the task.
pub(crate) enum RDidPlan {
    /// BIP32: paths reserved on the loop thread (pointer already advanced); the
    /// task derives the keys from a clone of the root. The root is boxed to keep
    /// the enum compact (it is the largest field by far).
    Bip32 {
        root: Box<ed25519_dalek_bip32::ExtendedSigningKey>,
        v_path: String,
        e_path: String,
        mediator: String,
    },
    /// VTA: the task creates the keys on the always-on admin session (cloned —
    /// cheap, shares the connection pool).
    Vta {
        admin_vta: vta_sdk::client::VtaClient,
        mediator: String,
    },
}

/// The created relationship DID plus the `key_info` entries to record in
/// `Config` on the loop thread. The secrets themselves were already inserted into
/// the (shared, `Arc`-based) TDK resolver inside the task, so they are visible to
/// the loop's TDK; only the `Config` bookkeeping is left for `apply`.
pub(crate) struct CreatedRDid {
    pub(crate) r_did: String,
    pub(crate) key_info: Vec<(String, KeyInfoConfig)>,
}

/// Build the [`RDidPlan`] on the loop thread. For BIP32 this reserves two unique
/// derivation paths and advances `path_pointer` (the only `Config` mutation the
/// pre-send step makes); for VTA it just snapshots the owned client/backend.
pub(crate) fn plan_relationship_did(
    config: &mut Config,
    mediator: &str,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<RDidPlan> {
    match &config.key_backend {
        KeyBackend::Bip32 { seed, .. } => {
            // `ExtendedSigningKey` (ed25519-dalek-bip32 0.3) is not `Clone`, so
            // reconstruct an owned root from the persisted seed — the same
            // derivation the load path uses, and a pure function of the seed, so
            // the rebuilt root is identical to the live one.
            let root = Box::new(
                ed25519_dalek_bip32::ExtendedSigningKey::from_seed(
                    &base64::prelude::BASE64_URL_SAFE_NO_PAD
                        .decode(secrecy::ExposeSecret::expose_secret(seed))
                        .map_err(|e| anyhow::anyhow!("couldn't decode BIP32 seed: {e}"))?,
                )
                .map_err(|e| anyhow::anyhow!("couldn't rebuild BIP32 root: {e}"))?,
            );
            let v_path = format!("m/3'/1'/1'/{}'", config.private.relationships.path_pointer);
            config.private.relationships.path_pointer += 1;
            let e_path = format!("m/3'/1'/1'/{}'", config.private.relationships.path_pointer);
            config.private.relationships.path_pointer += 1;
            Ok(RDidPlan::Bip32 {
                root,
                v_path,
                e_path,
                mediator: mediator.to_string(),
            })
        }
        KeyBackend::Vta { .. } => {
            // The runtime always holds an admin VTA session for a VTA backend
            // (built at startup). If it doesn't, R-DID creation can't proceed —
            // surface that up front rather than parking the loop to open one.
            let admin_vta = admin_vta.cloned().ok_or_else(|| {
                anyhow::anyhow!("no VTA session available to create a relationship DID")
            })?;
            Ok(RDidPlan::Vta {
                admin_vta,
                mediator: mediator.to_string(),
            })
        }
    }
}

impl RDidPlan {
    fn mediator(&self) -> &str {
        match self {
            RDidPlan::Bip32 { mediator, .. } | RDidPlan::Vta { mediator, .. } => mediator,
        }
    }

    /// I/O-only relationship-DID creation, run inside the spawned task. Creates
    /// the keys (BIP32 derivation or VTA round-trip), builds the did:peer,
    /// registers the secrets in the shared TDK resolver, **and registers the new
    /// R-DID listener** (built from the just-minted secrets — no resolver lookup,
    /// no `Config`). Returns the `Config` `key_info` entries for the loop thread
    /// to record. Never touches `Config`.
    ///
    /// `service` + `remote_p_did` are only used to register the post-establishment
    /// R-DID listener, exactly as the old inline path did right after key creation.
    pub(crate) async fn create_io(
        self,
        tdk: &TDK,
        service: &Messaging,
        remote_p_did: &str,
    ) -> Result<CreatedRDid> {
        let mediator = self.mediator().to_string();
        // Mint the keys and capture each one's *source material* (BIP32 path or
        // VTA key id) in verification-then-encryption order. Note we do NOT record
        // the secret ids yet: a freshly generated `Secret` carries a placeholder id
        // (`generate_ed25519` → a random base64 string, `generate_x25519` →
        // `"x25519"`), and `generate_did_peer_from_secrets` below rewrites those
        // ids to the did:peer verification-method ids. `key_info` must be built
        // from the *rewritten* ids — see the comment on that step.
        let (mut v_secret, mut e_secret, v_source, e_source) = match self {
            RDidPlan::Bip32 {
                root,
                v_path,
                e_path,
                ..
            } => {
                let v_key = root.derive(&v_path.parse::<DerivationPath>()?)?;
                let e_key = root.derive(&e_path.parse::<DerivationPath>()?)?;
                let v_secret = Secret::generate_ed25519(None, Some(v_key.signing_key.as_bytes()));
                let e_secret = Secret::generate_x25519(
                    None,
                    Some(&ed25519_private_to_x25519(e_key.signing_key.as_bytes())),
                )?;
                // NOTE: v_key/e_key hold BIP32-derived signing-key bytes on the
                // stack; ed25519-dalek-bip32 does not Zeroize, a known limitation.
                drop(v_key);
                drop(e_key);
                (
                    v_secret,
                    e_secret,
                    KeySourceMaterial::Derived { path: v_path },
                    KeySourceMaterial::Derived { path: e_path },
                )
            }
            RDidPlan::Vta { admin_vta, .. } => {
                let (v_secret, e_secret, sign_key_id, enc_key_id) =
                    create_relationship_keys(&admin_vta).await?;
                (
                    v_secret,
                    e_secret,
                    KeySourceMaterial::VtaManaged {
                        key_id: sign_key_id,
                    },
                    KeySourceMaterial::VtaManaged { key_id: enc_key_id },
                )
            }
        };

        // Build the did:peer from the secrets. This REWRITES each secret's `id` to
        // the did:peer verification-method id (`{did}#key-1` for verification,
        // `{did}#key-2` for the key-agreement key).
        let mut keys = vec![
            (PeerKeyRole::Verification, &mut v_secret),
            (PeerKeyRole::Encryption, &mut e_secret),
        ];
        let r_did = DID::generate_did_peer_from_secrets(&mut keys, Some(mediator.clone()))
            .map_err(|e| anyhow::anyhow!("Failed to create relationship DID: {e}"))?;
        drop(keys);

        // Record `key_info` under the FINAL did:peer-relative secret ids (set by
        // the call above), pairing each with its source material. This MUST run
        // after the did:peer mint: the reload path (`Relationships::
        // generate_profiles`) only re-registers a stored secret when its id
        // `starts_with` the R-DID, and packs DIDComm as the R-DID using the
        // `#key-1`/`#key-2` verification-method ids. Persisting the pre-mint
        // placeholder ids (the historical bug) left the reloaded R-DID with no
        // usable key-agreement secret, so mediator authentication looped forever
        // ("sender has no usable key agreement key").
        let key_info: Vec<(String, KeyInfoConfig)> = vec![
            (
                v_secret.id.clone(),
                KeyInfoConfig {
                    path: v_source,
                    create_time: Utc::now(),
                    purpose: KeyTypes::RelationshipVerification,
                },
            ),
            (
                e_secret.id.clone(),
                KeyInfoConfig {
                    path: e_source,
                    create_time: Utc::now(),
                    purpose: KeyTypes::RelationshipEncryption,
                },
            ),
        ];

        // Register the new R-DID listener from the just-minted secrets (the old
        // inline path did this right after key creation; failure is non-fatal).
        let listener_config = super::didcomm::relationship_listener_config_from_secrets(
            &r_did,
            remote_p_did,
            &mediator,
            vec![v_secret.clone(), e_secret.clone()],
        );
        if let Err(e) = super::didcomm::add_listener(service, &listener_config).await {
            tracing::warn!(did = %r_did, error = %e, "failed to add R-DID listener");
        }

        // Register the secrets in the shared TDK resolver (visible to the loop's
        // TDK — same `Arc`-backed resolver).
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(v_secret)
            .await;
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(e_secret)
            .await;

        Ok(CreatedRDid { r_did, key_info })
    }
}

/// Create a relationship's signing (Ed25519) + encryption (X25519) keys via the
/// VTA and fetch their secrets, on the given (admin) session. Returns
/// `(v_secret, e_secret, signing_key_id, encryption_key_id)`.
async fn create_relationship_keys(
    client: &vta_sdk::client::VtaClient,
) -> Result<(Secret, Secret, String, String)> {
    use vta_sdk::client::CreateKeyRequest;
    use vta_sdk::keys::KeyType;

    info!("creating Ed25519 signing key via VTA...");
    let sign_resp = vta::vta_retry("create relationship signing key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("relationship-signing".to_string()),
            context_id: None,
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create signing key: {e}"))?;
    let sign_secret_resp = vta::vta_retry("get relationship signing key secret", || {
        client.get_key_secret(&sign_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get signing key secret: {e}"))?;
    let mut v_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    v_secret.id = v_secret.get_public_keymultibase()?;

    info!("creating X25519 encryption key via VTA...");
    let enc_resp = vta::vta_retry("create relationship encryption key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::X25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("relationship-encryption".to_string()),
            context_id: None,
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create encryption key: {e}"))?;
    let enc_secret_resp = vta::vta_retry("get relationship encryption key secret", || {
        client.get_key_secret(&enc_resp.key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to get encryption key secret: {e}"))?;
    let mut e_secret = vta_sdk::did_key::secret_from_key_response(&enc_secret_resp)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    e_secret.id = e_secret.get_public_keymultibase()?;

    Ok((v_secret, e_secret, sign_resp.key_id, enc_resp.key_id))
}

/// Insert a brand-new contact for `did` with `alias`, mirroring the insert tail
/// of `ProtectedConfig::add_contact` (the DID-resolution validation and the
/// duplicate-alias check both already happened — resolution in the task, the
/// dup-alias check on the loop thread in `prepare_submit`). Infallible by the
/// time it runs.
fn insert_contact(config: &mut Config, did: &Arc<String>, alias: Option<String>) {
    let contact = Arc::new(Contact {
        did: Arc::clone(did),
        alias: alias.clone(),
    });
    config
        .private
        .contacts
        .contacts
        .insert(Arc::clone(did), Arc::clone(&contact));
    if let Some(a) = &alias {
        config
            .private
            .contacts
            .aliases
            .insert(a.clone(), Arc::clone(&contact));
    }
    config.public.logs.insert(
        LogFamily::Contact,
        format!(
            "Added contact ({}) alias({})",
            did,
            alias.as_deref().unwrap_or("N/A")
        ),
    );
}

/// Build a DIDComm relationship request message, id `msg_id`, carrying the
/// proofs that bind `our_did` to this request ([`did_binding_proofs`]). The
/// id is fixed up front because the proofs sign it: the respondent's accept
/// threads on it, and it is the only thing the accept is correlated by.
#[allow(clippy::too_many_arguments)]
async fn create_request_message(
    msg_id: &str,
    from: &str,
    to: &str,
    reason: Option<&str>,
    our_did: &str,
    friendly_name: Option<&str>,
    did_signer: &Secret,
    persona_signer: &Secret,
) -> Result<Message> {
    let (did_proof, persona_proof) =
        did_binding_proofs(our_did, from, to, msg_id, did_signer, persona_signer).await?;
    let mut msg = super::didcomm::build_didcomm_message(
        openvtc_core::protocol_urls::RELATIONSHIP_REQUEST,
        json!(RelationshipRequestBody {
            reason: reason.map(|r| r.to_string()),
            did: our_did.to_string(),
            name: friendly_name.map(|n| n.to_string()),
            did_proof: Some(did_proof),
            persona_proof,
        }),
        from,
        to,
        None,
    )?;
    msg.id = msg_id.to_string();
    Ok(msg)
}

/// The key that proves control of `our_did` for a handshake: the persona's own
/// authentication key when `our_did` is the persona, else the R-DID's signing
/// key from the TDK's resolver.
pub(crate) async fn relationship_did_signer(
    tdk: &TDK,
    our_did: &str,
    persona_did: &str,
    persona_auth: &Secret,
) -> Result<Secret> {
    if our_did == persona_did {
        return Ok(persona_auth.clone());
    }
    openvtc_core::relationships::relationship_signing_secret(tdk, our_did)
        .await
        .ok_or_else(|| anyhow::anyhow!("the relationship DID's signing key is not loaded"))
}

// ============================================================
// State-handler dispatch wrappers
// ============================================================

use crate::state_handler::{
    actions::RelationshipAction, dispatch_util, main_page::content::RelationshipsMode,
    resolve_did_to_display, state::State,
};
use openvtc_core::config::protected_config::Contact;
use openvtc_core::relationships::Relationship as RelRecord;

/// Owned inputs for the *I/O-only* half of a relationship network dispatch.
///
/// R14: the loop thread builds this (doing the fast, local pre-send work — DID
/// validation, contact add, R-DID key creation + listener registration), then a
/// `tokio::spawn`ed task does the slow network send with these owned values and
/// reports the result back as a [`RelationshipOutcome`]. It borrows nothing tied
/// to the loop's `Config`/`TDK`: `Messaging` is `Arc`-cheap to clone and the
/// message/ids are owned, so the future is `'static` + `Send`.
pub(crate) struct RelationshipSend {
    service: Messaging,
    /// The listener id the message is sent through, resolved on the loop thread
    /// (`listener_id_for_did`) so the task needs no `Config`. Persona listener for
    /// handshake messages; R-DID listener once established.
    listener_id: String,
    to_did: Arc<String>,
    message: Box<Message>,
    /// What to mutate + log once the send result is known, applied on the loop
    /// thread by [`RelationshipOutcome::apply`].
    effect: RelationshipEffect,
}

/// A relationship network dispatch ready to run off the loop thread.
///
/// The loop thread builds one of these (pre-send work done synchronously) and
/// `tokio::spawn`s [`RelationshipJob::run`]; the resulting [`RelationshipOutcome`]
/// is applied back on the loop thread. Both variants own everything they touch.
pub(crate) enum RelationshipJob {
    /// Ping / request-VRC: a single DIDComm send (no key creation). Boxed to keep
    /// the enum small (the effect payload carries several owned ids).
    Send(Box<RelationshipSend>),
    /// Create a relationship request: optionally mint an R-DID + listener first
    /// (the VTA round-trip / BIP32 derivation runs off the loop), then send the
    /// request via the persona listener.
    Create(Box<CreateJob>),
    /// Remove: tear down the (optional) R-DID listener, then the loop thread
    /// removes the relationship/contact records.
    Remove {
        service: Messaging,
        /// `Some` only when the relationship used a dedicated R-DID listener.
        listener_id: Option<String>,
        remote_p_did: String,
    },
}

/// Owned inputs for the backgrounded "create relationship request" job. All
/// `Config`/`TDK` reads are snapshotted on the loop thread into owned values so
/// the task is `'static` + `Send`.
pub(crate) struct CreateJob {
    tdk: TDK,
    service: Messaging,
    /// `Some` ⇒ mint an R-DID first; `None` ⇒ use the persona DID directly.
    rdid_plan: Option<RDidPlan>,
    /// Our persona DID (message `from`, and the listener the request is sent via).
    persona_did: Arc<String>,
    /// The persona's authentication key, which signs the DID binding.
    persona_auth: Secret,
    /// The request's message id, chosen on the loop thread so the provisional
    /// record carries it before any accept can arrive.
    msg_id: Arc<String>,
    persona_listener_id: String,
    respondent_did: Arc<String>,
    reason: Option<String>,
    friendly_name: Option<String>,
    /// Contact to add for the respondent (the alias the user entered), when no
    /// contact exists yet. `None` ⇒ a contact already exists; don't touch it.
    /// The DID **resolution** validation runs in the task (it is the create
    /// path's only network call besides the send) so it stays off the loop; the
    /// contact insert itself happens in `apply` on the loop thread.
    add_contact_alias: Option<Option<String>>,
}

impl CreateJob {
    async fn run(self) -> RelationshipOutcome {
        let CreateJob {
            tdk,
            service,
            rdid_plan,
            persona_did,
            persona_auth,
            msg_id,
            persona_listener_id,
            respondent_did,
            reason,
            friendly_name,
            add_contact_alias,
        } = self;

        // 0. Validate the respondent DID resolves (the create path's only
        //    non-send network call). Today this happened inside `add_contact`
        //    *before* the send; on resolve failure no contact was added and the
        //    create bailed — reproduce that by failing here before any mutation
        //    is applied (the contact is only inserted in `apply` on a non-failed
        //    resolve). Only when we'd add a brand-new contact (the user supplied
        //    an alias / it didn't exist) does the old path resolve.
        let contact_to_add = if let Some(alias) = add_contact_alias {
            if let Err(e) = tdk.did_resolver().resolve(&respondent_did).await {
                return RelationshipOutcome {
                    effect: RelationshipEffect::Create {
                        respondent_did,
                        our_did: persona_did,
                        msg_id: Arc::clone(&msg_id),
                        used_r_did: rdid_plan.is_some(),
                        key_info: Vec::new(),
                        contact_to_add: None,
                    },
                    result: Err(format!("Couldn't resolve DID: {e}")),
                };
            }
            Some(alias)
        } else {
            None
        };

        // 1. Mint the R-DID + listener off the loop (if requested). A failure here
        //    aborts before any send and is reported as the create error.
        let (our_did, key_info, used_r_did) = match rdid_plan {
            Some(plan) => match plan.create_io(&tdk, &service, &respondent_did).await {
                Ok(created) => (Arc::new(created.r_did), created.key_info, true),
                Err(e) => {
                    return RelationshipOutcome {
                        effect: RelationshipEffect::Create {
                            respondent_did,
                            our_did: persona_did,
                            msg_id: Arc::clone(&msg_id),
                            used_r_did: true,
                            key_info: Vec::new(),
                            contact_to_add,
                        },
                        result: Err(format!("{e}")),
                    };
                }
            },
            None => (Arc::clone(&persona_did), Vec::new(), false),
        };

        // 2. Build + send the request via the persona listener (handshake uses
        //    persona DIDs for routing; the R-DID is carried in the body).
        let msg = match async {
            let did_signer =
                relationship_did_signer(&tdk, &our_did, &persona_did, &persona_auth).await?;
            create_request_message(
                &msg_id,
                &persona_did,
                &respondent_did,
                reason.as_deref(),
                &our_did,
                friendly_name.as_deref(),
                &did_signer,
                &persona_auth,
            )
            .await
        }
        .await
        {
            Ok(m) => m,
            Err(e) => {
                return RelationshipOutcome {
                    effect: RelationshipEffect::Create {
                        respondent_did,
                        our_did,
                        msg_id: Arc::clone(&msg_id),
                        used_r_did,
                        key_info,
                        contact_to_add,
                    },
                    result: Err(format!("{e}")),
                };
            }
        };
        let result =
            super::didcomm::send_message_via(&service, &msg, &persona_listener_id, &respondent_did)
                .await
                .map_err(|e| format!("{e}"));

        RelationshipOutcome {
            effect: RelationshipEffect::Create {
                respondent_did,
                our_did,
                msg_id,
                used_r_did,
                key_info,
                contact_to_add,
            },
            result,
        }
    }
}

impl RelationshipJob {
    /// Run the network I/O (send, or listener teardown) and package the result
    /// for the loop. Called inside the spawned task; never touches `Config`/`TDK`.
    pub(crate) async fn run(self) -> RelationshipOutcome {
        match self {
            RelationshipJob::Send(send) => send.run().await,
            RelationshipJob::Create(job) => job.run().await,
            RelationshipJob::Remove {
                service,
                listener_id,
                remote_p_did,
            } => {
                if let Some(lid) = listener_id {
                    service.remove_listener(&lid).await;
                }
                RelationshipOutcome {
                    effect: RelationshipEffect::Remove { remote_p_did },
                    result: Ok(()),
                }
            }
        }
    }
}

impl RelationshipSend {
    /// Run the slow send (I/O only) and package the result for the loop. Called
    /// inside the spawned task; never touches `Config`/`TDK`.
    pub(crate) async fn run(self) -> RelationshipOutcome {
        let RelationshipSend {
            service,
            listener_id,
            to_did,
            message,
            effect,
        } = self;
        let result = super::didcomm::send_message_via(&service, &message, &listener_id, &to_did)
            .await
            .map_err(|e| format!("{e}"));
        RelationshipOutcome { effect, result }
    }
}

/// The post-send mutation a relationship network action applies on the loop
/// thread once its send completes. Each variant owns exactly the data the old
/// inline success/error block referenced, so [`RelationshipOutcome::apply`]
/// reproduces the pre-R14 final state byte-for-byte.
pub(crate) enum RelationshipEffect {
    /// `SubmitRequest`: on success, insert the relationship + outbound task and
    /// save; on failure, record the error. Mirrors `send_relationship_request`'s
    /// post-send tail + `handle_submit`'s UI block.
    Create {
        respondent_did: Arc<String>,
        our_did: Arc<String>,
        msg_id: Arc<String>,
        used_r_did: bool,
        /// `key_info` entries minted for a new R-DID (empty when the persona DID
        /// was used). Recorded into `config.key_info` on the loop thread — on
        /// success *and* failure, matching the pre-R14 in-memory state where key
        /// creation happened before the send (only success persists, via save).
        key_info: Vec<(String, KeyInfoConfig)>,
        /// A brand-new contact to insert for the respondent (the alias the user
        /// entered). `Some` only when the DID resolved and no contact existed;
        /// inserted on success *and* send-failure (the old path added it before
        /// the send). `None` when a contact already existed.
        contact_to_add: Option<Option<String>>,
    },
    /// `Ping`: on success, log + create the TrustPing task and save.
    Ping {
        our_did: Arc<String>,
        remote_did: Arc<String>,
        remote_p_did: String,
        msg_id: Arc<String>,
        display_name: String,
        using_rdid: bool,
    },
    /// `RequestVrc`: on success, create the outbound VRC-request task and save.
    RequestVrc {
        remote_p_did: String,
        msg_id: Arc<String>,
        display_name: String,
    },
    /// `Remove`: the R-DID listener (if any) was torn down in the task; remove
    /// the relationship + contact records here and save.
    Remove { remote_p_did: String },
}

/// The completed result of a relationship network dispatch: the post-send effect
/// plus the send's `Result` (stringified so it is `Send`/`'static`).
pub(crate) struct RelationshipOutcome {
    effect: RelationshipEffect,
    result: Result<(), String>,
}

impl RelationshipOutcome {
    /// Apply the post-send mutation on the loop thread. On send success this
    /// performs exactly the config mutation + save + status/log the old inline
    /// handler did *after* the await; on failure it records the same error
    /// status, leaving config untouched (so a failed send records no
    /// relationship/task — matching the pre-R14 ordering and durability).
    pub(crate) fn apply(
        self,
        state: &mut State,
        config: &mut Config,
        save: &mut crate::state_handler::save_coalesce::SaveScheduler,
    ) {
        // Accessor for the relationships-panel status slot, used by the
        // `dispatch_util` save/error helpers below (a free fn so its HRTB is
        // inferred correctly).
        fn status(mp: &mut crate::state_handler::main_page::MainPageState) -> &mut Option<String> {
            &mut mp.content_panel.relationships.status_message
        }
        match self.effect {
            RelationshipEffect::Create {
                respondent_did,
                our_did,
                msg_id,
                used_r_did,
                key_info,
                contact_to_add,
            } => {
                // Insert the brand-new contact (the DID resolved in the task; the
                // old path added it *before* the send, so do it on both success
                // and send-failure). `None` ⇒ a contact already existed.
                if let Some(alias) = contact_to_add {
                    insert_contact(config, &respondent_did, alias);
                }
                // Record any minted R-DID key metadata next — done on both
                // success and failure to match the pre-R14 in-memory state (the
                // secrets are already in the shared resolver; only `Config`
                // bookkeeping is left, and it only persists on the success save).
                for (id, info) in key_info {
                    config.key_info.insert(id, info);
                }
                match self.result {
                    Ok(()) => {
                        // Finalise the provisional record `prepare_submit` inserted.
                        // We must NOT blindly re-insert: a racing
                        // `RelationshipRequestAccepted` (the event loop kept draining
                        // while the send ran off-loop) may have already advanced this
                        // record to `Established`. Re-inserting a fresh `RequestSent`
                        // would clobber that established state and create a stale
                        // outbound task.
                        // Returns `Some(still_request_sent)` if the record exists,
                        // `None` if it went missing.
                        let outcome =
                            config
                                .private
                                .relationships
                                .get_mut(&respondent_did)
                                .map(|rel| {
                                    // Always record the real local DID so future
                                    // messages use the correct `our_did`.
                                    rel.our_did = Arc::clone(&our_did);
                                    if rel.state == RelationshipState::RequestSent {
                                        // No accept raced us: fill in the real
                                        // `task_id` (the send's msg_id) too.
                                        rel.task_id = Arc::clone(&msg_id);
                                        true
                                    } else {
                                        // A racing accept already finalised this
                                        // relationship; leave its state + task_id.
                                        false
                                    }
                                });

                        if outcome != Some(true) {
                            // Either the provisional record was raced to
                            // `Established` (the accept handler already logged +
                            // finalised, and creating an outbound task now would be
                            // stale) or it went missing — skip the outbound task +
                            // "request sent" UI. If the record exists, persist the
                            // `our_did` update made above; otherwise nothing changed.
                            if outcome == Some(false) {
                                // R11: coalesced save (was inline `save_config`).
                                save.mark_dirty();
                                state.main_page.sync_from_config(config);
                            }
                            return;
                        }

                        // No race: create the outbound task + log (post-send tail of
                        // `send_relationship_request`), tagged with the working
                        // community's persona (D10).
                        let our_persona = config.active_persona;
                        config.private.tasks.new_task_for(
                            &msg_id,
                            TaskType::RelationshipRequestOutbound {
                                to: Arc::clone(&respondent_did),
                            },
                            our_persona,
                        );
                        config.public.logs.insert(
                        LogFamily::Relationship,
                        format!(
                            "Relationship requested: remote DID({respondent_did}) Task ID({msg_id})"
                        ),
                    );
                        info!(to = %respondent_did, "relationship request sent");

                        state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
                        let detail = format!(
                            "Relationship Request Sent\n\
                         ─────────────────────────\n\
                         To (persona):  {respondent_did}\n\
                         Our DID:       {our_did}\n\
                         R-DID used:    {}\n\
                         Task ID:       {msg_id}",
                            if used_r_did { "yes" } else { "no" },
                        );
                        // The summary is what the Logs list shows, so it names
                        // the party; the detail block above keeps the raw DIDs
                        // for diagnosis. Same shape as the trust-ping path.
                        let display_name = resolve_did_to_display(config, &respondent_did);
                        dispatch_util::save_and_sync(
                            &mut state.main_page,
                            config,
                            save,
                            dispatch_util::Persist::SaveAndSync,
                            status,
                            format!("Request sent to {display_name}"),
                            dispatch_util::SyncLog::Detailed {
                                summary: format!("Relationship request sent to {display_name}"),
                                detail,
                            },
                        );
                    }
                    Err(e) => {
                        // The send failed, so the peer never received the request and
                        // no accept can have arrived — remove the provisional record
                        // so the failure state matches pre-R14 (contact + key_info
                        // in-memory, but NO relationship record). Guard on
                        // `RequestSent` defensively: should always hold here (an
                        // accept implies the send reached the peer), but never clobber
                        // a record an accept somehow advanced.
                        let still_request_sent = config
                            .private
                            .relationships
                            .get(&respondent_did)
                            .map(|rel| rel.state == RelationshipState::RequestSent)
                            .unwrap_or(false);
                        if still_request_sent {
                            config
                                .private
                                .relationships
                                .relationships
                                .remove(&respondent_did);
                        }
                        let err = anyhow::anyhow!("failed to send relationship request: {e}");
                        dispatch_util::record_error(
                            &mut state.main_page,
                            status,
                            "Failed to send relationship request",
                            &err,
                        );
                    }
                }
            }
            RelationshipEffect::Ping {
                our_did,
                remote_did,
                remote_p_did,
                msg_id,
                display_name,
                using_rdid,
            } => match self.result {
                Ok(()) => {
                    config.public.logs.insert(
                        LogFamily::Relationship,
                        format!("Sent ping to {remote_did} via {our_did}"),
                    );
                    let our_persona = config.active_persona;
                    config.private.tasks.new_task_for(
                        &msg_id,
                        TaskType::TrustPing {
                            from: Arc::clone(&our_did),
                            to: Arc::clone(&remote_did),
                            remote_p_did: Arc::new(remote_p_did.clone()),
                        },
                        our_persona,
                    );
                    info!(to = %remote_p_did, "trust-ping sent");

                    state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
                    dispatch_util::save_and_sync(
                        &mut state.main_page,
                        config,
                        save,
                        dispatch_util::Persist::SaveAndSync,
                        status,
                        "Ping sent",
                        dispatch_util::SyncLog::Detailed {
                            summary: format!(
                                "Trust-ping sent to {display_name}{}",
                                if using_rdid { " (via R-DID)" } else { "" }
                            ),
                            detail: format!(
                                "Trust-Ping Sent\n\
                                 ───────────────\n\
                                 To:              {display_name}\n\
                                 Sent to DID:     {remote_did}\n\
                                 Sent from DID:   {our_did}\n\
                                 Remote persona:  {remote_p_did}\n\
                                 Using R-DIDs:    {}\n\
                                 Routed via:      mediator",
                                if using_rdid { "yes" } else { "no" },
                            ),
                        },
                    );
                }
                Err(e) => {
                    state.main_page.content_panel.relationships.status_message =
                        Some(format!("Ping failed: {e:#}"));
                    state.main_page.log_detailed(
                        format!("Ping to {display_name} failed: {e}"),
                        format!(
                            "Trust-Ping Failed\n\
                             ─────────────────\n\
                             To (persona):    {remote_p_did}\n\
                             To (R-DID):      {remote_did}\n\
                             From (our DID):  {our_did}\n\
                             Error:           {e:#}",
                        ),
                    );
                }
            },
            RelationshipEffect::RequestVrc {
                remote_p_did,
                msg_id,
                display_name,
            } => match self.result {
                Ok(()) => {
                    let our_persona = config.active_persona;
                    config.private.tasks.new_task_for(
                        &msg_id,
                        TaskType::VRCRequestOutbound {
                            remote_p_did: Arc::new(remote_p_did.clone()),
                        },
                        our_persona,
                    );
                    config.public.logs.insert(
                        LogFamily::Relationship,
                        format!("Requested VRC from ({remote_p_did}) Task ID ({msg_id})"),
                    );
                    info!(to = %remote_p_did, "VRC request sent");
                    dispatch_util::save_and_sync(
                        &mut state.main_page,
                        config,
                        save,
                        dispatch_util::Persist::SaveAndSync,
                        status,
                        format!("VRC requested from {display_name}"),
                        dispatch_util::SyncLog::Detailed {
                            summary: format!("VRC requested from {display_name}"),
                            detail: format!(
                                "VRC Request Sent\n\
                                 ────────────────\n\
                                 To:      {display_name}\n\
                                 DID:     {remote_p_did}",
                            ),
                        },
                    );
                }
                Err(e) => {
                    let err = anyhow::anyhow!("{e}");
                    state.main_page.content_panel.relationships.status_message =
                        Some(format!("VRC request failed: {err:#}"));
                    state
                        .main_page
                        .log_error(format!("VRC request to {display_name} failed"), &err);
                }
            },
            RelationshipEffect::Remove { remote_p_did } => {
                // Listener teardown already ran in the task. Remove the records
                // here (post-`remove_listener` tail of `remove_relationship`).
                let key = Arc::new(remote_p_did.clone());
                config.private.relationships.remove(
                    &key,
                    &mut config.private.vrcs_issued,
                    &mut config.private.vrcs_received,
                );
                config
                    .private
                    .contacts
                    .remove_contact(&mut config.public.logs, &remote_p_did);
                config.public.logs.insert(
                    LogFamily::Relationship,
                    format!("Removed relationship with ({remote_p_did})"),
                );
                info!(remote = %remote_p_did, "relationship removed");

                state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
                dispatch_util::save_and_sync(
                    &mut state.main_page,
                    config,
                    save,
                    dispatch_util::Persist::SaveAndSync,
                    status,
                    "Relationship removed",
                    dispatch_util::SyncLog::Plain("Relationship removed".to_string()),
                );
            }
        }
    }
}

/// Backgrounded context-DID deletion: the VTA `delete_did_webvh` + listener
/// teardown run off the loop, then the local config cleanup + save apply on the
/// loop thread via [`DidDeleteOutcome`]. The guards (community-bound check, DID
/// resolution) ran on the loop thread before this was built.
pub(crate) struct DidDeleteJob {
    pub(crate) admin_vta: Option<vta_sdk::client::VtaClient>,
    pub(crate) service: Messaging,
    pub(crate) did: String,
    pub(crate) persona_id: openvtc_core::config::account::PersonaId,
    pub(crate) key_ids: Vec<String>,
}

impl DidDeleteJob {
    /// I/O-only: best-effort VTA delete + listener teardown (failures logged, not
    /// fatal — matching the old inline path), then hand the local cleanup back.
    pub(crate) async fn run(self) -> DidDeleteOutcome {
        let DidDeleteJob {
            admin_vta,
            service,
            did,
            persona_id,
            key_ids,
        } = self;
        if let Some(client) = admin_vta
            && let Err(e) =
                vta::vta_retry("delete WebVH DID", || client.delete_did_webvh(&did)).await
        {
            tracing::debug!("delete_did_webvh({did}) failed (continuing local cleanup): {e}");
        }
        let listener_id = super::didcomm::persona_listener_id(&did);
        service.remove_listener(&listener_id).await;
        DidDeleteOutcome {
            did,
            persona_id,
            key_ids,
        }
    }
}

/// Deletion of an orphan context-DID (persona) completed off the loop: the VTA
/// `delete_did_webvh` + listener teardown ran in the spawned task; the local
/// config cleanup + save are applied here on the loop thread.
pub(crate) struct DidDeleteOutcome {
    pub(crate) did: String,
    pub(crate) persona_id: openvtc_core::config::account::PersonaId,
    pub(crate) key_ids: Vec<String>,
}

impl DidDeleteOutcome {
    /// Apply the local cleanup (persona/identity/key removal + save + log),
    /// mirroring the tail of the old inline `delete_context_did`. The VTA delete
    /// and listener teardown already happened in the task (best-effort, as before
    /// — failures there were logged and did not block local cleanup).
    pub(crate) fn apply(
        self,
        state: &mut State,
        config: &mut Config,
        save: &mut crate::state_handler::save_coalesce::SaveScheduler,
    ) {
        config.account.personas.remove(&self.persona_id);
        config.identities.remove(&self.persona_id);
        for kid in &self.key_ids {
            config.key_info.remove(kid);
        }
        // R11: coalesced save (was inline `save_config`). Persisted by the
        // debounce arm, or by the Exit force-flush if the user quits first.
        save.mark_dirty();
        state.main_page.sync_from_config(config);
        state
            .main_page
            .log(format!("Removed identity {}", self.did));
    }
}

fn handle_open_detail(state: &mut State, index: usize) {
    state.main_page.content_panel.relationships.selected_index = index;
    state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
        index,
        selected_vrc: None,
    };
}

fn handle_start_new_request(
    state: &mut State,
    community_default: Option<RelationshipIdentifierDefault>,
) {
    state.main_page.content_panel.relationships.mode = RelationshipsMode::NewRequest {
        did_input: String::new(),
        alias_input: String::new(),
        reason_input: String::new(),
        // Pairwise by default (#241). The persona DID is a published,
        // resolvable `did:webvh` that often carries a verified agent name, so
        // reusing it across contacts makes correlation a lookup rather than an
        // inference. Opting out stays available on field 3, labelled with what
        // it costs.
        //
        // A community that declares `relationshipIdentifierDefault: attributed`
        // (a public community that wants a legible graph) seeds the persona DID
        // instead; the form explains that from `community_default`. The user can
        // still toggle it.
        generate_r_did: !matches!(
            community_default,
            Some(RelationshipIdentifierDefault::Attributed)
        ),
        community_default,
        active_field: 0,
    };
}

/// The working community's declared `relationshipIdentifierDefault`, which seeds
/// the new-relationship form's default and the "your community prefers …" hint
/// (issue #241). The working community is the selected one, falling back to the
/// account's default working membership; `None` in State-A (no working
/// community) or when the community declared nothing — both of which leave the
/// pairwise default standing.
fn working_community_relationship_default(
    config: &Config,
    state: &State,
) -> Option<RelationshipIdentifierDefault> {
    let (vtc, persona) = state
        .selected_community
        .clone()
        .or_else(|| config.account.default_working_membership())?;
    config
        .account
        .membership(&vtc, persona)
        .and_then(|c| c.relationship_identifier_default)
}

fn handle_cancel_or_back(state: &mut State) {
    state.main_page.content_panel.relationships.mode = RelationshipsMode::List;
    state.main_page.content_panel.relationships.status_message = None;
}

fn handle_input_update(state: &mut State, field: usize, value: String) {
    if let RelationshipsMode::NewRequest {
        ref mut did_input,
        ref mut alias_input,
        ref mut reason_input,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        match field {
            0 => *did_input = value,
            1 => *alias_input = value,
            _ => *reason_input = value,
        }
    }
}

fn handle_toggle_r_did(state: &mut State) {
    if let RelationshipsMode::NewRequest {
        ref mut generate_r_did,
        ..
    } = state.main_page.content_panel.relationships.mode
    {
        *generate_r_did = !*generate_r_did;
    }
}

/// Loop-thread preparation for `SubmitRequest`. Does the fast, local checks +
/// contact add (all done *before* the send today), reserves the R-DID plan, and
/// snapshots the message inputs into owned values. Returns the spawnable
/// [`RelationshipJob::Create`], or `Err` (recorded as a status) if a pre-send
/// validation fails — in which case no domain should have been claimed.
#[allow(clippy::too_many_arguments)]
async fn prepare_submit(
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &Messaging,
    state: &mut State,
    did: &str,
    alias: &str,
    reason: Option<&str>,
    generate_r_did: bool,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<RelationshipJob> {
    // Accept an agent name (`example.com/@bob`) in place of the DID. Resolve it
    // up front so every downstream key (dedup, contact, the provisional record)
    // is the DID, never the mutable name. A plain DID is left untouched — no
    // extra round-trip — and validated by the `did:` check below.
    let resolved_did;
    let did = if openvtc_core::agent_name::looks_like_agent_name(did) {
        resolved_did = openvtc_core::agent_name::resolve_identifier(tdk.did_resolver(), did)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        resolved_did.as_str()
    } else {
        did
    };
    // Validate DID format.
    if !did.starts_with("did:") {
        anyhow::bail!("Invalid DID: must start with 'did:'");
    }
    // Reject a duplicate established relationship.
    let respondent_arc = Arc::new(did.to_string());
    if let Some(rel) = config.private.relationships.get(&respondent_arc)
        && rel.state == RelationshipState::Established
    {
        anyhow::bail!("An established relationship already exists with this DID");
    }

    // Decide whether a brand-new contact must be added. The DID *resolution*
    // (the create path's only non-send network call) is deferred to the task so
    // it doesn't park the loop; the duplicate-alias check is local, so do it here
    // up front (it must reject *before* the send, as the old inline path did).
    let alias_opt = if alias.trim().is_empty() {
        None
    } else {
        Some(alias.trim().to_string())
    };
    let add_contact_alias = if config.private.contacts.find_contact(did).is_none() {
        if let Some(a) = &alias_opt
            && config.private.contacts.aliases.contains_key(a)
        {
            anyhow::bail!("Duplicate alias ({a}) detected! Existing alias must be removed first!");
        }
        Some(alias_opt)
    } else {
        None
    };

    // Reserve the R-DID plan (BIP32 path-pointer reservation is the only config
    // mutation; the VTA round-trip / derivation runs in the task).
    let rdid_plan = if generate_r_did {
        let mediator = config.mediator_did().to_string();
        Some(plan_relationship_did(config, &mediator, admin_vta)?)
    } else {
        None
    };

    let friendly_name = if config.public.friendly_name.is_empty() {
        None
    } else {
        Some(config.public.friendly_name.clone())
    };
    let persona_did = config.persona_did_arc();
    let persona_listener_id = super::didcomm::listener_id_for_did(&persona_did, config);
    // The persona's authentication key signs the binding of the relationship
    // DID to this request; without it the request cannot be proven, so it is
    // not sent.
    let persona_auth = config
        .get_persona_keys(tdk)
        .await
        .map_err(|e| anyhow::anyhow!("could not load the persona's authentication key: {e}"))?
        .authentication
        .secret;
    // The request's id, fixed now so the provisional record below carries it:
    // the accept is correlated by this thread id and nothing else.
    let msg_id = Arc::new(Uuid::new_v4().to_string());

    // Insert a *provisional* `RequestSent` record keyed by the respondent's
    // persona DID, BEFORE the send is even spawned. This closes a lost-update
    // race: the send runs off-loop while `didcomm_event_rx` keeps draining, so a
    // peer's `RelationshipRequestAccepted` can arrive before the Create outcome is
    // applied. The accept handler looks up `find_by_task_id(thid).or_else(get(
    // from_did))`; without this record both miss and the accept is dropped,
    // leaving the relationship stuck. We don't yet know the real `task_id`
    // (the send's msg_id) or any minted R-DID, so use placeholders: `task_id` is
    // empty (the accept's primary `find_by_task_id` misses harmlessly and falls
    // back to `get(from_did)`), and `our_did`/`remote_did`/`remote_p_did` are the
    // respondent DID. The accept's `from_did` equals this respondent DID, so the
    // `get(from_did)` fallback finds it and the `remote_p_did == from_did` check
    // passes. The Create outcome later fills in the real `our_did`.
    //
    // The accept is now correlated by `task_id` alone (no sender fallback), so
    // the provisional record carries the request's real id from the start.
    config.private.relationships.relationships.insert(
        Arc::clone(&respondent_arc),
        RelRecord {
            task_id: Arc::clone(&msg_id),
            our_did: Arc::clone(&persona_did),
            remote_p_did: Arc::clone(&respondent_arc),
            remote_did: Arc::clone(&respondent_arc),
            created: Utc::now(),
            state: RelationshipState::RequestSent,
            // Tag the relationship with the working community's persona (D10) so
            // it scopes to the right community on the main page (R-C-6).
            our_persona: config.active_persona,
            needs_reestablishment: false,
        },
    );

    // In-progress status (shown by the loop's post-arm state send).
    if generate_r_did {
        state.main_page.content_panel.relationships.status_message =
            Some("Creating relationship DID...".to_string());
        state
            .main_page
            .log("Creating relationship DID via key backend...");
    } else {
        state.main_page.content_panel.relationships.status_message =
            Some("Sending request...".to_string());
    }

    Ok(RelationshipJob::Create(Box::new(CreateJob {
        tdk: tdk.clone(),
        service: service.clone(),
        rdid_plan,
        persona_did,
        persona_auth,
        msg_id,
        persona_listener_id,
        respondent_did: respondent_arc,
        reason: reason.map(|s| s.to_string()),
        friendly_name,
        add_contact_alias,
    })))
}

/// Loop-thread preparation for `Ping`. Builds the ping message + resolves the
/// listener (all `Config` reads), then hands the slow `send_message_with_retry`
/// (~6 s on a dead peer) to the task. The TrustPing task + log are created in
/// `apply` on success.
fn prepare_ping(
    config: &mut Box<Config>,
    service: &Messaging,
    state: &mut State,
    remote_p_did: &str,
) -> Result<RelationshipJob> {
    let remote_key = Arc::new(remote_p_did.to_string());
    let (our_did, remote_did) = {
        let relationship = config
            .private
            .relationships
            .get(&remote_key)
            .ok_or_else(|| anyhow::anyhow!("No relationship found for {remote_p_did}"))?;
        (
            Arc::clone(&relationship.our_did),
            Arc::clone(&relationship.remote_did),
        )
    };
    let using_rdid = !config.is_persona_did(our_did.as_str());
    info!(our_did = %our_did, remote_did = %remote_did, is_r_did = using_rdid, "ping using relationship DIDs");

    let ping_msg = build_ping_message(&our_did, &remote_did)?;
    let msg_id = Arc::new(ping_msg.id.clone());
    let listener_id = super::didcomm::listener_id_for_did(&our_did, config);
    let display_name = resolve_did_to_display(config, remote_p_did);

    state.main_page.content_panel.relationships.status_message =
        Some("Sending ping...".to_string());

    Ok(RelationshipJob::Send(Box::new(RelationshipSend {
        service: service.clone(),
        listener_id,
        to_did: Arc::clone(&remote_did),
        message: Box::new(ping_msg),
        effect: RelationshipEffect::Ping {
            our_did,
            remote_did,
            remote_p_did: remote_p_did.to_string(),
            msg_id,
            display_name,
            using_rdid,
        },
    })))
}

/// Loop-thread preparation for `Remove`. Extracts the R-DID listener id (if any),
/// then the task tears the listener down; the record removal happens in `apply`.
fn prepare_remove(
    config: &mut Box<Config>,
    service: &Messaging,
    state: &mut State,
    remote_p_did: &str,
) -> RelationshipJob {
    let key = Arc::new(remote_p_did.to_string());
    let our_did = config
        .private
        .relationships
        .get(&key)
        .map(|rel| Arc::clone(&rel.our_did))
        .filter(|our_did| !config.is_persona_did(our_did.as_str()));
    let listener_id = our_did.map(|our_did| super::didcomm::listener_id_for_did(&our_did, config));
    // The confirmation is now resolved.
    state.main_page.content_panel.relationships.confirm_delete = None;
    state.main_page.content_panel.relationships.status_message =
        Some("Removing relationship...".to_string());
    RelationshipJob::Remove {
        service: service.clone(),
        listener_id,
        remote_p_did: remote_p_did.to_string(),
    }
}

/// Loop-thread preparation for `RequestVrc`. Builds the VRC-request message +
/// resolves the listener; the task sends it and `apply` records the task on
/// success. Mirrors the pre-R14 `credential_actions::send_vrc_request` split.
fn prepare_request_vrc(
    config: &mut Box<Config>,
    service: &Messaging,
    state: &mut State,
    remote_p_did: &str,
) -> Result<RelationshipJob> {
    use openvtc_core::vrc::VrcRequest;

    let remote_key = Arc::new(remote_p_did.to_string());
    let (our_did, remote_did) = {
        let relationship = config
            .private
            .relationships
            .get(&remote_key)
            .ok_or_else(|| anyhow::anyhow!("No relationship found for {remote_p_did}"))?;
        (
            Arc::clone(&relationship.our_did),
            Arc::clone(&relationship.remote_did),
        )
    };
    let message = VrcRequest { reason: None }.create_message(&remote_did, &our_did)?;
    let msg_id = Arc::new(message.id.clone());
    let listener_id = super::didcomm::listener_id_for_did(&our_did, config);
    let display_name = resolve_did_to_display(config, remote_p_did);

    state.main_page.content_panel.relationships.status_message =
        Some("Requesting VRC...".to_string());

    Ok(RelationshipJob::Send(Box::new(RelationshipSend {
        service: service.clone(),
        listener_id,
        to_did: remote_did,
        message: Box::new(message),
        effect: RelationshipEffect::RequestVrc {
            remote_p_did: remote_p_did.to_string(),
            msg_id,
            display_name,
        },
    })))
}

fn handle_edit_alias(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut crate::state_handler::save_coalesce::SaveScheduler,
    remote_p_did: &str,
    alias: &str,
) {
    config
        .private
        .contacts
        .remove_contact(&mut config.public.logs, remote_p_did);

    let alias_opt = if alias.trim().is_empty() {
        None
    } else {
        Some(alias.trim().to_string())
    };
    let contact_did = std::sync::Arc::new(remote_p_did.to_string());
    let contact = std::sync::Arc::new(Contact {
        did: contact_did.clone(),
        alias: alias_opt.clone(),
    });
    config
        .private
        .contacts
        .contacts
        .insert(contact_did, contact.clone());
    if let Some(ref a) = alias_opt {
        config.private.contacts.aliases.insert(a.clone(), contact);
    }

    config.public.logs.insert(
        openvtc_core::logs::LogFamily::Config,
        format!(
            "Alias updated for {}: {}",
            remote_p_did,
            alias_opt.as_deref().unwrap_or("(removed)")
        ),
    );

    // R11: coalesced save (was inline `save_config`).
    save.mark_dirty();
    state.main_page.sync_from_config(config);
    let index = state
        .main_page
        .content_panel
        .relationships
        .relationships
        .iter()
        .position(|r| r.remote_p_did == remote_p_did)
        .unwrap_or(0);
    state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
        index,
        selected_vrc: None,
    };
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        dispatch_util::Persist::None,
        |mp| &mut mp.content_panel.relationships.status_message,
        "Alias updated",
        dispatch_util::SyncLog::Plain("Alias updated".to_string()),
    );
}

/// Outcome of synchronously dispatching a `RelationshipAction` on the loop
/// thread (R14). Local actions are fully `Handled` here; network actions return
/// a `Spawn`able [`RelationshipJob`] for the loop to run off-thread, plus whether
/// it is a ping (so the loop can stamp `ping_sent_at` for pong-latency display).
pub(crate) enum RelationshipDispatch {
    /// Done synchronously (nav, input, edit-alias) — nothing to background.
    Handled,
    /// A network job to spawn; `is_ping` drives the `ping_sent_at` latency stamp.
    Spawn { job: RelationshipJob, is_ping: bool },
}

/// Whether a `RelationshipAction` is a network-bound action that the loop should
/// run off-thread (claiming the `Relationship` busy-domain first). Lets the loop
/// reject a busy domain *before* `dispatch` does any pre-send config mutation.
pub(crate) fn is_network(action: &RelationshipAction) -> bool {
    matches!(
        action,
        RelationshipAction::SubmitRequest { .. }
            | RelationshipAction::Ping { .. }
            | RelationshipAction::Remove { .. }
            | RelationshipAction::RequestVrc { .. }
    )
}

/// Dispatch a single `RelationshipAction`.
///
/// Local actions mutate `state` and return [`RelationshipDispatch::Handled`].
/// Network actions do the fast, loop-thread pre-send work (validation, contact
/// add, R-DID path reservation, message build) and return
/// [`RelationshipDispatch::Spawn`] for the loop to run off-thread; the post-send
/// config mutation is applied later by [`RelationshipOutcome::apply`]. A pre-send
/// failure is recorded as a status here and returns `Handled` (no job spawned, so
/// the loop releases the busy-domain immediately).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch(
    action: RelationshipAction,
    config: &mut Box<Config>,
    tdk: &TDK,
    service: &Messaging,
    state: &mut State,
    save: &mut crate::state_handler::save_coalesce::SaveScheduler,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> RelationshipDispatch {
    match action {
        RelationshipAction::Select(index) => {
            state.main_page.content_panel.relationships.selected_index = index;
        }
        RelationshipAction::OpenDetail(index) => handle_open_detail(state, index),
        RelationshipAction::StartNewRequest => {
            handle_start_new_request(state, working_community_relationship_default(config, state))
        }
        RelationshipAction::CancelNewRequest | RelationshipAction::Back => {
            handle_cancel_or_back(state)
        }
        RelationshipAction::InputUpdate { field, value } => {
            handle_input_update(state, field, value)
        }
        RelationshipAction::ToggleRDid => handle_toggle_r_did(state),
        RelationshipAction::FocusField(field) => {
            if let RelationshipsMode::NewRequest {
                ref mut active_field,
                ..
            } = state.main_page.content_panel.relationships.mode
            {
                *active_field = field;
            }
        }
        RelationshipAction::SubmitRequest {
            did,
            alias,
            reason,
            generate_r_did,
        } => {
            match prepare_submit(
                config,
                tdk,
                service,
                state,
                &did,
                &alias,
                reason.as_deref(),
                generate_r_did,
                admin_vta,
            )
            .await
            {
                Ok(job) => {
                    return RelationshipDispatch::Spawn {
                        job,
                        is_ping: false,
                    };
                }
                Err(e) => {
                    dispatch_util::record_error(
                        &mut state.main_page,
                        |mp| &mut mp.content_panel.relationships.status_message,
                        "Failed to send relationship request",
                        &e,
                    );
                }
            }
        }
        RelationshipAction::Ping { remote_p_did } => {
            match prepare_ping(config, service, state, &remote_p_did) {
                Ok(job) => return RelationshipDispatch::Spawn { job, is_ping: true },
                Err(e) => {
                    state.main_page.content_panel.relationships.status_message =
                        Some(format!("Ping failed: {e:#}"));
                    state.main_page.log_error("Failed to send trust-ping", &e);
                }
            }
        }
        RelationshipAction::Remove { remote_p_did } => {
            return RelationshipDispatch::Spawn {
                job: prepare_remove(config, service, state, &remote_p_did),
                is_ping: false,
            };
        }
        // R25 confirmation arming/cancel — pure state mutations, never network.
        RelationshipAction::ConfirmRemove { remote_p_did } => {
            state.main_page.content_panel.relationships.confirm_delete = Some(remote_p_did);
        }
        RelationshipAction::CancelRemove => {
            state.main_page.content_panel.relationships.confirm_delete = None;
        }
        RelationshipAction::StartEditAlias {
            index,
            current_alias,
        } => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::EditAlias {
                index,
                alias_input: current_alias,
            };
        }
        RelationshipAction::EditAliasUpdate(value) => {
            if let RelationshipsMode::EditAlias {
                ref mut alias_input,
                ..
            } = state.main_page.content_panel.relationships.mode
            {
                *alias_input = value;
            }
        }
        RelationshipAction::EditAlias {
            remote_p_did,
            alias,
        } => handle_edit_alias(config, state, save, &remote_p_did, &alias),
        RelationshipAction::CancelEditAlias { index } => {
            state.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                index,
                selected_vrc: None,
            };
        }
        RelationshipAction::RequestVrc { remote_p_did } => {
            match prepare_request_vrc(config, service, state, &remote_p_did) {
                Ok(job) => {
                    return RelationshipDispatch::Spawn {
                        job,
                        is_ping: false,
                    };
                }
                Err(e) => {
                    state.main_page.content_panel.relationships.status_message =
                        Some(format!("VRC request failed: {e:#}"));
                    let display_name = resolve_did_to_display(config, &remote_p_did);
                    state
                        .main_page
                        .log_error(format!("VRC request to {display_name} failed"), &e);
                }
            }
        }
    }
    RelationshipDispatch::Handled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;

    /// Build a relationship record (persona DID used as our_did, so it is *not*
    /// an R-DID) and register it in `config`. Returns the shared Arc.
    fn register_relationship(config: &mut Config, remote_p_did: &str) {
        let key = Arc::new(remote_p_did.to_string());
        let rel = RelRecord {
            task_id: Arc::new("task-1".to_string()),
            our_did: config.persona_did_arc(),
            remote_p_did: Arc::clone(&key),
            remote_did: Arc::clone(&key),
            created: Utc::now(),
            state: RelationshipState::Established,
            our_persona: config.active_persona,
            needs_reestablishment: false,
        };
        config.private.relationships.relationships.insert(key, rel);
    }

    /// Register an *established* relationship whose `our_did` is a pairwise
    /// R-DID (distinct from the persona DID), i.e. the post-handshake steady
    /// state that #241's "no silent revert" rule is about.
    fn register_pairwise_relationship(config: &mut Config, remote_p_did: &str, our_r_did: &str) {
        let key = Arc::new(remote_p_did.to_string());
        let rel = RelRecord {
            task_id: Arc::new("task-1".to_string()),
            our_did: Arc::new(our_r_did.to_string()),
            remote_p_did: Arc::clone(&key),
            // Their pairwise DID, not their persona DID.
            remote_did: Arc::new(format!("{remote_p_did}-rdid")),
            created: Utc::now(),
            state: RelationshipState::Established,
            our_persona: config.active_persona,
            needs_reestablishment: false,
        };
        config.private.relationships.relationships.insert(key, rel);
    }

    /// #241 criterion 3 — once a relationship holds an R-DID, a subsequent
    /// message must not revert to the persona DID. Guards the property on the
    /// ping path: the message `from`, the recipient, and the listener the send
    /// is routed through all come from the relationship record, never from the
    /// persona. A fallback here would re-expose the persona DID mid-relationship
    /// and defeat the pairwise default.
    #[tokio::test]
    async fn established_pairwise_relationship_never_pings_from_the_persona_did() {
        let mut config = Box::new(test_config());
        let mut state = State::default();
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = openvtc_core::didcomm::Messaging::start(event_tx);

        let remote = "did:peer:remote";
        let our_r_did = "did:peer:our-rdid";
        register_pairwise_relationship(&mut config, remote, our_r_did);

        let job = prepare_ping(&mut config, &service, &mut state, remote).expect("ping prepares");

        let RelationshipJob::Send(send) = job else {
            panic!("ping must produce a Send job");
        };

        assert_eq!(
            send.message.from.as_deref(),
            Some(our_r_did),
            "an established relationship must speak as its R-DID, not the persona DID"
        );
        assert_eq!(
            send.to_did.as_str(),
            format!("{remote}-rdid"),
            "the ping must address the remote's R-DID, not their persona DID"
        );
        assert_eq!(
            send.listener_id,
            openvtc_core::didcomm::listener_id_for_did(our_r_did, &config),
            "the send must route through the relationship listener"
        );
        assert!(
            matches!(
                send.effect,
                RelationshipEffect::Ping {
                    using_rdid: true,
                    ..
                }
            ),
            "the effect must record that the pairwise DID was used"
        );
    }

    /// #241 — the new-relationship mint default follows the working community's
    /// declared `relationshipIdentifierDefault`: `attributed` opts into the
    /// persona DID, everything else (pairwise, undeclared, or no working
    /// community at all) keeps the pairwise default.
    #[test]
    fn mint_default_follows_the_working_communitys_declaration() {
        use openvtc_core::config::account::{
            CommunityRecord, CommunityStatus, PersonaId, RelationshipIdentifierDefault,
        };

        let vtc = "did:webvh:example:vtc";
        let persona = PersonaId::new();
        let seed = |declared: Option<RelationshipIdentifierDefault>| {
            let mut config = test_config();
            let mut record = CommunityRecord::new_pending(
                vtc.to_string(),
                None,
                format!("openvtc/{vtc}"),
                persona,
                Uuid::new_v4(),
                Utc::now(),
            );
            record.status = CommunityStatus::Active;
            record.relationship_identifier_default = declared;
            config.account.add_membership(record);
            let state = State {
                selected_community: Some((vtc.to_string(), persona)),
                ..State::default()
            };
            (config, state)
        };

        // The lookup reports the community's declaration…
        let (config, state) = seed(Some(RelationshipIdentifierDefault::Attributed));
        assert_eq!(
            working_community_relationship_default(&config, &state),
            Some(RelationshipIdentifierDefault::Attributed)
        );
        // …and it seeds the form: attributed ⇒ persona DID, and the form carries
        // the declaration so it can explain the choice.
        let mut s = state.clone();
        handle_start_new_request(
            &mut s,
            working_community_relationship_default(&config, &state),
        );
        assert!(matches!(
            s.main_page.content_panel.relationships.mode,
            RelationshipsMode::NewRequest {
                generate_r_did: false,
                community_default: Some(RelationshipIdentifierDefault::Attributed),
                ..
            }
        ));

        let (config, state) = seed(Some(RelationshipIdentifierDefault::Pairwise));
        assert_eq!(
            working_community_relationship_default(&config, &state),
            Some(RelationshipIdentifierDefault::Pairwise)
        );

        let (config, state) = seed(None);
        assert_eq!(
            working_community_relationship_default(&config, &state),
            None
        );

        // State-A: no working community at all → None → pairwise stands.
        let config = test_config();
        let state = State::default();
        assert_eq!(
            working_community_relationship_default(&config, &state),
            None
        );
    }

    /// A successful Ping outcome creates the TrustPing task + activity log and
    /// sets the panel status to "Ping sent" — the same final state the old inline
    /// `handle_ping` success arm produced.
    #[test]
    fn ping_success_applies_task_and_status() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let remote = "did:peer:remote";
        register_relationship(&mut config, remote);

        let outcome = RelationshipOutcome {
            effect: RelationshipEffect::Ping {
                our_did: config.persona_did_arc(),
                remote_did: Arc::new(remote.to_string()),
                remote_p_did: remote.to_string(),
                msg_id: Arc::new("ping-msg".to_string()),
                display_name: "Remote".to_string(),
                using_rdid: false,
            },
            result: Ok(()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert_eq!(
            state
                .main_page
                .content_panel
                .relationships
                .status_message
                .as_deref(),
            Some("Ping sent")
        );
        assert!(
            config
                .private
                .tasks
                .get_by_id(&Arc::new("ping-msg".to_string()))
                .is_some(),
            "a TrustPing task must be created on success"
        );
    }

    /// A failed Ping outcome sets the "Ping failed" status and creates NO task —
    /// matching the old inline error arm (no config mutation on a failed send).
    #[test]
    fn ping_failure_sets_status_and_creates_no_task() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let remote = "did:peer:remote";
        register_relationship(&mut config, remote);

        let outcome = RelationshipOutcome {
            effect: RelationshipEffect::Ping {
                our_did: config.persona_did_arc(),
                remote_did: Arc::new(remote.to_string()),
                remote_p_did: remote.to_string(),
                msg_id: Arc::new("ping-msg".to_string()),
                display_name: "Remote".to_string(),
                using_rdid: false,
            },
            result: Err("dead peer".to_string()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        let status = state
            .main_page
            .content_panel
            .relationships
            .status_message
            .clone()
            .unwrap_or_default();
        assert!(status.starts_with("Ping failed"), "got: {status}");
        assert!(
            config
                .private
                .tasks
                .get_by_id(&Arc::new("ping-msg".to_string()))
                .is_none(),
            "no task must be created on a failed send"
        );
    }

    /// Insert the provisional `RequestSent` record that `prepare_submit` writes
    /// before the send is spawned (placeholder `task_id`, persona DID as
    /// `our_did`). Tests that exercise the Create `apply` start from this record,
    /// mirroring the real flow.
    fn insert_provisional(config: &mut Config, respondent: &Arc<String>) {
        config.private.relationships.relationships.insert(
            Arc::clone(respondent),
            RelRecord {
                task_id: Arc::new(String::new()),
                our_did: Arc::clone(respondent),
                remote_p_did: Arc::clone(respondent),
                remote_did: Arc::clone(respondent),
                created: Utc::now(),
                state: RelationshipState::RequestSent,
                our_persona: None,
                needs_reestablishment: false,
            },
        );
    }

    /// A successful Create outcome finalises the provisional record (real
    /// `task_id`/`our_did`), creates the outbound task, and records the minted
    /// R-DID key_info, reproducing the post-send tail of
    /// `send_relationship_request`.
    #[test]
    fn create_success_inserts_relationship_and_keyinfo() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let respondent = Arc::new("did:peer:respondent".to_string());
        insert_provisional(&mut config, &respondent);
        let our_did = Arc::new("did:peer:our-rdid".to_string());
        let key_info = vec![(
            "z-some-key".to_string(),
            KeyInfoConfig {
                path: KeySourceMaterial::Derived {
                    path: "m/3'/1'/1'/0'".to_string(),
                },
                create_time: Utc::now(),
                purpose: KeyTypes::RelationshipVerification,
            },
        )];

        let outcome = RelationshipOutcome {
            effect: RelationshipEffect::Create {
                respondent_did: Arc::clone(&respondent),
                our_did,
                msg_id: Arc::new("req-msg".to_string()),
                used_r_did: true,
                key_info,
                contact_to_add: Some(Some("Respondent".to_string())),
            },
            result: Ok(()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        let rel = config
            .private
            .relationships
            .get(&respondent)
            .expect("relationship record present on success");
        assert_eq!(
            rel.state,
            RelationshipState::RequestSent,
            "stays RequestSent (no accept raced)"
        );
        assert_eq!(
            rel.task_id.as_str(),
            "req-msg",
            "provisional placeholder task_id replaced by the real msg_id"
        );
        assert_eq!(
            rel.our_did.as_str(),
            "did:peer:our-rdid",
            "provisional persona our_did replaced by the minted R-DID"
        );
        assert!(
            config
                .private
                .tasks
                .get_by_id(&Arc::new("req-msg".to_string()))
                .is_some(),
            "an outbound RelationshipRequestOutbound task is created on success"
        );
        assert!(
            config.key_info.contains_key("z-some-key"),
            "minted R-DID key_info recorded"
        );
        assert_eq!(
            state
                .main_page
                .content_panel
                .relationships
                .status_message
                .as_deref(),
            // Names the party rather than echoing its DID: the fixture has a
            // contact alias for this peer, and the status line honours the same
            // alias → verified agent name → DID precedence as everywhere else.
            Some("Request sent to Respondent")
        );
    }

    /// Race guard: if a peer's `RelationshipRequestAccepted` advances the
    /// provisional record to `Established` *before* the Create SUCCESS outcome is
    /// applied, the success apply must NOT clobber that state back to
    /// `RequestSent`, must NOT create a stale outbound task, but must still update
    /// `our_did` to the real minted local DID.
    #[test]
    fn create_success_does_not_clobber_raced_established() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let respondent = Arc::new("did:peer:respondent".to_string());
        insert_provisional(&mut config, &respondent);
        // Simulate the racing accept: advance the provisional record to
        // Established (as the accept handler's `get(from_did)` fallback does).
        {
            let rel = config.private.relationships.get_mut(&respondent).unwrap();
            rel.state = RelationshipState::Established;
            rel.remote_did = Arc::new("did:peer:respondent-rdid".to_string());
        }

        let our_did = Arc::new("did:peer:our-rdid".to_string());
        let outcome = RelationshipOutcome {
            effect: RelationshipEffect::Create {
                respondent_did: Arc::clone(&respondent),
                our_did,
                msg_id: Arc::new("req-msg".to_string()),
                used_r_did: true,
                key_info: Vec::new(),
                contact_to_add: None,
            },
            result: Ok(()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        let rel = config.private.relationships.get(&respondent).unwrap();
        assert_eq!(
            rel.state,
            RelationshipState::Established,
            "raced Established state must be preserved, not reset to RequestSent"
        );
        assert_eq!(
            rel.our_did.as_str(),
            "did:peer:our-rdid",
            "our_did is still updated to the real minted local DID"
        );
        assert!(
            config
                .private
                .tasks
                .get_by_id(&Arc::new("req-msg".to_string()))
                .is_none(),
            "no stale outbound task for an already-established relationship"
        );
    }

    /// A failed Create still records the minted key_info in-memory (matching the
    /// pre-R14 ordering where key creation happened before the send) but removes
    /// the provisional relationship record (failure parity: contact + key_info
    /// in-memory, NO relationship record), and surfaces the error status.
    #[test]
    fn create_failure_records_keyinfo_but_no_relationship() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let respondent = Arc::new("did:peer:respondent".to_string());
        // `prepare_submit` pre-inserted a provisional record; a send failure must
        // remove it so no stuck `RequestSent` relationship is left behind.
        insert_provisional(&mut config, &respondent);

        let outcome = RelationshipOutcome {
            effect: RelationshipEffect::Create {
                respondent_did: Arc::clone(&respondent),
                our_did: Arc::new("did:peer:our-rdid".to_string()),
                msg_id: Arc::new("req-msg".to_string()),
                used_r_did: true,
                key_info: vec![(
                    "z-orphan".to_string(),
                    KeyInfoConfig {
                        path: KeySourceMaterial::Derived {
                            path: "m/3'/1'/1'/0'".to_string(),
                        },
                        create_time: Utc::now(),
                        purpose: KeyTypes::RelationshipVerification,
                    },
                )],
                contact_to_add: None,
            },
            result: Err("send failed".to_string()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(
            config.private.relationships.get(&respondent).is_none(),
            "provisional relationship removed on a failed send"
        );
        assert!(
            config
                .private
                .tasks
                .get_by_id(&Arc::new("req-msg".to_string()))
                .is_none(),
            "no outbound task on a failed send"
        );
        assert!(
            config.key_info.contains_key("z-orphan"),
            "key_info recorded in-memory even on failure (matches pre-R14)"
        );
        let status = state
            .main_page
            .content_panel
            .relationships
            .status_message
            .clone()
            .unwrap_or_default();
        assert!(status.starts_with("Error:"), "got: {status}");
    }

    /// A Remove outcome removes the relationship record and sets the status —
    /// the post-`remove_listener` tail of `remove_relationship` + `handle_remove`.
    #[test]
    fn remove_applies_record_removal() {
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        let remote = "did:peer:remote";
        register_relationship(&mut config, remote);

        let outcome = RelationshipOutcome {
            effect: RelationshipEffect::Remove {
                remote_p_did: remote.to_string(),
            },
            result: Ok(()),
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(
            config
                .private
                .relationships
                .get(&Arc::new(remote.to_string()))
                .is_none(),
            "relationship removed"
        );
        assert_eq!(
            state
                .main_page
                .content_panel
                .relationships
                .status_message
                .as_deref(),
            Some("Relationship removed")
        );
    }

    /// `DidDeleteOutcome::apply` removes the persona / identity / key_info and
    /// logs — the local-cleanup tail of the old inline `delete_context_did`.
    #[test]
    fn did_delete_applies_local_cleanup() {
        use openvtc_core::config::account::PersonaId;
        let mut config = test_config();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let mut state = State::default();
        config.key_info.insert(
            "z-persona-key".to_string(),
            KeyInfoConfig {
                path: KeySourceMaterial::Derived {
                    path: "m/0'".to_string(),
                },
                create_time: Utc::now(),
                purpose: KeyTypes::PersonaSigning,
            },
        );

        let outcome = DidDeleteOutcome {
            did: "did:webvh:example".to_string(),
            persona_id: PersonaId::new(),
            key_ids: vec!["z-persona-key".to_string()],
        };
        outcome.apply(&mut state, &mut config, &mut save);

        assert!(
            !config.key_info.contains_key("z-persona-key"),
            "key_info entry removed"
        );
    }

    // ----------------------------------------------------------------
    // Table tests for the pure mode-transition handlers. Each is a pure
    // function of `&mut State`; the tables drive the handler from a starting
    // `State` and assert on the resulting relationships-panel mode. Mirrors the
    // table-test style in `ui/pages/setup_flow/navigation.rs`.
    // ----------------------------------------------------------------

    fn rel_mode(state: &State) -> &RelationshipsMode {
        &state.main_page.content_panel.relationships.mode
    }

    /// Enter `NewRequest` with empty fields; `handle_cancel_or_back` returns to
    /// `List` clearing the status. Table over a couple of starting modes.
    #[test]
    fn start_new_request_and_cancel_back() {
        let mut state = State::default();
        handle_start_new_request(&mut state, None);
        // Pairwise is the default (#241) — a new request mints an R-DID unless
        // the operator deliberately turns it off.
        assert!(matches!(
            rel_mode(&state),
            RelationshipsMode::NewRequest {
                generate_r_did: true,
                active_field: 0,
                ..
            }
        ));

        // Cancel/back from any mode lands on List and clears the status.
        for start in [
            RelationshipsMode::NewRequest {
                did_input: "x".to_string(),
                alias_input: String::new(),
                reason_input: String::new(),
                generate_r_did: true,
                community_default: None,
                active_field: 2,
            },
            RelationshipsMode::Detail {
                index: 3,
                selected_vrc: None,
            },
        ] {
            let mut state = State::default();
            state.main_page.content_panel.relationships.mode = start;
            state.main_page.content_panel.relationships.status_message = Some("stale".to_string());
            handle_cancel_or_back(&mut state);
            assert!(matches!(rel_mode(&state), RelationshipsMode::List));
            assert!(
                state
                    .main_page
                    .content_panel
                    .relationships
                    .status_message
                    .is_none(),
                "cancel/back clears the status"
            );
        }
    }

    /// `handle_open_detail` enters `Detail { index, selected_vrc: None }` and
    /// records the selected index. Table over a few indices.
    #[test]
    fn open_detail_enters_detail() {
        for index in [0usize, 2, 17] {
            let mut state = State::default();
            handle_open_detail(&mut state, index);
            assert!(
                matches!(
                    rel_mode(&state),
                    RelationshipsMode::Detail { index: i, selected_vrc: None } if *i == index
                ),
                "open_detail({index})"
            );
            assert_eq!(
                state.main_page.content_panel.relationships.selected_index,
                index
            );
        }
    }

    /// `handle_input_update` routes by field index into the `NewRequest` form's
    /// did/alias/reason inputs, and is a no-op outside `NewRequest`.
    #[test]
    fn input_update_routes_by_field() {
        // (field, expected (did, alias, reason))
        let cases: &[(usize, (&str, &str, &str))] = &[
            (0, ("the-did", "", "")),
            (1, ("", "the-alias", "")),
            (2, ("", "", "the-reason")),
            (9, ("", "", "the-reason")), // default arm writes reason
        ];
        for (field, (did, alias, reason)) in cases {
            let mut state = State::default();
            handle_start_new_request(&mut state, None);
            let value = match field {
                0 => "the-did",
                1 => "the-alias",
                _ => "the-reason",
            };
            handle_input_update(&mut state, *field, value.to_string());
            match rel_mode(&state) {
                RelationshipsMode::NewRequest {
                    did_input,
                    alias_input,
                    reason_input,
                    ..
                } => {
                    assert_eq!(did_input, did, "field {field} did_input");
                    assert_eq!(alias_input, alias, "field {field} alias_input");
                    assert_eq!(reason_input, reason, "field {field} reason_input");
                }
                other => panic!("expected NewRequest, got {other:?}"),
            }
        }

        // No-op outside NewRequest.
        let mut state = State::default();
        handle_input_update(&mut state, 0, "ignored".to_string());
        assert!(matches!(rel_mode(&state), RelationshipsMode::List));
    }

    /// `handle_toggle_r_did` flips the `generate_r_did` flag only in `NewRequest`.
    #[test]
    fn toggle_r_did_flips_flag() {
        let mut state = State::default();
        handle_start_new_request(&mut state, None);
        // Starts pairwise (#241), so the first toggle is the opt-out.
        handle_toggle_r_did(&mut state);
        assert!(matches!(
            rel_mode(&state),
            RelationshipsMode::NewRequest {
                generate_r_did: false,
                ..
            }
        ));
        handle_toggle_r_did(&mut state);
        assert!(matches!(
            rel_mode(&state),
            RelationshipsMode::NewRequest {
                generate_r_did: true,
                ..
            }
        ));

        // No-op outside NewRequest.
        let mut state = State::default();
        handle_toggle_r_did(&mut state);
        assert!(matches!(rel_mode(&state), RelationshipsMode::List));
    }
}
