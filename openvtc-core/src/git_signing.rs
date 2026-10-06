//! did-git-sign identities for openvtc personas.
//!
//! did-git-sign does the signing: git runs it as `gpg.ssh.program`, it fetches
//! the persona's Ed25519 key from the VTA, signs, and its `commit-msg` hook
//! writes the `Signed-by-DID:` claim `verify-trust` checks. This module sets
//! that up for a persona openvtc already holds, so a member never runs
//! `did-git-sign init` or a `pnm` grant by hand:
//!
//! 1. **A credential of its own** ([`SignerCredential::generate`],
//!    [`grant_signer`]). openvtc mints a fresh
//!    `did:key` and grants it, through its admin session, `admin` of the
//!    persona's own context narrowed to [`SIGNER_CAPABILITIES`]: `sign-sshsig`,
//!    so the VTA signs each commit (`keys/sign-sshsig/0.1`) and the persona's
//!    key never leaves it. A VTA that predates that task gets
//!    [`LEGACY_SIGNER_CAPABILITIES`] instead (`key-export`, for the key to be
//!    fetched at sign time). did-git-sign never holds openvtc's account
//!    credential, which is admin of every persona's context; revoking signing
//!    is revoking that one entry. The grant is proven before anything is
//!    stored: the new credential connects, has the VTA sign (or, on an older
//!    VTA, fetches the key), and the signature must verify under the key the
//!    persona's DID document publishes.
//! 2. **A named profile** ([`install_identity`]): the credential in the OS
//!    keyring under the persona's `did:…#key-N`, its key in `allowed_signers`,
//!    a profile in `profiles.json`, and its include file — exactly what
//!    `did-git-sign init --profile` writes, through the library's own calls.
//!    No git configuration is written.
//! 3. **Per repository** ([`enable_in`] / [`disable_in`]): the `did-git-sign`
//!    binary's own `enable --profile` / `disable`, run in the checkout. Git
//!    needs that binary on `PATH` to sign at all, so it is the one thing
//!    openvtc requires rather than reimplements.
//!
//! The library's calls that read the process's current directory, or print,
//! are not used: openvtc is a TUI, and its working directory means nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use did_git_sign::config::SigningConfig;
use did_git_sign::profiles::{Profile, Profiles};
use did_git_sign::{enable, init};
use ed25519_dalek_bip32::ed25519_dalek::SigningKey;
use secrecy::{ExposeSecret, SecretString};
use vta_sdk::client::{AutoConnect, CreateAclRequest, VtaClient};
use vta_sdk::error::VtaError;
use vta_sdk::provision_client::EphemeralSetupKey;

use crate::config::KeyBackend;
use crate::errors::OpenVTCError;
use crate::git_workspace::CheckoutFacts;

/// What the signer's ACL entry is narrowed to: asking the VTA for an SSHSIG
/// signature (git's SSH commit-signing format) with the persona's key, and
/// nothing else a capability gates. The key never leaves the VTA, and the VTA
/// signs only SSHSIG statements for it — never bytes of the caller's choosing.
pub const SIGNER_CAPABILITIES: &[&str] = &["sign-sshsig"];

/// The narrowing for a VTA that predates `keys/sign-sshsig`: taking the key
/// out of the VTA at sign time, which is all such a VTA offers did-git-sign.
pub const LEGACY_SIGNER_CAPABILITIES: &[&str] = &["key-export"];

/// The task a VTA serves when it can sign commits itself.
const SIGN_SSHSIG_SLUG: &str = "keys/sign-sshsig";

/// The `did-git-sign` release whose CLI has `enable --profile` (0.14).
pub const MIN_BINARY: (u32, u32) = (0, 14);

/// How long a VTA round-trip during setup may take (R1.2).
const VTA_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `did-git-sign enable` / `disable` may take: local file edits, so a
/// hang means something is wrong.
const LOCAL_TIMEOUT: Duration = Duration::from_secs(30);

/// A persona's signing key, as did-git-sign needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonaSigner {
    /// The verification method commits are signed as, `did:…#key-N`.
    pub did_key_id: String,
    /// The VTA's id for that key.
    pub vta_key_id: String,
    /// Its Ed25519 public key.
    pub verifying_key: [u8; 32],
    /// The VTA context holding the key — the one the signer is granted.
    pub context: String,
    /// The persona's label, for the profile name and the ACL entry.
    pub label: String,
}

/// How to reach the VTA, from openvtc's own backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VtaEndpoint {
    pub vta_did: String,
    /// Empty for a VTA reached only over DIDComm.
    pub vta_url: String,
    pub mediator_did: Option<String>,
}

impl VtaEndpoint {
    /// The VTA openvtc's keys are in; `None` for a local (BIP-32) backend,
    /// which has no VTA for did-git-sign to fetch a key from.
    #[must_use]
    pub fn from_backend(backend: &KeyBackend) -> Option<Self> {
        match backend {
            KeyBackend::Vta {
                vta_did,
                vta_url,
                mediator_did,
                ..
            } => Some(Self {
                vta_did: vta_did.clone(),
                vta_url: vta_url.clone(),
                mediator_did: mediator_did.clone(),
            }),
            _ => None,
        }
    }
}

/// The signer's credential: a `did:key` and its private key.
pub struct SignerCredential {
    pub did: String,
    pub private_key_mb: SecretString,
}

impl SignerCredential {
    /// A fresh `did:key`, not yet granted anything.
    ///
    /// # Errors
    ///
    /// When key generation fails.
    pub fn generate() -> Result<Self, OpenVTCError> {
        let key = EphemeralSetupKey::generate().map_err(|e| {
            OpenVTCError::Config(format!("couldn't mint a signing credential: {e}"))
        })?;
        Ok(Self {
            did: key.did.clone(),
            private_key_mb: SecretString::from(key.private_key_multibase().to_string()),
        })
    }
}

/// The credential did-git-sign holds for `did_key_id`, read from the OS
/// keyring, so it can be proven again ([`verify_signer`]). Blocking.
#[must_use]
pub fn stored_credential(did_key_id: &str) -> Option<SignerCredential> {
    did_git_sign::config::load_vta_credentials(did_key_id)
        .ok()
        .map(|c| SignerCredential {
            did: c.credential_did,
            private_key_mb: SecretString::from(c.private_key_multibase),
        })
}

/// The ACL entry [`grant_signer`] asks for, narrowed to `capabilities`
/// ([`SIGNER_CAPABILITIES`], or [`LEGACY_SIGNER_CAPABILITIES`] for a VTA that
/// cannot sign commits itself).
pub fn signer_grant(
    did: &str,
    context: &str,
    label: &str,
    capabilities: &[&str],
) -> CreateAclRequest {
    CreateAclRequest::new(did, "admin")
        .contexts(vec![context.to_string()])
        .label(format!("did-git-sign · {label} (openvtc)"))
        .capabilities(capabilities.iter().map(|c| (*c).to_string()).collect())
}

/// Whether the VTA signs commits itself (`keys/sign-sshsig`), from its own
/// dispatch table (`trust-task-discovery`). An answer that does not list it —
/// or no answer — means an older VTA, which gets the legacy grant: a grant
/// naming a capability it does not know would be refused outright.
pub async fn vta_signs_sshsig(client: &VtaClient) -> bool {
    match tokio::time::timeout(
        VTA_TIMEOUT,
        client.supported_trust_tasks(&[SIGN_SSHSIG_SLUG]),
    )
    .await
    {
        Ok(Ok(answer)) => answer
            .supported_types
            .iter()
            .any(|t| t.contains(&format!("/{SIGN_SSHSIG_SLUG}/"))),
        Ok(Err(e)) => {
            tracing::debug!("trust-task-discovery failed; granting the legacy signer: {e}");
            false
        }
        Err(_) => false,
    }
}

/// Refuse a context whose admin would reach other personas' keys.
///
/// # Errors
///
/// When `context` is the account's top context — a persona minted before
/// per-persona contexts keeps its keys there, and admin of it is admin of
/// every persona.
pub fn check_context(context: &str, top_context_id: &str) -> Result<(), OpenVTCError> {
    if context.is_empty() || context == top_context_id {
        return Err(OpenVTCError::Config(
            "this persona's keys are in the account's own VTA context, so a signing credential \
             for it would reach every persona's keys. openvtc grants did-git-sign only a \
             persona's own context; use a persona minted with its own context, or run \
             `did-git-sign init` by hand if you accept that reach."
                .into(),
        ));
    }
    Ok(())
}

async fn timed<T>(
    what: &str,
    fut: impl Future<Output = Result<T, VtaError>>,
) -> Result<T, OpenVTCError> {
    match tokio::time::timeout(VTA_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(OpenVTCError::Config(format!("{what}: {e}"))),
        Err(_) => Err(OpenVTCError::Config(format!(
            "{what}: the VTA did not answer within {} s",
            VTA_TIMEOUT.as_secs()
        ))),
    }
}

/// Prove `cred` can do what signing does: connect to the VTA as it, have it
/// sign, and find the signature verifies under the key the persona publishes.
///
/// It asks for what did-git-sign will ask for: an SSHSIG signature
/// (`keys/sign-sshsig`), checked here against the persona's published key, so
/// the key never leaves the VTA. A VTA without that task, or a credential
/// granted before it existed (narrowed to `key-export`), is proven the older
/// way — the key is fetched and compared — which is also what did-git-sign's
/// default `auto` signer falls back to for them.
///
/// # Errors
///
/// When the connection, the signature, the export, or the comparison fails —
/// each said separately, so a refused grant never reads as a network fault
/// (R6.4).
pub async fn verify_signer(
    cred: &SignerCredential,
    signer: &PersonaSigner,
    endpoint: &VtaEndpoint,
) -> Result<(), OpenVTCError> {
    let connected = timed(
        "the signing credential could not connect to the VTA",
        VtaClient::connect_auto(AutoConnect {
            vta_url: &endpoint.vta_url,
            vta_did: &endpoint.vta_did,
            credential_did: &cred.did,
            private_key_multibase: cred.private_key_mb.expose_secret(),
            mediator_did: endpoint.mediator_did.as_deref(),
        }),
    )
    .await?;
    let remote = prove_remote_signing(&connected.client, signer).await;
    if !matches!(remote, Ok(RemoteProof::NotOffered)) {
        // A DIDComm session must be closed, whatever the answer was.
        connected.client.shutdown().await;
        return remote.map(|_| ());
    }
    let secret = timed(
        "the VTA refused the signing credential the persona's key",
        connected.client.get_key_secret(&signer.vta_key_id),
    )
    .await;
    connected.client.shutdown().await;
    let secret = secret?;
    if secret.key_type != vta_sdk::keys::KeyType::Ed25519 {
        return Err(OpenVTCError::Config(format!(
            "the persona's signing key is {:?}; did-git-sign signs with Ed25519 only",
            secret.key_type
        )));
    }
    let seed = vta_sdk::did_key::decode_private_key_multibase(&secret.private_key_multibase)
        .map_err(|e| OpenVTCError::Config(format!("the VTA's key could not be read: {e}")))?;
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if public != signer.verifying_key {
        return Err(OpenVTCError::Config(format!(
            "the VTA's key {} is not the key {} publishes; refusing to sign with it",
            signer.vta_key_id, signer.did_key_id
        )));
    }
    Ok(())
}

/// What asking the VTA to sign proved.
enum RemoteProof {
    /// It signed, and the signature verifies under the persona's key.
    Signed,
    /// Not on offer for this credential: the VTA has no `keys/sign-sshsig`, or
    /// the credential may not use it (one narrowed to `key-export`).
    NotOffered,
}

/// The digest the proof signs: SHA-512 of a fixed statement. What is signed is
/// an SSHSIG statement in the `git` namespace over it, which says nothing a
/// commit could be mistaken for.
const PROOF_MESSAGE: &[u8] = b"openvtc: proving did-git-sign's credential can sign";

async fn prove_remote_signing(
    client: &VtaClient,
    signer: &PersonaSigner,
) -> Result<RemoteProof, OpenVTCError> {
    use did_git_sign::vta::{RemoteSignature, sign_sshsig};
    let hash = vgi_core::sshsig_message_hash(PROOF_MESSAGE);
    let answer = tokio::time::timeout(VTA_TIMEOUT, sign_sshsig(client, &signer.vta_key_id, &hash))
        .await
        .map_err(|_| {
            OpenVTCError::Config(format!(
                "the VTA did not sign within {} s",
                VTA_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| OpenVTCError::Config(format!("the VTA refused to sign: {e}")))?;
    let raw = match answer {
        RemoteSignature::Signed(raw) => raw,
        RemoteSignature::Unsupported | RemoteSignature::NotPermitted(_) => {
            return Ok(RemoteProof::NotOffered);
        }
    };
    // The bytes the VTA signed are SSHSIG's signed data over the digest; check
    // the signature over them with the persona's published key.
    use ed25519_dalek_bip32::ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key = VerifyingKey::from_bytes(&signer.verifying_key)
        .map_err(|e| OpenVTCError::Config(format!("the persona's published key: {e}")))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|e| OpenVTCError::Config(format!("the VTA's signature: {e}")))?;
    key.verify(
        &vgi_core::sshsig_signed_data(vgi_core::GIT_SSHSIG_NAMESPACE, &hash),
        &signature,
    )
    .map_err(|_| {
        OpenVTCError::Config(format!(
            "the VTA's key {} is not the key {} publishes; refusing to sign with it",
            signer.vta_key_id, signer.did_key_id
        ))
    })?;
    Ok(RemoteProof::Signed)
}

/// Grant `cred` ([`SignerCredential::generate`]) the persona's context.
///
/// The grant is proven ([`verify_signer`]) before this returns, and revoked
/// again if the proof fails, so a failed setup leaves no entry behind. The
/// proof connects as the new credential, so the VTA's mediator must admit a
/// DID it has not seen — as it must for `did-git-sign init` and for every
/// commit signed afterwards.
///
/// # Errors
///
/// When the context is refused ([`check_context`]), the grant is refused, or
/// the proof fails.
pub async fn grant_signer(
    client: &VtaClient,
    cred: &SignerCredential,
    signer: &PersonaSigner,
    endpoint: &VtaEndpoint,
    top_context_id: &str,
) -> Result<(), OpenVTCError> {
    check_context(&signer.context, top_context_id)?;
    let capabilities = if vta_signs_sshsig(client).await {
        SIGNER_CAPABILITIES
    } else {
        LEGACY_SIGNER_CAPABILITIES
    };
    timed(
        "the VTA refused to grant did-git-sign the persona's context",
        client.create_acl(signer_grant(
            &cred.did,
            &signer.context,
            &signer.label,
            capabilities,
        )),
    )
    .await?;
    if let Err(e) = verify_signer(cred, signer, endpoint).await {
        if let Err(revoke) = timed("revoking it again", client.delete_acl(&cred.did)).await {
            tracing::warn!(did = %cred.did, "unproven signer grant left in place: {revoke}");
        }
        return Err(e);
    }
    Ok(())
}

/// Revoke a signer's ACL entry. Never openvtc's own: an identity set up before
/// openvtc minted signers may hold the account credential itself, and revoking
/// that would lock openvtc out of its own VTA.
///
/// # Errors
///
/// When the VTA refuses. An entry already gone is not an error.
pub async fn revoke_signer(
    client: &VtaClient,
    credential_did: &str,
    own_did: &str,
) -> Result<bool, OpenVTCError> {
    if credential_did == own_did {
        return Ok(false);
    }
    match tokio::time::timeout(VTA_TIMEOUT, client.delete_acl(credential_did)).await {
        Ok(Ok(())) => Ok(true),
        Ok(Err(VtaError::NotFound(_))) => Ok(false),
        Ok(Err(e)) => Err(OpenVTCError::Config(format!(
            "the VTA refused to revoke the signing credential: {e}"
        ))),
        Err(_) => Err(OpenVTCError::Config(
            "the VTA did not answer the revocation in time".into(),
        )),
    }
}

// ****************************************************************************
// The local install
// ****************************************************************************

/// A profile name for a persona: its label as a slug, made unique among the
/// profiles that name other identities. Reuses the name an identity already
/// has.
#[must_use]
pub fn profile_name(label: &str, did_key_id: &str, profiles: &Profiles) -> String {
    if let Some(name) = profiles.name_of(did_key_id) {
        return name.to_string();
    }
    let mut slug = String::new();
    for c in label.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let mut slug = slug.trim_matches('-').to_string();
    slug.truncate(48);
    let slug = slug.trim_end_matches('-');
    let base = if slug.is_empty() {
        "persona".to_string()
    } else {
        slug.to_string()
    };
    let base = if did_git_sign::profiles::validate_name(&base).is_ok() {
        base
    } else {
        "persona".to_string()
    };
    if !profiles.profiles.contains_key(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|n| !profiles.profiles.contains_key(n))
        .unwrap_or(base)
}

/// What [`install_identity`] wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledIdentity {
    pub profile: String,
    pub include: PathBuf,
    pub ssh_public_key: String,
    /// The credential this identity held before, if it was replaced — the
    /// caller revokes it.
    pub replaced_credential: Option<String>,
}

/// Store the signer for did-git-sign as a named profile. Blocking.
///
/// The first identity on the machine becomes did-git-sign's default (as
/// `init` does); later ones are added beside it. Re-running for an identity
/// that already exists replaces its credential and keeps its profile name.
///
/// # Errors
///
/// When the keyring, the profile file or the include file cannot be written.
pub fn install_identity(
    signer: &PersonaSigner,
    endpoint: &VtaEndpoint,
    cred: &SignerCredential,
) -> Result<InstalledIdentity, OpenVTCError> {
    let io = |what: &str, e: anyhow::Error| OpenVTCError::Config(format!("{what}: {e:#}"));
    let mut profiles =
        Profiles::load().map_err(|e| io("couldn't read did-git-sign's profiles", e))?;
    let name = profile_name(&signer.label, &signer.did_key_id, &profiles);
    let replaced_credential = did_git_sign::config::load_vta_credentials(&signer.did_key_id)
        .ok()
        .map(|c| c.credential_did)
        .filter(|did| *did != cred.did);
    let args = init::InstallArgs {
        global: false,
        did_key_id: signer.did_key_id.clone(),
        vta_key_id: signer.vta_key_id.clone(),
        credential_did: cred.did.clone(),
        credential_private_key_mb: cred.private_key_mb.expose_secret().to_string(),
        vta_did: endpoint.vta_did.clone(),
        vta_url: endpoint.vta_url.clone(),
        mediator_did: endpoint.mediator_did.clone(),
        user_name: None,
        verifying_key: &signer.verifying_key,
    };
    let default_exists = SigningConfig::default_global_path()
        .map(|p| p.exists())
        .unwrap_or(false);
    let ssh_public_key = if default_exists {
        init::add_identity(args).map_err(|e| io("couldn't store the signing identity", e))?
    } else {
        init::install(args)
            .map_err(|e| io("couldn't store the signing identity", e))?
            .ssh_public_key
    };
    profiles.profiles.insert(
        name.clone(),
        Profile {
            did_key_id: signer.did_key_id.clone(),
            vta_did: endpoint.vta_did.clone(),
            context: Some(signer.context.clone()),
        },
    );
    profiles
        .save()
        .map_err(|e| io("couldn't save did-git-sign's profiles", e))?;
    let include = enable::write_include(&name, &signer.did_key_id)
        .map_err(|e| io("couldn't write the signing settings", e))?;
    Ok(InstalledIdentity {
        profile: name,
        include,
        ssh_public_key,
        replaced_credential,
    })
}

/// What [`remove_identity`] removed.
#[derive(Debug, Default)]
pub struct RemovedIdentity {
    /// The credential it held, for the caller to revoke.
    pub credential_did: Option<String>,
    pub profiles_removed: Vec<String>,
    pub include_lines_removed: usize,
    pub warnings: Vec<String>,
}

/// Remove a persona's identity from did-git-sign: its keyring entries,
/// `allowed_signers` line, include files and the lines including them, and its
/// profiles. Blocking. Repositories that included it stop signing.
///
/// # Errors
///
/// When did-git-sign's files cannot be read.
pub fn remove_identity(did_key_id: &str) -> Result<RemovedIdentity, OpenVTCError> {
    let credential_did = did_git_sign::config::load_vta_credentials(did_key_id)
        .ok()
        .map(|c| c.credential_did);
    // `global = true`: the `false` form also inspects whatever repository the
    // process happens to be running in.
    let summary = init::uninstall(true, did_key_id)
        .map_err(|e| OpenVTCError::Config(format!("couldn't remove the identity: {e:#}")))?;
    let mut removed = RemovedIdentity {
        credential_did,
        include_lines_removed: summary.removed_include_lines,
        warnings: summary.warnings,
        ..RemovedIdentity::default()
    };
    if let Ok(mut profiles) = Profiles::load() {
        let names: Vec<String> = profiles
            .profiles
            .iter()
            .filter(|(_, p)| p.did_key_id == did_key_id)
            .map(|(n, _)| n.clone())
            .collect();
        for n in &names {
            profiles.profiles.remove(n);
        }
        if !names.is_empty() {
            if let Err(e) = profiles.save() {
                removed
                    .warnings
                    .push(format!("couldn't update profiles.json: {e:#}"));
            }
            removed.profiles_removed = names;
        }
    }
    Ok(removed)
}

/// What did-git-sign holds for one persona.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IdentityStatus {
    /// The profile naming this identity.
    pub profile: Option<String>,
    /// The credential in the keyring; `None` when there is none, and signing
    /// would fail.
    pub credential_did: Option<String>,
    /// The profile's include file, when it exists and signs as this identity.
    pub include: Option<PathBuf>,
    /// Whether did-git-sign's default identity is this one.
    pub default: bool,
}

impl IdentityStatus {
    /// Ready to be enabled in a repository.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.profile.is_some() && self.credential_did.is_some() && self.include.is_some()
    }

    /// Whether anything at all is set up.
    #[must_use]
    pub fn any(&self) -> bool {
        self.profile.is_some() || self.credential_did.is_some() || self.default
    }
}

/// Read what did-git-sign holds for `did_key_id`. Blocking; reads the OS
/// keyring.
#[must_use]
pub fn identity_status(did_key_id: &str) -> IdentityStatus {
    let profile = Profiles::load()
        .ok()
        .and_then(|p| p.name_of(did_key_id).map(str::to_string));
    let include = profile
        .as_deref()
        .and_then(|n| enable::include_path(n).ok())
        .filter(|p| enable::include_identity(p).as_deref() == Some(did_key_id));
    IdentityStatus {
        credential_did: did_git_sign::config::load_vta_credentials(did_key_id)
            .ok()
            .map(|c| c.credential_did),
        default: SigningConfig::default_global_path()
            .ok()
            .and_then(|p| SigningConfig::load(&p).ok())
            .is_some_and(|c| c.did_key_id == did_key_id),
        profile,
        include,
    }
}

/// Rewrite did-git-sign's hooks from this build's library — what re-running
/// `did-git-sign init` does for an outdated hook. Blocking.
///
/// # Errors
///
/// When the hook directory cannot be written.
pub fn refresh_hooks() -> Result<(), OpenVTCError> {
    init::install_hooks()
        .map_err(|e| OpenVTCError::Config(format!("couldn't write did-git-sign's hooks: {e:#}")))
}

/// The commit-msg hook the include files point repositories at.
#[must_use]
pub fn hook_file() -> Option<PathBuf> {
    enable::hooks_dir().ok().map(|d| d.join("commit-msg"))
}

// ****************************************************************************
// The binary
// ****************************************************************************

/// The `did-git-sign` git will run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinaryStatus {
    Found {
        version: String,
    },
    /// Older than [`MIN_BINARY`]: it cannot `enable --profile`.
    TooOld {
        version: String,
    },
    /// Not on `PATH` — git cannot sign with it.
    Missing,
}

/// `major.minor` of a `did-git-sign --version` line.
fn parse_version(out: &str) -> Option<(String, (u32, u32))> {
    let version = out.split_whitespace().last()?.trim().to_string();
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((version, (major, minor)))
}

/// Ask `did-git-sign --version`. Blocking.
#[must_use]
pub fn binary_status() -> BinaryStatus {
    let Ok(out) = Command::new("did-git-sign")
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return BinaryStatus::Missing;
    };
    match parse_version(&String::from_utf8_lossy(&out.stdout)) {
        Some((version, v)) if v >= MIN_BINARY => BinaryStatus::Found { version },
        Some((version, _)) => BinaryStatus::TooOld { version },
        None => BinaryStatus::Missing,
    }
}

/// Run `did-git-sign <args>` in `dir`, bounded. The error is what it said.
fn run_in(dir: &Path, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new("did-git-sign")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("couldn't run did-git-sign: {e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() >= LOCAL_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("did-git-sign did not finish in time".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("couldn't wait for did-git-sign: {e}")),
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("couldn't read did-git-sign's output: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        Err(err
            .strip_prefix("Error: ")
            .unwrap_or(err)
            .lines()
            .next()
            .unwrap_or("did-git-sign failed")
            .to_string())
    }
}

/// `did-git-sign enable --profile <profile>` in the checkout at `repo`.
///
/// # Errors
///
/// What did-git-sign said — for example that another tool owns
/// `core.hooksPath` there.
pub fn enable_in(repo: &Path, profile: &str) -> Result<(), String> {
    run_in(repo, &["enable", "--profile", profile]).map(|_| ())
}

/// `did-git-sign disable` in the checkout at `repo`.
///
/// # Errors
///
/// What did-git-sign said.
pub fn disable_in(repo: &Path) -> Result<(), String> {
    run_in(repo, &["disable"]).map(|_| ())
}

// ****************************************************************************
// Reading a checkout's signing
// ****************************************************************************

/// How a commit in one checkout would be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckoutSigning {
    /// Not by did-git-sign.
    Off,
    /// By did-git-sign, as `did_key_id`. `here` when the checkout's own config
    /// includes the settings (`enable`); otherwise they come from a directory
    /// or global include.
    On {
        did_key_id: String,
        profile: Option<String>,
        here: bool,
    },
    /// Signed, but another tool's `core.hooksPath` replaces did-git-sign's
    /// hooks, so no `Signed-by-DID:` claim is written and CI fails the commit
    /// as `noSignerDid`.
    NoClaim {
        did_key_id: String,
        hooks_path: String,
    },
}

/// Read a checkout's signing from what git reports there.
#[must_use]
pub fn checkout_signing(facts: &CheckoutFacts, profiles: &Profiles) -> CheckoutSigning {
    let here = facts.includes.iter().any(|v| enable::is_our_include(v));
    let signs = facts.ssh_program.as_deref() == Some("did-git-sign") && facts.gpgsign;
    let Some(did_key_id) = facts.signing_key.clone().filter(|_| signs) else {
        return CheckoutSigning::Off;
    };
    if let (Some(hooks_path), Ok(ours)) = (&facts.hooks_path, enable::hooks_dir()) {
        let expanded = crate::git_workspace::expand_tilde(hooks_path);
        if expanded != ours {
            return CheckoutSigning::NoClaim {
                did_key_id,
                hooks_path: hooks_path.clone(),
            };
        }
    }
    CheckoutSigning::On {
        profile: profiles.name_of(&did_key_id).map(str::to_string),
        did_key_id,
        here,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles_with(name: &str, did: &str) -> Profiles {
        let mut p = Profiles::default();
        p.profiles.insert(
            name.into(),
            Profile {
                did_key_id: did.into(),
                vta_did: "did:webvh:vta".into(),
                context: None,
            },
        );
        p
    }

    #[test]
    fn profile_names_are_slugs_and_unique() {
        let none = Profiles::default();
        assert_eq!(
            profile_name("Alice @ Acme", "did:a#key-0", &none),
            "alice-acme"
        );
        assert_eq!(profile_name("  ", "did:a#key-0", &none), "persona");
        assert_eq!(profile_name("Ünïcode", "did:a#key-0", &none), "n-code");
        let taken = profiles_with("alice", "did:other#key-0");
        assert_eq!(profile_name("Alice", "did:a#key-0", &taken), "alice-2");
        let mine = profiles_with("work", "did:a#key-0");
        assert_eq!(profile_name("Alice", "did:a#key-0", &mine), "work");
        for label in [
            "Alice @ Acme",
            "x",
            "A very long persona label that keeps going on and on",
        ] {
            let n = profile_name(label, "did:a#key-0", &none);
            assert!(did_git_sign::profiles::validate_name(&n).is_ok(), "{n}");
        }
    }

    #[test]
    fn the_account_context_is_refused() {
        assert!(check_context("openvtc", "openvtc").is_err());
        assert!(check_context("", "openvtc").is_err());
        assert!(check_context("openvtc/alice", "openvtc").is_ok());
    }

    #[test]
    fn the_grant_is_narrowed_to_sshsig_signing_in_one_context() {
        let req = signer_grant(
            "did:key:z6Mk",
            "openvtc/alice",
            "Alice",
            SIGNER_CAPABILITIES,
        );
        assert_eq!(req.role, "admin");
        assert_eq!(req.allowed_contexts, vec!["openvtc/alice".to_string()]);
        // The key never leaves the VTA: no `key-export`, no general `sign`.
        assert_eq!(req.capabilities, vec!["sign-sshsig".to_string()]);
        assert!(
            req.label
                .as_deref()
                .unwrap_or_default()
                .contains("did-git-sign")
        );
        assert!(!req.handoff);
    }

    #[test]
    fn an_older_vta_gets_the_key_export_grant() {
        let req = signer_grant(
            "did:key:z6Mk",
            "openvtc/alice",
            "Alice",
            LEGACY_SIGNER_CAPABILITIES,
        );
        assert_eq!(req.capabilities, vec!["key-export".to_string()]);
    }

    #[test]
    fn versions_are_read() {
        assert_eq!(
            parse_version("did-git-sign 0.15.1\n"),
            Some(("0.15.1".into(), (0, 15)))
        );
        assert_eq!(parse_version("nonsense"), None);
        assert!((0, 13) < MIN_BINARY && (0, 14) >= MIN_BINARY && (1, 0) >= MIN_BINARY);
    }

    fn facts(key: Option<&str>, program: Option<&str>, gpgsign: bool) -> CheckoutFacts {
        CheckoutFacts {
            is_repo: true,
            signing_key: key.map(str::to_string),
            ssh_program: program.map(str::to_string),
            gpgsign,
            ..CheckoutFacts::default()
        }
    }

    #[test]
    fn a_checkout_signs_only_when_git_would_call_did_git_sign() {
        let p = profiles_with("alice", "did:a#key-0");
        assert_eq!(
            checkout_signing(&facts(None, None, false), &p),
            CheckoutSigning::Off
        );
        assert_eq!(
            checkout_signing(&facts(Some("did:a#key-0"), Some("ssh-keygen"), true), &p),
            CheckoutSigning::Off
        );
        assert_eq!(
            checkout_signing(&facts(Some("did:a#key-0"), Some("did-git-sign"), false), &p),
            CheckoutSigning::Off
        );
        let mut f = facts(Some("did:a#key-0"), Some("did-git-sign"), true);
        f.hooks_path = enable::hooks_dir().ok().map(|d| d.display().to_string());
        assert_eq!(
            checkout_signing(&f, &p),
            CheckoutSigning::On {
                did_key_id: "did:a#key-0".into(),
                profile: Some("alice".into()),
                here: false
            }
        );
        f.includes = vec![enable::include_path("alice").unwrap().display().to_string()];
        assert!(matches!(
            checkout_signing(&f, &p),
            CheckoutSigning::On { here: true, .. }
        ));
        f.hooks_path = Some(".husky".into());
        assert!(matches!(
            checkout_signing(&f, &p),
            CheckoutSigning::NoClaim { .. }
        ));
    }
}
