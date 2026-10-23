//! `openvtc signing enable [<repo-path>]`: the headless form of pressing `e`
//! ("sign here") in the Repos panel.
//!
//! Sets did-git-sign up for the persona if it is not (a fresh `did:key`,
//! granted the persona's VTA context and proven, then stored as a named
//! profile), then runs `did-git-sign enable --profile` in the checkout, so
//! `git commit -S` there signs as the persona with a `Signed-by-DID:` claim.
//!
//! The persona is `--persona` when given, else the only persona holding an
//! active membership.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Arg, ArgMatches, Command};
use did_git_sign::profiles::Profiles;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context::persona_context;
use openvtc_core::config::secured_config::KeySourceMaterial;
use openvtc_core::config::{Config, KeyBackend};
use openvtc_core::git_signing::{
    self, BinaryStatus, CheckoutSigning, PersonaSigner, SignerCredential, VtaEndpoint,
};
use openvtc_core::git_workspace::{self, RepoCoords};
use vta_sdk::client::VtaClient;

use crate::headless::{self, Admin, step, warn};
use crate::state_handler::DeferredLoad;

/// The `signing` subcommand's definition.
pub fn command() -> Command {
    Command::new("signing")
        .about("Set up did-git-sign commit signing without the TUI")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("enable")
                .about("Make a checkout sign commits as your persona (the TUI's `e` in Repos)")
                .long_about(
                    "Make a checkout sign commits as your persona: the headless form of \
                     pressing e in the TUI's Repos panel.\n\n\
                     If did-git-sign holds no working identity for the persona, a fresh \
                     signing credential is granted the persona's own VTA context, proven, \
                     and stored as a did-git-sign profile. Then `did-git-sign enable \
                     --profile` runs in the checkout, so `git commit -S` signs there with a \
                     Signed-by-DID claim. Needs did-git-sign on PATH and the VTA reachable.",
                )
                .args([
                    Arg::new("path")
                        .value_name("REPO_PATH")
                        .default_value(".")
                        .help("The checkout to sign in (default: the current directory)"),
                    Arg::new("persona").long("persona").value_name("NAME").help(
                        "The persona to sign as: its DID, label or agent name. Needed \
                         only when more than one persona holds an active membership.",
                    ),
                ]),
        )
}

/// Run `openvtc signing <sub>`.
pub async fn run(args: &ArgMatches, deferred: DeferredLoad) -> Result<()> {
    match args.subcommand() {
        Some(("enable", m)) => {
            let path = m.get_one::<String>("path").map_or(".", String::as_str);
            let persona = m.get_one::<String>("persona").map(String::as_str);
            enable(Path::new(path), persona, deferred).await
        }
        _ => bail!("unknown `signing` subcommand"),
    }
}

async fn enable(path: &Path, persona_arg: Option<&str>, deferred: DeferredLoad) -> Result<()> {
    let repo = repo_root(path)?;
    let coords = origin(&repo).as_deref().and_then(RepoCoords::from_remote);
    match &coords {
        Some(c) => step(format!(
            "Checkout {} ({})",
            git_workspace::display_path(&repo),
            c.resource()
        )),
        None => step(format!(
            "Checkout {} (no forge origin recognised)",
            git_workspace::display_path(&repo)
        )),
    }

    step("Unlocking the account and connecting to the VTA…");
    let (config, tdk, client) = headless::load_account(deferred, Admin::Open).await?;
    let result = sign(
        &repo,
        coords.as_ref(),
        persona_arg,
        &config,
        &tdk,
        client.as_ref(),
    )
    .await;
    if let Some(client) = client {
        client.shutdown().await;
    }
    let done = result?;
    println!("{done}");
    Ok(())
}

async fn sign(
    repo: &Path,
    coords: Option<&RepoCoords>,
    persona_arg: Option<&str>,
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    client: Option<&VtaClient>,
) -> Result<String> {
    let endpoint = VtaEndpoint::from_backend(&config.key_backend).ok_or_else(|| {
        anyhow!("openvtc's keys are not held by a VTA, so there is no key for did-git-sign")
    })?;

    let persona = match persona_arg {
        Some(name) => headless::find_persona(config, name)?,
        None => only_member(config)?,
    };

    let signer = persona_signer(config, tdk, persona)
        .await
        .map_err(|e| anyhow!(e))?;
    step(format!(
        "Persona '{}' ({})",
        signer.label, signer.did_key_id
    ));

    let profile_name = set_up(&signer, &endpoint, client, config).await?;

    match blocking(git_signing::binary_status).await? {
        BinaryStatus::Found { .. } => {}
        BinaryStatus::TooOld { version } => bail!(
            "did-git-sign {version} is too old to `enable --profile`; install a newer one \
             (`cargo install did-git-sign`)"
        ),
        BinaryStatus::Missing => bail!(
            "did-git-sign is not on PATH, and git runs it to sign every commit. Install it \
             (`cargo install did-git-sign`), then run this again"
        ),
    }
    step(format!(
        "Enabling profile '{profile_name}' in the checkout…"
    ));
    let (r, p) = (repo.to_path_buf(), profile_name.clone());
    blocking(move || git_signing::enable_in(&r, &p))
        .await?
        .map_err(|e| anyhow!("did-git-sign enable failed: {e}"))?;

    // Read it back, as the TUI's probe would.
    if let Some(c) = coords {
        let facts = git_workspace::inspect(repo, c);
        match git_signing::checkout_signing(&facts, &Profiles::load().unwrap_or_default()) {
            CheckoutSigning::On { did_key_id, .. } if did_key_id == signer.did_key_id => {}
            CheckoutSigning::NoClaim { hooks_path, .. } => warn(format!(
                "core.hooksPath is {hooks_path}, so did-git-sign's hook does not run and \
                 commits carry no Signed-by-DID claim"
            )),
            other => warn(format!(
                "the checkout does not read as signing yet: {other:?}"
            )),
        }
    }
    Ok(format!(
        "Commits in {} are signed as '{profile_name}' ({}).",
        git_workspace::display_path(repo),
        signer.did_key_id
    ))
}

/// The TUI's `set_up(false)`: reuse a ready identity, else grant, prove and
/// store a new credential. Returns the did-git-sign profile name.
async fn set_up(
    signer: &PersonaSigner,
    endpoint: &VtaEndpoint,
    client: Option<&VtaClient>,
    config: &Config,
) -> Result<String> {
    let did = signer.did_key_id.clone();
    let status = blocking(move || git_signing::identity_status(&did)).await?;
    if status.ready() {
        step("did-git-sign already holds this persona's identity");
        blocking(git_signing::refresh_hooks).await??;
        return status
            .profile
            .ok_or_else(|| anyhow!("did-git-sign's profile went missing"));
    }

    let client = client.ok_or_else(|| {
        anyhow!("no admin session with the VTA, so did-git-sign cannot be granted a credential")
    })?;
    let top_context_id = &config.account.top_context_id;
    git_signing::check_context(&signer.context, top_context_id)?;
    step(format!(
        "Granting a new signing credential the persona's context '{}'…",
        signer.context
    ));
    let cred = SignerCredential::generate()?;
    git_signing::grant_signer(client, &cred, signer, endpoint, top_context_id).await?;
    let new_did = cred.did.clone();
    let own = own_did(config);

    step("Storing the identity for did-git-sign…");
    let installed = {
        let (s, e) = (signer.clone(), endpoint.clone());
        blocking(move || git_signing::install_identity(&s, &e, &cred)).await?
    };
    let installed = match installed {
        Ok(i) => i,
        Err(e) => {
            // Stored nowhere, so take the grant back.
            if let Err(r) = git_signing::revoke_signer(client, &new_did, &own).await {
                tracing::warn!("couldn't revoke an unstored signer grant: {r}");
            }
            return Err(e.into());
        }
    };
    if let Some(old) = &installed.replaced_credential
        && let Err(e) = git_signing::revoke_signer(client, old, &own).await
    {
        warn(format!(
            "couldn't revoke did-git-sign's previous credential {old}: {e}"
        ));
    }
    Ok(installed.profile)
}

fn own_did(config: &Config) -> String {
    match &config.key_backend {
        KeyBackend::Vta { credential_did, .. } => credential_did.clone(),
        _ => String::new(),
    }
}

/// The persona's signing key as did-git-sign needs it. Mirrors the Repos
/// panel's `persona_signer`.
async fn persona_signer(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    persona: PersonaId,
) -> Result<PersonaSigner, String> {
    let keys = config
        .get_persona_keys_for(persona, tdk)
        .await
        .map_err(|e| format!("couldn't read this persona's signing key: {e}"))?;
    let did_key_id = keys.signing.secret.id.clone();
    if !did_key_id.contains('#') {
        return Err(format!(
            "this persona's signing key has no verification method id ({did_key_id})"
        ));
    }
    let KeySourceMaterial::VtaManaged { key_id } = &keys.signing.source else {
        return Err(
            "this persona's signing key is not held by a VTA, so did-git-sign has nowhere to \
             fetch it from"
                .into(),
        );
    };
    let public = keys.signing.secret.get_public_bytes();
    let verifying_key: [u8; 32] = public.try_into().map_err(|_| {
        format!(
            "this persona's signing key is {} bytes; did-git-sign signs with Ed25519 only",
            public.len()
        )
    })?;
    let record = config
        .account
        .personas
        .get(&persona)
        .ok_or_else(|| "this persona is not in the account".to_string())?;
    Ok(PersonaSigner {
        did_key_id,
        vta_key_id: key_id.clone(),
        verifying_key,
        context: persona_context(record, &config.account.top_context_id).to_string(),
        label: record
            .label
            .clone()
            .filter(|l| !l.trim().is_empty())
            .unwrap_or_else(|| "persona".into()),
    })
}

/// The only persona holding an active membership.
fn only_member(config: &Config) -> Result<PersonaId> {
    let mut members: Vec<PersonaId> = config
        .account
        .memberships()
        .filter(|c| c.status.is_active())
        .map(|c| c.persona_ref)
        .collect();
    members.sort();
    members.dedup();
    match members.as_slice() {
        [one] => Ok(*one),
        [] => bail!(
            "no persona holds an active community membership; choose one with --persona. {}",
            headless::persona_listing(config)
        ),
        _ => bail!(
            "more than one persona holds an active membership; choose one with --persona. {}",
            headless::persona_listing(config)
        ),
    }
}

// ****************************************************************************
// The checkout
// ****************************************************************************

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Process::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The working tree's top directory, or an error when `path` is not in one.
fn repo_root(path: &Path) -> Result<PathBuf> {
    let abs = std::fs::canonicalize(path)
        .with_context(|| format!("no such directory: {}", path.display()))?;
    git(&abs, &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("{} is not inside a git checkout", abs.display()))
}

fn origin(repo: &Path) -> Option<String> {
    git(repo, &["remote", "get-url", "origin"])
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow!("background task failed: {e}"))
}
