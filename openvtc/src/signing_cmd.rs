//! `openvtc signing enable [<repo-path>]`: the headless form of pressing `e`
//! ("sign here") in the Repos panel.
//!
//! Sets did-git-sign up for the persona if it is not (a fresh `did:key`,
//! granted the persona's VTA context and proven, then stored as a named
//! profile), then runs `did-git-sign enable --profile` in the checkout, so
//! `git commit -S` there signs as the persona with a `Signed-by-DID:` claim.
//!
//! The persona is the one the checkout belongs to: `--persona` when given,
//! else the one already signing there, else the community a forge-account
//! choice ties the repository to, else the only persona holding an active
//! membership.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Arg, ArgMatches, Command};
use console::style;
use did_git_sign::profiles::Profiles;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context::persona_context;
use openvtc_core::config::secured_config::KeySourceMaterial;
use openvtc_core::config::{Config, KeyBackend};
use openvtc_core::git_signing::{
    self, BinaryStatus, CheckoutSigning, PersonaSigner, SignerCredential, VtaEndpoint,
};
use openvtc_core::git_workspace::{self, RepoCoords, WorkspaceSettings};
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
use vta_sdk::client::VtaClient;

use crate::colors::{CLI_CAUTION, CLI_INFO, Themed};
use crate::{SuppliedUnlockCode, load_fast, redact_paths};

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
                        "The persona to sign as, by label or DID. Needed only when the \
                         checkout could belong to more than one persona.",
                    ),
                ]),
        )
}

/// Run `openvtc signing <sub>`.
pub async fn run(
    args: &ArgMatches,
    profile: &str,
    unlock: Option<&SuppliedUnlockCode>,
) -> Result<()> {
    match args.subcommand() {
        Some(("enable", m)) => {
            let path = m.get_one::<String>("path").map_or(".", String::as_str);
            let persona = m.get_one::<String>("persona").map(String::as_str);
            enable(Path::new(path), persona, profile, unlock).await
        }
        _ => bail!("unknown `signing` subcommand"),
    }
}

fn step(msg: impl std::fmt::Display) {
    eprintln!("{} {msg}", style("•").themed(CLI_INFO));
}

async fn enable(
    path: &Path,
    persona_arg: Option<&str>,
    profile: &str,
    unlock: Option<&SuppliedUnlockCode>,
) -> Result<()> {
    let repo = repo_root(path)?;
    let coords = origin(&repo).as_deref().and_then(coords_from_remote);
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
    let (config, tdk, client) = load(profile, unlock).await?;
    let result = sign(
        &repo,
        coords.as_ref(),
        persona_arg,
        profile,
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
    profile: &str,
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    client: Option<&VtaClient>,
) -> Result<String> {
    let endpoint = VtaEndpoint::from_backend(&config.key_backend).ok_or_else(|| {
        anyhow!("openvtc's keys are not held by a VTA, so there is no key for did-git-sign")
    })?;

    // What the checkout signs as now, for the persona choice.
    let current_key = coords.and_then(|c| {
        let facts = git_workspace::inspect(repo, c);
        match git_signing::checkout_signing(&facts, &Profiles::load().unwrap_or_default()) {
            CheckoutSigning::On { did_key_id, .. }
            | CheckoutSigning::NoClaim { did_key_id, .. } => Some(did_key_id),
            CheckoutSigning::Off => None,
        }
    });
    let hinted = coords
        .map(|c| hinted_communities(profile, c))
        .unwrap_or_default();
    let persona = choose_persona(
        &candidates(config),
        persona_arg,
        current_key.as_deref(),
        &hinted,
    )
    .map_err(|e| anyhow!(e))?;

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
            CheckoutSigning::NoClaim { hooks_path, .. } => eprintln!(
                "{}",
                style(format!(
                    "warning: core.hooksPath is {hooks_path}, so did-git-sign's hook does not \
                     run and commits carry no Signed-by-DID claim"
                ))
                .themed(CLI_CAUTION)
            ),
            other => eprintln!(
                "{}",
                style(format!(
                    "warning: the checkout does not read as signing yet: {other:?}"
                ))
                .themed(CLI_CAUTION)
            ),
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
        eprintln!(
            "{}",
            style(format!(
                "warning: couldn't revoke did-git-sign's previous credential {old}: {e}"
            ))
            .themed(CLI_CAUTION)
        );
    }
    Ok(installed.profile)
}

/// Load the account and keep the admin VTA session `load_step2` opens.
async fn load(
    profile: &str,
    unlock: Option<&SuppliedUnlockCode>,
) -> Result<(Config, affinidi_tdk::TDK, Option<VtaClient>)> {
    let deferred =
        load_fast(profile, unlock).map_err(|e| anyhow!("{}", redact_paths(&e.to_string())))?;
    let mut tdk = affinidi_tdk::TDK::new(
        affinidi_tdk::common::config::TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .map_err(|e| anyhow!("TDK config: {e}"))?,
        None,
    )
    .await
    .map_err(|e| anyhow!("TDK init failed: {e}"))?;

    #[cfg(feature = "openpgp-card")]
    struct TouchPrompt;
    #[cfg(feature = "openpgp-card")]
    impl openvtc_core::config::TokenInteractions for TouchPrompt {
        fn touch_notify(&self) {
            eprintln!("Touch your security token to continue…");
        }
        fn touch_completed(&self) {}
    }
    #[cfg(feature = "openpgp-card")]
    let no_token_pin = SecretString::new(String::new().into());

    let (config, session) = Config::load_step2(
        &mut tdk,
        profile,
        deferred.public_config,
        deferred.unlock_passphrase.as_ref(),
        #[cfg(feature = "openpgp-card")]
        deferred.user_pin.as_ref().unwrap_or(&no_token_pin),
        #[cfg(feature = "openpgp-card")]
        &TouchPrompt,
        None,
    )
    .await
    .map_err(|e| anyhow!("account not loaded: {}", redact_paths(&e.to_string())))?;
    // As the TUI does: open one when the load did not hand one back.
    let session = match session {
        Some(s) => Some(s),
        None if matches!(config.key_backend, KeyBackend::Vta { .. }) => {
            openvtc_core::config::build_runtime_vta_client(&config.key_backend)
                .await
                .ok()
        }
        None => None,
    };
    Ok((config, tdk, session))
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

// ****************************************************************************
// Choosing the persona
// ****************************************************************************

/// A persona, with the active communities it is a member of.
#[derive(Clone, Debug)]
struct Candidate {
    id: PersonaId,
    label: String,
    did: String,
    communities: Vec<String>,
}

fn candidates(config: &Config) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = config
        .account
        .personas
        .values()
        .map(|p| Candidate {
            id: p.persona_id,
            label: p.label.clone().unwrap_or_default(),
            did: p.did.clone(),
            communities: Vec::new(),
        })
        .collect();
    for c in config.account.communities_for_display(false) {
        if !c.status.is_active() {
            continue;
        }
        if let Some(p) = out.iter_mut().find(|p| p.id == c.persona_ref) {
            p.communities.push(c.vtc_did.clone());
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.did.cmp(&b.did)));
    out
}

/// Communities whose stored forge-account choice names this repository or
/// its forge: the only local record tying a checkout to a community.
fn hinted_communities(profile: &str, coords: &RepoCoords) -> Vec<String> {
    let Ok(settings) =
        WorkspaceSettings::path(profile).and_then(|p| WorkspaceSettings::load_from(&p))
    else {
        return Vec::new();
    };
    let resource = coords.resource();
    let by_repo: Vec<String> = settings
        .credentials
        .iter()
        .filter(|(_, c)| c.repos.contains_key(&resource))
        .map(|(v, _)| v.clone())
        .collect();
    if !by_repo.is_empty() {
        return by_repo;
    }
    settings
        .credentials
        .iter()
        .filter(|(_, c)| c.forges.contains_key(&coords.host))
        .map(|(v, _)| v.clone())
        .collect()
}

/// Pick the persona for a checkout. In order: `--persona`, the persona the
/// checkout already signs as, the communities the settings tie it to, the
/// only persona with an active membership.
fn choose_persona(
    all: &[Candidate],
    arg: Option<&str>,
    current_key: Option<&str>,
    hinted: &[String],
) -> Result<PersonaId, String> {
    if let Some(name) = arg {
        let found: Vec<&Candidate> = all
            .iter()
            .filter(|p| p.did == name || p.label.eq_ignore_ascii_case(name))
            .collect();
        return match found.as_slice() {
            [one] => Ok(one.id),
            [] => Err(format!("no persona '{name}'. {}", listing(all))),
            _ => Err(format!(
                "more than one persona is labelled '{name}'; name it by DID. {}",
                listing(all)
            )),
        };
    }
    if let Some(key) = current_key
        && let Some(p) = all
            .iter()
            .find(|p| key.split_once('#').is_some_and(|(did, _)| did == p.did))
    {
        return Ok(p.id);
    }
    let unique = |pool: Vec<&Candidate>| match pool.as_slice() {
        [one] => Some(one.id),
        _ => None,
    };
    if let Some(id) = unique(
        all.iter()
            .filter(|p| p.communities.iter().any(|c| hinted.contains(c)))
            .collect(),
    ) {
        return Ok(id);
    }
    let members: Vec<&Candidate> = all.iter().filter(|p| !p.communities.is_empty()).collect();
    if members.is_empty() {
        return Err(format!(
            "no persona holds an active community membership; choose one with --persona. {}",
            listing(all)
        ));
    }
    unique(members).ok_or_else(|| {
        format!(
            "this checkout could belong to more than one persona; choose one with --persona. {}",
            listing(all)
        )
    })
}

fn listing(all: &[Candidate]) -> String {
    if all.is_empty() {
        return "The account has no personas.".into();
    }
    let rows: Vec<String> = all
        .iter()
        .map(|p| {
            let label = if p.label.is_empty() {
                "(unlabelled)"
            } else {
                &p.label
            };
            format!(
                "\n  {label}  {}  ({} active communit{})",
                p.did,
                p.communities.len(),
                if p.communities.len() == 1 { "y" } else { "ies" }
            )
        })
        .collect();
    format!("Personas:{}", rows.concat())
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

/// A remote URL as forge coordinates, in the forms git accepts:
/// `https://host/owner/repo(.git)`, `ssh://[user@]host[:port]/owner/repo`,
/// scp-like `user@host:owner/repo`.
fn coords_from_remote(url: &str) -> Option<RepoCoords> {
    let url = url.trim();
    let (host, path) = if let Some((scheme, rest)) = url.split_once("://") {
        if !matches!(scheme, "https" | "http" | "ssh" | "git") {
            return None;
        }
        let (authority, path) = rest.split_once('/')?;
        let host = authority.rsplit('@').next()?.split(':').next()?;
        (host, path)
    } else {
        let (authority, path) = url.split_once(':')?;
        if authority.contains('/') {
            return None;
        }
        (authority.rsplit('@').next()?, path)
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    RepoCoords::parse(&format!("{}/{path}", host.to_ascii_lowercase())).ok()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow!("background task failed: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn remotes_parse_to_coords() {
        for url in [
            "https://github.com/acme/widgets.git",
            "https://user@GitHub.com/acme/widgets/",
            "ssh://git@github.com:22/acme/widgets.git",
            "git@github.com:acme/widgets.git",
        ] {
            assert_eq!(
                coords_from_remote(url).map(|c| c.resource()).as_deref(),
                Some("github.com/acme/widgets"),
                "{url}"
            );
        }
        assert!(coords_from_remote("/srv/git/widgets").is_none());
        assert!(coords_from_remote("file:///srv/acme/widgets").is_none());
        assert!(coords_from_remote("https://github.com/acme").is_none());
    }

    fn cand(n: u128, label: &str, communities: &[&str]) -> Candidate {
        Candidate {
            id: PersonaId(uuid::Uuid::from_u128(n)),
            label: label.into(),
            did: format!("did:webvh:{label}"),
            communities: communities.iter().map(|c| (*c).to_string()).collect(),
        }
    }

    #[test]
    fn persona_choice_order() {
        let all = [cand(1, "work", &["vtc:a"]), cand(2, "home", &["vtc:b"])];
        let id = |n| PersonaId(uuid::Uuid::from_u128(n));

        // Ambiguous without a hint.
        assert!(choose_persona(&all, None, None, &[]).is_err());
        // --persona by label or DID.
        assert_eq!(choose_persona(&all, Some("HOME"), None, &[]), Ok(id(2)));
        assert_eq!(
            choose_persona(&all, Some("did:webvh:work"), None, &[]),
            Ok(id(1))
        );
        assert!(choose_persona(&all, Some("nobody"), None, &[]).is_err());
        // Already signing as one.
        assert_eq!(
            choose_persona(&all, None, Some("did:webvh:home#key-1"), &[]),
            Ok(id(2))
        );
        // Tied to a community by the settings.
        assert_eq!(
            choose_persona(&all, None, None, &["vtc:a".into()]),
            Ok(id(1))
        );
        // The only member.
        let one = [cand(1, "work", &["vtc:a"]), cand(2, "spare", &[])];
        assert_eq!(choose_persona(&one, None, None, &[]), Ok(id(1)));
        // Nobody is a member.
        assert!(choose_persona(&[cand(3, "x", &[])], None, None, &[]).is_err());
    }
}
