//! `openvtc repo sign [<repo-path>]`: the headless form of pressing `e`
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
use openvtc_core::config::Config;
use openvtc_core::git_signing::{self, BinaryStatus, CheckoutSigning, VtaEndpoint};
use openvtc_core::git_workspace::{self, RepoCoords};
use vta_sdk::client::VtaClient;

use crate::headless::{self, Admin, step, warn};
use crate::state_handler::DeferredLoad;
use crate::state_handler::repos_workspace;

/// The `repo sign` subcommand's definition.
pub fn command() -> Command {
    Command::new("sign")
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
        ])
}

/// Run `openvtc repo sign`.
pub async fn run(m: &ArgMatches, deferred: DeferredLoad) -> Result<()> {
    let path = m.get_one::<String>("path").map_or(".", String::as_str);
    let persona = m.get_one::<String>("persona").map(String::as_str);
    enable(Path::new(path), persona, deferred).await
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
        None => headless::only_member(config)?,
    };

    let signer = repos_workspace::persona_signer(config, tdk, persona)
        .await
        .map_err(|e| anyhow!(e))?;
    step(format!(
        "Persona '{}' ({})",
        signer.label, signer.did_key_id
    ));

    step("Setting up did-git-sign for the persona…");
    let profile_name = repos_workspace::set_up_identity(
        &signer,
        &endpoint,
        client,
        &config.account.top_context_id,
        &repos_workspace::own_did(config),
        false,
    )
    .await
    .map_err(|e| anyhow!(e))?;

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
    repos_workspace::blocking(f).await.map_err(|e| anyhow!(e))
}
