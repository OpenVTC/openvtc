//! The Repos panel's local half: this machine's checkouts of a community's
//! repositories, and did-git-sign set up to sign in them as the persona the
//! member holds in that community.
//!
//! The panel's `git-ns` side ([`super::repos_actions`]) says what the community
//! governs; this module says what is here. Nothing in it talks to the
//! community. It talks to git and did-git-sign
//! ([`openvtc_core::git_workspace`], [`openvtc_core::git_signing`]), and to the
//! VTA only to grant and revoke did-git-sign's own credential.
//!
//! Two kinds of background work, in their own domains so neither waits on the
//! other or on a `git-ns` send:
//!
//! - **Probes** ([`DispatchDomain::GitWorkspaceProbe`]) read every located
//!   checkout and, when asked, did-git-sign's identity, binary and hook. One
//!   runs when the view opens, after the community's answer lands (it names the
//!   repositories to look for), after every local change, and every
//!   [`PROBE_EVERY`] while the view is open — so a commit made in a terminal
//!   shows here without a refresh. The keyring is read only when asked, not on
//!   the periodic probe.
//! - **Jobs** ([`DispatchDomain::GitWorkspace`]) change something: clone,
//!   set up, enable, disable, remove. Each is one key, and does everything it
//!   needs: `c` clones, sets did-git-sign up if it is not, and enables the new
//!   checkout, so a member goes from "not here" to "commits are signed as me"
//!   in one step.
//!
//! `f` chooses the forge account a repository (or every repository of the
//! community on that forge) uses for clone, fetch and push
//! ([`openvtc_core::forge_credential`]): looking for gh's accounts and the
//! keys in `~/.ssh` is a job, and so is storing the choice and writing it into
//! the checkouts it covers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use affinidi_tdk::TDK;
use did_git_sign::profiles::Profiles;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context::persona_context;
use openvtc_core::config::secured_config::KeySourceMaterial;
use openvtc_core::config::{Config, KeyBackend};
use openvtc_core::forge_credential::{self, ForgeCredential};
use openvtc_core::git_signing::{
    self, CheckoutSigning, IdentityStatus, PersonaSigner, SignerCredential, VtaEndpoint,
};
use openvtc_core::git_workspace::{
    self, CLONE_TIMEOUT, CloneProtocol, CredentialScope, ForgeFacts, RepoCoords, WorkspaceSettings,
};
use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::WorkspaceAction as W;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::repos::{
    AccountForm, CheckoutView, ReposScreen, ReposView, Severity, SignerHealth, WorkspaceChange,
    WorkspaceForm,
};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

const DOMAIN: DispatchDomain = DispatchDomain::GitWorkspace;
const PROBE: DispatchDomain = DispatchDomain::GitWorkspaceProbe;

/// How often an open view re-reads its checkouts unasked.
pub(crate) const PROBE_EVERY: Duration = Duration::from_secs(20);

/// Longest path kept in a form field.
const MAX_PATH: usize = 1024;

fn view_mut(state: &mut State) -> Option<&mut ReposView> {
    state.main_page.content_panel.repos.view.as_mut()
}

/// The repository the keys act on: highlighted on the list, open on a
/// repository's screen.
pub(crate) fn target(view: &ReposView) -> Option<String> {
    match &view.screen {
        ReposScreen::List => view
            .my_repos()
            .get(view.selected)
            .map(|r| r.resource.clone()),
        ReposScreen::Repo { resource } => Some(resource.clone()),
        ReposScreen::NewRepo(_) => None,
    }
}

// ****************************************************************************
// View-only changes (shared nav reducer)
// ****************************************************************************

/// Apply a view-only action. Returns `false` for the ones the loop services.
pub(crate) fn reduce(state: &mut State, action: &W) -> bool {
    if matches!(
        action,
        W::Clone
            | W::Sign
            | W::Unsign
            | W::SetUp
            | W::Confirm
            | W::SettingsSubmit
            | W::UseSubmit
            | W::AccountStart
            | W::AccountSubmit
            | W::Fork
            | W::RemotesToSsh
    ) {
        return false;
    }
    let Some(view) = view_mut(state) else {
        return true;
    };
    let ws = &mut view.workspace;
    match action {
        W::RemoveArm => {
            if ws.health.as_ref().is_some_and(|h| h.identity.any()) {
                ws.confirm = Some(WorkspaceChange::RemoveIdentity);
            } else {
                view.note(
                    Severity::Warning,
                    "did-git-sign holds no identity for this persona — nothing to remove.",
                );
            }
        }
        W::Cancel => {
            ws.confirm = None;
            ws.form = None;
        }
        W::SettingsStart => {
            ws.form = Some(WorkspaceForm::Settings {
                root: git_workspace::display_path(&ws.settings.root),
                protocol: ws.settings.protocol,
                error: None,
            });
        }
        W::SettingsInput(value) => {
            if let Some(WorkspaceForm::Settings { root, error, .. }) = ws.form.as_mut() {
                *root = value.chars().take(MAX_PATH).collect();
                *error = None;
            }
        }
        W::SettingsProtocol => {
            if let Some(WorkspaceForm::Settings { protocol, .. }) = ws.form.as_mut() {
                // Automatic → HTTPS → SSH → automatic.
                *protocol = match protocol {
                    None => Some(CloneProtocol::Https),
                    Some(CloneProtocol::Https) => Some(CloneProtocol::Ssh),
                    Some(CloneProtocol::Ssh) => None,
                };
            }
        }
        W::UseStart => match target(view) {
            Some(resource) => {
                view.workspace.form = Some(WorkspaceForm::UsePath {
                    resource,
                    path: String::new(),
                    error: None,
                });
            }
            None => view.note(Severity::Warning, "Highlight a repository first."),
        },
        W::UseInput(value) => {
            if let Some(WorkspaceForm::UsePath { path, error, .. }) = ws.form.as_mut() {
                *path = value.chars().take(MAX_PATH).collect();
                *error = None;
            }
        }
        W::AccountPick(pick) => {
            if let Some(WorkspaceForm::Account(form)) = ws.form.as_mut() {
                form.pick = (*pick).min(form.visible().len().saturating_sub(1));
                form.error = None;
            }
        }
        W::AccountAuthor => {
            if let Some(WorkspaceForm::Account(form)) = ws.form.as_mut() {
                form.keep_author = !form.keep_author;
            }
        }
        W::AccountScope => {
            if let Some(WorkspaceForm::Account(form)) = ws.form.as_mut() {
                form.toggle_scope();
            }
        }
        W::AccountInput(value) => {
            if let Some(WorkspaceForm::Account(form)) = ws.form.as_mut() {
                form.path = value.chars().take(MAX_PATH).collect();
                form.error = None;
            }
        }
        W::Copied(text) => {
            let severity = if text.starts_with('✗') {
                Severity::Error
            } else {
                Severity::Success
            };
            view.note(severity, text.clone());
        }
        W::Clone
        | W::Sign
        | W::Unsign
        | W::SetUp
        | W::Confirm
        | W::SettingsSubmit
        | W::UseSubmit
        | W::AccountStart
        | W::AccountSubmit
        | W::Fork
        | W::RemotesToSsh => {}
    }
    true
}

// ****************************************************************************
// Opening: settings, and the persona's signing key
// ****************************************************************************

/// The persona's signing key as did-git-sign needs it, from what openvtc
/// already holds: the DID document's assertion method, its VTA key id, and the
/// context the persona's keys live in.
async fn persona_signer(
    config: &Config,
    tdk: &TDK,
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

/// Fill the workspace when the view opens: the profile's settings and the
/// persona's signing key. The probe follows.
pub(crate) async fn open(ctx: &mut ActionCtx<'_>) {
    let Some(persona) = ctx
        .state
        .main_page
        .content_panel
        .repos
        .view
        .as_ref()
        .map(|v| v.persona)
    else {
        return;
    };
    let settings =
        WorkspaceSettings::path(ctx.profile).and_then(|p| WorkspaceSettings::load_from(&p));
    let signer = persona_signer(ctx.config, ctx.tdk, persona).await;
    let Some(view) = view_mut(ctx.state) else {
        return;
    };
    let ws = &mut view.workspace;
    ws.profile = ctx.profile.to_string();
    match settings {
        Ok(s) => ws.settings = s,
        Err(e) => view.note(
            Severity::Warning,
            format!("couldn't read the workspace settings, using the defaults: {e}"),
        ),
    }
    view.workspace.signer = Some(signer);
    view.workspace.want_probe(true);
    probe_if_due(ctx.state, ctx.dispatch_tx, ctx.in_flight);
}

// ****************************************************************************
// Probing
// ****************************************************************************

/// What a probe reads, resolved on the loop thread.
struct ProbeInput {
    vtc_did: String,
    persona: PersonaId,
    did_key_id: Option<String>,
    settings: WorkspaceSettings,
    resources: Vec<String>,
    identity: bool,
    /// Forge hosts not read yet ([`git_workspace::ForgeFacts`]).
    forge_hosts: Vec<String>,
}

/// What a probe found. Applied on the loop thread.
pub(crate) struct ProbeOutcome {
    vtc_did: String,
    persona: PersonaId,
    health: Option<SignerHealth>,
    checkouts: HashMap<String, CheckoutView>,
    forges: HashMap<String, ForgeFacts>,
}

impl ProbeOutcome {
    pub(crate) fn apply(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        if let Some(health) = self.health {
            view.workspace.health = Some(health);
        }
        view.workspace.checkouts = self.checkouts;
        view.workspace.forges.extend(self.forges);
        view.workspace.probed_at = Some(Instant::now());
    }
}

/// Read did-git-sign and every located checkout. Blocking.
fn run_probe(input: ProbeInput) -> ProbeOutcome {
    let health = input.identity.then(|| {
        let (hook_path, hook) = super::signing_health::hook_health();
        SignerHealth {
            identity: input
                .did_key_id
                .as_deref()
                .map(git_signing::identity_status)
                .unwrap_or_default(),
            binary: git_signing::binary_status(),
            hook,
            hook_path,
        }
    });
    let profiles = Profiles::load().unwrap_or_default();
    let checkouts = input
        .resources
        .iter()
        .filter_map(|resource| {
            let coords = RepoCoords::parse(resource).ok()?;
            let path = input.settings.locate(&coords)?;
            let facts = git_workspace::inspect(&path, &coords);
            let signing = git_signing::checkout_signing(&facts, &profiles);
            Some((resource.clone(), CheckoutView { facts, signing }))
        })
        .collect();
    // gh's protocol and the global credential helper, once per forge per view
    // (each call bounded).
    let forges = input
        .forge_hosts
        .iter()
        .map(|host| (host.clone(), forge_credential::forge_facts(host)))
        .collect();
    ProbeOutcome {
        vtc_did: input.vtc_did,
        persona: input.persona,
        health,
        checkouts,
        forges,
    }
}

/// Start a probe if one is wanted or the last is stale, and none is running.
pub(crate) fn probe_if_due(
    state: &mut State,
    dispatch_tx: &UnboundedSender<DispatchOutcome>,
    in_flight: &mut InFlight,
) {
    let Some(view) = view_mut(state) else {
        return;
    };
    let ws = &view.workspace;
    if ws.signer.is_none() {
        // Not opened yet: `open` has not filled the settings.
        return;
    }
    let stale = ws.probed_at.is_none_or(|t| t.elapsed() >= PROBE_EVERY);
    if (ws.probe_wanted.is_none() && !stale) || in_flight.is_busy(PROBE) {
        return;
    }
    let identity = ws.probe_wanted.unwrap_or(false) || ws.health.is_none();
    let resources: Vec<String> = view.my_repos().into_iter().map(|r| r.resource).collect();
    let mut forge_hosts: Vec<String> = resources
        .iter()
        .filter_map(|r| RepoCoords::parse(r).ok().map(|c| c.host))
        .filter(|h| !ws.forges.contains_key(h))
        .collect();
    forge_hosts.sort();
    forge_hosts.dedup();
    let input = ProbeInput {
        vtc_did: view.vtc_did.clone(),
        persona: view.persona,
        did_key_id: ws.did_key_id().map(str::to_string),
        settings: ws.settings.clone(),
        resources,
        identity,
        forge_hosts,
    };
    if !in_flight.try_begin(PROBE) {
        return;
    }
    view.workspace.probe_wanted = None;
    background_dispatch::spawn_dispatch(dispatch_tx.clone(), PROBE, async move {
        let vtc_did = input.vtc_did.clone();
        let persona = input.persona;
        let outcome = tokio::task::spawn_blocking(move || run_probe(input))
            .await
            .unwrap_or(ProbeOutcome {
                vtc_did,
                persona,
                health: None,
                checkouts: HashMap::new(),
                forges: HashMap::new(),
            });
        DispatchOutcome::WorkspaceProbe(outcome)
    });
}

// ****************************************************************************
// Jobs
// ****************************************************************************

/// What a job does.
enum Plan {
    /// Clone into the workspace over `protocol`, then sign there; `warning`
    /// says why the checkout may not be able to push.
    Clone {
        coords: RepoCoords,
        dest: PathBuf,
        protocol: CloneProtocol,
        warning: Option<String>,
    },
    /// Point the checkout's `origin` and `fork` remotes at their SSH URLs.
    RemotesToSsh { path: PathBuf },
    /// Make a checkout sign.
    Sign { path: PathBuf },
    /// Stop a checkout signing.
    Unsign { path: PathBuf },
    /// Set did-git-sign up, or repair it.
    SetUp,
    /// Remove the identity and revoke its credential.
    Remove,
    /// Adopt an existing checkout, then sign there.
    Use { coords: RepoCoords, path: PathBuf },
    /// Fork the repository to the chosen gh account and push there.
    Fork {
        coords: RepoCoords,
        path: PathBuf,
        login: String,
    },
    /// Look for gh's accounts and `~/.ssh`'s keys, then open the picker.
    Accounts {
        coords: RepoCoords,
        linked_login: Option<String>,
    },
    /// Store a forge-account choice (`None` removes it) and write it into
    /// every located checkout it covers, with each one's `origin`.
    Account {
        coords: RepoCoords,
        scope: CredentialScope,
        credential: Option<ForgeCredential>,
        checkouts: Vec<(RepoCoords, PathBuf, Option<String>)>,
    },
}

/// Everything a job needs, resolved on the loop thread.
struct WorkspaceJob {
    vtc_did: String,
    persona: PersonaId,
    plan: Plan,
    signer: Result<PersonaSigner, String>,
    endpoint: Option<VtaEndpoint>,
    client: Option<VtaClient>,
    top_context_id: String,
    own_did: String,
    settings: WorkspaceSettings,
    settings_path: Option<PathBuf>,
}

/// What a job did. Applied on the loop thread.
pub(crate) struct WorkspaceOutcome {
    vtc_did: String,
    persona: PersonaId,
    /// What to say: done, or why not.
    result: Result<String, String>,
    /// Settings the job changed (an adopted checkout, a forge account).
    settings: Option<WorkspaceSettings>,
    /// A form to open (the forge-account picker, once its rows are found).
    form: Option<WorkspaceForm>,
    /// `(resource, login, can push)`, when it was checked.
    push_access: Option<(String, String, bool)>,
}

impl WorkspaceOutcome {
    pub(crate) fn apply(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        view.workspace.busy = None;
        if let Some((resource, login, can)) = self.push_access {
            view.workspace.push_access.insert(resource, (login, can));
        }
        if let Some(settings) = self.settings {
            view.workspace.settings = settings;
        }
        match self.result {
            Ok(done) => {
                if matches!(
                    view.workspace.form,
                    Some(WorkspaceForm::UsePath { .. } | WorkspaceForm::Account(_))
                ) {
                    view.workspace.form = None;
                }
                if let Some(form) = self.form {
                    view.workspace.form = Some(form);
                    view.workspace.confirm = None;
                }
                view.note(Severity::Success, done);
            }
            Err(e) => {
                match view.workspace.form.as_mut() {
                    Some(WorkspaceForm::UsePath { error, .. }) => *error = Some(e.clone()),
                    Some(WorkspaceForm::Account(form)) => form.error = Some(e.clone()),
                    _ => {}
                }
                view.note(Severity::Error, e);
            }
        }
        view.workspace.want_probe(true);
    }
}

/// A job ended without an outcome (it panicked): stop showing it as running.
pub(crate) fn job_lost(state: &mut State, why: &str) {
    if let Some(view) = view_mut(state) {
        view.workspace.busy = None;
        view.note(Severity::Error, why.to_string());
        view.workspace.want_probe(true);
    }
}

/// Blocking work on the job's thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("the job stopped unexpectedly: {e}"))
}

/// Why signing cannot be enabled until the binary is installed.
const INSTALL_BINARY: &str = "did-git-sign is not on PATH, and git runs it to sign every commit. \
     Install it (`cargo install did-git-sign`), then press e here.";

impl WorkspaceJob {
    async fn run(self) -> WorkspaceOutcome {
        let (vtc_did, persona) = (self.vtc_did.clone(), self.persona);
        let mut settings = None;
        let mut form = None;
        let result = match &self.plan {
            Plan::Fork {
                coords,
                path,
                login,
            } => {
                let (c, p, l) = (coords.clone(), path.clone(), login.clone());
                blocking(move || {
                    forge_credential::gh_fork_for_push(&p, &c, &l, forge_credential::FORK_TIMEOUT)
                })
                .await
                .and_then(|r| r)
                .map(|()| {
                    format!(
                        "Forked {} to {login}. `git push` now goes to the fork (remote 'fork'); \
                         open the pull request from {login}:<branch>.",
                        git_ns_short(&coords.resource())
                    )
                })
            }
            Plan::Accounts {
                coords,
                linked_login,
            } => {
                let (gh, keys) = blocking(|| {
                    (
                        forge_credential::gh_accounts(forge_credential::GH_TIMEOUT),
                        forge_credential::ssh_keys(),
                    )
                })
                .await
                .unwrap_or_else(|e| (Err(forge_credential::GhError::Failed(e)), Vec::new()));
                let community = self.settings.credentials.get(&self.vtc_did);
                let opened = AccountForm::new(
                    coords.resource(),
                    coords.host.clone(),
                    community.and_then(|c| c.repos.get(&coords.resource()).cloned()),
                    community.and_then(|c| c.forges.get(&coords.host).cloned()),
                    gh.map_err(|e| e.to_string()),
                    keys,
                    linked_login.as_deref(),
                );
                form = Some(WorkspaceForm::Account(opened));
                Ok(format!(
                    "Choose the account {} uses for clone, fetch and push.",
                    git_ns_short(&coords.resource())
                ))
            }
            Plan::Account {
                coords,
                scope,
                credential,
                checkouts,
            } => match self
                .choose_account(coords, *scope, credential, checkouts)
                .await
            {
                Ok((updated, done)) => {
                    settings = Some(updated);
                    Ok(done)
                }
                Err(e) => Err(e),
            },
            Plan::Clone {
                coords,
                dest,
                protocol,
                warning,
            } => self
                .clone_and_sign(coords, dest, *protocol)
                .await
                .map(|done| match warning {
                    Some(w) => format!("{done} ▲ {w}"),
                    None => done,
                }),
            Plan::RemotesToSsh { path } => {
                let p = path.clone();
                blocking(move || git_workspace::switch_remotes_to_ssh(&p))
                    .await
                    .and_then(|r| r)
                    .map(|switched| {
                        let names: Vec<String> = switched
                            .iter()
                            .map(|(name, url)| format!("{name} → {url}"))
                            .collect();
                        format!(
                            "Switched to SSH: {}. git now pushes with your SSH key.",
                            names.join(", ")
                        )
                    })
            }
            Plan::Sign { path } => self.sign(path).await,
            Plan::Unsign { path } => {
                let path = path.clone();
                blocking(move || git_signing::disable_in(&path))
                    .await
                    .and_then(|r| r)
                    .map(|()| "This checkout no longer signs with did-git-sign.".to_string())
            }
            Plan::SetUp => self.set_up(true).await.map(|profile| {
                format!(
                    "did-git-sign is set up for this persona (profile '{profile}'). Press e on a \
                     checkout to sign there."
                )
            }),
            Plan::Remove => self.remove().await,
            Plan::Use { coords, path } => match self.adopt(coords, path).await {
                Ok(updated) => {
                    settings = Some(updated);
                    self.sign(path).await.map(|done| {
                        format!(
                            "Using {} for {}. {done}",
                            git_workspace::display_path(path),
                            git_ns_short(&coords.resource())
                        )
                    })
                }
                Err(e) => Err(e),
            },
        };
        // Whether the gh account can push here, once a clone or a choice
        // lands — said in words rather than as a 403 on the first push.
        let push_target = match &self.plan {
            Plan::Clone { coords, .. } | Plan::Account { coords, .. } if result.is_ok() => {
                let s = settings.as_ref().unwrap_or(&self.settings);
                s.credential_for(&self.vtc_did, coords)
                    .credential
                    .gh_login()
                    .map(|l| (coords.clone(), l.to_string()))
            }
            _ => None,
        };
        let mut push_access = None;
        if let Some((coords, login)) = push_target {
            let (c, l) = (coords.clone(), login.clone());
            if let Ok(Some(can)) = blocking(move || {
                forge_credential::gh_can_push(&c, &l, forge_credential::GH_TIMEOUT)
            })
            .await
            {
                push_access = Some((coords.resource(), login, can));
            }
        }
        WorkspaceOutcome {
            vtc_did,
            persona,
            result,
            settings,
            form,
            push_access,
        }
    }

    fn signer(&self) -> Result<&PersonaSigner, String> {
        self.signer.as_ref().map_err(Clone::clone)
    }

    /// Make sure did-git-sign holds a working identity for this persona, and
    /// return its profile name. `repair` also re-proves a stored credential
    /// against the VTA and rewrites the hooks.
    async fn set_up(&self, repair: bool) -> Result<String, String> {
        let signer = self.signer()?.clone();
        let did = signer.did_key_id.clone();
        let status: IdentityStatus = blocking({
            let did = did.clone();
            move || git_signing::identity_status(&did)
        })
        .await?;
        let endpoint = self
            .endpoint
            .clone()
            .ok_or("openvtc's keys are not held by a VTA, so there is no key for did-git-sign")?;
        let mut proven = status.ready() && !repair;
        if status.ready() && repair {
            let stored = blocking({
                let did = did.clone();
                move || git_signing::stored_credential(&did)
            })
            .await?;
            if let Some(cred) = stored {
                match git_signing::verify_signer(&cred, &signer, &endpoint).await {
                    Ok(()) => proven = true,
                    Err(e) => tracing::info!("did-git-sign's credential no longer works: {e}"),
                }
            }
        }
        if proven {
            blocking(git_signing::refresh_hooks)
                .await?
                .map_err(|e| e.to_string())?;
            return status
                .profile
                .ok_or_else(|| "did-git-sign's profile went missing".into());
        }
        // A new credential: granted, proven, then stored.
        let client = self.client.as_ref().ok_or(
            "openvtc has no session with its VTA right now, so it cannot grant did-git-sign a \
             credential — try again once it reconnects",
        )?;
        let cred = SignerCredential::generate().map_err(|e| e.to_string())?;
        git_signing::grant_signer(client, &cred, &signer, &endpoint, &self.top_context_id)
            .await
            .map_err(|e| e.to_string())?;
        let new_did = cred.did.clone();
        let installed = blocking({
            let signer = signer.clone();
            let endpoint = endpoint.clone();
            move || git_signing::install_identity(&signer, &endpoint, &cred)
        })
        .await
        .and_then(|r| r.map_err(|e| e.to_string()));
        let installed = match installed {
            Ok(i) => i,
            Err(e) => {
                // Stored nowhere, so take the grant back.
                if let Err(r) = git_signing::revoke_signer(client, &new_did, &self.own_did).await {
                    tracing::warn!("couldn't revoke an unstored signer grant: {r}");
                }
                return Err(e);
            }
        };
        if let Some(old) = &installed.replaced_credential
            && let Err(e) = git_signing::revoke_signer(client, old, &self.own_did).await
        {
            tracing::warn!("couldn't revoke did-git-sign's previous credential: {e}");
        }
        Ok(installed.profile)
    }

    /// Set up if needed, then `did-git-sign enable` in the checkout.
    async fn sign(&self, path: &std::path::Path) -> Result<String, String> {
        let profile = self.set_up(false).await?;
        if !matches!(
            blocking(git_signing::binary_status).await?,
            git_signing::BinaryStatus::Found { .. }
        ) {
            return Err(INSTALL_BINARY.into());
        }
        let path = path.to_path_buf();
        let p = profile.clone();
        blocking(move || git_signing::enable_in(&path, &p))
            .await
            .and_then(|r| r)?;
        Ok(format!("Commits here are signed as '{profile}'."))
    }

    async fn clone_and_sign(
        &self,
        coords: &RepoCoords,
        dest: &std::path::Path,
        protocol: CloneProtocol,
    ) -> Result<String, String> {
        let (c, d) = (coords.clone(), dest.to_path_buf());
        let credential = self
            .settings
            .credential_for(&self.vtc_did, coords)
            .credential;
        let account = match credential {
            ForgeCredential::GitDefault => String::new(),
            ref c => format!(" with {}", c.label()),
        };
        let author_note = blocking(move || {
            // A missing key or a logged-out gh account, said before git runs.
            credential.check(&c.host)?;
            let (author, note) = resolve_author(&credential, &c.host);
            git_workspace::clone_repo(
                &c,
                protocol,
                &credential,
                author.as_ref(),
                &d,
                CLONE_TIMEOUT,
            )
            .map(|()| note)
        })
        .await
        .and_then(|r| r)?;
        let at = git_workspace::display_path(dest);
        match self.sign(dest).await {
            Ok(done) => Ok(format!("Cloned into {at}{account}.{author_note} {done}")),
            // The clone stands; say what is left to do.
            Err(e) => Err(format!("Cloned into {at}, but it does not sign yet: {e}")),
        }
    }

    async fn remove(&self) -> Result<String, String> {
        let did = self.signer()?.did_key_id.clone();
        let removed = blocking(move || git_signing::remove_identity(&did))
            .await?
            .map_err(|e| e.to_string())?;
        let mut done = String::from("did-git-sign no longer holds this persona's identity");
        match (&removed.credential_did, &self.client) {
            (Some(cred), Some(client)) => {
                match git_signing::revoke_signer(client, cred, &self.own_did).await {
                    Ok(true) => done.push_str(", and its credential is revoked at the VTA"),
                    Ok(false) => {}
                    Err(e) => {
                        return Err(format!(
                            "{done}, but revoking its credential failed: {e}. It can still \
                             export this persona's key until it is revoked (pnm acl delete {cred})."
                        ));
                    }
                }
            }
            (Some(cred), None) => {
                return Err(format!(
                    "{done}, but openvtc has no VTA session to revoke its credential — revoke \
                     {cred} once it reconnects (pnm acl delete)."
                ));
            }
            (None, _) => {}
        }
        if removed.include_lines_removed > 0 {
            done.push_str(&format!(
                "; {} repository setting(s) that included it were removed",
                removed.include_lines_removed
            ));
        }
        for w in &removed.warnings {
            tracing::warn!("did-git-sign uninstall: {w}");
        }
        Ok(format!("{done}."))
    }

    /// Check `path` is a checkout of `coords`, and remember it.
    async fn adopt(
        &self,
        coords: &RepoCoords,
        path: &std::path::Path,
    ) -> Result<WorkspaceSettings, String> {
        let (c, p) = (coords.clone(), path.to_path_buf());
        let facts = blocking(move || git_workspace::inspect(&p, &c)).await?;
        let shown = git_workspace::display_path(path);
        if !facts.is_repo {
            return Err(format!("{shown} is not a git checkout."));
        }
        if !facts.origin_matches {
            return Err(match facts.origin {
                Some(origin) => format!(
                    "{shown} is a checkout of {origin}, not {}.",
                    coords.resource()
                ),
                None => format!("{shown} has no `origin` remote to check it against."),
            });
        }
        let mut settings = self.settings.clone();
        settings
            .checkouts
            .insert(coords.resource(), path.to_path_buf());
        if let Some(file) = self.settings_path.clone() {
            let s = settings.clone();
            blocking(move || s.save_to(&file))
                .await?
                .map_err(|e| e.to_string())?;
        }
        Ok(settings)
    }
}

impl WorkspaceJob {
    /// Check a forge-account choice, store it, and write what each covered
    /// checkout now uses into it. Returns the new settings and what to say.
    async fn choose_account(
        &self,
        coords: &RepoCoords,
        scope: CredentialScope,
        credential: &Option<ForgeCredential>,
        checkouts: &[(RepoCoords, PathBuf, Option<String>)],
    ) -> Result<(WorkspaceSettings, String), String> {
        if let Some(c) = credential.clone() {
            let host = coords.host.clone();
            blocking(move || c.check(&host)).await??;
        }
        let mut settings = self.settings.clone();
        settings.set_credential(&self.vtc_did, coords, scope, credential.clone());
        if let Some(file) = self.settings_path.clone() {
            let s = settings.clone();
            blocking(move || s.save_to(&file))
                .await?
                .map_err(|e| e.to_string())?;
        }
        let effective = settings.credential_for(&self.vtc_did, coords).credential;
        let what = match scope {
            CredentialScope::Repo => git_ns_short(&coords.resource()).to_string(),
            CredentialScope::Forge => format!("This community's {} repositories", coords.host),
        };
        let mut done = format!("{what} now use {}.", effective.label());
        let plan: Vec<(RepoCoords, PathBuf, Option<String>, ForgeCredential)> = checkouts
            .iter()
            .map(|(c, p, origin)| {
                (
                    c.clone(),
                    p.clone(),
                    origin.clone(),
                    settings.credential_for(&self.vtc_did, c).credential,
                )
            })
            .collect();
        let (results, author_notes) = blocking(move || {
            let mut notes: Vec<String> = Vec::new();
            let results = plan
                .into_iter()
                .map(|(c, path, origin, cred)| {
                    let (author, note) = resolve_author(&cred, &c.host);
                    if !note.is_empty() && !notes.contains(&note) {
                        notes.push(note);
                    }
                    let r =
                        forge_credential::apply_to_checkout(&path, &c.host, &cred, author.as_ref());
                    (c, path, origin, cred, r)
                })
                .collect::<Vec<_>>();
            (results, notes)
        })
        .await?;
        for note in author_notes {
            done.push_str(&note);
        }
        let mut failed = Vec::new();
        let mut applied = 0;
        for (c, path, origin, cred, r) in results {
            match r {
                Ok(()) => {
                    applied += 1;
                    if let Some(warning) = origin_mismatch(&cred, origin.as_deref()) {
                        done.push_str(&format!(" {}: {warning}", git_ns_short(&c.resource())));
                    }
                }
                Err(e) => failed.push(format!("{}: {e}", git_workspace::display_path(&path))),
            }
        }
        if applied > 0 {
            done.push_str(&format!(
                " Written into {applied} checkout{}.",
                if applied == 1 { "" } else { "s" }
            ));
        }
        if !failed.is_empty() {
            return Err(format!(
                "{done} But it could not be written into {}",
                failed.join("; ")
            ));
        }
        Ok((settings, done))
    }
}

/// The commit author a choice sets, looked up now (blocking, bounded); a
/// failed lookup leaves the member's own identity and says so.
fn resolve_author(
    credential: &ForgeCredential,
    host: &str,
) -> (Option<forge_credential::CommitAuthor>, String) {
    match credential.author(host) {
        Some(Ok(a)) => {
            let note = format!(" Commits are authored as {} <{}>.", a.name, a.email);
            (Some(a), note)
        }
        Some(Err(e)) => (None, format!(" Commits keep your own git identity: {e}")),
        None => (None, String::new()),
    }
}

/// A checkout whose `origin` speaks the other protocol never uses the account.
fn origin_mismatch(credential: &ForgeCredential, origin: Option<&str>) -> Option<String> {
    let origin = origin?;
    let https = origin.starts_with("https://") || origin.starts_with("http://");
    match credential {
        ForgeCredential::GhAccount { .. } if !https => Some(
            "its origin is an SSH URL, so the gh account is not used there — switch origin to \
             the https:// URL to use it."
                .into(),
        ),
        ForgeCredential::SshKey { .. } if https => Some(
            "its origin is an https:// URL, so the SSH key is not used there — switch origin \
             to the git@ URL to use it."
                .into(),
        ),
        _ => None,
    }
}

fn git_ns_short(resource: &str) -> &str {
    openvtc_core::git_ns::short_resource(resource)
}

/// openvtc's own DID at the VTA — never revoked.
fn own_did(config: &Config) -> String {
    match &config.key_backend {
        KeyBackend::Vta { credential_did, .. } => credential_did.clone(),
        _ => String::new(),
    }
}

/// Save the settings form.
fn save_settings(ctx: &mut ActionCtx<'_>) {
    let profile = ctx.profile.to_string();
    let Some(view) = view_mut(ctx.state) else {
        return;
    };
    let Some(WorkspaceForm::Settings { root, protocol, .. }) = view.workspace.form.clone() else {
        return;
    };
    let root_path = git_workspace::expand_tilde(&root);
    let refusal = if root.trim().is_empty() {
        Some("Name a directory.".to_string())
    } else if !root_path.is_absolute() {
        Some("Use an absolute path, or one starting with ~/.".to_string())
    } else if root_path.exists() && !root_path.is_dir() {
        Some(format!("{} is a file, not a directory.", root.trim()))
    } else {
        None
    };
    if let Some(why) = refusal {
        if let Some(WorkspaceForm::Settings { error, .. }) = view.workspace.form.as_mut() {
            *error = Some(why);
        }
        return;
    }
    let mut settings = view.workspace.settings.clone();
    settings.root = root_path;
    settings.protocol = protocol;
    let how = protocol.map_or_else(
        || "the forge account's protocol, else gh's, else HTTPS".to_string(),
        |p| p.label().to_string(),
    );
    match WorkspaceSettings::path(&profile).and_then(|p| settings.save_to(&p)) {
        Ok(()) => {
            view.workspace.settings = settings;
            view.workspace.form = None;
            view.workspace.want_probe(false);
            view.note(
                Severity::Success,
                format!(
                    "Checkouts go under {}, cloned over {how}.",
                    git_workspace::display_path(&view.workspace.settings.root),
                ),
            );
        }
        Err(e) => {
            if let Some(WorkspaceForm::Settings { error, .. }) = view.workspace.form.as_mut() {
                *error = Some(e.to_string());
            }
        }
    }
}

/// Service an action that runs git, did-git-sign or the VTA.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: W) {
    if action == W::SettingsSubmit {
        save_settings(ctx);
        probe_if_due(ctx.state, ctx.dispatch_tx, ctx.in_flight);
        return;
    }
    let linked = ctx.state.main_page.content_panel.repos.linked.clone();
    let Some(view) = view_mut(ctx.state) else {
        return;
    };
    if let Some(what) = &view.workspace.busy {
        view.note(Severity::Warning, format!("Still {what} — please wait."));
        return;
    }
    let target = target(view);
    let located = target
        .as_ref()
        .and_then(|r| view.workspace.checkouts.get(r))
        .map(|c| c.facts.path.clone());
    let short = target
        .as_deref()
        .map(git_ns_short)
        .unwrap_or_default()
        .to_string();
    let plan = match action {
        W::Clone => {
            let Some(resource) = target.clone() else {
                view.note(Severity::Warning, "Highlight a repository first.");
                return;
            };
            if let Some(path) = located {
                view.note(
                    Severity::Info,
                    format!(
                        "{short} is already checked out at {} — e makes it sign.",
                        git_workspace::display_path(&path)
                    ),
                );
                return;
            }
            let coords = match RepoCoords::parse(&resource) {
                Ok(c) => c,
                Err(e) => {
                    view.note(Severity::Error, e.to_string());
                    return;
                }
            };
            let dest = coords.default_path(&view.workspace.settings.root);
            let (protocol, _) = view.workspace.protocol_for(&view.vtc_did, &coords);
            let warning = view.workspace.https_clone_warning(&view.vtc_did, &coords);
            (
                Plan::Clone {
                    coords,
                    dest,
                    protocol,
                    warning,
                },
                format!("cloning {short}"),
            )
        }
        W::RemotesToSsh => {
            let Some(path) = located else {
                view.note(
                    Severity::Warning,
                    if target.is_some() {
                        format!("{short} is not checked out here.")
                    } else {
                        "Highlight a repository first.".to_string()
                    },
                );
                return;
            };
            (
                Plan::RemotesToSsh { path },
                format!("switching {short}'s remotes to SSH"),
            )
        }
        W::Sign | W::Unsign => {
            let Some(path) = located else {
                view.note(
                    Severity::Warning,
                    if target.is_some() {
                        format!(
                            "{short} is not checked out here — c clones it, u uses a checkout \
                             you already have."
                        )
                    } else {
                        "Highlight a repository first.".to_string()
                    },
                );
                return;
            };
            if action == W::Sign {
                (Plan::Sign { path }, format!("making {short} sign"))
            } else {
                (
                    Plan::Unsign { path },
                    format!("turning signing off in {short}"),
                )
            }
        }
        W::SetUp => (Plan::SetUp, "setting did-git-sign up".to_string()),
        W::Confirm => match view.workspace.confirm.take() {
            Some(WorkspaceChange::RemoveIdentity) => {
                (Plan::Remove, "removing the signing identity".to_string())
            }
            None => return,
        },
        W::UseSubmit => {
            let Some(WorkspaceForm::UsePath { resource, path, .. }) = view.workspace.form.clone()
            else {
                return;
            };
            let coords = match RepoCoords::parse(&resource) {
                Ok(c) => c,
                Err(e) => {
                    view.note(Severity::Error, e.to_string());
                    return;
                }
            };
            let path = git_workspace::expand_tilde(&path);
            if !path.is_absolute() {
                if let Some(WorkspaceForm::UsePath { error, .. }) = view.workspace.form.as_mut() {
                    *error = Some("Use an absolute path, or one starting with ~/.".into());
                }
                return;
            }
            (
                Plan::Use { coords, path },
                format!("checking the checkout of {short}"),
            )
        }
        W::Fork => {
            let Some(resource) = target.clone() else {
                view.note(Severity::Warning, "Highlight a repository first.");
                return;
            };
            let Some(path) = located else {
                view.note(
                    Severity::Warning,
                    format!("{short} is not checked out here — c clones it first."),
                );
                return;
            };
            let coords = match RepoCoords::parse(&resource) {
                Ok(c) => c,
                Err(e) => {
                    view.note(Severity::Error, e.to_string());
                    return;
                }
            };
            let credential = view
                .workspace
                .settings
                .credential_for(&view.vtc_did, &coords)
                .credential;
            let Some(login) = credential.gh_login().map(str::to_string) else {
                view.note(
                    Severity::Warning,
                    "Forking needs a gh account chosen for this repository (f).",
                );
                return;
            };
            (
                Plan::Fork {
                    coords,
                    path,
                    login: login.clone(),
                },
                format!("forking {short} to {login}"),
            )
        }
        W::AccountStart => {
            let Some(resource) = target.clone() else {
                view.note(Severity::Warning, "Highlight a repository first.");
                return;
            };
            let coords = match RepoCoords::parse(&resource) {
                Ok(c) => c,
                Err(e) => {
                    view.note(Severity::Error, e.to_string());
                    return;
                }
            };
            let linked_login = view
                .linked_on(&linked, &coords.host)
                .map(|a| a.login.clone());
            (
                Plan::Accounts {
                    coords,
                    linked_login,
                },
                "looking for gh accounts and SSH keys".to_string(),
            )
        }
        W::AccountSubmit => {
            let Some(WorkspaceForm::Account(form)) = view.workspace.form.clone() else {
                return;
            };
            let credential = match form.choice() {
                Ok(c) => c,
                Err(e) => {
                    if let Some(WorkspaceForm::Account(f)) = view.workspace.form.as_mut() {
                        f.error = Some(e);
                    }
                    return;
                }
            };
            let coords = match RepoCoords::parse(&form.resource) {
                Ok(c) => c,
                Err(e) => {
                    view.note(Severity::Error, e.to_string());
                    return;
                }
            };
            // The located checkouts the choice covers: this one, or every one
            // of this community on the forge.
            let checkouts = view
                .workspace
                .checkouts
                .iter()
                .filter(|(_, c)| c.facts.is_repo)
                .filter_map(|(r, c)| {
                    let rc = RepoCoords::parse(r).ok()?;
                    let covered = match form.scope {
                        CredentialScope::Repo => rc == coords,
                        CredentialScope::Forge => rc.host == coords.host,
                    };
                    covered.then(|| (rc, c.facts.path.clone(), c.facts.origin.clone()))
                })
                .collect();
            (
                Plan::Account {
                    coords,
                    scope: form.scope,
                    credential,
                    checkouts,
                },
                "choosing the forge account".to_string(),
            )
        }
        _ => return,
    };
    let (plan, busy) = plan;
    let job = WorkspaceJob {
        vtc_did: view.vtc_did.clone(),
        persona: view.persona,
        plan,
        signer: view
            .workspace
            .signer
            .clone()
            .unwrap_or_else(|| Err("the view has not finished opening".into())),
        endpoint: VtaEndpoint::from_backend(&ctx.config.key_backend),
        client: ctx.admin_vta.cloned(),
        top_context_id: ctx.config.account.top_context_id.clone(),
        own_did: own_did(ctx.config),
        settings: view.workspace.settings.clone(),
        settings_path: WorkspaceSettings::path(ctx.profile).ok(),
    };
    if !ctx.in_flight.try_begin(DOMAIN) {
        view.note(Severity::Warning, InFlight::busy_message(DOMAIN));
        return;
    }
    view.note(Severity::Progress, format!("{}…", capitalise(&busy)));
    view.workspace.busy = Some(busy);
    background_dispatch::spawn_dispatch(ctx.dispatch_tx.clone(), DOMAIN, async move {
        DispatchOutcome::Workspace(job.run().await)
    });
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// How a checkout reads, in a few words, for the list.
#[must_use]
pub(crate) fn summary(view: &ReposView, resource: &str) -> (String, Severity) {
    let Some(checkout) = view.workspace.checkouts.get(resource) else {
        return ("not cloned".into(), Severity::Info);
    };
    if !checkout.facts.is_repo {
        return ("not a git checkout".into(), Severity::Error);
    }
    match (&checkout.signing, view.workspace.signs_as_me(checkout)) {
        (CheckoutSigning::On { .. }, Some(true)) => ("signed".into(), Severity::Success),
        (CheckoutSigning::On { .. }, _) => ("signs as another identity".into(), Severity::Error),
        (CheckoutSigning::NoClaim { .. }, _) => ("no DID claim".into(), Severity::Error),
        (CheckoutSigning::Off, _) => ("not signing".into(), Severity::Warning),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::state_handler::main_page::repos::Workspace;
    use openvtc_core::git_workspace::{CheckoutFacts, CloneProtocol};

    fn view() -> ReposView {
        let mut v = ReposView::new(
            "did:webvh:vtc".into(),
            PersonaId(uuid::Uuid::nil()),
            "did:webvh:me".into(),
            "Acme".into(),
        );
        v.workspace = Workspace {
            signer: Some(Ok(PersonaSigner {
                did_key_id: "did:webvh:me#key-0".into(),
                vta_key_id: "k".into(),
                verifying_key: [0; 32],
                context: "openvtc/me".into(),
                label: "Me".into(),
            })),
            ..Workspace::default()
        };
        v
    }

    fn state_with(v: ReposView) -> State {
        let mut s = State::default();
        s.main_page.content_panel.repos.view = Some(v);
        s
    }

    fn checkout(signing: CheckoutSigning) -> CheckoutView {
        CheckoutView {
            facts: CheckoutFacts {
                is_repo: true,
                ..CheckoutFacts::default()
            },
            signing,
        }
    }

    #[test]
    fn the_loop_services_what_runs_something() {
        let mut s = state_with(view());
        for a in [
            W::Clone,
            W::Sign,
            W::Unsign,
            W::SetUp,
            W::Confirm,
            W::SettingsSubmit,
            W::UseSubmit,
            W::AccountStart,
            W::AccountSubmit,
        ] {
            assert!(!reduce(&mut s, &a), "{a:?} belongs to the loop");
        }
        for a in [
            W::SettingsStart,
            W::SettingsProtocol,
            W::Cancel,
            W::UseStart,
        ] {
            assert!(reduce(&mut s, &a), "{a:?} is view-only");
        }
    }

    #[test]
    fn the_settings_form_edits_and_cancels() {
        let mut s = state_with(view());
        reduce(&mut s, &W::SettingsStart);
        reduce(&mut s, &W::SettingsInput("~/code".into()));
        reduce(&mut s, &W::SettingsProtocol);
        let ws = &s
            .main_page
            .content_panel
            .repos
            .view
            .as_ref()
            .unwrap()
            .workspace;
        assert_eq!(
            ws.form,
            Some(WorkspaceForm::Settings {
                root: "~/code".into(),
                protocol: Some(CloneProtocol::Https),
                error: None
            })
        );
        // Tab cycles: automatic → HTTPS → SSH → automatic.
        let protocol = |s: &State| match &s
            .main_page
            .content_panel
            .repos
            .view
            .as_ref()
            .unwrap()
            .workspace
            .form
        {
            Some(WorkspaceForm::Settings { protocol, .. }) => *protocol,
            _ => panic!("the settings form is open"),
        };
        reduce(&mut s, &W::SettingsProtocol);
        assert_eq!(protocol(&s), Some(CloneProtocol::Ssh));
        reduce(&mut s, &W::SettingsProtocol);
        assert_eq!(protocol(&s), None);
        reduce(&mut s, &W::Cancel);
        assert!(
            s.main_page
                .content_panel
                .repos
                .view
                .as_ref()
                .unwrap()
                .workspace
                .form
                .is_none()
        );
    }

    #[test]
    fn removing_is_armed_only_when_there_is_something_to_remove() {
        let mut s = state_with(view());
        reduce(&mut s, &W::RemoveArm);
        assert!(
            s.main_page
                .content_panel
                .repos
                .view
                .as_ref()
                .unwrap()
                .workspace
                .confirm
                .is_none()
        );

        let mut v = view();
        v.workspace.health = Some(SignerHealth {
            identity: IdentityStatus {
                profile: Some("me".into()),
                ..IdentityStatus::default()
            },
            binary: git_signing::BinaryStatus::Missing,
            hook: crate::state_handler::main_page::repos::HookHealth::Missing,
            hook_path: None,
        });
        let mut s = state_with(v);
        reduce(&mut s, &W::RemoveArm);
        assert_eq!(
            s.main_page
                .content_panel
                .repos
                .view
                .as_ref()
                .unwrap()
                .workspace
                .confirm,
            Some(WorkspaceChange::RemoveIdentity)
        );
    }

    #[test]
    fn a_checkout_summary_names_who_signs() {
        let mut v = view();
        assert_eq!(summary(&v, "github.com/acme/w").0, "not cloned");
        v.workspace
            .checkouts
            .insert("github.com/acme/w".into(), checkout(CheckoutSigning::Off));
        assert_eq!(summary(&v, "github.com/acme/w").0, "not signing");
        v.workspace.checkouts.insert(
            "github.com/acme/w".into(),
            checkout(CheckoutSigning::On {
                did_key_id: "did:webvh:me#key-0".into(),
                profile: Some("me".into()),
                here: true,
            }),
        );
        assert_eq!(
            summary(&v, "github.com/acme/w"),
            ("signed".into(), Severity::Success)
        );
        v.workspace.checkouts.insert(
            "github.com/acme/w".into(),
            checkout(CheckoutSigning::On {
                did_key_id: "did:webvh:someone-else#key-0".into(),
                profile: None,
                here: false,
            }),
        );
        assert_eq!(summary(&v, "github.com/acme/w").1, Severity::Error);
    }

    #[test]
    fn a_probe_is_wanted_after_a_job_lands() {
        let mut s = state_with(view());
        WorkspaceOutcome {
            vtc_did: "did:webvh:vtc".into(),
            persona: PersonaId(uuid::Uuid::nil()),
            result: Ok("done".into()),
            settings: None,
            form: None,
            push_access: None,
        }
        .apply(&mut s);
        let v = s.main_page.content_panel.repos.view.as_ref().unwrap();
        assert_eq!(v.workspace.probe_wanted, Some(true));
        assert!(v.workspace.busy.is_none());
        assert_eq!(v.status_text(), Some("done"));
    }

    #[test]
    fn an_outcome_for_another_community_is_dropped() {
        let mut s = state_with(view());
        WorkspaceOutcome {
            vtc_did: "did:webvh:other".into(),
            persona: PersonaId(uuid::Uuid::nil()),
            result: Ok("done".into()),
            settings: None,
            form: None,
            push_access: None,
        }
        .apply(&mut s);
        let v = s.main_page.content_panel.repos.view.as_ref().unwrap();
        assert!(v.workspace.probe_wanted.is_none());
    }

    fn gh(login: &str, active: bool) -> forge_credential::GhAccount {
        forge_credential::GhAccount {
            host: "github.com".into(),
            login: login.into(),
            active,
        }
    }

    fn picker(
        repo: Option<ForgeCredential>,
        forge: Option<ForgeCredential>,
        linked: Option<&str>,
    ) -> AccountForm {
        AccountForm::new(
            "github.com/acme/widgets".into(),
            "github.com".into(),
            repo,
            forge,
            Ok(vec![
                gh("alice", true),
                gh("alice-work", false),
                forge_credential::GhAccount {
                    host: "ghe.example.com".into(),
                    login: "elsewhere".into(),
                    active: true,
                },
            ]),
            vec![PathBuf::from("/h/.ssh/id_ed25519")],
            linked,
        )
    }

    #[test]
    fn the_picker_offers_this_forges_accounts_and_keys() {
        use crate::state_handler::main_page::repos::AccountOption as O;
        let f = picker(None, None, None);
        assert_eq!(
            f.scope,
            CredentialScope::Forge,
            "nothing chosen: the community's choice"
        );
        assert_eq!(
            f.visible().into_iter().cloned().collect::<Vec<_>>(),
            vec![
                O::GitDefault,
                O::Gh {
                    login: "alice".into(),
                    active: true
                },
                O::Gh {
                    login: "alice-work".into(),
                    active: false
                },
                O::SshKey(PathBuf::from("/h/.ssh/id_ed25519")),
                O::EnterPath,
            ],
            "another forge's gh account is not offered; Inherit is a repository's"
        );
        assert_eq!(f.picked(), Some(&O::GitDefault));
        assert_eq!(f.choice(), Ok(None), "the default on a forge clears it");
    }

    #[test]
    fn the_linked_login_is_preselected_only_when_nothing_is_chosen() {
        use crate::state_handler::main_page::repos::AccountOption as O;
        let f = picker(None, None, Some("alice-work"));
        assert!(matches!(f.picked(), Some(O::Gh { login, .. }) if login == "alice-work"));
        let chosen = picker(
            None,
            Some(ForgeCredential::gh("alice".into())),
            Some("alice-work"),
        );
        assert!(matches!(chosen.picked(), Some(O::Gh { login, .. }) if login == "alice"));
        let unknown = picker(None, None, Some("nobody"));
        assert_eq!(unknown.picked(), Some(&O::GitDefault));
    }

    #[test]
    fn a_repository_choice_opens_in_repository_scope_and_toggles() {
        use crate::state_handler::main_page::repos::AccountOption as O;
        let key = ForgeCredential::SshKey {
            path: PathBuf::from("/elsewhere/id_x"),
        };
        let mut f = picker(Some(key.clone()), None, None);
        assert_eq!(f.scope, CredentialScope::Repo);
        assert_eq!(f.visible()[0], &O::Inherit);
        assert_eq!(
            f.picked(),
            Some(&O::SshKey(PathBuf::from("/elsewhere/id_x"))),
            "a key chosen outside ~/.ssh is still offered"
        );
        assert_eq!(f.choice(), Ok(Some(key.clone())));
        f.toggle_scope();
        assert_eq!(f.scope, CredentialScope::Forge);
        assert_eq!(f.choice(), Ok(Some(key)), "the same row stays highlighted");
        f.toggle_scope();
        f.pick = 0;
        assert_eq!(
            f.choice(),
            Ok(None),
            "Inherit removes the repository's choice"
        );
        f.pick = 1;
        assert_eq!(
            f.choice(),
            Ok(Some(ForgeCredential::GitDefault)),
            "a repository can opt out of its forge's account"
        );
    }

    #[test]
    fn the_picker_moves_types_and_reports() {
        let mut v = view();
        v.workspace.form = Some(WorkspaceForm::Account(picker(None, None, None)));
        let mut s = state_with(v);
        let form = |s: &State| match s
            .main_page
            .content_panel
            .repos
            .view
            .as_ref()
            .unwrap()
            .workspace
            .form
            .clone()
        {
            Some(WorkspaceForm::Account(f)) => f,
            other => panic!("{other:?}"),
        };
        assert!(reduce(&mut s, &W::AccountPick(99)));
        assert!(form(&s).typing(), "clamped to the last row, the path");
        assert_eq!(
            form(&s).choice(),
            Err("Type the path of the private key.".into())
        );
        assert!(reduce(&mut s, &W::AccountInput("/k/id_work".into())));
        assert_eq!(
            form(&s).choice(),
            Ok(Some(ForgeCredential::SshKey {
                path: PathBuf::from("/k/id_work")
            }))
        );
        // A refusal lands in the form, and the form stays open.
        WorkspaceOutcome {
            vtc_did: "did:webvh:vtc".into(),
            persona: PersonaId(uuid::Uuid::nil()),
            result: Err("The key file ~/k/id_work is missing.".into()),
            settings: None,
            form: None,
            push_access: None,
        }
        .apply(&mut s);
        assert_eq!(
            form(&s).error.as_deref(),
            Some("The key file ~/k/id_work is missing.")
        );
        assert!(reduce(&mut s, &W::Cancel));
        let v = s.main_page.content_panel.repos.view.as_ref().unwrap();
        assert!(v.workspace.form.is_none());
    }

    #[test]
    fn found_accounts_open_the_picker() {
        let mut s = state_with(view());
        WorkspaceOutcome {
            vtc_did: "did:webvh:vtc".into(),
            persona: PersonaId(uuid::Uuid::nil()),
            result: Ok("Choose the account.".into()),
            settings: None,
            form: Some(WorkspaceForm::Account(picker(None, None, None))),
            push_access: None,
        }
        .apply(&mut s);
        let v = s.main_page.content_panel.repos.view.as_ref().unwrap();
        assert!(matches!(v.workspace.form, Some(WorkspaceForm::Account(_))));
    }

    #[test]
    fn gh_missing_is_said_in_the_picker() {
        let f = AccountForm::new(
            "github.com/acme/widgets".into(),
            "github.com".into(),
            None,
            None,
            Err(forge_credential::GhError::NotInstalled.to_string()),
            Vec::new(),
            None,
        );
        assert_eq!(
            f.gh_note.as_deref(),
            Some("gh is not installed (or not on PATH)")
        );
        assert_eq!(f.visible().len(), 2, "git default and a typed path");
    }

    #[test]
    fn a_checkout_on_the_other_protocol_is_called_out() {
        let gh = ForgeCredential::gh("alice".into());
        assert!(origin_mismatch(&gh, Some("git@github.com:acme/widgets.git")).is_some());
        assert!(origin_mismatch(&gh, Some("https://github.com/acme/widgets.git")).is_none());
        let key = ForgeCredential::SshKey {
            path: PathBuf::from("/k"),
        };
        assert!(origin_mismatch(&key, Some("https://github.com/acme/widgets.git")).is_some());
        assert!(origin_mismatch(&ForgeCredential::GitDefault, Some("x")).is_none());
    }

    #[test]
    fn a_gh_account_can_keep_the_members_own_author() {
        let mut v = view();
        let mut f = picker(None, None, Some("alice"));
        assert!(!f.keep_author);
        assert_eq!(f.choice(), Ok(Some(ForgeCredential::gh("alice".into()))));
        f.keep_author = true;
        v.workspace.form = Some(WorkspaceForm::Account(f));
        let mut s = state_with(v);
        assert!(!reduce(&mut s, &W::Fork), "forking runs gh");
        assert!(reduce(&mut s, &W::AccountAuthor));
        let Some(WorkspaceForm::Account(f)) = s
            .main_page
            .content_panel
            .repos
            .view
            .as_ref()
            .unwrap()
            .workspace
            .form
            .clone()
        else {
            panic!("the picker is open");
        };
        assert!(!f.keep_author, "a toggles it back");
        let kept = picker(
            Some(ForgeCredential::GhAccount {
                login: "alice".into(),
                keep_author: true,
            }),
            None,
            None,
        );
        assert!(kept.keep_author, "a stored choice opens as it was saved");
    }

    #[test]
    fn push_access_is_remembered_from_an_outcome() {
        let mut s = state_with(view());
        WorkspaceOutcome {
            vtc_did: "did:webvh:vtc".into(),
            persona: PersonaId(uuid::Uuid::nil()),
            result: Ok("Cloned.".into()),
            settings: None,
            form: None,
            push_access: Some(("github.com/acme/widgets".into(), "alice".into(), false)),
        }
        .apply(&mut s);
        let v = s.main_page.content_panel.repos.view.as_ref().unwrap();
        assert_eq!(
            v.workspace.push_access.get("github.com/acme/widgets"),
            Some(&("alice".to_string(), false))
        );
    }
}
