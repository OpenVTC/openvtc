//! Which forge account a checkout uses for clone, fetch and push.
//!
//! git authenticates to a forge with whatever this machine's git config says:
//! the global `core.sshCommand`, ssh-agent's keys, a credential helper. A member
//! with several accounts on one forge — a work and a personal GitHub login, say
//! — needs a different one per community, and sometimes per repository. This
//! module is that choice ([`ForgeCredential`]) and how it is applied to git.
//!
//! # What is stored
//!
//! Only references: a path to an SSH private key, or the login of an account
//! the `gh` CLI holds. Never a token, never key material. The choice lives in
//! the workspace settings ([`crate::git_workspace::WorkspaceSettings`]), keyed
//! by community and forge host, with an optional per-repository override.
//!
//! # How it is applied
//!
//! - **SSH key**: `core.sshCommand = ssh -i '<path>' -o IdentitiesOnly=yes`, so
//!   ssh offers that key and no other.
//! - **gh account**: a credential helper scoped to `https://<forge>` that asks
//!   `gh auth token --hostname <forge> --user <login>` for the token. An empty
//!   helper entry before it resets the helpers inherited from the global config,
//!   so the machine's default account is not tried first. Needs gh 2.40 or
//!   later (multi-account support). `gh auth git-credential` cannot be used: it
//!   always answers with the host's *active* account.
//! - **Git default**: nothing is written; git does what it did before.
//!
//! A clone passes the settings as `git clone --config`, which writes them into
//! the new checkout before anything is fetched — so the first fetch already
//! uses the chosen account, and every later fetch and push does too. An
//! existing checkout gets them with `git config --local`. Either way openvtc
//! also writes [`MARKER_KEY`], which is how it reads back which account a
//! checkout uses, and how it knows which keys it may remove when the choice
//! changes (it never removes a `core.sshCommand` it did not write).
//!
//! # Untrusted input
//!
//! A login and a key path end up inside a string git hands to a shell (a `!`
//! credential helper, `core.sshCommand`). So a login is held to GitHub's login
//! alphabet ([`valid_login`]) and a key path may not contain a quote or a
//! control character ([`validate_key_path`]); the host is already a DNS name
//! ([`crate::git_workspace::RepoCoords::parse`]). Everything else is passed to
//! git and gh as separate arguments, never through a shell.
//!
//! Everything here is blocking (it runs `git` and `gh`); call it off the
//! runtime loop.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::git_workspace::{CloneProtocol, RepoCoords};

/// The longest a `gh` call may run (R1.2). `gh auth status` checks every
/// account's token against the forge, so it is a network call.
pub const GH_TIMEOUT: Duration = Duration::from_secs(20);

/// The longest `gh repo fork` may run: it waits for the forge to create the
/// fork.
pub const FORK_TIMEOUT: Duration = Duration::from_secs(90);

/// The longest a local `git config` call may run.
const GIT_CONFIG_TIMEOUT: Duration = Duration::from_secs(10);

/// The local git config key openvtc writes beside the settings it applies:
/// `ssh:<path>` or `gh:<login>`.
pub const MARKER_KEY: &str = "openvtc.forgeCredential";

/// Written as `true` when openvtc also set the checkout's `user.name` and
/// `user.email`, so it knows it may remove them when the choice changes.
pub const AUTHOR_MARKER_KEY: &str = "openvtc.forgeAuthor";

/// Who commits made in a checkout are authored as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitAuthor {
    pub name: String,
    pub email: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The account git uses to reach a forge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ForgeCredential {
    /// Whatever this machine's git config does — openvtc writes nothing.
    GitDefault,
    /// This SSH private key, and no other.
    SshKey { path: PathBuf },
    /// This account of the `gh` CLI, over HTTPS. Commits are authored as the
    /// account too (its `users.noreply` address), unless `keep_author`: then
    /// the member's own git identity stays.
    GhAccount {
        login: String,
        #[serde(default, skip_serializing_if = "is_false")]
        keep_author: bool,
    },
}

impl ForgeCredential {
    /// A gh account, authoring commits as that account.
    #[must_use]
    pub fn gh(login: String) -> Self {
        ForgeCredential::GhAccount {
            login,
            keep_author: false,
        }
    }

    /// Whether two choices reach the forge as the same account, whatever they
    /// say about the commit author.
    #[must_use]
    pub fn same_account(&self, other: &Self) -> bool {
        match (self, other) {
            (
                ForgeCredential::GhAccount { login: a, .. },
                ForgeCredential::GhAccount { login: b, .. },
            ) => a == b,
            _ => self == other,
        }
    }

    /// The gh login, for a gh account.
    #[must_use]
    pub fn gh_login(&self) -> Option<&str> {
        match self {
            ForgeCredential::GhAccount { login, .. } => Some(login),
            _ => None,
        }
    }

    /// Look up the commit author this choice sets: a gh account's
    /// `users.noreply` identity, unless it keeps the member's own. `None`:
    /// nothing to set. Blocking; calls `gh api` (bounded).
    #[must_use]
    pub fn author(&self, host: &str) -> Option<Result<CommitAuthor, String>> {
        match self {
            ForgeCredential::GhAccount {
                login,
                keep_author: false,
            } => Some(gh_noreply_author(host, login, GH_TIMEOUT)),
            _ => None,
        }
    }

    /// A few words for the panel.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            ForgeCredential::GitDefault => "git default".into(),
            ForgeCredential::SshKey { path } => {
                format!("SSH key {}", crate::git_workspace::display_path(path))
            }
            ForgeCredential::GhAccount { login, .. } => format!("gh account {login}"),
        }
    }

    /// The protocol a clone with this credential must use: an SSH key only
    /// works over SSH, a gh token only over HTTPS. `fallback` is the
    /// workspace's choice, for the git default.
    #[must_use]
    pub fn protocol(&self, fallback: CloneProtocol) -> CloneProtocol {
        match self {
            ForgeCredential::GitDefault => fallback,
            ForgeCredential::SshKey { .. } => CloneProtocol::Ssh,
            ForgeCredential::GhAccount { .. } => CloneProtocol::Https,
        }
    }

    /// The value of [`MARKER_KEY`] for this credential; `None` for the default.
    #[must_use]
    pub fn marker(&self) -> Option<String> {
        match self {
            ForgeCredential::GitDefault => None,
            ForgeCredential::SshKey { path } => Some(format!("ssh:{}", path.display())),
            ForgeCredential::GhAccount { login, .. } => Some(format!("gh:{login}")),
        }
    }

    /// Read a [`MARKER_KEY`] value back.
    #[must_use]
    pub fn from_marker(marker: &str) -> Option<Self> {
        if let Some(path) = marker.strip_prefix("ssh:") {
            return (!path.is_empty()).then(|| ForgeCredential::SshKey {
                path: PathBuf::from(path),
            });
        }
        marker
            .strip_prefix("gh:")
            .filter(|l| valid_login(l))
            .map(|login| ForgeCredential::gh(login.to_string()))
    }

    /// Check the choice is still usable before git relies on it: the key file
    /// is there, gh holds the account. Blocking; calls `gh` for an account.
    ///
    /// # Errors
    ///
    /// A sentence naming what is missing.
    pub fn check(&self, host: &str) -> Result<(), String> {
        match self {
            ForgeCredential::GitDefault => Ok(()),
            ForgeCredential::SshKey { path } => validate_key_path(path).map(|_| ()),
            ForgeCredential::GhAccount { login, .. } => gh_check_account(host, login, GH_TIMEOUT),
        }
    }
}

// ****************************************************************************
// Validation
// ****************************************************************************

/// A forge login openvtc will put in a credential helper: GitHub's alphabet —
/// letters, digits and single hyphens, not at either end, at most 39.
#[must_use]
pub fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 39
        && !login.starts_with('-')
        && !login.ends_with('-')
        && !login.contains("--")
        && login.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Check a path names an SSH private key openvtc can hand to ssh, and return
/// it as given.
///
/// # Errors
///
/// When it is not absolute, is missing, is not a file, is the public half, or
/// holds a character that could break out of the quoted `core.sshCommand`.
pub fn validate_key_path(path: &Path) -> Result<PathBuf, String> {
    let shown = crate::git_workspace::display_path(path);
    let Some(text) = path.to_str() else {
        return Err(format!(
            "{shown} is not a UTF-8 path openvtc can pass to ssh."
        ));
    };
    if text
        .chars()
        .any(|c| c == '\'' || c == '"' || c.is_control())
    {
        return Err(format!(
            "{shown} contains a quote or control character; rename the key file."
        ));
    }
    if !path.is_absolute() {
        return Err("Use an absolute path, or one starting with ~/.".into());
    }
    if text.ends_with(".pub") {
        return Err(format!(
            "{shown} is the public half of the key; choose the private key file (no .pub)."
        ));
    }
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => Ok(path.to_path_buf()),
        Ok(_) => Err(format!("{shown} is not a file.")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("The key file {shown} is missing."))
        }
        Err(e) => Err(format!("couldn't read the key file {shown}: {e}")),
    }
}

/// SSH private keys in `dir` named the way ssh-keygen names them: `id_*`,
/// without the `.pub` halves. Sorted; empty when `dir` cannot be read.
#[must_use]
pub fn ssh_keys_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut keys: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("id_") && !name.ends_with(".pub")
        })
        .map(|e| e.path())
        .filter(|p| p.is_file() && validate_key_path(p).is_ok())
        .collect();
    keys.sort();
    keys
}

/// The SSH keys in `~/.ssh`.
#[must_use]
pub fn ssh_keys() -> Vec<PathBuf> {
    dirs::home_dir()
        .map(|h| ssh_keys_in(&h.join(".ssh")))
        .unwrap_or_default()
}

// ****************************************************************************
// git settings
// ****************************************************************************

/// The `credential.<url>.helper` key for a forge.
fn helper_key(host: &str) -> String {
    format!("credential.https://{host}.helper")
}

/// The `credential.<url>.username` key for a forge.
fn username_key(host: &str) -> String {
    format!("credential.https://{host}.username")
}

/// `core.sshCommand` for a key. `batch` adds `BatchMode=yes`, for openvtc's own
/// clone (nothing can answer a prompt); the checkout's saved setting leaves it
/// out, so a passphrase prompt still works in the member's terminal.
fn ssh_command(path: &Path, batch: bool) -> String {
    format!(
        "ssh -i '{}' -o IdentitiesOnly=yes{}",
        path.display(),
        if batch { " -o BatchMode=yes" } else { "" }
    )
}

/// The `!` credential helper that answers with a gh account's token. `host`
/// and `login` are validated, so nothing in them is special to the shell.
fn gh_helper(host: &str, login: &str) -> String {
    format!(
        "!f() {{ test \"$1\" = get || exit 0; \
         t=$(gh auth token --hostname {host} --user {login}) || exit 1; \
         echo username={login}; echo \"password=$t\"; }}; f"
    )
}

/// The `(key, value)` pairs a checkout gets for `credential` on `host`, in the
/// order they are written, with `author` as `user.name` / `user.email` when
/// given. Repeated keys are added, not replaced. Empty for the git default.
///
/// # Errors
///
/// When the login or key path would not be safe inside the shell string git
/// runs, or the author holds a control character.
pub fn local_settings(
    credential: &ForgeCredential,
    host: &str,
    author: Option<&CommitAuthor>,
) -> Result<Vec<(String, String)>, String> {
    let Some(marker) = credential.marker() else {
        return Ok(Vec::new());
    };
    let mut out = match credential {
        ForgeCredential::GitDefault => Vec::new(),
        ForgeCredential::SshKey { path } => {
            check_key_text(path)?;
            vec![("core.sshCommand".to_string(), ssh_command(path, false))]
        }
        ForgeCredential::GhAccount { login, .. } => {
            if !valid_login(login) {
                return Err(format!("'{login}' is not a forge login openvtc will use."));
            }
            vec![
                // An empty helper resets the list git built from the global
                // config, so the machine's default account is not tried first.
                (helper_key(host), String::new()),
                (helper_key(host), gh_helper(host, login)),
                (username_key(host), login.clone()),
            ]
        }
    };
    if let Some(a) = author {
        if [&a.name, &a.email]
            .iter()
            .any(|v| v.is_empty() || v.chars().any(char::is_control))
        {
            return Err("the commit author has an empty or control-character field.".into());
        }
        out.push(("user.name".into(), a.name.clone()));
        out.push(("user.email".into(), a.email.clone()));
        out.push((AUTHOR_MARKER_KEY.into(), "true".into()));
    }
    out.push((MARKER_KEY.to_string(), marker));
    Ok(out)
}

/// Only the textual checks of [`validate_key_path`] — for settings built from a
/// path that was checked when it was chosen.
fn check_key_text(path: &Path) -> Result<(), String> {
    match path.to_str() {
        Some(t)
            if path.has_root() && !t.chars().any(|c| c == '\'' || c == '"' || c.is_control()) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "{} is not a key path openvtc will put on a command line.",
            crate::git_workspace::display_path(path)
        )),
    }
}

/// The arguments for `git` that clone `coords` into `dest` with `credential`:
/// the global `-c` that makes openvtc's own run non-interactive, then
/// `clone --config …` for every setting the checkout keeps, then `--`, the URL
/// and the destination. No shell is involved.
///
/// # Errors
///
/// When the credential is not one openvtc will write ([`local_settings`]).
pub fn clone_args(
    coords: &RepoCoords,
    protocol: CloneProtocol,
    credential: &ForgeCredential,
    author: Option<&CommitAuthor>,
    dest: &Path,
) -> Result<Vec<OsString>, String> {
    let mut args: Vec<OsString> = Vec::new();
    if let ForgeCredential::SshKey { path } = credential {
        // Wins over the `--config` value for this run only.
        args.push("-c".into());
        args.push(format!("core.sshCommand={}", ssh_command(path, true)).into());
    }
    args.extend(["clone".into(), "--quiet".into()]);
    for (key, value) in local_settings(credential, &coords.host, author)? {
        args.push("--config".into());
        args.push(format!("{key}={value}").into());
    }
    args.push("--".into());
    args.push(coords.clone_url(credential.protocol(protocol)).into());
    args.push(dest.as_os_str().to_owned());
    Ok(args)
}

/// `git -C <dir> config --local …`, bounded, never prompting.
fn git_config(dir: &Path, args: &[&str]) -> Result<Output, String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(["config", "--local"])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0");
    run_bounded(cmd, GIT_CONFIG_TIMEOUT).map_err(|e| match e {
        RunError::NotInstalled => "git is not installed (or not on PATH).".to_string(),
        RunError::TimedOut => "git config did not answer in time.".to_string(),
        RunError::Io(e) => format!("couldn't run git: {e}"),
    })
}

/// The credential a checkout was set to use, read back from its own config;
/// `None` when openvtc wrote none (the git default, or the member's own
/// settings).
#[must_use]
pub fn applied_in(dir: &Path) -> Option<ForgeCredential> {
    let out = git_config(dir, &["--get", MARKER_KEY]).ok()?;
    if !out.status.success() {
        return None;
    }
    ForgeCredential::from_marker(String::from_utf8_lossy(&out.stdout).trim())
}

/// Make the checkout at `dir` use `credential` on `host` (and `author`, when
/// given): remove what openvtc wrote for the previous choice, then write the
/// new settings. A setting the
/// member wrote themselves is left alone, except that choosing an SSH key
/// replaces the checkout's own `core.sshCommand` (the choice is that key).
///
/// # Errors
///
/// When git refuses a change; the sentence says which.
pub fn apply_to_checkout(
    dir: &Path,
    host: &str,
    credential: &ForgeCredential,
    author: Option<&CommitAuthor>,
) -> Result<(), String> {
    let settings = local_settings(credential, host, author)?;
    // Undo the previous choice — only what its marker says openvtc wrote.
    let unset = |key: &str| -> Result<(), String> {
        let out = git_config(dir, &["--unset-all", "--", key])?;
        // 5: the key was not there. Nothing to undo.
        match out.status.code() {
            Some(0 | 5) => Ok(()),
            _ => Err(format!(
                "git could not remove {key} from {}: {}",
                crate::git_workspace::display_path(dir),
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    };
    match applied_in(dir) {
        Some(ForgeCredential::SshKey { .. }) => unset("core.sshCommand")?,
        Some(ForgeCredential::GhAccount { .. }) => {
            unset(&helper_key(host))?;
            unset(&username_key(host))?;
        }
        Some(ForgeCredential::GitDefault) | None => {}
    }
    if git_config(dir, &["--get", AUTHOR_MARKER_KEY]).is_ok_and(|o| o.status.success()) {
        unset("user.name")?;
        unset("user.email")?;
        unset(AUTHOR_MARKER_KEY)?;
    }
    unset(MARKER_KEY)?;
    if matches!(credential, ForgeCredential::SshKey { .. }) {
        // A key replaces any sshCommand openvtc did not write too: it is the
        // member's explicit choice for this checkout.
        unset("core.sshCommand")?;
    }
    for (key, value) in &settings {
        let out = git_config(dir, &["--add", "--", key, value])?;
        if !out.status.success() {
            return Err(format!(
                "git could not set {key} in {}: {}",
                crate::git_workspace::display_path(dir),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    Ok(())
}

// ****************************************************************************
// gh
// ****************************************************************************

/// One account the gh CLI holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GhAccount {
    pub host: String,
    pub login: String,
    /// The one gh uses for this host when no account is named.
    pub active: bool,
}

/// Why gh's accounts could not be listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GhError {
    NotInstalled,
    TimedOut,
    Failed(String),
}

impl std::fmt::Display for GhError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GhError::NotInstalled => write!(f, "gh is not installed (or not on PATH)"),
            GhError::TimedOut => write!(
                f,
                "gh did not answer within {} seconds",
                GH_TIMEOUT.as_secs()
            ),
            GhError::Failed(why) => write!(f, "gh could not list its accounts: {why}"),
        }
    }
}

/// `gh auth status --json hosts`: `{"hosts":{"<host>":[{"login":…,"active":…}]}}`.
#[derive(Deserialize)]
struct GhStatusJson {
    hosts: std::collections::BTreeMap<String, Vec<GhStatusEntry>>,
}

#[derive(Deserialize)]
struct GhStatusEntry {
    login: Option<String>,
    #[serde(default)]
    active: bool,
}

/// Parse `gh auth status --json hosts`. Logins gh reports that openvtc would
/// not put in a helper are left out.
#[must_use]
pub fn parse_gh_status_json(text: &str) -> Option<Vec<GhAccount>> {
    let parsed: GhStatusJson = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    for (host, entries) in parsed.hosts {
        for e in entries {
            if let Some(login) = e.login.filter(|l| valid_login(l)) {
                out.push(GhAccount {
                    host: host.clone(),
                    login,
                    active: e.active,
                });
            }
        }
    }
    Some(out)
}

/// Parse the human `gh auth status` output, for a gh too old for `--json`:
/// `✓ Logged in to <host> account <login> (…)` (newer) or
/// `✓ Logged in to <host> as <login> (…)` (older), then `- Active account: true`.
#[must_use]
pub fn parse_gh_status_text(text: &str) -> Vec<GhAccount> {
    let mut out: Vec<GhAccount> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.split_once("Logged in to ").map(|(_, r)| r) {
            let mut words = rest.split_whitespace();
            let (Some(host), Some(_), Some(login)) = (words.next(), words.next(), words.next())
            else {
                continue;
            };
            if valid_login(login) {
                out.push(GhAccount {
                    host: host.to_string(),
                    login: login.to_string(),
                    active: false,
                });
            }
        } else if line.contains("Active account: true")
            && let Some(last) = out.last_mut()
        {
            last.active = true;
        }
    }
    out
}

/// The accounts the gh CLI holds, on every host. Bounded by `timeout`.
///
/// # Errors
///
/// When gh is missing, does not answer in time, or its answer cannot be read.
pub fn gh_accounts(timeout: Duration) -> Result<Vec<GhAccount>, GhError> {
    let run = |args: &[&str]| -> Result<Output, GhError> {
        let mut cmd = Command::new("gh");
        cmd.args(args).env("GH_PROMPT_DISABLED", "1");
        run_bounded(cmd, timeout).map_err(|e| match e {
            RunError::NotInstalled => GhError::NotInstalled,
            RunError::TimedOut => GhError::TimedOut,
            RunError::Io(e) => GhError::Failed(e),
        })
    };
    let out = run(&["auth", "status", "--json", "hosts"])?;
    if out.status.success()
        && let Some(accounts) = parse_gh_status_json(&String::from_utf8_lossy(&out.stdout))
    {
        return Ok(accounts);
    }
    // An older gh with no `--json`: read what it prints for people. It exits
    // non-zero when any account has a problem, and prints to either stream.
    let out = run(&["auth", "status"])?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let accounts = parse_gh_status_text(&text);
    if accounts.is_empty() && !out.status.success() {
        let why = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("no accounts")
            .to_string();
        if why.contains("not logged in") {
            return Ok(Vec::new());
        }
        return Err(GhError::Failed(why));
    }
    Ok(accounts)
}

/// `gh api users/<login>`: the account's numeric id.
#[derive(Deserialize)]
struct GhUser {
    id: u64,
    login: String,
}

/// The `users.noreply` identity of a forge account: `<id>+<login>@users.noreply.<host>`,
/// which the forge attributes to that account (and shows as Verified when the
/// commit is signed by a key it knows).
#[must_use]
pub fn noreply_author(host: &str, id: u64, login: &str) -> CommitAuthor {
    CommitAuthor {
        name: login.to_string(),
        email: format!("{id}+{login}@users.noreply.{host}"),
    }
}

/// Look up `login`'s noreply author on `host` with `gh api` (bounded).
///
/// # Errors
///
/// A sentence: gh missing, no answer, or an answer for another account.
pub fn gh_noreply_author(
    host: &str,
    login: &str,
    timeout: Duration,
) -> Result<CommitAuthor, String> {
    if !valid_login(login) {
        return Err(format!("'{login}' is not a forge login openvtc will use."));
    }
    let mut cmd = Command::new("gh");
    cmd.args(["api", "--hostname", host, &format!("users/{login}")])
        .env("GH_PROMPT_DISABLED", "1");
    let out = match run_bounded(cmd, timeout) {
        Ok(out) => out,
        Err(RunError::NotInstalled) => return Err("gh is not installed (or not on PATH).".into()),
        Err(RunError::TimedOut) => {
            return Err(format!(
                "gh did not answer within {} seconds.",
                timeout.as_secs()
            ));
        }
        Err(RunError::Io(e)) => return Err(format!("couldn't run gh: {e}")),
    };
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("couldn't look {login} up on {host}: {why}"));
    }
    parse_gh_user(&String::from_utf8_lossy(&out.stdout), host, login)
}

/// Read `gh api users/<login>` into the noreply author, checking it answered
/// for that login.
fn parse_gh_user(text: &str, host: &str, login: &str) -> Result<CommitAuthor, String> {
    let user: GhUser = serde_json::from_str(text).map_err(|e| {
        format!("{host} answered the lookup of {login} in a shape openvtc does not read: {e}")
    })?;
    if !user.login.eq_ignore_ascii_case(login) {
        return Err(format!(
            "{host} answered for {} when asked for {login}.",
            user.login
        ));
    }
    Ok(noreply_author(host, user.id, &user.login))
}

/// Whether `login` can push to `coords`, from `gh api repos/<owner>/<repo>`
/// read with that account's own token (bounded). `None` when it could not be
/// told. The token is passed to that one gh call in its environment only.
#[must_use]
pub fn gh_can_push(coords: &RepoCoords, login: &str, timeout: Duration) -> Option<bool> {
    if !valid_login(login) {
        return None;
    }
    let mut cmd = Command::new("gh");
    cmd.args(["auth", "token", "--hostname", &coords.host, "--user", login])
        .env("GH_PROMPT_DISABLED", "1");
    let out = run_bounded(cmd, timeout)
        .ok()
        .filter(|o| o.status.success())?;
    let token = String::from_utf8(out.stdout).ok()?.trim().to_string();
    let mut cmd = Command::new("gh");
    cmd.args([
        "api",
        "--hostname",
        &coords.host,
        &format!("repos/{}/{}", coords.owner, coords.repo),
    ])
    .env("GH_PROMPT_DISABLED", "1")
    .env(
        if coords.host == "github.com" {
            "GH_TOKEN"
        } else {
            "GH_ENTERPRISE_TOKEN"
        },
        token,
    );
    let out = run_bounded(cmd, timeout)
        .ok()
        .filter(|o| o.status.success())?;
    parse_push_permission(&String::from_utf8_lossy(&out.stdout))
}

/// `permissions.push` from `gh api repos/<owner>/<repo>`.
fn parse_push_permission(text: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v.get("permissions")?.get("push")?.as_bool()
}

/// Fork `coords` (the checkout at `dir`) to `login`'s account and point the
/// checkout to push there: `gh repo fork --remote --remote-name fork`, run in
/// the checkout with that account's token, then `remote.pushDefault = fork`.
/// Bounded.
///
/// # Errors
///
/// A sentence saying which step failed.
pub fn gh_fork_for_push(
    dir: &Path,
    coords: &RepoCoords,
    login: &str,
    timeout: Duration,
) -> Result<(), String> {
    if !valid_login(login) {
        return Err(format!("'{login}' is not a forge login openvtc will use."));
    }
    let mut cmd = Command::new("gh");
    cmd.args(["auth", "token", "--hostname", &coords.host, "--user", login])
        .env("GH_PROMPT_DISABLED", "1");
    let out = run_bounded(cmd, timeout).map_err(|_| "gh could not give a token.".to_string())?;
    if !out.status.success() {
        return Err(explain_gh_token_failure(
            &String::from_utf8_lossy(&out.stderr),
            &coords.host,
            login,
        ));
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut cmd = Command::new("gh");
    cmd.current_dir(dir)
        .args([
            // No repository argument: gh forks the checkout's own (its
            // `origin`), and only then adds the remote.
            "repo",
            "fork",
            "--remote",
            "--remote-name",
            "fork",
        ])
        .env("GH_PROMPT_DISABLED", "1")
        .env(
            if coords.host == "github.com" {
                "GH_TOKEN"
            } else {
                "GH_ENTERPRISE_TOKEN"
            },
            token,
        );
    let out = run_bounded(cmd, timeout).map_err(|e| match e {
        RunError::NotInstalled => "gh is not installed (or not on PATH).".to_string(),
        RunError::TimedOut => format!(
            "gh repo fork did not finish within {} seconds.",
            timeout.as_secs()
        ),
        RunError::Io(e) => format!("couldn't run gh: {e}"),
    })?;
    if !out.status.success() {
        return Err(format!(
            "gh could not fork {} as {login}: {}",
            coords.resource(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let out = git_config(dir, &["remote.pushDefault", "fork"])?;
    if !out.status.success() {
        return Err(format!(
            "forked, but git could not set remote.pushDefault: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Explain a failed `gh auth token --user`.
fn explain_gh_token_failure(stderr: &str, host: &str, login: &str) -> String {
    if stderr.contains("unknown flag") {
        return "this gh cannot choose between accounts; update gh to 2.40 or later, or use an \
                SSH key for this repository."
            .into();
    }
    if stderr.contains("no oauth token") || stderr.contains("not logged") {
        return format!(
            "gh has no account {login} logged in on {host}. Log it in with `gh auth login \
             --hostname {host}`, or choose another account (f)."
        );
    }
    let last = stderr
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("no reason given");
    format!("gh could not give a token for {login} on {host}: {last}")
}

/// Check gh holds a token for `login` on `host`. The token itself is read and
/// dropped; it is never kept or logged.
///
/// # Errors
///
/// A sentence: gh missing, too old, the account not logged in, or no answer.
pub fn gh_check_account(host: &str, login: &str, timeout: Duration) -> Result<(), String> {
    if !valid_login(login) {
        return Err(format!("'{login}' is not a forge login openvtc will use."));
    }
    let mut cmd = Command::new("gh");
    cmd.args(["auth", "token", "--hostname", host, "--user", login])
        .env("GH_PROMPT_DISABLED", "1");
    match run_bounded(cmd, timeout) {
        Ok(out) if out.status.success() && !out.stdout.trim_ascii().is_empty() => Ok(()),
        Ok(out) => Err(explain_gh_token_failure(
            &String::from_utf8_lossy(&out.stderr),
            host,
            login,
        )),
        Err(RunError::NotInstalled) => Err(
            "gh is not installed (or not on PATH), so its accounts cannot be used. Install the \
             GitHub CLI, or choose an SSH key (f)."
                .into(),
        ),
        Err(RunError::TimedOut) => Err(format!(
            "gh did not answer within {} seconds.",
            timeout.as_secs()
        )),
        Err(RunError::Io(e)) => Err(format!("couldn't run gh: {e}")),
    }
}

// ****************************************************************************
// Bounded subprocesses
// ****************************************************************************

/// Why a bounded command did not finish.
#[derive(Debug)]
enum RunError {
    NotInstalled,
    TimedOut,
    Io(String),
}

/// Run `cmd` with no stdin, capturing both streams, and kill it if it outlives
/// `timeout` (R1.2).
fn run_bounded(mut cmd: Command, timeout: Duration) -> Result<Output, RunError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunError::NotInstalled
        } else {
            RunError::Io(e.to_string())
        }
    })?;
    // Drain both pipes on their own threads: a full pipe would block the child.
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::TimedOut);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(RunError::Io(e.to_string())),
        }
    };
    Ok(Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widgets() -> RepoCoords {
        RepoCoords::parse("github.com/acme/widgets").unwrap()
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn logins_are_held_to_the_forge_alphabet() {
        for ok in ["alice", "a", "Alice-Work", "a1-b2", &"x".repeat(39)] {
            assert!(valid_login(ok), "{ok}");
        }
        for bad in [
            "",
            "-alice",
            "alice-",
            "al--ice",
            "al ice",
            "al;ice",
            "$(id)",
            "a'b",
            &"x".repeat(40),
        ] {
            assert!(!valid_login(bad), "{bad:?}");
        }
    }

    #[test]
    fn key_paths_are_checked_in_words() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_work");
        std::fs::write(&key, "k").unwrap();
        std::fs::write(dir.path().join("id_work.pub"), "p").unwrap();
        assert_eq!(validate_key_path(&key).unwrap(), key);
        let missing = validate_key_path(&dir.path().join("id_gone")).unwrap_err();
        assert!(missing.contains("is missing"), "{missing}");
        let public = validate_key_path(&dir.path().join("id_work.pub")).unwrap_err();
        assert!(public.contains("public half"), "{public}");
        let quoted = validate_key_path(&dir.path().join("id_'x")).unwrap_err();
        assert!(quoted.contains("quote"), "{quoted}");
        let relative = validate_key_path(Path::new("id_work")).unwrap_err();
        assert!(relative.contains("absolute"), "{relative}");
        assert!(
            validate_key_path(dir.path())
                .unwrap_err()
                .contains("not a file")
        );
    }

    #[test]
    fn keys_are_found_without_their_public_halves() {
        let dir = tempfile::tempdir().unwrap();
        for f in [
            "id_ed25519",
            "id_ed25519.pub",
            "id_work",
            "known_hosts",
            "config",
        ] {
            std::fs::write(dir.path().join(f), "x").unwrap();
        }
        assert_eq!(
            ssh_keys_in(dir.path()),
            vec![dir.path().join("id_ed25519"), dir.path().join("id_work")]
        );
        assert!(ssh_keys_in(&dir.path().join("none")).is_empty());
    }

    #[test]
    fn markers_round_trip() {
        for c in [
            ForgeCredential::SshKey {
                path: PathBuf::from("/home/a/.ssh/id_work"),
            },
            ForgeCredential::gh("alice".into()),
        ] {
            assert_eq!(ForgeCredential::from_marker(&c.marker().unwrap()), Some(c));
        }
        assert_eq!(ForgeCredential::GitDefault.marker(), None);
        assert_eq!(ForgeCredential::from_marker("gh:$(id)"), None);
        assert_eq!(ForgeCredential::from_marker("other"), None);
    }

    #[test]
    fn a_default_clone_is_unchanged() {
        let args = clone_args(
            &widgets(),
            CloneProtocol::Https,
            &ForgeCredential::GitDefault,
            None,
            Path::new("/w/widgets"),
        )
        .unwrap();
        assert_eq!(
            strings(&args),
            [
                "clone",
                "--quiet",
                "--",
                "https://github.com/acme/widgets.git",
                "/w/widgets"
            ]
        );
    }

    #[test]
    fn an_ssh_key_clone_uses_that_key_over_ssh() {
        let cred = ForgeCredential::SshKey {
            path: PathBuf::from("/home/a/.ssh/id_work"),
        };
        let args = strings(
            &clone_args(
                &widgets(),
                CloneProtocol::Https,
                &cred,
                None,
                Path::new("/w/x"),
            )
            .unwrap(),
        );
        assert_eq!(
            args,
            [
                "-c",
                "core.sshCommand=ssh -i '/home/a/.ssh/id_work' -o IdentitiesOnly=yes -o BatchMode=yes",
                "clone",
                "--quiet",
                "--config",
                "core.sshCommand=ssh -i '/home/a/.ssh/id_work' -o IdentitiesOnly=yes",
                "--config",
                "openvtc.forgeCredential=ssh:/home/a/.ssh/id_work",
                "--",
                "git@github.com:acme/widgets.git",
                "/w/x"
            ]
        );
    }

    #[test]
    fn a_gh_clone_uses_that_account_over_https() {
        let cred = ForgeCredential::gh("alice-work".into());
        let args = strings(
            &clone_args(
                &widgets(),
                CloneProtocol::Ssh,
                &cred,
                None,
                Path::new("/w/x"),
            )
            .unwrap(),
        );
        assert_eq!(args[..2], ["clone", "--quiet"]);
        assert_eq!(
            args[2..4],
            ["--config", "credential.https://github.com.helper="]
        );
        assert!(args[5].starts_with("credential.https://github.com.helper=!f() {"));
        assert!(
            args[5].contains("gh auth token --hostname github.com --user alice-work"),
            "{}",
            args[5]
        );
        assert_eq!(args[7], "credential.https://github.com.username=alice-work");
        assert_eq!(args[9], "openvtc.forgeCredential=gh:alice-work");
        assert_eq!(
            args[10..],
            ["--", "https://github.com/acme/widgets.git", "/w/x"]
        );
    }

    #[test]
    fn unsafe_choices_are_refused_before_git_sees_them() {
        let bad_login = ForgeCredential::gh("a;rm -rf".into());
        assert!(
            clone_args(
                &widgets(),
                CloneProtocol::Https,
                &bad_login,
                None,
                Path::new("/w")
            )
            .is_err()
        );
        let bad_key = ForgeCredential::SshKey {
            path: PathBuf::from("/tmp/k'; touch x"),
        };
        assert!(
            clone_args(
                &widgets(),
                CloneProtocol::Ssh,
                &bad_key,
                None,
                Path::new("/w")
            )
            .is_err()
        );
    }

    const GH_JSON: &str = r#"{"hosts":{"github.com":[
        {"state":"success","active":true,"host":"github.com","login":"alice","tokenSource":"keyring","scopes":"repo","gitProtocol":"https"},
        {"state":"success","active":false,"host":"github.com","login":"alice-work","tokenSource":"keyring"}],
        "ghe.acme.com":[{"state":"error","active":true,"host":"ghe.acme.com","login":"al","error":"bad"}]}}"#;

    #[test]
    fn gh_status_json_is_read() {
        let accounts = parse_gh_status_json(GH_JSON).unwrap();
        assert_eq!(
            accounts,
            vec![
                GhAccount {
                    host: "ghe.acme.com".into(),
                    login: "al".into(),
                    active: true
                },
                GhAccount {
                    host: "github.com".into(),
                    login: "alice".into(),
                    active: true
                },
                GhAccount {
                    host: "github.com".into(),
                    login: "alice-work".into(),
                    active: false
                },
            ]
        );
        assert!(parse_gh_status_json("not json").is_none());
        assert_eq!(parse_gh_status_json(r#"{"hosts":{}}"#), Some(vec![]));
    }

    #[test]
    fn gh_status_text_is_read_for_an_older_gh() {
        let text = "github.com\n  ✓ Logged in to github.com account alice (keyring)\n  \
                    - Active account: true\n  - Git operations protocol: https\n\n  \
                    ✓ Logged in to github.com account alice-work (keyring)\n  \
                    - Active account: false\n";
        assert_eq!(
            parse_gh_status_text(text),
            vec![
                GhAccount {
                    host: "github.com".into(),
                    login: "alice".into(),
                    active: true
                },
                GhAccount {
                    host: "github.com".into(),
                    login: "alice-work".into(),
                    active: false
                },
            ]
        );
        let older = "github.com\n  ✓ Logged in to github.com as bob (oauth_token)\n";
        assert_eq!(parse_gh_status_text(older)[0].login, "bob");
        assert!(parse_gh_status_text("You are not logged into any GitHub hosts.").is_empty());
    }

    #[test]
    fn gh_token_failures_say_what_to_do() {
        let none = explain_gh_token_failure(
            "no oauth token found for github.com account bob",
            "github.com",
            "bob",
        );
        assert!(none.contains("no account bob logged in"), "{none}");
        let old = explain_gh_token_failure("unknown flag: --user", "github.com", "bob");
        assert!(old.contains("2.40"), "{old}");
    }

    /// git, with only the config this test gives it.
    fn isolated_git(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", dir.join("empty.gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn local_all(dir: &Path, key: &str) -> Vec<String> {
        git_config(dir, &["--get-all", key])
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Written to a real repository, read back, switched, and cleared — and a
    /// `core.sshCommand` the member wrote survives a gh choice.
    #[test]
    fn local_config_is_written_read_back_and_replaced() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.gitconfig"), "").unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(isolated_git(&repo, &["init", "-q"]));
        let key = dir.path().join("id_work");
        std::fs::write(&key, "k").unwrap();

        assert_eq!(applied_in(&repo), None);
        let ssh = ForgeCredential::SshKey { path: key.clone() };
        apply_to_checkout(&repo, "github.com", &ssh, None).unwrap();
        assert_eq!(applied_in(&repo), Some(ssh));
        assert_eq!(
            local_all(&repo, "core.sshCommand"),
            [format!("ssh -i '{}' -o IdentitiesOnly=yes", key.display())]
        );

        let gh = ForgeCredential::gh("alice".into());
        apply_to_checkout(&repo, "github.com", &gh, None).unwrap();
        assert_eq!(applied_in(&repo), Some(gh.clone()));
        assert!(
            local_all(&repo, "core.sshCommand").is_empty(),
            "openvtc's key is removed"
        );
        let helpers = local_all(&repo, "credential.https://github.com.helper");
        assert_eq!(helpers.len(), 2);
        assert_eq!(helpers[0], "");
        assert!(helpers[1].contains("--user alice"));

        // Applying it again does not stack helpers.
        apply_to_checkout(&repo, "github.com", &gh, None).unwrap();
        assert_eq!(
            local_all(&repo, "credential.https://github.com.helper").len(),
            2
        );

        // The member's own sshCommand is left alone by a gh choice.
        assert!(git_config(&repo, &["core.sshCommand", "ssh -i /mine"]).is_ok());
        apply_to_checkout(&repo, "github.com", &ForgeCredential::GitDefault, None).unwrap();
        assert_eq!(applied_in(&repo), None);
        assert!(local_all(&repo, "credential.https://github.com.helper").is_empty());
        assert!(local_all(&repo, "credential.https://github.com.username").is_empty());
        assert_eq!(local_all(&repo, "core.sshCommand"), ["ssh -i /mine"]);
    }

    /// A real clone from a local repository keeps the chosen settings.
    #[test]
    fn a_clone_writes_the_choice_into_the_checkout() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.gitconfig"), "").unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        assert!(isolated_git(&src, &["init", "-q"]));
        let gh = ForgeCredential::gh("alice".into());
        // The URL is swapped for the local source: same arguments otherwise.
        let mut args = clone_args(
            &widgets(),
            CloneProtocol::Https,
            &gh,
            Some(&noreply_author("github.com", 7, "alice")),
            &dir.path().join("dst"),
        )
        .unwrap();
        let n = args.len();
        args[n - 2] = src.as_os_str().to_owned();
        let ok = Command::new("git")
            .args(&args)
            .env("GIT_CONFIG_GLOBAL", dir.path().join("empty.gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok);
        let dst = dir.path().join("dst");
        assert_eq!(applied_in(&dst), Some(gh));
        assert_eq!(
            local_all(&dst, "user.email"),
            ["7+alice@users.noreply.github.com"]
        );
    }

    #[test]
    fn the_noreply_author_is_read_from_the_forge() {
        let a = parse_gh_user(
            r#"{"login":"Alice-Work","id":12345,"type":"User"}"#,
            "github.com",
            "alice-work",
        )
        .unwrap();
        assert_eq!(a.name, "Alice-Work");
        assert_eq!(a.email, "12345+Alice-Work@users.noreply.github.com");
        assert!(parse_gh_user(r#"{"login":"bob","id":1}"#, "github.com", "alice").is_err());
        assert!(parse_gh_user("{}", "github.com", "alice").is_err());
    }

    #[test]
    fn push_permission_is_read() {
        assert_eq!(
            parse_push_permission(r#"{"permissions":{"admin":false,"push":false,"pull":true}}"#),
            Some(false)
        );
        assert_eq!(
            parse_push_permission(r#"{"permissions":{"push":true}}"#),
            Some(true)
        );
        assert_eq!(parse_push_permission(r#"{"name":"x"}"#), None);
    }

    #[test]
    fn a_gh_choice_sets_the_author_unless_kept() {
        let author = noreply_author("github.com", 9, "alice");
        let settings = local_settings(
            &ForgeCredential::gh("alice".into()),
            "github.com",
            Some(&author),
        )
        .unwrap();
        assert!(settings.contains(&("user.name".into(), "alice".into())));
        assert!(settings.contains(&(
            "user.email".into(),
            "9+alice@users.noreply.github.com".into()
        )));
        let kept = ForgeCredential::GhAccount {
            login: "alice".into(),
            keep_author: true,
        };
        assert!(kept.author("github.com").is_none(), "nothing to look up");
        assert!(ForgeCredential::gh("alice".into()).same_account(&kept));
        let bad = CommitAuthor {
            name: "a\nb".into(),
            email: "x".into(),
        };
        assert!(local_settings(&kept, "github.com", Some(&bad)).is_err());
    }

    /// The author openvtc wrote is removed with the choice; one the member
    /// wrote is never touched.
    #[test]
    fn the_author_is_written_and_removed_with_the_choice() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.gitconfig"), "").unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(isolated_git(&repo, &["init", "-q"]));
        let author = noreply_author("github.com", 9, "alice");
        let gh = ForgeCredential::gh("alice".into());
        apply_to_checkout(&repo, "github.com", &gh, Some(&author)).unwrap();
        assert_eq!(local_all(&repo, "user.name"), ["alice"]);
        apply_to_checkout(&repo, "github.com", &gh, Some(&author)).unwrap();
        assert_eq!(local_all(&repo, "user.email").len(), 1, "not stacked");
        apply_to_checkout(&repo, "github.com", &ForgeCredential::GitDefault, None).unwrap();
        assert!(local_all(&repo, "user.name").is_empty());
        assert!(local_all(&repo, "user.email").is_empty());

        assert!(git_config(&repo, &["user.email", "me@example.com"]).is_ok());
        let kept = ForgeCredential::GhAccount {
            login: "alice".into(),
            keep_author: true,
        };
        apply_to_checkout(&repo, "github.com", &kept, None).unwrap();
        apply_to_checkout(&repo, "github.com", &ForgeCredential::GitDefault, None).unwrap();
        assert_eq!(local_all(&repo, "user.email"), ["me@example.com"]);
    }

    /// A helper in the global (or system) config — `osxkeychain` holding
    /// another account's cached token, say — is never asked once a gh account
    /// is chosen: the empty entry resets the list for that forge.
    #[test]
    fn a_global_helper_is_not_consulted_for_a_chosen_account() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("global.gitconfig");
        std::fs::write(
            &global,
            "[credential]\n\thelper = \"!f() { echo username=cached-other; echo password=stale; }; f\"\n",
        )
        .unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        // Build the repository with the isolated config, then fill.
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(&repo)
                .env("GIT_CONFIG_GLOBAL", &global)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap()
                .status
                .success()
        );
        let fill = |repo: &Path| -> String {
            use std::io::Write;

            let mut child = Command::new("git")
                .args(["credential", "fill"])
                .current_dir(repo)
                .env("GIT_CONFIG_GLOBAL", &global)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"protocol=https\nhost=github.com\n\n")
                .unwrap();
            String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned()
        };
        assert!(
            fill(&repo).contains("username=cached-other"),
            "the global helper answers by default"
        );
        apply_to_checkout(
            &repo,
            "github.com",
            &ForgeCredential::gh("alice".into()),
            None,
        )
        .unwrap();
        assert!(
            !fill(&repo).contains("cached-other"),
            "the chosen account's helper is the only one"
        );
    }
}
