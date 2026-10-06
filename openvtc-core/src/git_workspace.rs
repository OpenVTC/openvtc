//! Local checkouts of a community's repositories.
//!
//! The Repos panel shows a member the repositories a community governs
//! (`git-ns/view`); this module is the local half — where each one is checked
//! out on this machine, what state that checkout is in, and cloning one that is
//! not there yet. Commit signing itself is did-git-sign's ([`crate::git_signing`]);
//! what is read here is only what git reports about a checkout, so the panel can
//! say whether a commit made in it would be signed, and as whom.
//!
//! # Layout
//!
//! A checkout lives at `<root>/<forge-host>/<owner>/<repo>` unless the member
//! pointed openvtc at one somewhere else ([`WorkspaceSettings::checkouts`]). The
//! layout mirrors the forge-qualified resource the community uses
//! (`github.com/acme/widgets`), so two forges or two owners can never collide
//! on disk, and finding a checkout needs no scan.
//!
//! # Untrusted input
//!
//! A resource comes from the community's answer. It reaches a command line (as
//! a clone URL) and the filesystem (as a path), so [`RepoCoords::parse`] admits
//! only what the `git-ns` schema does — a DNS host and two plain segments — and
//! refuses anything that could read as an option (`-…`) or climb out of the
//! workspace (`..`). Every git invocation also passes `--` before a URL or path.
//!
//! Everything here is blocking (it runs `git` and touches the filesystem); call
//! it off the runtime loop.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::public_config::profile_dir;
use crate::errors::OpenVTCError;
use crate::forge_credential::{self, ForgeCredential};

/// The longest a clone may run before it is stopped (R1.2). Generous — a large
/// repository over a slow link is a legitimate wait — but finite, so a clone
/// that hangs on the network ends in an error rather than a spinner forever.
pub const CLONE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// A repository's place on its forge: `github.com/acme/widgets` as its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoCoords {
    pub host: String,
    pub owner: String,
    pub repo: String,
}

/// A host the `git-ns` schema admits: lowercase DNS labels, at least two.
fn valid_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// An owner or repository name: never an option, never a path step.
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 100
        && !segment.starts_with('-')
        && !segment.starts_with('.')
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

impl RepoCoords {
    /// Parse a forge-qualified resource, `<host>/<owner>/<repo>`.
    ///
    /// # Errors
    ///
    /// When the resource is not exactly three parts, or a part is one git or
    /// the filesystem could misread.
    pub fn parse(resource: &str) -> Result<Self, OpenVTCError> {
        let parts: Vec<&str> = resource.split('/').collect();
        let [host, owner, repo] = parts.as_slice() else {
            return Err(OpenVTCError::Config(format!(
                "'{resource}' is not a repository (expected <forge>/<owner>/<repo>)"
            )));
        };
        if !valid_host(host) || !valid_segment(owner) || !valid_segment(repo) {
            return Err(OpenVTCError::Config(format!(
                "'{resource}' is not a repository name openvtc will use on disk or on a \
                 command line"
            )));
        }
        Ok(Self {
            host: (*host).to_string(),
            owner: (*owner).to_string(),
            repo: (*repo).to_string(),
        })
    }

    /// `<host>/<owner>/<repo>`, as the community writes it.
    #[must_use]
    pub fn resource(&self) -> String {
        format!("{}/{}/{}", self.host, self.owner, self.repo)
    }

    /// The URL to clone from.
    #[must_use]
    pub fn clone_url(&self, protocol: CloneProtocol) -> String {
        match protocol {
            CloneProtocol::Https => {
                format!("https://{}/{}/{}.git", self.host, self.owner, self.repo)
            }
            CloneProtocol::Ssh => format!("git@{}:{}/{}.git", self.host, self.owner, self.repo),
        }
    }

    /// Where this repository is checked out under `root` by default.
    #[must_use]
    pub fn default_path(&self, root: &Path) -> PathBuf {
        root.join(&self.host).join(&self.owner).join(&self.repo)
    }

    /// Whether a remote URL names this repository, in any of the forms git
    /// accepts: `https://host/owner/repo(.git)`, `ssh://[user@]host[:port]/owner/repo`,
    /// or scp-like `user@host:owner/repo`. Case-insensitive, as forges are.
    #[must_use]
    pub fn matches_remote(&self, url: &str) -> bool {
        remote_coords(url).is_some_and(|(host, path)| {
            host.eq_ignore_ascii_case(&self.host)
                && path.eq_ignore_ascii_case(&format!("{}/{}", self.owner, self.repo))
        })
    }
}

/// A remote URL as `(host, owner/repo)`, with any `.git` and trailing slash gone.
fn remote_coords(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    let (host, path) = if let Some((scheme, rest)) = url.split_once("://") {
        if !matches!(scheme, "https" | "http" | "ssh" | "git") {
            return None;
        }
        let (authority, path) = rest.split_once('/')?;
        let host = authority.rsplit('@').next()?;
        // An ssh URL may carry a port; an https one may too.
        let host = host.split(':').next()?;
        (host, path)
    } else {
        // scp-like: [user@]host:path — but not a Windows or relative path.
        let (authority, path) = url.split_once(':')?;
        if authority.contains('/') {
            return None;
        }
        (authority.rsplit('@').next()?, path)
    };
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let path = path.trim_start_matches('/');
    (!host.is_empty() && !path.is_empty()).then(|| (host.to_string(), path.to_string()))
}

/// How a repository is cloned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloneProtocol {
    /// `https://…` — works without an SSH key; a private repository needs a
    /// credential helper.
    #[default]
    Https,
    /// `git@host:…` — uses the SSH key the forge account has.
    Ssh,
}

impl CloneProtocol {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            CloneProtocol::Https => "HTTPS",
            CloneProtocol::Ssh => "SSH",
        }
    }

    #[must_use]
    pub fn toggled(self) -> Self {
        match self {
            CloneProtocol::Https => CloneProtocol::Ssh,
            CloneProtocol::Ssh => CloneProtocol::Https,
        }
    }
}

/// `~/src`: where checkouts go until the member chooses somewhere else.
#[must_use]
pub fn default_root() -> PathBuf {
    dirs::home_dir().map_or_else(|| PathBuf::from("src"), |h| h.join("src"))
}

/// A path as typed: a leading `~/` is the home directory.
#[must_use]
pub fn expand_tilde(input: &str) -> PathBuf {
    let input = input.trim();
    match (input.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ if input == "~" => dirs::home_dir().unwrap_or_else(|| PathBuf::from(input)),
        _ => PathBuf::from(input),
    }
}

/// A path for display: the home directory as `~`.
#[must_use]
pub fn display_path(path: &Path) -> String {
    if let Some(home) = dirs::home_dir()
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return if rest.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~/{}", rest.display())
        };
    }
    path.display().to_string()
}

/// Which forge accounts one community's checkouts use: one per forge host, and
/// any repository that differs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityCredentials {
    /// By forge host (`github.com`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub forges: BTreeMap<String, ForgeCredential>,
    /// By resource (`github.com/acme/widgets`); wins over the forge's.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub repos: BTreeMap<String, ForgeCredential>,
}

/// Where a forge-account choice applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialScope {
    /// This repository only.
    Repo,
    /// Every repository of the community on this forge without its own.
    Forge,
}

/// Which credential a repository uses, and where that came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialChoice {
    pub credential: ForgeCredential,
    /// `None`: nothing chosen, so the git default.
    pub scope: Option<CredentialScope>,
}

/// Where this machine keeps a profile's checkouts. Not secret — paths and a
/// preference — so it lives in a plain file beside the public config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    /// The directory checkouts are cloned under.
    #[serde(default = "default_root")]
    pub root: PathBuf,
    #[serde(default)]
    pub protocol: CloneProtocol,
    /// Checkouts the member pointed openvtc at outside the default layout, by
    /// resource.
    #[serde(default)]
    pub checkouts: BTreeMap<String, PathBuf>,
    /// Forge accounts, by community DID. References only (a key path, a gh
    /// login) — never a token or a key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, CommunityCredentials>,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            root: default_root(),
            protocol: CloneProtocol::default(),
            checkouts: BTreeMap::new(),
            credentials: BTreeMap::new(),
        }
    }
}

impl WorkspaceSettings {
    /// `git-workspace.json` (or `git-workspace-<profile>.json`) in the
    /// profile's config directory.
    ///
    /// # Errors
    ///
    /// When the profile name is invalid or there is no home directory.
    pub fn path(profile: &str) -> Result<PathBuf, OpenVTCError> {
        let mut path = profile_dir(profile)?;
        if profile == "default" {
            path.push("git-workspace.json");
        } else {
            path.push(format!("git-workspace-{profile}.json"));
        }
        Ok(path)
    }

    /// Read the settings at `path`; a missing file is the defaults.
    ///
    /// # Errors
    ///
    /// When the file exists but cannot be read or parsed.
    pub fn load_from(path: &Path) -> Result<Self, OpenVTCError> {
        match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).map_err(|e| {
                OpenVTCError::Config(format!("couldn't parse {}: {e}", path.display()))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(OpenVTCError::Config(format!(
                "couldn't read {}: {e}",
                path.display()
            ))),
        }
    }

    /// Write the settings to `path`, atomically: a reader never sees half a
    /// file.
    ///
    /// # Errors
    ///
    /// When the directory or file cannot be written.
    pub fn save_to(&self, path: &Path) -> Result<(), OpenVTCError> {
        let io = |e: std::io::Error| {
            OpenVTCError::Config(format!("couldn't write {}: {e}", path.display()))
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| OpenVTCError::Config(format!("workspace settings: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, data).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)
    }

    /// Where `coords` is checked out, if it is: the path the member gave, else
    /// the default layout's, whichever exists.
    #[must_use]
    pub fn locate(&self, coords: &RepoCoords) -> Option<PathBuf> {
        self.checkouts
            .get(&coords.resource())
            .filter(|p| p.is_dir())
            .cloned()
            .or_else(|| Some(coords.default_path(&self.root)).filter(|p| p.is_dir()))
    }

    /// The forge account `coords` uses in the community `vtc_did`: the
    /// repository's own choice, else the forge's, else the git default.
    #[must_use]
    pub fn credential_for(&self, vtc_did: &str, coords: &RepoCoords) -> CredentialChoice {
        let community = self.credentials.get(vtc_did);
        if let Some(c) = community.and_then(|c| c.repos.get(&coords.resource())) {
            return CredentialChoice {
                credential: c.clone(),
                scope: Some(CredentialScope::Repo),
            };
        }
        if let Some(c) = community.and_then(|c| c.forges.get(&coords.host)) {
            return CredentialChoice {
                credential: c.clone(),
                scope: Some(CredentialScope::Forge),
            };
        }
        CredentialChoice {
            credential: ForgeCredential::GitDefault,
            scope: None,
        }
    }

    /// Choose the account for `coords`' repository or forge; `None` removes the
    /// choice (a repository then follows its forge's, a forge the git default).
    pub fn set_credential(
        &mut self,
        vtc_did: &str,
        coords: &RepoCoords,
        scope: CredentialScope,
        credential: Option<ForgeCredential>,
    ) {
        let community = self.credentials.entry(vtc_did.to_string()).or_default();
        let (map, key) = match scope {
            CredentialScope::Repo => (&mut community.repos, coords.resource()),
            CredentialScope::Forge => (&mut community.forges, coords.host.clone()),
        };
        match credential {
            Some(c) => {
                map.insert(key, c);
            }
            None => {
                map.remove(&key);
            }
        }
        if community.forges.is_empty() && community.repos.is_empty() {
            self.credentials.remove(vtc_did);
        }
    }
}

// ****************************************************************************
// Reading a checkout
// ****************************************************************************

/// `git -C <dir> …`, never prompting, never taking optional locks (a status
/// read must not contend with the member's own git in that repository).
fn git_in(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null());
    cmd
}

/// Run git in `dir`; `None` when it fails or prints nothing.
fn git_read(dir: &Path, args: &[&str]) -> Option<String> {
    let out = git_in(dir).args(args).stderr(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
    (!v.is_empty()).then_some(v)
}

/// The commit at `HEAD`, and whether it would pass as signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadCommit {
    pub short: String,
    pub subject: String,
    /// git's `%G?`: `G` good, `U` good but unknown validity, `N` unsigned,
    /// `B` bad, `E` could not be checked, and the rest.
    pub signature: char,
    /// The `Signed-by-DID:` trailer — the claim `verify-trust` reads.
    pub signed_by_did: Option<String>,
}

/// What git reports about one checkout. Facts only; the panel decides what
/// they mean for signing.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CheckoutFacts {
    pub path: PathBuf,
    /// A git work tree at all.
    pub is_repo: bool,
    /// The `origin` remote's URL.
    pub origin: Option<String>,
    /// Whether `origin` names the repository it was looked up for.
    pub origin_matches: bool,
    /// The checked-out branch; `None` when detached.
    pub branch: Option<String>,
    pub upstream: bool,
    pub ahead: u32,
    pub behind: u32,
    /// Changed or untracked paths.
    pub changed: u32,
    /// The repository's own `include.path` values (`.git/config` only).
    pub includes: Vec<String>,
    /// The `did-git-sign.key` git will sign as here, from any scope.
    pub signing_key: Option<String>,
    /// The `gpg.ssh.program` git will call, from any scope.
    pub ssh_program: Option<String>,
    /// Whether commits are signed by default here (`commit.gpgsign`).
    pub gpgsign: bool,
    /// The `core.hooksPath` in effect, from any scope.
    pub hooks_path: Option<String>,
    pub head: Option<HeadCommit>,
    /// `user.name` and `user.email` as git will author a commit here, from any
    /// scope.
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    /// The forge account openvtc set this checkout to use
    /// ([`forge_credential::MARKER_KEY`]); `None` when it set none.
    pub credential: Option<ForgeCredential>,
}

/// Parse `git status --porcelain=v2 --branch` output.
fn parse_status(out: &str, facts: &mut CheckoutFacts) {
    for line in out.lines() {
        if let Some(head) = line.strip_prefix("# branch.head ") {
            facts.branch = (head != "(detached)").then(|| head.to_string());
        } else if line.starts_with("# branch.upstream ") {
            facts.upstream = true;
        } else if let Some(ab) = line.strip_prefix("# branch.ab ") {
            for part in ab.split_whitespace() {
                if let Some(n) = part.strip_prefix('+') {
                    facts.ahead = n.parse().unwrap_or(0);
                } else if let Some(n) = part.strip_prefix('-') {
                    facts.behind = n.parse().unwrap_or(0);
                }
            }
        } else if !line.starts_with('#') && !line.is_empty() {
            facts.changed += 1;
        }
    }
}

/// Parse the `git log -1` line [`inspect`] asks for: fields split by `\x1f`.
fn parse_head(out: &str) -> Option<HeadCommit> {
    let mut parts = out.splitn(4, '\x1f');
    let short = parts.next()?.trim().to_string();
    let subject = parts.next().unwrap_or_default().to_string();
    let signature = parts.next().and_then(|s| s.chars().next()).unwrap_or('N');
    let signed_by_did = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.split(',').next_back())
        .map(|s| s.trim().to_string());
    (!short.is_empty()).then_some(HeadCommit {
        short,
        subject,
        signature,
        signed_by_did,
    })
}

/// Read one checkout. Never fails: what git cannot say is left unset.
#[must_use]
pub fn inspect(path: &Path, coords: &RepoCoords) -> CheckoutFacts {
    let mut facts = CheckoutFacts {
        path: path.to_path_buf(),
        ..CheckoutFacts::default()
    };
    if git_read(path, &["rev-parse", "--is-inside-work-tree"]).as_deref() != Some("true") {
        return facts;
    }
    facts.is_repo = true;
    facts.origin = git_read(path, &["remote", "get-url", "origin"]);
    facts.origin_matches = facts
        .origin
        .as_deref()
        .is_some_and(|u| coords.matches_remote(u));
    if let Some(out) = git_read(path, &["status", "--porcelain=v2", "--branch"]) {
        parse_status(&out, &mut facts);
    }
    facts.includes = git_read(path, &["config", "--local", "--get-all", "include.path"])
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default();
    facts.signing_key = git_read(path, &["config", "--get", "did-git-sign.key"]);
    facts.ssh_program = git_read(path, &["config", "--get", "gpg.ssh.program"]);
    facts.gpgsign = git_read(path, &["config", "--type=bool", "--get", "commit.gpgsign"])
        .as_deref()
        == Some("true");
    facts.hooks_path = git_read(path, &["config", "--get", "core.hooksPath"]);
    facts.author_name = git_read(path, &["config", "--get", "user.name"]);
    facts.author_email = git_read(path, &["config", "--get", "user.email"]);
    facts.credential = git_read(
        path,
        &["config", "--local", "--get", forge_credential::MARKER_KEY],
    )
    .as_deref()
    .and_then(ForgeCredential::from_marker);
    facts.head = git_read(
        path,
        &[
            "log",
            "-1",
            "--format=%h%x1f%s%x1f%G?%x1f%(trailers:key=Signed-by-DID,valueonly,separator=%x2C)",
        ],
    )
    .as_deref()
    .and_then(parse_head);
    facts
}

// ****************************************************************************
// Cloning
// ****************************************************************************

/// Why a clone failed, in words that say what to do — told apart by what git
/// printed, so an auth refusal never reads as a network fault (R6.4).
fn explain_clone_failure(stderr: &str, protocol: CloneProtocol) -> String {
    let lower = stderr.to_ascii_lowercase();
    let last = stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("git clone failed")
        .to_string();
    if lower.contains("could not read username")
        || lower.contains("authentication failed")
        || lower.contains("terminal prompts disabled")
    {
        return match protocol {
            CloneProtocol::Https => "the forge asked for credentials, and openvtc cannot prompt \
                 for them. Choose a forge account for this repository (f), configure a git \
                 credential helper for this forge, or switch the workspace to SSH (w)."
                .into(),
            CloneProtocol::Ssh => format!("the forge refused the credentials: {last}"),
        };
    }
    if lower.contains("permission denied (publickey)") || lower.contains("host key verification") {
        return format!(
            "SSH was refused ({last}). Load a key your forge account knows into ssh-agent, \
             choose the key for this repository (f), accept the host key once with \
             `ssh -T git@<forge>`, or switch the workspace to HTTPS (w)."
        );
    }
    if lower.contains("repository not found") || lower.contains("not found") {
        return format!(
            "the forge says the repository does not exist, or your account cannot see it \
             ({last}). A private repository needs your linked forge account to hold access."
        );
    }
    if lower.contains("could not resolve host")
        || lower.contains("connection timed out")
        || lower.contains("network is unreachable")
        || lower.contains("connection refused")
    {
        return format!("the forge could not be reached: {last}");
    }
    last
}

/// Whether `dir` is missing or an empty directory — somewhere a clone may go.
fn free_for_clone(dir: &Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Clone `coords` into `dest`, which must not exist yet (or be empty), with
/// the forge account `credential` — which the new checkout keeps for every
/// later fetch and push ([`forge_credential::clone_args`]).
///
/// Never prompts: with no terminal to ask on, an HTTPS remote that wants a
/// password fails, and SSH runs in batch mode unless the member configured
/// `core.sshCommand` themselves. A clone that outlives `timeout` is stopped and
/// what it wrote removed.
///
/// # Errors
///
/// A sentence saying why, and what to do about it.
pub fn clone_repo(
    coords: &RepoCoords,
    protocol: CloneProtocol,
    credential: &ForgeCredential,
    author: Option<&forge_credential::CommitAuthor>,
    dest: &Path,
    timeout: Duration,
) -> Result<(), String> {
    if !free_for_clone(dest) {
        return Err(format!(
            "{} already exists and is not empty. If it is a checkout of this repository, \
             use it instead (u).",
            display_path(dest)
        ));
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("couldn't create {}: {e}", display_path(parent)))?;
    }
    let protocol = credential.protocol(protocol);
    let mut cmd = Command::new("git");
    cmd.args(forge_credential::clone_args(
        coords, protocol, credential, author, dest,
    )?)
    .env("GIT_TERMINAL_PROMPT", "0")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    if matches!(credential, ForgeCredential::SshKey { .. }) {
        // The chosen key's command must win; the environment would beat it.
        cmd.env_remove("GIT_SSH_COMMAND");
    } else {
        let user_ssh = std::env::var_os("GIT_SSH_COMMAND").is_some()
            || git_read(
                Path::new("."),
                &["config", "--global", "--get", "core.sshCommand"],
            )
            .is_some();
        if !user_ssh {
            cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
        }
    }
    let mut child = cmd.spawn().map_err(|e| format!("couldn't run git: {e}"))?;
    // Drain stderr on its own thread: a clone that prints more than a pipe
    // holds would otherwise block forever on a full buffer.
    let mut stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(s) = stderr.as_mut() {
            let _ = s.read_to_string(&mut text);
        }
        text
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("couldn't wait for git: {e}")),
        }
    };
    let stderr = reader.join().unwrap_or_default();
    match status {
        Some(s) if s.success() => Ok(()),
        outcome => {
            // git removes a failed clone's directory itself; a killed one may
            // leave a partial tree behind.
            if dest.exists() && !free_for_clone(dest) && outcome.is_none() {
                let _ = std::fs::remove_dir_all(dest);
            }
            Err(match outcome {
                None => format!(
                    "the clone took longer than {} minutes and was stopped",
                    timeout.as_secs() / 60
                ),
                Some(_) => explain_clone_failure(&stderr, protocol),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widgets() -> RepoCoords {
        RepoCoords::parse("github.com/acme/widgets").unwrap()
    }

    #[test]
    fn a_resource_parses_into_its_parts() {
        let c = widgets();
        assert_eq!(
            (c.host.as_str(), c.owner.as_str(), c.repo.as_str()),
            ("github.com", "acme", "widgets")
        );
        assert_eq!(c.resource(), "github.com/acme/widgets");
    }

    #[test]
    fn resources_that_could_be_misread_are_refused() {
        for bad in [
            "github.com/acme",
            "github.com/acme/widgets/extra",
            "github.com/-acme/widgets",
            "github.com/acme/--upload-pack=evil",
            "github.com/../widgets",
            "github.com/acme/..",
            "github.com/acme/.hidden",
            "localhost/acme/widgets",
            "GitHub.com/acme/widgets",
            "github.com/acme/wid gets",
            "github.com/acme/wid;gets",
            "",
        ] {
            assert!(RepoCoords::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn clone_urls_follow_the_protocol() {
        let c = widgets();
        assert_eq!(
            c.clone_url(CloneProtocol::Https),
            "https://github.com/acme/widgets.git"
        );
        assert_eq!(
            c.clone_url(CloneProtocol::Ssh),
            "git@github.com:acme/widgets.git"
        );
    }

    #[test]
    fn the_default_path_mirrors_the_resource() {
        assert_eq!(
            widgets().default_path(Path::new("/w")),
            Path::new("/w")
                .join("github.com")
                .join("acme")
                .join("widgets")
        );
    }

    #[test]
    fn every_remote_form_matches_its_repository() {
        let c = widgets();
        for url in [
            "https://github.com/acme/widgets.git",
            "https://github.com/acme/widgets",
            "https://github.com/acme/widgets/",
            "https://user@github.com/Acme/Widgets.git",
            "git@github.com:acme/widgets.git",
            "github.com:acme/widgets",
            "ssh://git@github.com/acme/widgets.git",
            "ssh://git@github.com:22/acme/widgets",
        ] {
            assert!(c.matches_remote(url), "{url} should match");
        }
        for url in [
            "https://github.com/acme/gadgets.git",
            "https://codeberg.org/acme/widgets.git",
            "git@github.com:other/widgets.git",
            "/local/path/widgets",
            "file:///tmp/acme/widgets",
        ] {
            assert!(!c.matches_remote(url), "{url} should not match");
        }
    }

    #[test]
    fn porcelain_status_is_read() {
        let mut f = CheckoutFacts::default();
        parse_status(
            "# branch.oid abc\n# branch.head main\n# branch.upstream origin/main\n\
             # branch.ab +2 -1\n1 .M N... 100644 100644 100644 a b src/x.rs\n? new.txt\n",
            &mut f,
        );
        assert_eq!(f.branch.as_deref(), Some("main"));
        assert!(f.upstream);
        assert_eq!((f.ahead, f.behind, f.changed), (2, 1, 2));

        let mut d = CheckoutFacts::default();
        parse_status("# branch.oid abc\n# branch.head (detached)\n", &mut d);
        assert_eq!(d.branch, None);
        assert!(!d.upstream);
    }

    #[test]
    fn the_head_line_is_read() {
        let h = parse_head("abc1234\x1ffix: thing\x1fG\x1fdid:webvh:x:e.com#key-0").unwrap();
        assert_eq!(h.short, "abc1234");
        assert_eq!(h.subject, "fix: thing");
        assert_eq!(h.signature, 'G');
        assert_eq!(h.signed_by_did.as_deref(), Some("did:webvh:x:e.com#key-0"));

        let unsigned = parse_head("abc1234\x1fwip\x1fN\x1f").unwrap();
        assert_eq!(unsigned.signature, 'N');
        assert_eq!(unsigned.signed_by_did, None);
    }

    #[test]
    fn settings_round_trip_and_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("git-workspace.json");
        assert_eq!(
            WorkspaceSettings::load_from(&path).unwrap(),
            WorkspaceSettings::default()
        );
        let mut s = WorkspaceSettings {
            root: dir.path().join("code"),
            protocol: CloneProtocol::Ssh,
            ..WorkspaceSettings::default()
        };
        s.checkouts
            .insert("github.com/acme/widgets".into(), dir.path().join("w"));
        s.set_credential(
            "did:webvh:x:c.example",
            &widgets(),
            CredentialScope::Repo,
            Some(ForgeCredential::gh("alice".into())),
        );
        s.save_to(&path).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("\"gh_account\""), "{saved}");
        assert_eq!(WorkspaceSettings::load_from(&path).unwrap(), s);
    }

    #[test]
    fn a_repository_choice_wins_over_its_forge() {
        let mut s = WorkspaceSettings::default();
        let c = widgets();
        let other = RepoCoords::parse("github.com/acme/gadgets").unwrap();
        assert_eq!(s.credential_for("did:c", &c).scope, None);
        let work = ForgeCredential::gh("alice-work".into());
        let key = ForgeCredential::SshKey {
            path: PathBuf::from("/k/id_x"),
        };
        s.set_credential("did:c", &c, CredentialScope::Forge, Some(work.clone()));
        s.set_credential("did:c", &c, CredentialScope::Repo, Some(key.clone()));
        assert_eq!(s.credential_for("did:c", &c).credential, key);
        assert_eq!(
            s.credential_for("did:c", &c).scope,
            Some(CredentialScope::Repo)
        );
        assert_eq!(s.credential_for("did:c", &other).credential, work);
        assert_eq!(
            s.credential_for("did:other", &c).credential,
            ForgeCredential::GitDefault,
            "another community's choice does not leak"
        );
        s.set_credential("did:c", &c, CredentialScope::Repo, None);
        assert_eq!(s.credential_for("did:c", &c).credential, work);
        s.set_credential("did:c", &c, CredentialScope::Forge, None);
        assert!(s.credentials.is_empty());
    }

    #[test]
    fn locate_prefers_the_given_path_then_the_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = WorkspaceSettings {
            root: dir.path().to_path_buf(),
            ..WorkspaceSettings::default()
        };
        let c = widgets();
        assert_eq!(s.locate(&c), None);
        let laid_out = c.default_path(dir.path());
        std::fs::create_dir_all(&laid_out).unwrap();
        assert_eq!(s.locate(&c), Some(laid_out));
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        s.checkouts.insert(c.resource(), elsewhere.clone());
        assert_eq!(s.locate(&c), Some(elsewhere));
    }

    #[test]
    fn clone_failures_say_what_to_do() {
        let https = explain_clone_failure(
            "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
            CloneProtocol::Https,
        );
        assert!(https.contains("credential helper"), "{https}");
        let ssh = explain_clone_failure(
            "git@github.com: Permission denied (publickey).\nfatal: Could not read from remote",
            CloneProtocol::Ssh,
        );
        assert!(ssh.contains("ssh-agent"), "{ssh}");
        let net = explain_clone_failure(
            "fatal: unable to access: Could not resolve host: github.com",
            CloneProtocol::Https,
        );
        assert!(net.contains("could not be reached"), "{net}");
    }

    /// A real clone from a local bare repository, and the facts read back.
    #[test]
    fn a_local_clone_is_inspected() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        // An empty global config, on every platform (`/dev/null` is not one).
        let empty = dir.path().join("empty.gitconfig");
        std::fs::write(&empty, "").unwrap();
        let run = |args: &[&str], cwd: &Path| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_GLOBAL", &empty)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?}");
        };
        std::fs::create_dir_all(&src).unwrap();
        run(&["init", "-q", "-b", "main"], &src);
        run(
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "first",
            ],
            &src,
        );
        let dest = dir.path().join("checkout");
        let out = Command::new("git")
            .args(["clone", "-q", "--"])
            .arg(&src)
            .arg(&dest)
            .output()
            .unwrap();
        assert!(out.status.success());
        let facts = inspect(&dest, &widgets());
        assert!(facts.is_repo);
        assert!(!facts.origin_matches, "a local path is not the forge");
        assert_eq!(facts.branch.as_deref(), Some("main"));
        assert_eq!(
            facts.head.as_ref().map(|h| h.subject.as_str()),
            Some("first")
        );

        let missing = inspect(&dir.path().join("nope"), &widgets());
        assert!(!missing.is_repo);
    }

    #[test]
    fn a_clone_into_a_non_empty_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), "x").unwrap();
        let err = clone_repo(
            &widgets(),
            CloneProtocol::Https,
            &ForgeCredential::GitDefault,
            None,
            dir.path(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(err.contains("not empty"), "{err}");
    }
}
