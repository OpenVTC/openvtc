//! State for the per-community Repos panel (git namespaces), opened from the
//! Communities panel with `r`.
//!
//! Everything shown is one `git-ns/view` answer ([`ReposView::data`]) read
//! through the pure helpers in [`openvtc_core::git_ns`]; every change is a
//! signed `git-ns/*` task whose reply is matched by thread id, after which the
//! view is read again. Nothing of that is persisted: the VTC is the record.
//!
//! Beside it, [`Workspace`] is this machine's half: where each repository is
//! checked out and whether a commit there would be signed, and did-git-sign
//! as this persona would use it. That is read from git and did-git-sign
//! ([`openvtc_core::git_workspace`], [`openvtc_core::git_signing`]), never
//! from the community.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};
use openvtc_core::config::account::PersonaId;
use openvtc_core::git_ns::{self, GitRight, Visibility, view};
use openvtc_core::git_signing::{BinaryStatus, CheckoutSigning, IdentityStatus, PersonaSigner};
use openvtc_core::git_workspace::{CheckoutFacts, CloneProtocol, WorkspaceSettings};

/// Longest name or DID kept for display.
pub const MAX_NAME: usize = 256;

/// How a status line reads: its colour comes from this, never from its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Neutral information.
    Info,
    /// A request is on its way; cleared when its answer lands.
    Progress,
    /// A change the community confirmed.
    Success,
    /// Nothing was done, and why (a key that does not apply here).
    Warning,
    /// A refusal, a failed send, a timeout, a contract mismatch.
    Error,
}

/// One status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub text: String,
    pub severity: Severity,
}

impl Status {
    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            severity: Severity::Error,
        }
    }

    #[must_use]
    pub fn warning(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            severity: Severity::Warning,
        }
    }
}

/// Load phase of the view read.
#[derive(Clone, Debug, PartialEq)]
pub enum ReposPhase {
    Loading,
    Loaded,
    Failed(String),
}

/// Which screen of the panel is showing.
#[derive(Clone, Debug, PartialEq)]
pub enum ReposScreen {
    /// *My repos*, the account row, signing, and each repository's checkout.
    List,
    /// One repository: its people and their rights, or its creation steps.
    Repo { resource: String },
    /// The new-repository form.
    NewRepo(NewRepoForm),
}

/// Choices for a grant's expiry, in days; `None` is "never".
pub const EXPIRY_CHOICES: [Option<i64>; 4] = [None, Some(30), Some(90), Some(365)];

/// The label for an expiry choice.
#[must_use]
pub fn expiry_label(choice: Option<i64>) -> String {
    match choice {
        None => "never".into(),
        Some(365) => "1 year".into(),
        Some(d) => format!("{d} days"),
    }
}

/// The add-person form on a repository.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AddPersonForm {
    pub resource: String,
    /// 0 person, 1 right, 2 expiry, 3 reason.
    pub field: usize,
    /// Typed filter over known people, or — in `external` mode — the DID
    /// being pasted.
    pub query: String,
    /// Paste a DID for someone who is not in the picker (an external signer,
    /// if the community's policy allows one).
    pub external: bool,
    /// Highlighted candidate.
    pub pick: usize,
    /// Index into [`GitRight::REPO_RIGHTS`].
    pub right: usize,
    /// Index into [`EXPIRY_CHOICES`].
    pub expiry: usize,
    pub reason: String,
    /// Why the community refused the last attempt, shown in the form so the
    /// member can change what they asked for (a `policyDenied` especially).
    pub error: Option<Status>,
}

impl AddPersonForm {
    pub const FIELDS: usize = 4;

    #[must_use]
    pub fn new(resource: String) -> Self {
        Self {
            resource,
            ..Self::default()
        }
    }

    /// The right chosen.
    #[must_use]
    pub fn right(&self) -> GitRight {
        GitRight::REPO_RIGHTS[self.right.min(GitRight::REPO_RIGHTS.len() - 1)]
    }

    /// When the grant would lapse, measured from `now`.
    #[must_use]
    pub fn expires_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        EXPIRY_CHOICES[self.expiry.min(EXPIRY_CHOICES.len() - 1)]
            .map(|days| now + TimeDelta::days(days))
    }
}

/// The new-repository form.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NewRepoForm {
    /// Index into the namespaces the member may create in.
    pub namespace: usize,
    /// 0 namespace, 1 name, 2 visibility, 3 description, 4 owners.
    pub field: usize,
    pub name: String,
    pub visibility: Visibility,
    pub description: String,
    /// Owners named so far, besides the requester. Sent as `owners` only
    /// when non-empty; absent, the VTC makes the requester the sole owner
    /// (accepted only when their `git.repo.create` is an explicit record).
    pub owners: Vec<String>,
    /// Typed filter over known people, or — in `owner_external` mode — the
    /// DID being pasted, for the owner picker on field 4.
    pub owner_query: String,
    /// Paste a DID for someone not in the picker.
    pub owner_external: bool,
    /// Highlighted owner-picker candidate.
    pub owner_pick: usize,
    pub error: Option<Status>,
}

impl NewRepoForm {
    pub const FIELDS: usize = 5;
}

/// A change armed and waiting for `y` — the consent surface for anything
/// above the `normal` class, and for every removal.
#[derive(Clone, Debug, PartialEq)]
pub struct ArmedChange {
    pub request: git_ns::Request,
    /// The sentence the confirmation shows.
    pub summary: String,
}

/// What an in-flight request was for, so its reply lands in the right place.
#[derive(Clone, Debug, PartialEq)]
pub enum Purpose {
    /// Read the view.
    View,
    /// A change; the string says what, for the status line.
    Change(String),
    /// Begin linking a forge account.
    LinkStart,
    /// Poll a link attempt.
    LinkPoll,
}

/// A request sent and awaiting its reply.
#[derive(Clone, Debug)]
pub struct Pending {
    pub thid: String,
    pub sent_at: Instant,
    pub purpose: Purpose,
}

/// Where a forge-account link attempt is.
#[derive(Clone, Debug, PartialEq)]
pub enum LinkPhase {
    /// `account/link` sent.
    Starting,
    /// The member is authorising on the forge; the panel polls.
    Waiting,
    Linked {
        login: String,
        id: String,
    },
    Expired,
    Failed(String),
}

/// A forge-account link attempt.
#[derive(Clone, Debug)]
pub struct LinkFlow {
    pub forge: String,
    pub phase: LinkPhase,
    pub link_id: Option<String>,
    /// Where to authorise.
    pub url: Option<String>,
    /// The device code, for a device flow (GitHub).
    pub user_code: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// The in-flight poll, if any.
    pub poll: Option<Pending>,
    /// When the last poll was sent, to keep to the five-second floor.
    pub last_poll: Option<Instant>,
}

impl LinkFlow {
    #[must_use]
    pub fn starting(forge: String) -> Self {
        Self {
            forge,
            phase: LinkPhase::Starting,
            link_id: None,
            url: None,
            user_code: None,
            expires_at: None,
            poll: None,
            last_poll: None,
        }
    }

    /// Whether a poll is due at `now`: waiting, nothing in flight, the floor
    /// passed and the attempt not yet lapsed.
    #[must_use]
    pub fn poll_due(&self, now: Instant, wall: DateTime<Utc>) -> bool {
        self.phase == LinkPhase::Waiting
            && self.link_id.is_some()
            && self.poll.is_none()
            && self
                .last_poll
                .is_none_or(|t| now.duration_since(t) >= git_ns::LINK_POLL_INTERVAL)
            && self.expires_at.is_none_or(|e| wall < e)
    }
}

/// A forge account linked in this session. `git-ns/view` reports no account
/// bindings, so a link made here is what the account row can show.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkedAccount {
    pub vtc_did: String,
    pub forge: String,
    pub login: String,
    pub id: String,
}

/// What was found at did-git-sign's commit-msg hook.
#[derive(Clone, Debug, PartialEq)]
pub enum HookHealth {
    /// This release's hook.
    Current { version: u32 },
    /// An older did-git-sign's hook; setting signing up again (`s`) rewrites it.
    Outdated { installed: u32, current: u32 },
    /// A newer did-git-sign wrote it.
    Newer { installed: u32, current: u32 },
    /// A commit-msg hook did-git-sign did not write.
    Foreign,
    /// No hook there: did-git-sign was never set up on this machine.
    Missing,
    /// No config directory to look in.
    NowhereToLook,
}

/// did-git-sign as this persona would use it: the identity it holds, the
/// binary git runs, and the hook that writes the `Signed-by-DID:` claim.
#[derive(Clone, Debug, PartialEq)]
pub struct SignerHealth {
    pub identity: IdentityStatus,
    pub binary: BinaryStatus,
    /// The commit-msg hook did-git-sign's include files point git at.
    pub hook: HookHealth,
    pub hook_path: Option<String>,
}

/// One checkout on this machine, and how a commit made in it would be signed.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckoutView {
    pub facts: CheckoutFacts,
    pub signing: CheckoutSigning,
}

/// A form over the workspace, shown on top of the screen.
#[derive(Clone, Debug, PartialEq)]
pub enum WorkspaceForm {
    /// `w`: where checkouts go, and how they are cloned.
    Settings {
        root: String,
        protocol: CloneProtocol,
        error: Option<String>,
    },
    /// `u`: a checkout of `resource` that already exists somewhere.
    UsePath {
        resource: String,
        path: String,
        error: Option<String>,
    },
}

/// A local change armed for `y`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceChange {
    /// Remove this persona's identity from did-git-sign and revoke its
    /// credential at the VTA.
    RemoveIdentity,
}

/// The local half of the panel: checkouts, and signing.
#[derive(Clone, Debug, Default)]
pub struct Workspace {
    /// The profile the settings belong to.
    pub profile: String,
    pub settings: WorkspaceSettings,
    /// The persona's signing key, resolved from the config when the view
    /// opens; the error says why it could not be.
    pub signer: Option<Result<PersonaSigner, String>>,
    /// `None` until probed.
    pub health: Option<SignerHealth>,
    /// Located checkouts, by resource.
    pub checkouts: HashMap<String, CheckoutView>,
    pub probed_at: Option<Instant>,
    /// A probe is wanted (after the view or a change lands); `identity` when
    /// it should also read the keyring.
    pub probe_wanted: Option<bool>,
    /// What a running job is doing.
    pub busy: Option<String>,
    pub form: Option<WorkspaceForm>,
    pub confirm: Option<WorkspaceChange>,
}

impl Workspace {
    /// The persona's signing VM id, if it resolved.
    #[must_use]
    pub fn did_key_id(&self) -> Option<&str> {
        self.signer
            .as_ref()
            .and_then(|s| s.as_ref().ok())
            .map(|s| s.did_key_id.as_str())
    }

    /// Ask for a probe; `identity` is sticky until one runs.
    pub fn want_probe(&mut self, identity: bool) {
        self.probe_wanted = Some(self.probe_wanted.unwrap_or(false) || identity);
    }

    /// How a checkout's signing reads for this persona.
    #[must_use]
    pub fn signs_as_me(&self, checkout: &CheckoutView) -> Option<bool> {
        match &checkout.signing {
            CheckoutSigning::On { did_key_id, .. } => {
                Some(Some(did_key_id.as_str()) == self.did_key_id())
            }
            _ => None,
        }
    }
}

/// The last `repo/create` answer: which repository, and — where no bot can
/// create it — the steps a person must take.
#[derive(Clone, Debug, PartialEq)]
pub struct CreatedRepo {
    pub resource: String,
    pub manual_steps: Vec<String>,
}

/// The Repos view for one community.
#[derive(Clone, Debug)]
pub struct ReposView {
    pub vtc_did: String,
    pub persona: PersonaId,
    /// The persona's DID in this community — "me" in every right.
    pub me: String,
    pub community_name: String,
    pub phase: ReposPhase,
    /// The last `git-ns/view` answer.
    pub data: Option<Arc<view::Response>>,
    /// Verified display names for DIDs, where known.
    pub labels: HashMap<String, String>,
    pub screen: ReposScreen,
    /// Highlighted row: a repository on the list, a person on a repository.
    pub selected: usize,
    pub add: Option<AddPersonForm>,
    pub confirm: Option<ArmedChange>,
    pub pending: Option<Pending>,
    pub link: Option<LinkFlow>,
    pub created: Option<CreatedRepo>,
    pub workspace: Workspace,
    /// The last thing the panel has to say, with how it should read.
    pub status: Option<Status>,
}

impl ReposView {
    #[must_use]
    pub fn new(vtc_did: String, persona: PersonaId, me: String, community_name: String) -> Self {
        Self {
            vtc_did,
            persona,
            me,
            community_name,
            phase: ReposPhase::Loading,
            data: None,
            labels: HashMap::new(),
            screen: ReposScreen::List,
            selected: 0,
            add: None,
            confirm: None,
            pending: None,
            link: None,
            created: None,
            workspace: Workspace::default(),
            status: None,
        }
    }

    /// The member's repositories.
    #[must_use]
    pub fn my_repos(&self) -> Vec<git_ns::MyRepo> {
        self.data
            .as_deref()
            .map(|d| git_ns::my_repos(d, &self.me))
            .unwrap_or_default()
    }

    /// The namespaces the member may create in.
    #[must_use]
    pub fn creatable(&self) -> Vec<git_ns::Creatable> {
        self.data
            .as_deref()
            .map(|d| git_ns::creatable_namespaces(d, &self.me))
            .unwrap_or_default()
    }

    /// Every unratified break-glass record the view returned — the banner.
    #[must_use]
    pub fn break_glass(&self, now: DateTime<Utc>) -> Vec<git_ns::BreakGlassAlert> {
        self.data
            .as_deref()
            .map(|d| git_ns::unratified_break_glass(d, &self.me, now))
            .unwrap_or_default()
    }

    /// The people on a repository.
    #[must_use]
    pub fn people(&self, resource: &str) -> Vec<git_ns::Person> {
        self.data
            .as_deref()
            .map(|d| git_ns::people_on(d, resource))
            .unwrap_or_default()
    }

    /// The drift outstanding on a repository, as selectors, in the order
    /// the view reported it.
    #[must_use]
    pub fn drift(&self, resource: &str) -> Vec<git_ns::DriftRef> {
        self.repo(resource)
            .map(|r| r.sync.drift.iter().map(git_ns::DriftRef::of).collect())
            .unwrap_or_default()
    }

    /// The rows a repository screen highlights: its people, then its drift.
    #[must_use]
    pub fn repo_rows(&self, resource: &str) -> usize {
        self.people(resource).len() + self.drift(resource).len()
    }

    /// The drift item highlighted on the open repository, if the highlight is
    /// past the people.
    #[must_use]
    pub fn highlighted_drift(&self) -> Option<(String, git_ns::DriftRef)> {
        let ReposScreen::Repo { resource } = &self.screen else {
            return None;
        };
        let index = self.selected.checked_sub(self.people(resource).len())?;
        let item = self.drift(resource).into_iter().nth(index)?;
        Some((resource.clone(), item))
    }

    /// The namespace a repository lives in.
    #[must_use]
    pub fn namespace_of(&self, resource: &str) -> Option<&view::GitNamespace> {
        self.data
            .as_deref()
            .and_then(|d| git_ns::namespace_of(d, resource))
    }

    /// The repository record, if the view has it.
    #[must_use]
    pub fn repo(&self, resource: &str) -> Option<&view::RepoSummary> {
        self.data
            .as_deref()
            .and_then(|d| d.repos.iter().find(|r| *r.resource == *resource))
    }

    /// The member's strongest right on a repository.
    #[must_use]
    pub fn my_right(&self, resource: &str) -> Option<GitRight> {
        let data = self.data.as_deref()?;
        let repo = self.repo(resource)?;
        git_ns::my_right_on(data, &self.me, repo)
    }

    /// Whether the member governs a repository — may add, revoke, transfer
    /// and archive there.
    #[must_use]
    pub fn governs(&self, resource: &str) -> bool {
        self.my_right(resource)
            .is_some_and(|r| r >= GitRight::RepoOwn)
    }

    /// A DID as the panel names it: "you", a verified name, or the DID.
    ///
    /// Always sanitised: every DID here came from the VTC, and a DID may carry
    /// bidi overrides or zero-width characters (the schema only forbids
    /// whitespace) that would make one person's name read as another's.
    #[must_use]
    pub fn name_of(&self, did: &str) -> String {
        if did == self.me {
            return "you".into();
        }
        let raw = self.labels.get(did).map_or(did, String::as_str);
        super::sanitize_display(raw, MAX_NAME)
    }

    /// Say something, with an explicit severity.
    pub fn note(&mut self, severity: Severity, text: impl Into<String>) {
        self.status = Some(Status {
            text: text.into(),
            severity,
        });
    }

    /// Drop an "awaiting the reply" line once the reply is in.
    pub fn clear_progress(&mut self) {
        if self
            .status
            .as_ref()
            .is_some_and(|s| s.severity == Severity::Progress)
        {
            self.status = None;
        }
    }

    /// The status text, for tests.
    #[cfg(test)]
    #[must_use]
    pub fn status_text(&self) -> Option<&str> {
        self.status.as_ref().map(|s| s.text.as_str())
    }

    /// The people the add-person picker offers for `query`: everyone the view
    /// names except the member, matched on DID or name.
    #[must_use]
    pub fn candidates(&self, query: &str) -> Vec<String> {
        let q = query.trim().to_lowercase();
        self.data
            .as_deref()
            .map(git_ns::known_dids)
            .unwrap_or_default()
            .into_iter()
            .filter(|did| *did != self.me)
            .filter(|did| {
                q.is_empty()
                    || did.to_lowercase().contains(&q)
                    || self
                        .labels
                        .get(did)
                        .is_some_and(|l| l.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// The forge account linked in this session on `forge`, if any.
    #[must_use]
    pub fn linked_on<'a>(
        &self,
        linked: &'a [LinkedAccount],
        forge: &str,
    ) -> Option<&'a LinkedAccount> {
        linked
            .iter()
            .find(|a| a.vtc_did == self.vtc_did && a.forge == forge)
    }
}

/// Wrapper so `ContentPanelState` stays `Default`-derivable.
#[derive(Clone, Debug, Default)]
pub struct ReposState {
    pub view: Option<ReposView>,
    /// Accounts linked this session, kept across closing and reopening the
    /// view.
    pub linked: Vec<LinkedAccount>,
}
