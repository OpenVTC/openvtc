//! State for the per-community Repos panel (git namespaces), opened from the
//! Communities panel with `r`.
//!
//! Everything shown is one `git-ns/view` answer ([`ReposView::data`]) read
//! through the pure helpers in [`openvtc_core::git_ns`]; every change is a
//! signed `git-ns/*` task whose reply is matched by thread id, after which the
//! view is read again. Nothing here is persisted: the VTC is the record.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};
use openvtc_core::config::account::PersonaId;
use openvtc_core::git_ns::{self, GitRight, Visibility, view};

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
    /// *My repos*, the account row and signing health.
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
    pub error: Option<String>,
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
    /// 0 namespace, 1 name, 2 visibility, 3 description.
    pub field: usize,
    pub name: String,
    pub visibility: Visibility,
    pub description: String,
    pub error: Option<String>,
}

impl NewRepoForm {
    pub const FIELDS: usize = 4;
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

/// The did-git-sign commit-msg hook git would run, as did-git-sign's own
/// `commit_msg_hook_status` finds it.
#[derive(Clone, Debug, PartialEq)]
pub enum HookHealth {
    /// Not checked yet.
    Checking,
    /// This release's hook.
    Current { version: u32 },
    /// An older did-git-sign's hook; `did-git-sign init` replaces it.
    Outdated { installed: u32, current: u32 },
    /// A newer did-git-sign wrote it.
    Newer { installed: u32, current: u32 },
    /// A commit-msg hook did-git-sign did not write.
    Foreign { path: String },
    /// No hook where git will look.
    Missing { path: String },
    /// Not in a repository and no global `core.hooksPath`: nowhere to look.
    NoGlobalHooks,
    /// git could not be asked.
    Unknown(String),
}

/// Can this persona sign commits here: did-git-sign's install, and its hook.
#[derive(Clone, Debug, PartialEq)]
pub struct SigningHealth {
    /// The verification method did-git-sign signs with, when it is set up for
    /// this persona.
    pub key_id: Option<String>,
    pub hook: HookHealth,
}

impl Default for SigningHealth {
    fn default() -> Self {
        Self {
            key_id: None,
            hook: HookHealth::Checking,
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
    pub signing: SigningHealth,
    pub status_message: Option<String>,
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
            signing: SigningHealth::default(),
            status_message: None,
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

    /// The people on a repository.
    #[must_use]
    pub fn people(&self, resource: &str) -> Vec<git_ns::Person> {
        self.data
            .as_deref()
            .map(|d| git_ns::people_on(d, resource))
            .unwrap_or_default()
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
    #[must_use]
    pub fn name_of(&self, did: &str) -> String {
        if did == self.me {
            return "you".into();
        }
        self.labels
            .get(did)
            .cloned()
            .unwrap_or_else(|| did.to_string())
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
