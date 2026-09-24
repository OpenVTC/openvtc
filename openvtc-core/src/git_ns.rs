//! Git namespaces — the member side of the `git-ns/*` Trust Task family.
//!
//! A community can govern repositories on the forges it has bound: who may
//! create them, who owns each, whose commits the CI check accepts. The VTC is
//! the source of truth; this module is how a member reads and changes it.
//!
//! # What lives here
//!
//! - [`Request`]: one variant per task a member sends — `view`,
//!   `repo/create`, `right/grant`, `right/revoke`, `repo/transfer`,
//!   `repo/archive`, `account/link`, `account/link-status`. Every payload is
//!   built through the generated `trust_tasks_rs::specs::git_ns` types, so a
//!   value the schema refuses (a DID without a method, an uppercase resource,
//!   a reason over 1024 characters) fails here, before anything is sent.
//! - [`build_signed`]: the addressed, dated, **signed** document. Six of the
//!   eight tasks declare the proof REQUIRED; `view` and `account/link-status`
//!   declare it RECOMMENDED. The VTC reads the actor from the verified
//!   signer, never from the payload, so every document is signed — for the
//!   two reads that is what the specification recommends, and it keeps the
//!   actor the same whichever transport carried the document.
//! - [`parse_reply`] and [`Reply`]: the VTC's answer, typed, or a
//!   [`Refusal`] whose [`Refusal::explain`] says what to do about it.
//! - Pure readings of a `git-ns/view` answer the panel renders from:
//!   [`my_repos`], [`creatable_namespaces`], [`people_on`], [`RepoStatus`].
//!
//! # Carriage
//!
//! Documents go to the VTC in the DIDComm Trust Task binding envelope over
//! the persona's mediator, exactly like the capability tasks
//! ([`crate::capabilities::send_capability_document`]); the VTC's
//! `git-ns/*` dispatcher is reached through its ordinary Trust Task spine
//! (VTI #1694), which verifies the proof before a handler runs.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::git_ns::account::{
    link::v0_1 as link, link_status::v0_1 as link_status,
};
use trust_tasks_rs::specs::git_ns::repo::{
    archive::v0_1 as archive, create::v0_1 as create, transfer::v0_1 as transfer,
};
use trust_tasks_rs::specs::git_ns::right::{grant::v0_1 as grant, revoke::v0_1 as revoke};
use uuid::Uuid;

use crate::errors::OpenVTCError;

/// The generated `git-ns/account/link-status/0.1` types.
pub use link_status::ResponseState as LinkState;
/// The generated `git-ns/view/0.1` types, which the panel renders from.
pub use trust_tasks_rs::specs::git_ns::view::v0_1 as view;

/// Every `git-ns` task URI starts with this.
pub const TYPE_PREFIX: &str = "https://trusttasks.org/spec/git-ns/";

/// The forge whose account link is a device flow — a code the member types
/// at a fixed URL. Every other forge the bridge serves (Forgejo) uses an
/// authorisation-code URL the member opens instead.
pub const DEVICE_FLOW_FORGE: &str = "github.com";

/// How often `account/link-status` may be polled. The specification says a
/// client **SHOULD** poll no faster than every five seconds.
pub const LINK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn conversion(what: &str, e: impl std::fmt::Display) -> OpenVTCError {
    OpenVTCError::Config(format!("{what}: {e}"))
}

// ****************************************************************************
// Rights
// ****************************************************************************

/// One of the five git rights. The strings are carried verbatim: each is also
/// the TRQP `action` the VTC publishes the right under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitRight {
    /// Author commits the CI check accepts.
    CommitSign,
    /// Merge and triage on the forge.
    RepoMaintain,
    /// Grant and revoke rights on the repository; transfer; archive.
    RepoOwn,
    /// Create a repository in the namespace.
    RepoCreate,
    /// Everything, on every repository in the namespace.
    NsAdmin,
}

impl GitRight {
    /// The three rights a person can be given on one repository, weakest
    /// first — the order the add-person form offers them in.
    pub const REPO_RIGHTS: [GitRight; 3] = [
        GitRight::CommitSign,
        GitRight::RepoMaintain,
        GitRight::RepoOwn,
    ];

    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GitRight::NsAdmin => "git.ns.admin",
            GitRight::RepoCreate => "git.repo.create",
            GitRight::RepoOwn => "git.repo.own",
            GitRight::RepoMaintain => "git.repo.maintain",
            GitRight::CommitSign => "git.commit.sign",
        }
    }

    /// Parse the wire string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "git.ns.admin" => GitRight::NsAdmin,
            "git.repo.create" => GitRight::RepoCreate,
            "git.repo.own" => GitRight::RepoOwn,
            "git.repo.maintain" => GitRight::RepoMaintain,
            "git.commit.sign" => GitRight::CommitSign,
            _ => return None,
        })
    }

    /// What a member calls it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            GitRight::NsAdmin => "namespace admin",
            GitRight::RepoCreate => "repo creator",
            GitRight::RepoOwn => "owner",
            GitRight::RepoMaintain => "maintainer",
            GitRight::CommitSign => "committer",
        }
    }

    /// One line on what holding it means, for the add-person form.
    #[must_use]
    pub fn meaning(self) -> &'static str {
        match self {
            GitRight::CommitSign => "can land signed commits; no forge role",
            GitRight::RepoMaintain => "also merges pull requests; forge `maintain`",
            GitRight::RepoOwn => "also grants rights here; forge `admin`",
            GitRight::RepoCreate => "creates repositories in the namespace",
            GitRight::NsAdmin => "governs every repository in the namespace",
        }
    }

    /// Whether the right applies to a namespace rather than one repository.
    #[must_use]
    pub fn is_namespace_level(self) -> bool {
        matches!(self, GitRight::NsAdmin | GitRight::RepoCreate)
    }

    fn from_view(right: &view::Right) -> Option<Self> {
        Self::parse(&right.to_string())
    }
}

/// How much confirmation a change warrants — the design's consent classes
/// (`vtc-git-namespaces-design.md` §6), which the VTC applies too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsentClass {
    /// Grant or revoke `commit.sign` or `maintain`; create; link.
    Normal,
    /// Grant or revoke `own` or `repo.create`; transfer; archive.
    Elevated,
    /// Grant or revoke `ns.admin`.
    Destructive,
}

impl ConsentClass {
    /// Whether the member must confirm before it is sent.
    #[must_use]
    pub fn needs_confirmation(self) -> bool {
        self != ConsentClass::Normal
    }

    /// What the confirmation says about it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ConsentClass::Normal => "normal",
            ConsentClass::Elevated => "elevated",
            ConsentClass::Destructive => "destructive",
        }
    }
}

// ****************************************************************************
// Requests
// ****************************************************************************

/// Repository visibility on the forge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Visibility {
    #[default]
    Public,
    Private,
}

impl Visibility {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
        }
    }
}

/// One `git-ns/*` task a member sends to their community.
#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    /// `git-ns/view/0.1` — what the caller may see, optionally narrowed.
    View { resource: Option<String> },
    /// `git-ns/repo/create/0.1`.
    Create {
        namespace: String,
        name: String,
        visibility: Visibility,
        description: Option<String>,
    },
    /// `git-ns/right/grant/0.1`.
    Grant {
        subject: String,
        right: GitRight,
        resource: String,
        expires_at: Option<DateTime<Utc>>,
        reason: Option<String>,
    },
    /// `git-ns/right/revoke/0.1`.
    Revoke {
        subject: String,
        right: GitRight,
        resource: String,
        reason: Option<String>,
    },
    /// `git-ns/repo/transfer/0.1` — hand the caller's ownership to `to`.
    Transfer { resource: String, to: String },
    /// `git-ns/repo/archive/0.1`.
    Archive { resource: String },
    /// `git-ns/account/link/0.1` — begin linking a forge account.
    Link { forge: String },
    /// `git-ns/account/link-status/0.1`.
    LinkStatus { link_id: String },
}

fn opt_text(s: Option<&String>) -> Option<&str> {
    s.map(|s| s.trim()).filter(|s| !s.is_empty())
}

impl Request {
    /// The task's type URI.
    #[must_use]
    pub fn type_uri(&self) -> &'static str {
        use trust_tasks_rs::Payload as _;
        match self {
            Request::View { .. } => view::Payload::TYPE_URI,
            Request::Create { .. } => create::Payload::TYPE_URI,
            Request::Grant { .. } => grant::Payload::TYPE_URI,
            Request::Revoke { .. } => revoke::Payload::TYPE_URI,
            Request::Transfer { .. } => transfer::Payload::TYPE_URI,
            Request::Archive { .. } => archive::Payload::TYPE_URI,
            Request::Link { .. } => link::Payload::TYPE_URI,
            Request::LinkStatus { .. } => link_status::Payload::TYPE_URI,
        }
    }

    /// Whether the task's specification declares the proof REQUIRED. Every
    /// document is signed regardless (see the module docs); this is what the
    /// specification says, for tests and diagnostics.
    #[must_use]
    pub fn proof_required(&self) -> bool {
        use trust_tasks_rs::Payload as _;
        match self {
            Request::View { .. } => view::Payload::IS_PROOF_REQUIRED,
            Request::Create { .. } => create::Payload::IS_PROOF_REQUIRED,
            Request::Grant { .. } => grant::Payload::IS_PROOF_REQUIRED,
            Request::Revoke { .. } => revoke::Payload::IS_PROOF_REQUIRED,
            Request::Transfer { .. } => transfer::Payload::IS_PROOF_REQUIRED,
            Request::Archive { .. } => archive::Payload::IS_PROOF_REQUIRED,
            Request::Link { .. } => link::Payload::IS_PROOF_REQUIRED,
            Request::LinkStatus { .. } => link_status::Payload::IS_PROOF_REQUIRED,
        }
    }

    /// The consent class of this change.
    #[must_use]
    pub fn consent_class(&self) -> ConsentClass {
        match self {
            Request::Grant { right, .. } | Request::Revoke { right, .. } => match right {
                GitRight::NsAdmin => ConsentClass::Destructive,
                GitRight::RepoOwn | GitRight::RepoCreate => ConsentClass::Elevated,
                GitRight::RepoMaintain | GitRight::CommitSign => ConsentClass::Normal,
            },
            Request::Transfer { .. } | Request::Archive { .. } => ConsentClass::Elevated,
            Request::View { .. }
            | Request::Create { .. }
            | Request::Link { .. }
            | Request::LinkStatus { .. } => ConsentClass::Normal,
        }
    }

    /// The payload, built through the generated types.
    ///
    /// # Errors
    ///
    /// A value the task's schema refuses — named, so the form can say which.
    pub fn payload(&self) -> Result<Value, OpenVTCError> {
        let value = match self {
            Request::View { resource } => {
                let resource = resource
                    .as_deref()
                    .map(view::Resource::try_from)
                    .transpose()
                    .map_err(|e| conversion("resource", e))?;
                let p: view::Payload = view::Payload::builder()
                    .resource(resource)
                    .try_into()
                    .map_err(|e| conversion("git-ns/view payload", e))?;
                serde_json::to_value(p)
            }
            Request::Create {
                namespace,
                name,
                visibility,
                description,
            } => {
                let visibility = create::RepoVisibility::try_from(visibility.as_str())
                    .map_err(|e| conversion("visibility", e))?;
                let description = opt_text(description.as_ref())
                    .map(create::PayloadDescription::try_from)
                    .transpose()
                    .map_err(|e| conversion("description", e))?;
                let p: create::Payload = create::Payload::builder()
                    .namespace(namespace.as_str())
                    .name(name.trim().to_lowercase())
                    .visibility(visibility)
                    .description(description)
                    .try_into()
                    .map_err(|e| conversion("repository", e))?;
                serde_json::to_value(p)
            }
            Request::Grant {
                subject,
                right,
                resource,
                expires_at,
                reason,
            } => {
                let reason = opt_text(reason.as_ref())
                    .map(grant::PayloadReason::try_from)
                    .transpose()
                    .map_err(|e| conversion("reason", e))?;
                let p: grant::Payload = grant::Payload::builder()
                    .subject(subject.trim())
                    .right(right.as_str())
                    .resource(resource.as_str())
                    .expires_at(*expires_at)
                    .reason(reason)
                    .try_into()
                    .map_err(|e| conversion("grant", e))?;
                serde_json::to_value(p)
            }
            Request::Revoke {
                subject,
                right,
                resource,
                reason,
            } => {
                let reason = opt_text(reason.as_ref())
                    .map(revoke::PayloadReason::try_from)
                    .transpose()
                    .map_err(|e| conversion("reason", e))?;
                let p: revoke::Payload = revoke::Payload::builder()
                    .subject(subject.trim())
                    .right(right.as_str())
                    .resource(resource.as_str())
                    .reason(reason)
                    .try_into()
                    .map_err(|e| conversion("revoke", e))?;
                serde_json::to_value(p)
            }
            Request::Transfer { resource, to } => {
                let p: transfer::Payload = transfer::Payload::builder()
                    .resource(resource.as_str())
                    .to(to.trim())
                    .try_into()
                    .map_err(|e| conversion("transfer", e))?;
                serde_json::to_value(p)
            }
            Request::Archive { resource } => {
                let p: archive::Payload = archive::Payload::builder()
                    .resource(resource.as_str())
                    .try_into()
                    .map_err(|e| conversion("archive", e))?;
                serde_json::to_value(p)
            }
            Request::Link { forge } => {
                let p: link::Payload = link::Payload::builder()
                    .forge(forge.as_str())
                    .try_into()
                    .map_err(|e| conversion("forge", e))?;
                serde_json::to_value(p)
            }
            Request::LinkStatus { link_id } => {
                let p: link_status::Payload = link_status::Payload::builder()
                    .link_id(link_id.as_str())
                    .try_into()
                    .map_err(|e| conversion("link id", e))?;
                serde_json::to_value(p)
            }
        };
        value.map_err(|e| conversion("serialise git-ns payload", e))
    }
}

/// Build the request as an addressed, dated, signed Trust Task document.
///
/// The document id is fresh; it opens the exchange, so it is the `threadId`
/// the reply carries (SPEC §4.9) and what the caller correlates on.
///
/// # Errors
///
/// A payload the schema refuses, or a signing failure.
pub async fn build_signed(
    request: &Request,
    issuer_did: &str,
    vtc_did: &str,
    signer: &Secret,
) -> Result<TrustTask<Value>, OpenVTCError> {
    let payload = request.payload()?;
    let mut doc = crate::trust_task_doc::build(
        request.type_uri(),
        issuer_did,
        vtc_did,
        format!("urn:uuid:{}", Uuid::new_v4()),
        payload,
    )?;
    crate::capabilities::sign_document(&mut doc, signer).await?;
    Ok(doc)
}

// ****************************************************************************
// Replies
// ****************************************************************************

/// The VTC's answer to one request.
#[derive(Clone, Debug)]
pub enum Reply {
    View(Box<view::Response>),
    Created(Box<create::Response>),
    Granted(Box<grant::Response>),
    Revoked(Box<revoke::Response>),
    Transferred(Box<transfer::Response>),
    Archived(Box<archive::Response>),
    LinkStarted(Box<link::Response>),
    LinkStatus(Box<link_status::Response>),
    /// A `trust-task-error`.
    Refused(Refusal),
    /// A `git-ns` response whose payload does not match the schema this client
    /// was built against — a contract mismatch between client and VTC, which
    /// is neither a refusal nor a transport failure (R6.4).
    Unreadable {
        task: String,
        detail: String,
    },
}

/// Whether an inbound document type may be a `git-ns` reply.
#[must_use]
pub fn is_reply_type(typ: &str) -> bool {
    typ.starts_with(TYPE_PREFIX) || crate::messaging::is_trust_task_error_type(typ)
}

/// Classify a reply document, keyed by the thread it answers.
///
/// `None` when the document is neither a `git-ns` response nor a
/// `trust-task-error`, or carries no `threadId`. The thread is a dispatch key,
/// not a check: the caller correlates it against the request it has
/// outstanding and drops anything else.
#[must_use]
pub fn parse_reply(doc: &TrustTask<Value>) -> Option<(String, Reply)> {
    use trust_tasks_rs::Payload as _;
    let thid = doc.thread_id.clone()?;
    if doc.type_uri.slug() == "trust-task-error" {
        return Some((
            thid,
            Reply::Refused(Refusal::from_error_payload(&doc.payload)),
        ));
    }
    if !doc.type_uri.is_response() {
        return None;
    }
    let uri = doc.type_uri.to_string();
    fn read<T: serde::de::DeserializeOwned>(
        payload: &Value,
        wrap: impl FnOnce(Box<T>) -> Reply,
        task: &str,
    ) -> Reply {
        match serde_json::from_value::<T>(payload.clone()) {
            Ok(r) => wrap(Box::new(r)),
            Err(e) => Reply::Unreadable {
                task: task.to_string(),
                detail: e.to_string(),
            },
        }
    }
    let p = &doc.payload;
    let reply = match uri.as_str() {
        u if u == view::Response::TYPE_URI => read(p, Reply::View, "git-ns/view"),
        u if u == create::Response::TYPE_URI => read(p, Reply::Created, "git-ns/repo/create"),
        u if u == grant::Response::TYPE_URI => read(p, Reply::Granted, "git-ns/right/grant"),
        u if u == revoke::Response::TYPE_URI => read(p, Reply::Revoked, "git-ns/right/revoke"),
        u if u == transfer::Response::TYPE_URI => {
            read(p, Reply::Transferred, "git-ns/repo/transfer")
        }
        u if u == archive::Response::TYPE_URI => read(p, Reply::Archived, "git-ns/repo/archive"),
        u if u == link::Response::TYPE_URI => read(p, Reply::LinkStarted, "git-ns/account/link"),
        u if u == link_status::Response::TYPE_URI => {
            read(p, Reply::LinkStatus, "git-ns/account/link-status")
        }
        _ => return None,
    };
    Some((thid, reply))
}

/// A `trust-task-error` from the VTC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The wire code: a framework code (`permissionDenied`) or a declared one
    /// (`git-ns:policyDenied`, `git-ns/right/grant:expiryInPast`).
    pub code: String,
    /// The VTC's own sentence, when it gave one.
    pub message: Option<String>,
}

impl Refusal {
    fn from_error_payload(payload: &Value) -> Self {
        Refusal {
            code: payload
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            message: payload
                .get("message")
                .and_then(Value::as_str)
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty()),
        }
    }

    /// Whether the right the member asked to remove is already gone. The
    /// revoke specification says a client that only needs the right gone
    /// **MAY** treat `notGranted` as success.
    #[must_use]
    pub fn is_already_gone(&self) -> bool {
        self.code == revoke::error_codes::NOT_GRANTED.code
    }

    /// Whether the community's own policy refused — the one refusal that is a
    /// community decision rather than a rule, and the one the add-person form
    /// shows in place, not as a passing status.
    #[must_use]
    pub fn is_policy_denied(&self) -> bool {
        self.code == grant::error_codes::POLICY_DENIED.code
    }

    /// What happened and what to do about it, for an operator.
    ///
    /// Each declared code gets the fix it implies; the VTC's own sentence is
    /// kept where it carries detail the code does not (which policy rule,
    /// which right). Framework codes are split the way R6.4 asks: an
    /// authorisation refusal, a proof problem and a contract mismatch each
    /// read differently.
    #[must_use]
    pub fn explain(&self) -> String {
        let detail = self
            .message
            .as_deref()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        let code = self.code.as_str();
        match code {
            c if c == grant::error_codes::UNKNOWN_NAMESPACE.code => {
                "No namespace bound to this community covers that. Refresh (r) — an \
                 administrator may have unbound it."
                    .to_string()
            }
            c if c == grant::error_codes::NAMESPACE_NOT_BOUND.code => {
                "That namespace is still being bound. Nothing can be created or granted in it \
                 until an administrator finishes binding it."
                    .to_string()
            }
            c if c == grant::error_codes::UNKNOWN_REPO.code => {
                "The community does not record that repository. Refresh (r) — it may have been \
                 renamed on the forge."
                    .to_string()
            }
            c if c == grant::error_codes::REPO_NOT_ACTIVE.code => {
                "The repository is not active (still being created, archived or detached). \
                 Refresh (r) to see its state; a repository still being created takes changes \
                 once it is."
                    .to_string()
            }
            c if c == grant::error_codes::SCOPE_VIOLATION.code => {
                "That right does not fit that resource, or reaches outside what you govern: \
                 owner and maintainer apply to one repository; namespace admin and repo creator \
                 to a namespace."
                    .to_string()
            }
            c if c == grant::error_codes::ESCALATION.code => {
                "None of your rights here lets you grant or revoke that right. Ask an owner of \
                 the repository or a namespace admin."
                    .to_string()
            }
            c if c == grant::error_codes::MEMBERS_ONLY.code => {
                "Namespace admin and repo creator go only to current members, and that DID is \
                 not one. Repository rights for outside contributors are the community's policy."
                    .to_string()
            }
            c if c == grant::error_codes::POLICY_DENIED.code => format!(
                "The community's git policy refused this{detail}. It is the community's \
                 decision (git_ns.rego) — for example whether outside contributors may sign \
                 commits, or which visibilities are allowed. Ask a community administrator."
            ),
            c if c == grant::error_codes::EXPIRY_IN_PAST.code => {
                "The expiry is not in the future. Choose a later one, or none.".to_string()
            }
            c if c == revoke::error_codes::LAST_OWNER.code => {
                "That would leave the repository with no owner. Add another owner first (a, \
                 owner), then try again."
                    .to_string()
            }
            c if c == revoke::error_codes::LAST_ADMIN.code => {
                "That would leave the namespace with no admin. Make someone else namespace \
                 admin first."
                    .to_string()
            }
            c if c == revoke::error_codes::NOT_GRANTED.code => {
                "No such right is recorded — it may already be gone, and an implied right \
                 (an owner's commit right) cannot be revoked on its own. Refresh (r)."
                    .to_string()
            }
            c if c == create::error_codes::NAME_TAKEN.code => {
                "The community already records a repository with that name. Choose another."
                    .to_string()
            }
            c if c == transfer::error_codes::NOT_OWNER.code => {
                "You hold no owner record of your own on this repository to hand over. A \
                 namespace admin's ownership is implied — grant owner to them instead (a)."
                    .to_string()
            }
            c if c == transfer::error_codes::SELF_TRANSFER.code => {
                "You already own it. Choose someone else to hand it to.".to_string()
            }
            c if c == link::error_codes::UNSUPPORTED_FORGE.code => {
                "No bridge serves that forge for this community, so there is nothing to link \
                 an account to. An administrator binds a namespace with the community's app \
                 first."
                    .to_string()
            }
            c if c == link_status::error_codes::UNKNOWN_LINK.code => {
                "The community no longer knows that link attempt — it expired or finished. \
                 Start linking again (l)."
                    .to_string()
            }
            "permissionDenied" if self.is_elevated_gate() => format!(
                "This is an elevated action. Until the community can ask a member to step up, \
                 only a community administrator may perform it{detail}. Ask one to do it, or \
                 to grant it through the admin console."
            ),
            "permissionDenied" => format!(
                "The community refused{detail}. You need a right on or above this resource \
                 (git-ns rights are separate from community roles), and to be a current member."
            ),
            "proofRequired" | "proofInvalid" | "identityMismatch" => format!(
                "The community could not verify this persona's signature{detail}. Check the \
                 persona's signing key under My Identity, then try again."
            ),
            "unsupportedType" | "unsupportedVersion" => format!(
                "This community does not serve git namespaces (git-ns 0.1){detail}. Its VTC \
                 may predate them."
            ),
            "malformedRequest" => format!(
                "The community could not read the request{detail}. This client and the VTC \
                 disagree on the git-ns contract — update openvtc, or tell the community's \
                 operator."
            ),
            "unavailable" => {
                format!("The community's bridge did not answer in time{detail}. Try again shortly.")
            }
            _ => format!("The community refused with {code}{detail}."),
        }
    }

    /// The VTC's stand-in for a member step-up: it admits elevated and
    /// destructive changes only from a community administrator
    /// (`[git_ns] elevated_requires_admin`, VTI #1694).
    fn is_elevated_gate(&self) -> bool {
        self.message.as_deref().is_some_and(|m| {
            m.contains("elevated_requires_admin")
                || m.contains("step-up")
                || m.contains("elevated action")
                || m.contains("destructive action")
        })
    }
}

// ****************************************************************************
// Reading a view
// ****************************************************************************

/// Whether `outer` contains `inner` by whole path segment — `github.com/acme`
/// contains `github.com/acme/widgets` and itself, and not
/// `github.com/acme-labs/x`.
#[must_use]
pub fn contains(outer: &str, inner: &str) -> bool {
    inner == outer
        || inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A namespace's resource, `<forge>/<owner>`.
#[must_use]
pub fn namespace_resource(ns: &view::GitNamespace) -> String {
    format!("{}/{}", *ns.forge, *ns.owner)
}

/// Whether nobody but a person can create repositories in this namespace: a
/// manual-mode namespace, or a personal account (design §8).
#[must_use]
pub fn is_manual(ns: &view::GitNamespace) -> bool {
    matches!(ns.mode, view::GitNamespaceMode::Manual)
        || matches!(ns.kind, Some(view::GitNamespaceKind::User))
}

/// A repository resource without its forge, `owner/name`, for display.
#[must_use]
pub fn short_resource(resource: &str) -> &str {
    resource.split_once('/').map_or(resource, |(_, rest)| rest)
}

/// Where a repository is, for its row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoStatus {
    /// Reserved; the bridge (or a person) is still creating it.
    /// `done` of `total` steps.
    Creating {
        done: usize,
        total: usize,
    },
    /// Active and matching the forge.
    Ok,
    /// Active, and the forge differs from the record in `count` ways.
    Drift {
        count: usize,
    },
    /// Active; not yet compared with the forge.
    Checking,
    Archived,
    Detached,
    /// Its last owner left; namespace admins hold it until they name one.
    Orphaned,
    /// On the forge, not governed.
    Unmanaged,
}

impl RepoStatus {
    /// Read a repository record.
    #[must_use]
    pub fn of(repo: &view::RepoSummary) -> Self {
        match repo.state {
            view::RepoSummaryState::PendingCreate => {
                let steps = creation_steps(repo);
                RepoStatus::Creating {
                    done: steps.iter().filter(|(_, done)| *done).count(),
                    total: steps.len(),
                }
            }
            view::RepoSummaryState::Archived => RepoStatus::Archived,
            view::RepoSummaryState::Detached => RepoStatus::Detached,
            view::RepoSummaryState::Orphaned => RepoStatus::Orphaned,
            view::RepoSummaryState::Unmanaged => RepoStatus::Unmanaged,
            _ => match repo.sync.state {
                view::SyncState::Drift => RepoStatus::Drift {
                    count: repo.sync.drift.len(),
                },
                view::SyncState::InSync => RepoStatus::Ok,
                _ => RepoStatus::Checking,
            },
        }
    }

    /// The word on the row.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            RepoStatus::Creating { done, total } => format!("creating {done}/{total}"),
            RepoStatus::Ok => "ok".into(),
            RepoStatus::Drift { count } => format!("drift ({count})"),
            RepoStatus::Checking => "checking".into(),
            RepoStatus::Archived => "archived".into(),
            RepoStatus::Detached => "detached".into(),
            RepoStatus::Orphaned => "orphaned".into(),
            RepoStatus::Unmanaged => "unmanaged".into(),
        }
    }
}

/// The steps of creating a repository (design §5.3), each with whether the
/// record says it is done. The name is reserved by the time the record exists;
/// the forge id arrives when the forge has created it; the four bootstrap
/// flags are what turns commit trust on.
#[must_use]
pub fn creation_steps(repo: &view::RepoSummary) -> Vec<(&'static str, bool)> {
    let b = &repo.bootstrap;
    vec![
        ("Name reserved in the community", true),
        ("Repository created on the forge", repo.forge_id.is_some()),
        ("verify-trust workflow committed", b.workflow),
        ("Platform keyring committed", b.keyring),
        ("TRUST_REGISTRY_DID and VTC_DID set", b.variables),
        (
            "\"Verify commit trust\" required, no bypass",
            b.required_check,
        ),
    ]
}

/// One of the caller's repositories, for the *My repos* list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyRepo {
    pub resource: String,
    /// The strongest right the caller holds on it, explicitly or by
    /// implication.
    pub right: GitRight,
    pub status: RepoStatus,
}

/// The strongest right `me` holds on a repository, explicitly or by
/// implication: a namespace admin owns every repository in the namespace, a
/// namespace-wide `commit.sign` covers each one, and being listed as an owner
/// is ownership.
#[must_use]
pub fn my_right_on(resp: &view::Response, me: &str, repo: &view::RepoSummary) -> Option<GitRight> {
    let resource: &str = &repo.resource;
    let mut best = repo
        .owners
        .iter()
        .any(|o| **o == *me)
        .then_some(GitRight::RepoOwn);
    for r in resp.rights.iter().filter(|r| *r.subject == *me) {
        let Some(right) = GitRight::from_view(&r.right) else {
            continue;
        };
        if !contains(&r.resource, resource) {
            continue;
        }
        let effective = match right {
            GitRight::NsAdmin => GitRight::NsAdmin,
            // `repo.create` on the namespace says nothing about this repo.
            GitRight::RepoCreate => continue,
            other => other,
        };
        best = best.max(Some(effective));
    }
    best
}

/// The repositories `me` holds any right on, strongest first then by name.
#[must_use]
pub fn my_repos(resp: &view::Response, me: &str) -> Vec<MyRepo> {
    let mut out: Vec<MyRepo> = resp
        .repos
        .iter()
        .filter_map(|repo| {
            Some(MyRepo {
                resource: repo.resource.to_string(),
                right: my_right_on(resp, me, repo)?,
                status: RepoStatus::of(repo),
            })
        })
        .collect();
    out.sort_by(|a, b| a.resource.cmp(&b.resource));
    out
}

/// A namespace `me` may create repositories in, and who said so.
#[derive(Clone, Debug)]
pub struct Creatable {
    pub namespace: view::GitNamespace,
    /// `grantedBy` of the right that allows it.
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
}

/// The bound namespaces `me` holds `repo.create` or `ns.admin` on.
#[must_use]
pub fn creatable_namespaces(resp: &view::Response, me: &str) -> Vec<Creatable> {
    resp.namespaces
        .iter()
        .filter(|ns| matches!(ns.state, view::GitNamespaceState::Bound))
        .filter_map(|ns| {
            let res = namespace_resource(ns);
            let right = resp.rights.iter().find(|r| {
                *r.subject == *me
                    && *r.resource == res
                    && matches!(
                        GitRight::from_view(&r.right),
                        Some(GitRight::RepoCreate | GitRight::NsAdmin)
                    )
            })?;
            Some(Creatable {
                namespace: ns.clone(),
                granted_by: right.granted_by.to_string(),
                granted_at: right.granted_at,
            })
        })
        .collect()
}

/// The namespace a repository lives in.
#[must_use]
pub fn namespace_of<'a>(
    resp: &'a view::Response,
    resource: &str,
) -> Option<&'a view::GitNamespace> {
    resp.namespaces
        .iter()
        .find(|ns| contains(&namespace_resource(ns), resource))
}

/// One person's right on a repository, as the repository view lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub did: String,
    pub right: GitRight,
    /// `None` for an owner the view names without a record the caller may
    /// see (owners are visible to every member; their records are not).
    pub granted_by: Option<String>,
    pub granted_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
    /// Whether the record is on the namespace rather than the repository —
    /// a namespace-wide committer, shown but not revocable from here.
    pub namespace_wide: bool,
}

/// Everyone the caller may see holding a right on `resource`: its owners, and
/// every record on it or on its namespace. Strongest right first.
#[must_use]
pub fn people_on(resp: &view::Response, resource: &str) -> Vec<Person> {
    let mut people: Vec<Person> = resp
        .rights
        .iter()
        .filter(|r| contains(&r.resource, resource))
        .filter_map(|r| {
            let right = GitRight::from_view(&r.right)?;
            if right == GitRight::RepoCreate {
                return None;
            }
            Some(Person {
                did: r.subject.to_string(),
                right,
                granted_by: Some(r.granted_by.to_string()),
                granted_at: Some(r.granted_at),
                expires_at: r.expires_at,
                reason: r.reason.as_ref().map(|s| s.to_string()),
                namespace_wide: *r.resource != *resource,
            })
        })
        .collect();
    if let Some(repo) = resp.repos.iter().find(|r| *r.resource == *resource) {
        for owner in &repo.owners {
            let listed = people
                .iter()
                .any(|p| p.did == **owner && p.right == GitRight::RepoOwn);
            if !listed {
                people.push(Person {
                    did: owner.to_string(),
                    right: GitRight::RepoOwn,
                    granted_by: None,
                    granted_at: None,
                    expires_at: None,
                    reason: None,
                    namespace_wide: false,
                });
            }
        }
    }
    people.sort_by(|a, b| b.right.cmp(&a.right).then_with(|| a.did.cmp(&b.did)));
    people
}

/// The distinct forges a bridge serves for this community — the ones an
/// account can be linked on.
#[must_use]
pub fn linkable_forges(resp: &view::Response) -> Vec<String> {
    let mut forges: Vec<String> = resp
        .namespaces
        .iter()
        .filter(|ns| matches!(ns.mode, view::GitNamespaceMode::Bridge))
        .map(|ns| ns.forge.to_string())
        .collect();
    forges.sort();
    forges.dedup();
    forges
}

/// Every DID the view names — owners, subjects, granters — for the member
/// picker. The community publishes no member directory to members, so these
/// are the people the caller can already see.
#[must_use]
pub fn known_dids(resp: &view::Response) -> Vec<String> {
    let mut dids: Vec<String> = resp
        .repos
        .iter()
        .flat_map(|r| r.owners.iter().map(|o| o.to_string()))
        .chain(
            resp.rights
                .iter()
                .flat_map(|r| [r.subject.to_string(), r.granted_by.to_string()]),
        )
        .collect();
    dids.sort();
    dids.dedup();
    dids
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::json;

    const BOB: &str = "did:webvh:QmBobScid2:acme-vtc.example:bob";
    const ALICE: &str = "did:webvh:QmAliceScid1:acme-vtc.example:alice";
    const DAN: &str = "did:webvh:QmDanScid4:dan.example";
    const VTC: &str = "did:webvh:QmVtcScid7:acme-vtc.example";

    /// The specification's own "What Bob sees" answer.
    fn bob_view() -> view::Response {
        serde_json::from_value(json!({
            "namespaces": [{
                "id": "ns_01J8Z6Q4M2", "forge": "github.com", "owner": "acme",
                "kind": "organization", "mode": "bridge", "state": "bound"
            }],
            "repos": [
                {
                    "resource": "github.com/acme/widgets", "forgeId": "812736451",
                    "visibility": "public", "state": "active",
                    "owners": [ALICE, "did:webvh:QmCarolScid3:acme-vtc.example:carol"],
                    "bootstrap": {"workflow": true, "keyring": true, "variables": true, "requiredCheck": true},
                    "sync": {"state": "drift", "checkedAt": "2026-09-23T09:58:00Z", "drift": [{
                        "type": "roleAdded", "resource": "github.com/acme/widgets",
                        "account": {"forge": "github.com", "id": "5550123", "login": "eve-dev"},
                        "observed": "write"
                    }]}
                },
                {
                    "resource": "github.com/acme/gadgets", "forgeId": "812736990",
                    "visibility": "public", "state": "active", "owners": [BOB],
                    "bootstrap": {"workflow": true, "keyring": true, "variables": true, "requiredCheck": true},
                    "sync": {"state": "inSync", "checkedAt": "2026-09-23T09:58:00Z", "drift": []}
                },
                {
                    "resource": "github.com/acme/sprockets",
                    "visibility": "private", "state": "pendingCreate", "owners": [BOB],
                    "bootstrap": {"workflow": true, "keyring": false, "variables": false, "requiredCheck": false},
                    "sync": {"state": "pending", "drift": []}
                }
            ],
            "rights": [
                {"subject": BOB, "right": "git.repo.create", "resource": "github.com/acme",
                 "grantedBy": ALICE, "grantedAt": "2026-09-23T10:00:01Z"},
                {"subject": BOB, "right": "git.repo.own", "resource": "github.com/acme/gadgets",
                 "grantedBy": BOB, "grantedAt": "2026-09-23T10:05:00Z"},
                {"subject": DAN, "right": "git.commit.sign", "resource": "github.com/acme/gadgets",
                 "grantedBy": BOB, "grantedAt": "2026-09-23T11:00:01Z",
                 "expiresAt": "2026-12-22T00:00:00Z", "reason": "External contributor for the 1.0 push"}
            ]
        }))
        .unwrap()
    }

    // --- payload construction ---------------------------------------------

    /// A grant is built through the generated type and matches the
    /// specification's own example payload member for member.
    #[test]
    fn a_grant_payload_matches_the_specification() {
        let req = Request::Grant {
            subject: DAN.into(),
            right: GitRight::CommitSign,
            resource: "github.com/acme/gadgets".into(),
            expires_at: Some("2026-12-22T00:00:00Z".parse().unwrap()),
            reason: Some("External contributor for the 1.0 push".into()),
        };
        assert_eq!(
            req.payload().unwrap(),
            json!({
                "subject": DAN,
                "right": "git.commit.sign",
                "resource": "github.com/acme/gadgets",
                "expiresAt": "2026-12-22T00:00:00Z",
                "reason": "External contributor for the 1.0 push"
            })
        );
        assert_eq!(
            req.type_uri(),
            "https://trusttasks.org/spec/git-ns/right/grant/0.1"
        );
        assert!(req.proof_required());
    }

    /// Each request's payload validates against its own task's schema — the
    /// generated round trip is the proof — and names the right task.
    #[test]
    fn every_request_builds_a_payload_its_task_accepts() {
        let cases = [
            (Request::View { resource: None }, "git-ns/view", false),
            (
                Request::View {
                    resource: Some("github.com/acme".into()),
                },
                "git-ns/view",
                false,
            ),
            (
                Request::Create {
                    namespace: "ns_01J8Z6Q4M2".into(),
                    name: "Gadgets".into(),
                    visibility: Visibility::Public,
                    description: Some("  ".into()),
                },
                "git-ns/repo/create",
                true,
            ),
            (
                Request::Revoke {
                    subject: DAN.into(),
                    right: GitRight::CommitSign,
                    resource: "github.com/acme/gadgets".into(),
                    reason: Some("1.0 shipped".into()),
                },
                "git-ns/right/revoke",
                true,
            ),
            (
                Request::Transfer {
                    resource: "github.com/acme/widgets".into(),
                    to: BOB.into(),
                },
                "git-ns/repo/transfer",
                true,
            ),
            (
                Request::Archive {
                    resource: "github.com/acme/widgets".into(),
                },
                "git-ns/repo/archive",
                true,
            ),
            (
                Request::Link {
                    forge: "codeberg.org".into(),
                },
                "git-ns/account/link",
                true,
            ),
            (
                Request::LinkStatus {
                    link_id: "lnk_4Tq9Xw2P".into(),
                },
                "git-ns/account/link-status",
                false,
            ),
        ];
        for (req, slug, proof) in cases {
            let payload = req.payload().unwrap_or_else(|e| panic!("{slug}: {e}"));
            assert!(req.type_uri().contains(slug), "{slug}");
            assert_eq!(req.proof_required(), proof, "{slug}");
            assert!(payload.is_object(), "{slug}");
        }
        // The name is lowercased and a blank description left out.
        let create = Request::Create {
            namespace: "ns_1".into(),
            name: "Gadgets".into(),
            visibility: Visibility::Private,
            description: Some("  ".into()),
        };
        assert_eq!(
            create.payload().unwrap(),
            json!({"namespace": "ns_1", "name": "gadgets", "visibility": "private"})
        );
    }

    /// What the schema refuses fails here, naming the field, before anything
    /// is sent.
    #[test]
    fn a_value_the_schema_refuses_fails_before_sending() {
        let not_a_did = Request::Grant {
            subject: "kai".into(),
            right: GitRight::CommitSign,
            resource: "github.com/acme/widgets".into(),
            expires_at: None,
            reason: None,
        };
        assert!(
            not_a_did
                .payload()
                .unwrap_err()
                .to_string()
                .contains("grant")
        );
        let unqualified = Request::Archive {
            resource: "acme/widgets".into(),
        };
        assert!(unqualified.payload().is_err(), "the forge is never implied");
        let long_reason = Request::Revoke {
            subject: DAN.into(),
            right: GitRight::CommitSign,
            resource: "github.com/acme/widgets".into(),
            reason: Some("x".repeat(1025)),
        };
        assert!(
            long_reason
                .payload()
                .unwrap_err()
                .to_string()
                .contains("reason")
        );
    }

    /// The document is addressed, dated and signed by the issuer's key —
    /// for the reads too, whose proof is only RECOMMENDED.
    #[tokio::test]
    async fn every_document_is_signed_and_addressed() {
        use affinidi_tdk::dids::{DID, KeyType};
        let (me, signer) = DID::generate_did_key(KeyType::Ed25519).unwrap();
        for req in [
            Request::View { resource: None },
            Request::Archive {
                resource: "github.com/acme/widgets".into(),
            },
        ] {
            let doc = build_signed(&req, &me, VTC, &signer).await.unwrap();
            assert_eq!(doc.issuer.as_deref(), Some(me.as_str()));
            assert_eq!(doc.recipient.as_deref(), Some(VTC));
            assert!(doc.issued_at.is_some());
            assert!(doc.id.starts_with("urn:uuid:"));
            let proof = serde_json::to_value(doc.proof.as_ref().unwrap()).unwrap();
            assert!(
                proof["verificationMethod"]
                    .as_str()
                    .unwrap()
                    .starts_with(&me)
            );
            assert_eq!(doc.type_uri.to_string(), req.type_uri());
        }
    }

    #[test]
    fn consent_classes_follow_the_design() {
        let grant = |right| Request::Grant {
            subject: DAN.into(),
            right,
            resource: "github.com/acme/x".into(),
            expires_at: None,
            reason: None,
        };
        assert_eq!(
            grant(GitRight::CommitSign).consent_class(),
            ConsentClass::Normal
        );
        assert_eq!(
            grant(GitRight::RepoMaintain).consent_class(),
            ConsentClass::Normal
        );
        assert_eq!(
            grant(GitRight::RepoOwn).consent_class(),
            ConsentClass::Elevated
        );
        assert_eq!(
            grant(GitRight::RepoCreate).consent_class(),
            ConsentClass::Elevated
        );
        assert_eq!(
            grant(GitRight::NsAdmin).consent_class(),
            ConsentClass::Destructive
        );
        assert_eq!(
            Request::Archive {
                resource: "github.com/acme/x".into()
            }
            .consent_class(),
            ConsentClass::Elevated
        );
        assert!(!ConsentClass::Normal.needs_confirmation());
        assert!(ConsentClass::Elevated.needs_confirmation());
    }

    // --- replies -----------------------------------------------------------

    fn reply_doc(type_uri: &str, payload: Value) -> TrustTask<Value> {
        serde_json::from_value(json!({
            "id": "urn:uuid:ba0c0a3a-f777-47e9-af0c-75522e86cb02",
            "type": type_uri,
            "threadId": "urn:uuid:req-1",
            "issuer": VTC,
            "recipient": BOB,
            "issuedAt": "2026-09-24T08:00:01Z",
            "payload": payload,
        }))
        .unwrap()
    }

    #[test]
    fn a_view_response_is_read_typed() {
        let payload = serde_json::to_value(bob_view()).unwrap();
        let (thid, reply) = parse_reply(&reply_doc(
            "https://trusttasks.org/spec/git-ns/view/0.1#response",
            payload,
        ))
        .unwrap();
        assert_eq!(thid, "urn:uuid:req-1");
        assert!(matches!(reply, Reply::View(v) if v.repos.len() == 3));
    }

    #[test]
    fn a_link_response_carries_the_device_code() {
        let (_, reply) = parse_reply(&reply_doc(
            "https://trusttasks.org/spec/git-ns/account/link/0.1#response",
            json!({"linkId": "lnk_4Tq9Xw2P", "url": "https://github.com/login/device",
                   "userCode": "WDJB-MJHT", "expiresAt": "2026-09-23T10:15:00Z"}),
        ))
        .unwrap();
        let Reply::LinkStarted(r) = reply else {
            panic!("expected a link response");
        };
        assert_eq!(
            r.user_code.as_deref().map(|c| c.as_str()),
            Some("WDJB-MJHT")
        );
    }

    /// A response the schema does not accept is a contract mismatch, not a
    /// refusal and not silence.
    #[test]
    fn a_response_off_contract_is_unreadable_not_dropped() {
        let (_, reply) = parse_reply(&reply_doc(
            "https://trusttasks.org/spec/git-ns/right/grant/0.1#response",
            json!({"right": {"subject": "nobody"}}),
        ))
        .unwrap();
        assert!(matches!(reply, Reply::Unreadable { task, .. } if task == "git-ns/right/grant"));
    }

    #[test]
    fn a_request_or_a_foreign_family_is_not_a_reply() {
        assert!(
            parse_reply(&reply_doc(
                "https://trusttasks.org/spec/git-ns/view/0.1",
                json!({})
            ))
            .is_none()
        );
        assert!(
            parse_reply(&reply_doc(
                "https://trusttasks.org/spec/governance/capability/list/0.1#response",
                json!({})
            ))
            .is_none()
        );
        assert!(is_reply_type(
            "https://trusttasks.org/spec/git-ns/view/0.1#response"
        ));
        assert!(!is_reply_type(
            "https://trusttasks.org/spec/governance/capability/list/0.1"
        ));
    }

    #[test]
    fn an_error_is_a_refusal_with_its_code() {
        let (_, reply) = parse_reply(&reply_doc(
            "https://trusttasks.org/spec/trust-task-error/0.1",
            json!({"code": "git-ns:policyDenied", "message": "external signers are not allowed here"}),
        ))
        .unwrap();
        let Reply::Refused(refusal) = reply else {
            panic!("expected a refusal");
        };
        assert!(refusal.is_policy_denied());
        let text = refusal.explain();
        assert!(
            text.contains("external signers are not allowed here"),
            "{text}"
        );
        assert!(text.contains("community administrator"), "{text}");
    }

    // --- error mapping -----------------------------------------------------

    fn refusal(code: &str, message: Option<&str>) -> Refusal {
        Refusal {
            code: code.into(),
            message: message.map(str::to_string),
        }
    }

    /// Every code the member-side tasks declare has its own explanation, and
    /// each suggests something to do.
    #[test]
    fn every_declared_code_is_explained() {
        let declared = grant::ERROR_CODES
            .iter()
            .chain(revoke::ERROR_CODES)
            .chain(create::ERROR_CODES)
            .chain(transfer::ERROR_CODES)
            .chain(archive::ERROR_CODES)
            .chain(link::ERROR_CODES)
            .chain(link_status::ERROR_CODES);
        for code in declared {
            let text = refusal(code.code, None).explain();
            assert!(
                !text.starts_with("The community refused with"),
                "{} has no explanation",
                code.code
            );
        }
    }

    #[test]
    fn specific_codes_suggest_their_fix() {
        assert!(
            refusal("git-ns:lastOwner", None)
                .explain()
                .contains("Add another owner")
        );
        assert!(
            refusal("git-ns/repo/create:nameTaken", None)
                .explain()
                .contains("Choose another")
        );
        assert!(
            refusal("git-ns/account/link-status:unknownLink", None)
                .explain()
                .contains("again")
        );
        assert!(refusal("git-ns/right/revoke:notGranted", None).is_already_gone());
    }

    /// R6.4: an authorisation refusal, a proof problem, a contract mismatch
    /// and an unavailable bridge each read differently.
    #[test]
    fn framework_codes_are_told_apart() {
        let denied = refusal("permissionDenied", Some("not a member")).explain();
        let proof = refusal("proofInvalid", None).explain();
        let contract = refusal("malformedRequest", Some("unknown field")).explain();
        let unsupported = refusal("unsupportedType", None).explain();
        let unavailable = refusal("unavailable", None).explain();
        let all = [&denied, &proof, &contract, &unsupported, &unavailable];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(proof.contains("signing key"));
        assert!(contract.contains("update openvtc"));
        assert!(unsupported.contains("does not serve git namespaces"));
    }

    /// The VTC's admin-only stand-in for step-up reads as that, not as a
    /// missing right.
    #[test]
    fn the_elevated_gate_says_who_can_do_it() {
        let gate = refusal(
            "permissionDenied",
            Some(
                "repo.transfer is a elevated action, which needs a step-up this community cannot \
                 yet ask a member for; until it can, only a community administrator may perform \
                 it (`[git_ns] elevated_requires_admin`)",
            ),
        );
        let text = gate.explain();
        assert!(text.starts_with("This is an elevated action"), "{text}");
    }

    // --- reading a view ----------------------------------------------------

    #[test]
    fn containment_is_by_whole_segment() {
        assert!(contains("github.com/acme", "github.com/acme/widgets"));
        assert!(contains("github.com/acme", "github.com/acme"));
        assert!(!contains("github.com/acme", "github.com/acme-labs/x"));
        assert!(!contains("github.com/acme", "codeberg.org/acme/widgets"));
    }

    /// Bob owns gadgets and sprockets; on widgets he holds nothing he can
    /// see, so it is not his.
    #[test]
    fn my_repos_are_the_ones_i_hold_a_right_on() {
        let mine = my_repos(&bob_view(), BOB);
        let names: Vec<_> = mine.iter().map(|r| r.resource.as_str()).collect();
        assert_eq!(
            names,
            ["github.com/acme/gadgets", "github.com/acme/sprockets"]
        );
        assert!(mine.iter().all(|r| r.right == GitRight::RepoOwn));
        assert_eq!(mine[0].status, RepoStatus::Ok);
        assert_eq!(mine[1].status, RepoStatus::Creating { done: 2, total: 6 });

        // Dan's namespace-less commit right shows as committer.
        let dans = my_repos(&bob_view(), DAN);
        assert_eq!(dans.len(), 1);
        assert_eq!(dans[0].right, GitRight::CommitSign);
    }

    /// A namespace admin's ownership of every repository is implied.
    #[test]
    fn a_namespace_admin_holds_every_repo() {
        let mut v = bob_view();
        v.rights.push(
            serde_json::from_value(json!({
                "subject": ALICE, "right": "git.ns.admin", "resource": "github.com/acme",
                "grantedBy": ALICE, "grantedAt": "2026-09-23T09:00:00Z"
            }))
            .unwrap(),
        );
        let mine = my_repos(&v, ALICE);
        assert_eq!(mine.len(), 3);
        assert!(mine.iter().all(|r| r.right == GitRight::NsAdmin));
    }

    #[test]
    fn drift_is_a_status_of_its_own() {
        let v = bob_view();
        assert_eq!(RepoStatus::of(&v.repos[0]), RepoStatus::Drift { count: 1 });
        assert_eq!(RepoStatus::Drift { count: 1 }.label(), "drift (1)");
    }

    #[test]
    fn bob_may_create_in_acme_and_says_who_allowed_it() {
        let c = creatable_namespaces(&bob_view(), BOB);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].granted_by, ALICE);
        assert!(!is_manual(&c[0].namespace));
        assert!(creatable_namespaces(&bob_view(), DAN).is_empty());
    }

    /// Owners come first, and an owner the caller has no record for is still
    /// listed — owners are public to members.
    #[test]
    fn people_on_a_repo_include_every_visible_owner() {
        let v = bob_view();
        let gadgets = people_on(&v, "github.com/acme/gadgets");
        assert_eq!(gadgets[0].did, BOB);
        assert_eq!(gadgets[0].right, GitRight::RepoOwn);
        assert_eq!(gadgets[1].did, DAN);
        assert_eq!(
            gadgets[1].reason.as_deref(),
            Some("External contributor for the 1.0 push")
        );

        let widgets = people_on(&v, "github.com/acme/widgets");
        assert_eq!(widgets.len(), 2);
        assert!(widgets.iter().all(|p| p.granted_by.is_none()));
    }

    #[test]
    fn forges_and_known_people_come_from_the_view() {
        let v = bob_view();
        assert_eq!(linkable_forges(&v), ["github.com"]);
        let known = known_dids(&v);
        assert!(known.contains(&DAN.to_string()));
        assert!(known.contains(&ALICE.to_string()));
        assert_eq!(short_resource("github.com/acme/widgets"), "acme/widgets");
    }
}
