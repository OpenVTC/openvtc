//! The Repos panel: a community's git repositories, from the member's side.
//!
//! Opened from Communities with `r`. Every read and change is one signed
//! `git-ns/*` task sent to the community's VTC ([`openvtc_core::git_ns`]),
//! off the loop thread in [`DispatchDomain::GitNs`], exactly as the
//! capabilities view sends its governance documents: the view waits on the
//! request's thread id from before the send is spawned, the VTC's answer
//! arrives later on the inbound channel, and [`apply_replies`] matches it to
//! what is pending. After any change the view is read again — the VTC is the
//! record, so nothing is patched locally.
//!
//! Changes above the `normal` consent class (design §6: owner, transfer,
//! archive), every removal and every drift resolution are armed first and
//! sent only on `y` ([`ArmedChange`]). The VTC may still refuse an elevated change from a
//! member who is not a community administrator — it cannot yet ask a member
//! to step up (VTI #1694, `[git_ns] elevated_requires_admin`) — and the
//! refusal says so ([`openvtc_core::git_ns::Refusal::explain`]).
//!
//! View-only changes go through [`reduce`], which both loops share. An action
//! that reads the config or sends a task is planned by [`plan`], which is
//! pure and returns a [`ReposEffect`]: the ordered [`Step`]s still owed. The
//! runner ([`run`], [`run_steps`]) takes each in turn; a send ([`Outbound`])
//! looks up the persona's signing key, builds the request, claims
//! [`DispatchDomain::GitNs`], and only once claimed arms the view and applies
//! its [`Commit`]. The sweep ([`plan_tick`]) and a refresh after a landed
//! change plan their sends the same way.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use openvtc_core::capabilities::{RequestDocument, correlation_thread};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::git_ns::{self, GitRight, Reply, Request};

use crate::state_handler::actions::ReposAction as Act;
use crate::state_handler::actions::WorkspaceAction;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome};
use crate::state_handler::main_page::repos::{
    AddPersonForm, ArmedChange, CreatedRepo, EXPIRY_CHOICES, LinkFlow, LinkPhase, LinkedAccount,
    NewRepoForm, Pending, Purpose, ReposPhase, ReposScreen, ReposView, Severity, Status,
};
use crate::state_handler::main_page::sanitize_display;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

pub(crate) use crate::state_handler::community_request::CommunityLoop as Loop;
pub(crate) use crate::state_handler::community_request::REPLY_WINDOW;
use crate::state_handler::community_request::{
    Sender, answered_by, capitalise, sender, sign_and_send,
};

const DOMAIN: DispatchDomain = DispatchDomain::GitNs;

/// How long `account/link` waits: the VTC itself waits up to 30 s for its
/// bridge to begin the forge's flow, and the answer then has to travel back.
pub(crate) const LINK_START_WINDOW: Duration = Duration::from_secs(60);

/// The reply window for a request of this purpose.
pub(crate) fn reply_window(purpose: &Purpose) -> Duration {
    match purpose {
        Purpose::LinkStart => LINK_START_WINDOW,
        _ => REPLY_WINDOW,
    }
}

/// A `git-ns` answer as it arrived, threaded on the request it answers
/// ([`openvtc_core::inbound::ThreadedReply`]).
pub(crate) type InboundReply = openvtc_core::inbound::ThreadedReply<Reply>;

/// Longest text kept in a form field. Past every schema limit (a repository
/// name is 100, a DID 2048, a reason 1024), so an over-long paste is refused
/// by the schema with a reason rather than trimmed into something else.
const MAX_INPUT: usize = 2048;

fn view_mut(state: &mut State) -> Option<&mut ReposView> {
    state.main_page.content_panel.repos.view.as_mut()
}

fn clip(value: &str) -> String {
    value.chars().take(MAX_INPUT).collect()
}

// ****************************************************************************
// View-only changes (shared nav reducer)
// ****************************************************************************

/// Apply a view-only action. Returns `false` for the actions that read the
/// config or send a task, which the runtime loop services through
/// [`dispatch`].
pub(crate) fn reduce(state: &mut State, action: &Act) -> bool {
    match action {
        Act::Workspace(w) => return super::repos_workspace::reduce(state, w),
        Act::Open(_)
        | Act::Refresh
        | Act::NewSubmit
        | Act::AddSubmit
        | Act::Confirm
        | Act::LinkStart => return false,
        Act::Back => {
            back(state);
            return true;
        }
        _ => {}
    }
    let Some(view) = view_mut(state) else {
        return true;
    };
    match action {
        Act::Select(i) => {
            let count = match &view.screen {
                ReposScreen::List => view.my_repos().len(),
                ReposScreen::Repo { resource } => view.repo_rows(resource),
                ReposScreen::NewRepo(_) => 0,
            };
            view.selected = (*i).min(count.saturating_sub(1));
        }
        Act::OpenRepo => {
            if let Some(repo) = view.my_repos().get(view.selected) {
                view.screen = ReposScreen::Repo {
                    resource: repo.resource.clone(),
                };
                view.selected = 0;
                view.status = None;
            }
        }
        Act::NewStart => {
            if view.creatable().is_empty() {
                view.note(
                    Severity::Warning,
                    "You hold no right to create repositories here. A namespace admin grants \
                     `repo creator` on a namespace.",
                );
            } else {
                view.screen = ReposScreen::NewRepo(NewRepoForm::default());
                view.status = None;
            }
        }
        Act::NewField(f) => {
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.field = f % NewRepoForm::FIELDS;
            }
        }
        Act::NewInput { field, value } => {
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                match field {
                    1 => form.name = clip(value),
                    3 => form.description = clip(value),
                    _ => {}
                }
                form.error = None;
            }
        }
        Act::NewNamespace(i) => {
            let count = view.creatable().len();
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.namespace = (*i).min(count.saturating_sub(1));
            }
        }
        Act::NewVisibility => {
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.visibility = match form.visibility {
                    git_ns::Visibility::Public => git_ns::Visibility::Private,
                    git_ns::Visibility::Private => git_ns::Visibility::Public,
                };
            }
        }
        Act::NewOwnerQuery(value) => {
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.owner_query = clip(value);
                form.owner_pick = 0;
                form.error = None;
            }
        }
        Act::NewOwnerToggleExternal => {
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.owner_external = !form.owner_external;
                form.owner_query.clear();
                form.owner_pick = 0;
                form.error = None;
            }
        }
        Act::NewOwnerPick(i) => {
            let query = if let ReposScreen::NewRepo(form) = &view.screen {
                form.owner_query.clone()
            } else {
                String::new()
            };
            let count = view.candidates(&query).len();
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.owner_pick = (*i).min(count.saturating_sub(1));
            }
        }
        Act::NewOwnerAdd => new_owner_add(view),
        // Sent only when the owner query is already empty (repos_key
        // decides): a chip-input backspace, dropping the last owner added.
        Act::NewOwnerRemoveLast => {
            if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.owners.pop();
                form.error = None;
            }
        }
        Act::AddStart => {
            if let ReposScreen::Repo { resource } = &view.screen {
                if view.governs(resource) {
                    view.add = Some(AddPersonForm::new(resource.clone()));
                    view.status = None;
                } else {
                    view.note(
                        Severity::Warning,
                        "Only an owner of this repository or a namespace admin can add people.",
                    );
                }
            }
        }
        Act::AddField(f) => {
            if let Some(form) = view.add.as_mut() {
                form.field = f % AddPersonForm::FIELDS;
            }
        }
        Act::AddInput { field, value } => {
            if let Some(form) = view.add.as_mut() {
                match field {
                    0 => {
                        form.query = clip(value);
                        form.pick = 0;
                    }
                    3 => form.reason = clip(value),
                    _ => {}
                }
                form.error = None;
            }
        }
        Act::AddToggleExternal => {
            if let Some(form) = view.add.as_mut() {
                form.external = !form.external;
                form.query.clear();
                form.pick = 0;
                form.error = None;
            }
        }
        Act::AddPick(i) => {
            let query = view
                .add
                .as_ref()
                .map(|f| f.query.clone())
                .unwrap_or_default();
            let count = view.candidates(&query).len();
            if let Some(form) = view.add.as_mut() {
                form.pick = (*i).min(count.saturating_sub(1));
            }
        }
        Act::AddRight(i) => {
            if let Some(form) = view.add.as_mut() {
                form.right = (*i).min(GitRight::REPO_RIGHTS.len() - 1);
            }
        }
        Act::AddExpiry(i) => {
            if let Some(form) = view.add.as_mut() {
                form.expiry = (*i).min(EXPIRY_CHOICES.len() - 1);
            }
        }
        Act::RevokeArm => arm_revoke(view),
        Act::TransferArm => arm_transfer(view),
        Act::ArchiveArm => arm_archive(view),
        Act::DriftRevertArm => arm_drift(view, git_ns::DriftAction::Revert),
        Act::DriftAdoptArm => arm_drift(view, git_ns::DriftAction::Adopt),
        Act::Cancel => view.confirm = None,
        Act::LinkDismiss => view.link = None,
        Act::Back
        | Act::Workspace(_)
        | Act::Open(_)
        | Act::Refresh
        | Act::NewSubmit
        | Act::AddSubmit
        | Act::Confirm
        | Act::LinkStart => {}
    }
    true
}

/// Close the innermost thing open: a confirmation, a form, a repository, then
/// the panel.
fn back(state: &mut State) {
    let repos = &mut state.main_page.content_panel.repos;
    let Some(view) = repos.view.as_mut() else {
        return;
    };
    if view.confirm.take().is_some()
        || view.add.take().is_some()
        || view.workspace.confirm.take().is_some()
        || view.workspace.form.take().is_some()
    {
        return;
    }
    match view.screen {
        ReposScreen::List => repos.view = None,
        ReposScreen::Repo { .. } | ReposScreen::NewRepo(_) => {
            view.screen = ReposScreen::List;
            view.selected = 0;
        }
    }
}

/// The person highlighted on the open repository.
fn highlighted(view: &ReposView) -> Option<(String, git_ns::Person)> {
    let ReposScreen::Repo { resource } = &view.screen else {
        return None;
    };
    let person = view.people(resource).get(view.selected)?.clone();
    Some((resource.clone(), person))
}

fn arm_revoke(view: &mut ReposView) {
    let Some((resource, person)) = highlighted(view) else {
        return;
    };
    if person.namespace_wide {
        view.note(
            Severity::Warning,
            "That right is held on the whole namespace; a namespace admin revokes it there.",
        );
        return;
    }
    if person.granted_by.is_none() {
        view.note(
            Severity::Warning,
            "You cannot see that owner's record, so only an owner of this repository or a \
             namespace admin can revoke it.",
        );
        return;
    }
    if person.did != view.me && !view.governs(&resource) {
        view.note(
            Severity::Warning,
            "Only an owner or a namespace admin can revoke someone else's right.",
        );
        return;
    }
    let request = Request::Revoke {
        subject: person.did.clone(),
        right: person.right,
        resource: resource.clone(),
        reason: None,
    };
    let who = if person.did == view.me {
        "your own".to_string()
    } else {
        format!("{}'s", view.name_of(&person.did))
    };
    view.confirm = Some(ArmedChange {
        summary: format!(
            "Revoke {who} {} right on {}? It is withdrawn from the Trust Registry.",
            person.right.label(),
            git_ns::short_resource(&resource)
        ),
        request,
    });
}

fn arm_transfer(view: &mut ReposView) {
    let Some((resource, person)) = highlighted(view) else {
        return;
    };
    if person.did == view.me {
        view.note(
            Severity::Warning,
            "Highlight the person to hand ownership to, then press t.",
        );
        return;
    }
    view.confirm = Some(ArmedChange {
        summary: format!(
            "Hand your ownership of {} to {}? You keep any other right you hold there.",
            git_ns::short_resource(&resource),
            view.name_of(&person.did)
        ),
        request: Request::Transfer {
            resource,
            to: person.did,
        },
    });
}

fn arm_archive(view: &mut ReposView) {
    let ReposScreen::Repo { resource } = &view.screen else {
        return;
    };
    if !view.governs(resource) {
        view.note(
            Severity::Warning,
            "Only an owner of this repository or a namespace admin can archive it.",
        );
        return;
    }
    view.confirm = Some(ArmedChange {
        summary: format!(
            "Archive {}? It is archived on the forge and every commit right on it is revoked. \
             There is no unarchive.",
            git_ns::short_resource(resource)
        ),
        request: Request::Archive {
            resource: resource.clone(),
        },
    });
}

/// Arm resolving the highlighted drift item — `git-ns/drift/resolve`, which
/// is an owner's decision: `git.repo.own` there, explicit or implied by
/// namespace admin. Always armed: either way it changes the forge or the
/// record, and the VTC gates it as the grant or revocation it amounts to.
fn arm_drift(view: &mut ReposView, action: git_ns::DriftAction) {
    let Some((resource, item)) = view.highlighted_drift() else {
        view.note(
            Severity::Warning,
            "Highlight a drift item (↓ past the people), then press v to revert it.",
        );
        return;
    };
    if !view.governs(&resource) {
        view.note(
            Severity::Warning,
            "Resolving drift is an owner's decision: only an owner of this repository or a \
             namespace admin can revert or adopt it.",
        );
        return;
    }
    let Some(ns) = view.namespace_of(&resource).cloned() else {
        view.note(
            Severity::Warning,
            "The community's view names no namespace for this repository — r to refresh.",
        );
        return;
    };
    let short = git_ns::short_resource(&resource).to_string();
    let (weighs_as, summary) = match action {
        git_ns::DriftAction::Revert => {
            if !git_ns::has_bridge(&ns) {
                view.note(
                    Severity::Warning,
                    "This namespace is governed in manual mode: no bridge can undo a forge-side \
                     change, so it is fixed on the forge by hand.",
                );
                return;
            }
            (
                git_ns::revert_weighs_as(&ns, &item),
                format!(
                    "Revert {} on {short}? {} to match the community's rights; no right \
                     changes.",
                    item.describe(),
                    capitalise(item.revert_effect())
                ),
            )
        }
        git_ns::DriftAction::Adopt => {
            let Some(right) = git_ns::adoptable_right(&ns, &item) else {
                view.note(
                    Severity::Warning,
                    if item.kind == "roleAdded" || item.kind == "roleChanged" {
                        "No git right corresponds to that forge role, so there is nothing to \
                         adopt. Revert it (v) instead."
                    } else {
                        "Only a role added or raised on the forge can be adopted. Revert this \
                         one (v) instead."
                    },
                );
                return;
            };
            // An adoption must name the member who receives the right
            // (git-ns/drift/resolve 0.3, `subject`), and git-ns/view tells a
            // member only their own account links — so this panel cannot
            // show, or name, who that is. Nothing is sent: a 0.1 adopt, which
            // names nobody, would grant to whoever holds the link when it
            // runs, and the community refuses it.
            view.note(
                Severity::Warning,
                format!(
                    "Adopting {} would grant {} to the member who linked that forge account, and \
                     the community shows you only your own links — so this panel cannot tell you \
                     who that is. Adopt it from the admin console, or with `cnm git drift \
                     resolve … adopt --subject <their DID>`, where the member is shown and named. \
                     Revert (v) works here.",
                    item.describe(),
                    right.label()
                ),
            );
            let _ = short;
            return;
        }
    };
    let request = Request::DriftResolve {
        resource,
        action,
        item,
        reason: None,
        weighs_as,
    };
    // Said in the confirmation, because the VTC may refuse an elevated change
    // from a member who is not a community administrator.
    let class = request.consent_class();
    let summary = if class.needs_confirmation() {
        format!(
            "{summary} This is an {} change: it weighs as {} {}, which only a community \
             administrator may do until the community can ask a member to step up.",
            class.label(),
            match action {
                git_ns::DriftAction::Adopt => "granting",
                git_ns::DriftAction::Revert => "revoking",
            },
            weighs_as.label()
        )
    } else {
        summary
    };
    view.confirm = Some(ArmedChange { summary, request });
}

// ****************************************************************************
// Loop-side actions: the send job
// ****************************************************************************

/// One `git-ns/*` send, off the loop.
pub(crate) struct ReposJob {
    sender: Sender,
    vtc_did: String,
    persona: PersonaId,
    /// Built on the loop, unsigned: its id is the thread the view was armed
    /// with before this job was spawned, and signing does not change it.
    doc: RequestDocument,
    purpose: Purpose,
}

impl background_dispatch::Job for ReposJob {
    fn domain(&self) -> DispatchDomain {
        DOMAIN
    }

    async fn execute(self) -> DispatchOutcome {
        DispatchOutcome::Repos(self.run().await)
    }
}

impl ReposJob {
    /// Sign and send. I/O only.
    pub(crate) async fn run(mut self) -> ReposOutcome {
        let thid = correlation_thread(&self.doc).to_string();
        let result = sign_and_send(&self.sender, &self.vtc_did, &mut self.doc).await;
        ReposOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            thid,
            purpose: self.purpose,
            result,
        }
    }
}

/// Arm the view to await the answer threaded on `thid`.
///
/// Called on the loop before the send is spawned, never from its outcome: the
/// answer travels the inbound channel, not the dispatch one, and a VTC that
/// refuses at once can have it dispatched first — to find nothing pending, be
/// dropped, and leave the view to time out on a request that was answered.
fn arm(view: &mut ReposView, thid: String, purpose: Purpose, now: Instant) {
    if purpose == Purpose::LinkPoll {
        if let Some(link) = view.link.as_mut() {
            link.last_poll = Some(now);
            link.poll = Some(Pending {
                thid,
                sent_at: now,
                purpose,
            });
        }
        return;
    }
    if let Purpose::Change(what) = &purpose {
        view.note(
            Severity::Progress,
            format!("{what}… awaiting the community's reply"),
        );
    }
    view.pending = Some(Pending {
        thid,
        sent_at: now,
        purpose,
    });
}

/// What a send did. Data only; applied on the loop thread.
pub(crate) struct ReposOutcome {
    vtc_did: String,
    persona: PersonaId,
    /// The thread the view was armed with for this request.
    thid: String,
    purpose: Purpose,
    /// Why the send failed, if it did.
    result: Result<(), String>,
}

impl ReposOutcome {
    /// Say the send never left. A send that did needs nothing: the view was
    /// armed before it was spawned, and its answer may already be applied.
    ///
    /// A failure is applied only while the view still waits on *this*
    /// request's thread — not after the view closed or moved to another
    /// community, nor once a newer request has taken the slot, whose wait a
    /// stale failure must not end.
    pub(crate) fn apply(self, state: &mut State) {
        let Err(e) = self.result else {
            return;
        };
        let Some(view) = view_mut(state) else {
            return;
        };
        let slot = if self.purpose == Purpose::LinkPoll {
            view.link.as_ref().and_then(|l| l.poll.as_ref())
        } else {
            view.pending.as_ref()
        };
        if view.vtc_did != self.vtc_did
            || view.persona != self.persona
            || slot.is_none_or(|p| p.thid != self.thid)
        {
            tracing::debug!(
                thid = %self.thid,
                "git-ns send failed for a request the view no longer waits on: {e}"
            );
            return;
        }
        if self.purpose == Purpose::LinkPoll {
            // A poll that did not leave is retried once its backed-off
            // interval passes.
            tracing::debug!("git-ns link poll failed to send: {e}");
            return link_poll_failed(
                state,
                Instant::now(),
                format!("couldn't check the link with the community: {e}"),
            );
        }
        view.pending = None;
        match self.purpose {
            Purpose::View => {
                if view.data.is_none() {
                    view.phase = ReposPhase::Failed(format!(
                        "could not send the query to the community: {e}"
                    ));
                } else {
                    view.note(Severity::Error, format!("couldn't refresh: {e}"));
                }
            }
            Purpose::Change(what) => {
                view.note(Severity::Error, format!("couldn't send ({what}): {e}"));
                tracing::error!("git-ns change failed to send: {e}");
            }
            Purpose::LinkStart => {
                if let Some(link) = view.link.as_mut() {
                    link.phase = LinkPhase::Failed(format!("couldn't send: {e}"));
                }
            }
            Purpose::LinkPoll => {}
        }
    }
}

// ****************************************************************************
// Loop-side actions: the reducer
// ****************************************************************************

/// What a loop-side action needs beyond the state change [`plan`] already made.
pub(crate) enum ReposEffect {
    /// A local workspace action ([`super::repos_workspace::dispatch`]).
    Workspace(WorkspaceAction),
    /// Fill the workspace of the view just opened
    /// ([`super::repos_workspace::open`]), then run the steps.
    Opened(Vec<Step>),
    /// Run the steps, in order.
    Steps(Vec<Step>),
}

/// One thing the runner does, in the order [`plan`] lists them.
pub(crate) enum Step {
    /// Start a workspace probe, if one is due.
    Probe,
    /// A read is starting: an empty view shows it loading, and the status
    /// line is cleared.
    Reading,
    /// Say something on the status line: a request refused before it was
    /// built, because another still awaits its answer.
    Note(Severity, String),
    /// Look up the persona's signing key, build the request, claim the lane,
    /// and arm the view once claimed ([`Outbound`]).
    Send(Box<Outbound>),
    /// Start reading the did-git-sign install, if that is due
    /// ([`super::settings_actions::maybe_refresh_did_git_sign`]).
    CheckDidGitSign,
}

/// A `git-ns/*` request for the open view, decided on the loop and not yet
/// built: its document names the persona's DID, which the key lookup resolves.
pub(crate) struct Outbound {
    /// The community it goes to.
    pub(crate) vtc_did: String,
    /// The persona it is sent as.
    pub(crate) persona: PersonaId,
    pub(crate) request: Request,
    pub(crate) purpose: Purpose,
    /// Suppress the busy message, for sends nobody pressed a key for (polls,
    /// a refresh after a change). A failed key lookup or build is said anyway.
    pub(crate) quiet: bool,
    /// The view change owed once the send is claimed and armed.
    pub(crate) commit: Option<Commit>,
}

/// A view change made only once a send has claimed the lane.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Commit {
    /// Show a link attempt to this forge as starting.
    LinkStarting(String),
}

/// Plan a loop-side action. Pure: it reads `config`, makes only the changes
/// the action makes before anything is sent (opening the view, wanting a
/// probe, spending a confirmation, marking a form, arming a confirmation,
/// saying there is no forge to link), and returns what the loop still owes.
pub(crate) fn plan(state: &mut State, config: &Config, action: Act) -> ReposEffect {
    match action {
        Act::Workspace(w) => ReposEffect::Workspace(w),
        Act::Open(index) => {
            open_view(state, config, index);
            let mut steps = vec![Step::Reading];
            steps.extend(plan_read(state, false));
            ReposEffect::Opened(steps)
        }
        Act::Refresh => {
            if let Some(view) = view_mut(state) {
                view.workspace.want_probe(true);
            }
            let mut steps = vec![Step::Probe, Step::Reading];
            steps.extend(plan_read(state, false));
            ReposEffect::Steps(steps)
        }
        Act::NewSubmit => ReposEffect::Steps(plan_new(state).into_iter().collect()),
        Act::AddSubmit => ReposEffect::Steps(plan_add(state).into_iter().collect()),
        Act::Confirm => {
            let armed = view_mut(state).and_then(|v| v.confirm.take());
            let step = armed.and_then(|armed| {
                let what = describe(&armed.request);
                plan_send(state, armed.request, Purpose::Change(what), false, None)
            });
            ReposEffect::Steps(step.into_iter().collect())
        }
        Act::LinkStart => ReposEffect::Steps(plan_link_start(state).into_iter().collect()),
        // View-only: the shared reducer handled these before the loop saw them.
        _ => ReposEffect::Steps(Vec::new()),
    }
}

/// Plan sending `request` for the open view: nothing with no view open; a
/// "still waiting" note (none when `quiet`) while another request awaits its
/// answer; else the send.
///
/// One request awaits its answer at a time. A second would take the pending
/// slot, and the first answer — a grant, say — would then match nothing and
/// be dropped unannounced. Polls have their own slot.
fn plan_send(
    state: &mut State,
    request: Request,
    purpose: Purpose,
    quiet: bool,
    commit: Option<Commit>,
) -> Option<Step> {
    let view = view_mut(state)?;
    if purpose != Purpose::LinkPoll
        && let Some(waiting) = &view.pending
    {
        return (!quiet).then(|| {
            Step::Note(
                Severity::Warning,
                match &waiting.purpose {
                    Purpose::Change(what) => {
                        format!("Still waiting for the community's answer ({what}).")
                    }
                    _ => "Still waiting for the community's answer.".into(),
                },
            )
        });
    }
    Some(Step::Send(Box::new(Outbound {
        vtc_did: view.vtc_did.clone(),
        persona: view.persona,
        request,
        purpose,
        quiet,
        commit,
    })))
}

/// Plan reading the view again.
fn plan_read(state: &mut State, quiet: bool) -> Option<Step> {
    plan_send(
        state,
        Request::View { resource: None },
        Purpose::View,
        quiet,
        None,
    )
}

/// Open the panel for the Active community at a Communities display index.
/// An index that names no Active community leaves the panel as it is.
fn open_view(state: &mut State, config: &Config, index: usize) {
    let target = config
        .account
        .communities_for_display(state.main_page.content_panel.communities.show_archived)
        .get(index)
        .filter(|c| c.status.is_active())
        .map(|c| {
            (
                c.vtc_did.clone(),
                c.persona_ref,
                crate::state_handler::community_label(
                    config,
                    &c.vtc_did,
                    c.display_name.as_deref(),
                    256,
                ),
            )
        });
    let Some((vtc, persona, name)) = target else {
        return;
    };
    let me = config
        .identities
        .get(&persona)
        .map(|id| id.persona_did().to_string())
        .unwrap_or_default();
    state.main_page.content_panel.repos.view = Some(ReposView::new(vtc, persona, me, name));
}

/// What a change is, for the status line while it is in flight.
fn describe(request: &Request) -> String {
    match request {
        Request::Create { name, .. } => format!("creating {name}"),
        Request::Grant {
            right, resource, ..
        } => format!(
            "granting {} on {}",
            right.label(),
            git_ns::short_resource(resource)
        ),
        Request::Revoke {
            right, resource, ..
        } => format!(
            "revoking {} on {}",
            right.label(),
            git_ns::short_resource(resource)
        ),
        Request::Transfer { resource, .. } => {
            format!("transferring {}", git_ns::short_resource(resource))
        }
        Request::Archive { resource } => {
            format!("archiving {}", git_ns::short_resource(resource))
        }
        Request::DriftResolve {
            resource, action, ..
        } => format!(
            "{} drift on {}",
            match action {
                git_ns::DriftAction::Adopt => "adopting",
                git_ns::DriftAction::Revert => "reverting",
            },
            git_ns::short_resource(resource)
        ),
        Request::View { .. } => "reading".into(),
        Request::Link { forge } => format!("linking {forge}"),
        Request::LinkStatus { .. } => "checking the link".into(),
    }
}

fn plan_new(state: &mut State) -> Option<Step> {
    let view = view_mut(state)?;
    let ReposScreen::NewRepo(form) = &view.screen else {
        return None;
    };
    let creatable = view.creatable();
    let ns = creatable.get(form.namespace)?;
    let owners = if form.owners.is_empty() {
        None
    } else {
        Some(form.owners.clone())
    };
    let request = Request::Create {
        namespace: ns.namespace.id.to_string(),
        name: form.name.clone(),
        visibility: form.visibility,
        description: Some(form.description.clone()),
        owners: owners.clone(),
    };
    // The schema is checked here, so a bad name is refused in the form, by
    // name, before anything is sent.
    if let Err(e) = request.payload() {
        if let ReposScreen::NewRepo(form) = &mut view.screen {
            form.error = Some(Status::error(e.to_string()));
        }
        return None;
    }
    let class = request.consent_class();
    if class.needs_confirmation() {
        let owner_names = owners
            .unwrap_or_default()
            .iter()
            .map(|d| view.name_of(d))
            .collect::<Vec<_>>()
            .join(", ");
        view.confirm = Some(ArmedChange {
            summary: format!(
                "Create {} owned by {owner_names}? This is an {} change: it grants git.repo.own.",
                form.name,
                class.label()
            ),
            request,
        });
        return None;
    }
    let what = describe(&request);
    plan_send(state, request, Purpose::Change(what), false, None)
}

/// Add the owner picker's highlighted candidate, or its pasted DID, to the
/// new-repository form's `owners`.
fn new_owner_add(view: &mut ReposView) {
    let ReposScreen::NewRepo(form) = &view.screen else {
        return;
    };
    let did = if form.owner_external {
        let d = form.owner_query.trim().to_string();
        if d.is_empty() {
            return;
        }
        d
    } else {
        let Some(d) = view
            .candidates(&form.owner_query)
            .get(form.owner_pick)
            .cloned()
        else {
            return;
        };
        d
    };
    let ReposScreen::NewRepo(form) = &mut view.screen else {
        return;
    };
    if !form.owners.contains(&did) {
        form.owners.push(did);
    }
    form.owner_query.clear();
    form.owner_pick = 0;
    form.error = None;
}

fn plan_add(state: &mut State) -> Option<Step> {
    let view = view_mut(state)?;
    let form = view.add.clone()?;
    let subject = if form.external {
        form.query.trim().to_string()
    } else {
        match view.candidates(&form.query).get(form.pick) {
            Some(did) => did.clone(),
            // Nobody known matches: a typed DID is taken as pasted.
            None if form.query.trim().starts_with("did:") => form.query.trim().to_string(),
            None => {
                if let Some(f) = view.add.as_mut() {
                    f.error = Some(Status::warning(
                        "Pick someone, or press Ctrl+D to paste a DID for someone not listed.",
                    ));
                }
                return None;
            }
        }
    };
    let right = form.right();
    let request = Request::Grant {
        subject: subject.clone(),
        right,
        resource: form.resource.clone(),
        expires_at: form.expires_at(Utc::now()),
        reason: Some(form.reason.clone()),
    };
    if let Err(e) = request.payload() {
        if let Some(f) = view.add.as_mut() {
            f.error = Some(Status::error(e.to_string()));
        }
        return None;
    }
    let class = request.consent_class();
    if class.needs_confirmation() {
        view.confirm = Some(ArmedChange {
            summary: format!(
                "Grant {} {} on {}? This is an {} change: {}.",
                view.name_of(&subject),
                right.label(),
                git_ns::short_resource(&form.resource),
                class.label(),
                right.meaning()
            ),
            request,
        });
        return None;
    }
    let what = describe(&request);
    plan_send(state, request, Purpose::Change(what), false, None)
}

fn plan_link_start(state: &mut State) -> Option<Step> {
    let view = view_mut(state)?;
    let forges = view
        .data
        .as_deref()
        .map(git_ns::linkable_forges)
        .unwrap_or_default();
    // GitHub first when a bridge serves it: it is the forge the design leads with.
    let Some(forge) = forges
        .iter()
        .find(|f| f.as_str() == git_ns::DEVICE_FLOW_FORGE)
        .or_else(|| forges.first())
        .cloned()
    else {
        view.note(
            Severity::Warning,
            "No bridge serves a forge for this community yet, so there is no account to link.",
        );
        return None;
    };
    // The attempt is shown only once its request is actually on its way
    // ([`Commit::LinkStarting`]): a send refused here (still waiting, busy, no
    // signing key) says why and leaves no "starting…" line that nothing will
    // ever answer.
    plan_send(
        state,
        Request::Link {
            forge: forge.clone(),
        },
        Purpose::LinkStart,
        false,
        Some(Commit::LinkStarting(forge)),
    )
}

// ****************************************************************************
// Loop-side actions: the effect runner
// ****************************************************************************

/// Service an action that reads the config or sends a task: [`plan`] it,
/// then [`run`] what it asks for.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: Act) {
    let effect = plan(ctx.state, ctx.config, action);
    run(ctx, effect).await;
}

/// Run an action's effect.
pub(crate) async fn run(ctx: &mut ActionCtx<'_>, effect: ReposEffect) {
    let steps = match effect {
        ReposEffect::Workspace(w) => {
            super::repos_workspace::dispatch(ctx, w);
            return;
        }
        ReposEffect::Opened(steps) => {
            let warning = super::repos_workspace::open(ctx).await;
            run_steps(&mut Loop::from_ctx(ctx), steps).await;
            // Said after the steps: their read clears the status line first.
            if let Some(warning) = warning
                && let Some(view) = view_mut(ctx.state)
            {
                view.note(Severity::Warning, warning);
            }
            return;
        }
        ReposEffect::Steps(steps) => steps,
    };
    run_steps(&mut Loop::from_ctx(ctx), steps).await;
}

/// Run steps in order. The loop's own arms (an answer that landed a change,
/// the sweep) run theirs here too.
pub(crate) async fn run_steps(lp: &mut Loop<'_>, steps: Vec<Step>) {
    for step in steps {
        match step {
            Step::Probe => {
                super::repos_workspace::probe_if_due(lp.state, lp.dispatch_tx, lp.in_flight);
            }
            Step::Reading => {
                if let Some(view) = view_mut(lp.state) {
                    if view.data.is_none() {
                        view.phase = ReposPhase::Loading;
                    }
                    view.status = None;
                }
            }
            Step::Note(severity, text) => {
                if let Some(view) = view_mut(lp.state) {
                    view.note(severity, text);
                }
            }
            Step::Send(outbound) => send(lp, *outbound).await,
            Step::CheckDidGitSign => super::settings_actions::maybe_refresh_did_git_sign(
                lp.state,
                lp.in_flight,
                lp.dispatch_tx,
            ),
        }
    }
}

/// Say why a send never left: a first read fails the view, a link poll backs
/// off ([`link_poll_failed`]), anything else is said on the status line.
fn refuse(state: &mut State, purpose: &Purpose, e: String) {
    if *purpose == Purpose::LinkPoll {
        return link_poll_failed(state, Instant::now(), e);
    }
    if let Some(view) = view_mut(state) {
        if view.data.is_none() && *purpose == Purpose::View {
            view.phase = ReposPhase::Failed(e);
        } else {
            view.note(Severity::Error, e);
        }
    }
}

/// A link poll failed at `now` for `why`: the next one backs off, and `why`
/// is said on the status line only when it is not the failure said last, so
/// a poll that keeps failing the same way does not repeat itself every tick.
fn link_poll_failed(state: &mut State, now: Instant, why: String) {
    let Some(view) = view_mut(state) else {
        return;
    };
    let say = view
        .link
        .as_mut()
        .is_some_and(|link| link.poll_failed(now, &why));
    if say {
        view.note(Severity::Error, why);
    }
}

/// Send one planned request: the key lookup, the build, the claim (its busy
/// message only when not `quiet`), then — once claimed — the view armed on
/// the request's thread and the commit applied. A lookup or build that fails
/// says why; a busy lane arms nothing.
async fn send(lp: &mut Loop<'_>, outbound: Outbound) {
    let Outbound {
        vtc_did,
        persona,
        request,
        purpose,
        quiet,
        commit,
    } = outbound;
    let sender = match sender(lp.config, lp.tdk, persona, &vtc_did).await {
        Ok(s) => s,
        Err(e) => return refuse(lp.state, &purpose, e),
    };
    // Built here rather than in the job so its id — the thread the answer
    // carries — is known before the send is spawned, and the view can wait
    // on it at once (see `arm`).
    let doc = match git_ns::build(&request, &sender.persona_did, &vtc_did) {
        Ok(doc) => doc,
        Err(e) => {
            let e = match &purpose {
                Purpose::Change(what) => format!("couldn't send ({what}): {e}"),
                _ => format!("couldn't send: {e}"),
            };
            return refuse(lp.state, &purpose, e);
        }
    };
    let thid = correlation_thread(&doc).to_string();
    let job = ReposJob {
        sender,
        vtc_did,
        persona,
        doc,
        purpose: purpose.clone(),
    };
    let state = &mut *lp.state;
    let started = background_dispatch::dispatch(job, lp.in_flight, lp.dispatch_tx, |msg| {
        if !quiet && let Some(view) = view_mut(state) {
            view.note(Severity::Warning, msg);
        }
    });
    if !started {
        return;
    }
    // Armed in the same loop turn as the spawn, so the answer — applied by
    // this loop — always finds the view waiting on it.
    if let Some(view) = view_mut(lp.state) {
        arm(view, thid, purpose, Instant::now());
        if let Some(Commit::LinkStarting(forge)) = commit {
            view.link = Some(LinkFlow::starting(forge));
        }
    }
}

/// Read the view again, from the loop's own arms (an answer that landed a
/// change).
pub(crate) async fn refresh(lp: &mut Loop<'_>, quiet: bool) {
    let steps = plan_read(lp.state, quiet).into_iter().collect();
    run_steps(lp, steps).await;
}

// ****************************************************************************
// Replies, timeouts and polling (called from the runtime loop)
// ****************************************************************************

/// Apply the community's answers. Returns whether the view should be read
/// again — after every change that landed.
pub(crate) fn apply_replies(
    state: &mut State,
    config: &Config,
    replies: Vec<InboundReply>,
) -> bool {
    let mut refresh = false;
    for inbound in replies {
        // A thread id is a correlation key, not a credential: an answer is
        // taken only from the community the view is asking — sent by it, and
        // issued by it. Anyone who learned a thread id could otherwise answer
        // for the community.
        let Some(vtc) = state
            .main_page
            .content_panel
            .repos
            .view
            .as_ref()
            .map(|v| v.vtc_did.clone())
        else {
            continue;
        };
        if !answered_by(&vtc, &inbound.from, inbound.issuer.as_deref()) {
            tracing::warn!(
                from = %inbound.from,
                issuer = ?inbound.issuer,
                thid = %inbound.thid,
                "git-ns reply not from the community the Repos view is asking — dropped"
            );
            continue;
        }
        refresh |= apply_reply(state, config, &inbound.thid, inbound.reply);
    }
    refresh
}

fn apply_reply(state: &mut State, config: &Config, thid: &str, reply: Reply) -> bool {
    let repos = &mut state.main_page.content_panel.repos;
    let Some(view) = repos.view.as_mut() else {
        return false;
    };
    // A link poll answers on its own thread.
    if view
        .link
        .as_ref()
        .and_then(|l| l.poll.as_ref())
        .is_some_and(|p| p.thid == thid)
    {
        let mut linked = None;
        if let Some(link) = view.link.as_mut() {
            link.poll_answered();
            match reply {
                Reply::LinkStatus(r) => match r.state {
                    git_ns::LinkState::Linked => {
                        let (login, id) = r
                            .account
                            .as_ref()
                            .map(|a| (sanitize_display(&a.login, 100), sanitize_display(&a.id, 64)))
                            .unwrap_or_default();
                        linked = Some(LinkedAccount {
                            vtc_did: view.vtc_did.clone(),
                            forge: link.forge.clone(),
                            login: login.clone(),
                            id: id.clone(),
                        });
                        link.phase = LinkPhase::Linked { login, id };
                    }
                    git_ns::LinkState::Expired => link.phase = LinkPhase::Expired,
                    git_ns::LinkState::Failed => {
                        link.phase = LinkPhase::Failed(
                            "the forge account could not be linked — it may already be linked \
                             to another member. Try again (l), or ask a community administrator."
                                .into(),
                        );
                    }
                    _ => {}
                },
                Reply::Refused(r) => link.phase = LinkPhase::Failed(r.explain()),
                other => {
                    link.phase = LinkPhase::Failed(unexpected(&other));
                }
            }
        }
        if let Some(account) = linked {
            repos
                .linked
                .retain(|a| !(a.vtc_did == account.vtc_did && a.forge == account.forge));
            repos.linked.push(account);
        }
        return false;
    }

    if view.pending.as_ref().is_none_or(|p| p.thid != thid) {
        // Uncorrelated: a reply to a request this view did not make, or one it
        // gave up on. Logged, never silent: an answer dropped here is a view
        // that will report the community as not answering. A refusal is
        // offered here whatever it refuses, so one that is not ours is routine.
        if matches!(reply, Reply::Refused(_)) {
            tracing::debug!(
                %thid,
                pending = ?view.pending.as_ref().map(|p| &p.thid),
                "refusal matches no pending git-ns request — not ours"
            );
        } else {
            tracing::warn!(
                %thid,
                pending = ?view.pending.as_ref().map(|p| &p.thid),
                "git-ns reply matches no pending request — dropped"
            );
        }
        return false;
    }
    let Some(pending) = view.pending.take() else {
        return false;
    };
    match (reply, pending.purpose) {
        (Reply::View(data), _) => {
            view.labels = git_ns::known_dids(&data)
                .into_iter()
                .filter_map(|did| {
                    config
                        .agent_name_for(&did)
                        .map(|n| (did.clone(), n.to_string()))
                })
                .collect();
            view.data = Some(Arc::new(*data));
            // The repositories to look for on this machine may have changed.
            view.workspace.want_probe(false);
            view.phase = ReposPhase::Loaded;
            let count = match &view.screen {
                ReposScreen::List => view.my_repos().len(),
                ReposScreen::Repo { resource } => view.repo_rows(resource),
                ReposScreen::NewRepo(_) => 1,
            };
            view.selected = view.selected.min(count.saturating_sub(1));
            view.clear_progress();
            false
        }
        (Reply::Created(r), _) => {
            let resource = r.repo.resource.to_string();
            let manual_steps: Vec<String> = r
                .manual_steps
                .iter()
                .map(|s| sanitize_display(s, 1024))
                .collect();
            view.note(
                Severity::Success,
                if manual_steps.is_empty() {
                    format!(
                        "Reserved {}. The community's bridge is creating it — the steps below fill \
                     in as it goes (r to refresh).",
                        git_ns::short_resource(&resource)
                    )
                } else {
                    format!(
                        "Reserved {}. No bot can create it here: follow the steps below, and it \
                     becomes active once it is adopted.",
                        git_ns::short_resource(&resource)
                    )
                },
            );
            view.created = Some(CreatedRepo {
                resource: resource.clone(),
                manual_steps,
            });
            // Go to the new repository only from the form that asked for it: a
            // member who has since moved on is not pulled back.
            if matches!(view.screen, ReposScreen::NewRepo(_)) {
                view.screen = ReposScreen::Repo { resource };
                view.selected = 0;
            }
            true
        }
        (Reply::Granted(r), _) => {
            let rec = &r.right;
            view.add = None;
            view.note(
                Severity::Success,
                format!(
                    "Granted {} {} on {}. It is published to the Trust Registry, where anyone can \
                 read it.",
                    view.name_of(&rec.subject),
                    rec.right,
                    git_ns::short_resource(&rec.resource)
                ),
            );
            true
        }
        (Reply::Revoked(r), _) => {
            let rec = &r.revoked;
            view.note(
                Severity::Success,
                format!(
                    "Revoked {}'s {} on {}.",
                    view.name_of(&rec.subject),
                    rec.right,
                    git_ns::short_resource(&rec.resource)
                ),
            );
            true
        }
        (Reply::Transferred(r), _) => {
            view.note(
                Severity::Success,
                format!(
                    "Handed over {}. Owners now: {}.",
                    git_ns::short_resource(&r.repo.resource),
                    r.repo
                        .owners
                        .iter()
                        .map(|o| view.name_of(o))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            true
        }
        (Reply::Archived(r), _) => {
            view.note(
                Severity::Success,
                format!(
                    "Archived {}; {} commit right(s) revoked.",
                    git_ns::short_resource(&r.repo.resource),
                    r.rights_revoked
                ),
            );
            view.screen = ReposScreen::List;
            view.selected = 0;
            true
        }
        (Reply::DriftResolved(r), _) => {
            let left = r.sync.drift.len();
            let then = if left == 0 {
                "The bridge inspects the repository again to confirm it (r to refresh).".to_string()
            } else {
                format!("{left} drift item(s) still outstanding (r to refresh).")
            };
            let text = match &r.right {
                Some(rec) => format!(
                    "Adopted: {} now holds {} on {}, published to the Trust Registry. {then}",
                    view.name_of(&rec.subject),
                    rec.right,
                    git_ns::short_resource(&rec.resource)
                ),
                None => format!("Reverted: the community's bridge is re-applying it. {then}"),
            };
            view.note(Severity::Success, text);
            true
        }
        (Reply::LinkStarted(r), _) => {
            if let Some(link) = view.link.as_mut() {
                if link_url_ok(&r.url, &link.forge) {
                    link.phase = LinkPhase::Waiting;
                    link.link_id = Some(r.link_id.to_string());
                    link.url = Some(r.url.clone());
                    link.user_code = r.user_code.as_ref().map(|c| sanitize_display(c, 64));
                    link.expires_at = Some(r.expires_at);
                } else {
                    link.phase = LinkPhase::Failed(format!(
                        "The community offered a link that is not an https address on {} — not \
                         shown. Tell the community's operator.",
                        link.forge
                    ));
                }
            }
            false
        }
        (Reply::Refused(r), Purpose::Change(_)) if r.is_already_gone() => {
            view.note(Severity::Success, "That right was already gone.");
            true
        }
        (Reply::Refused(r), Purpose::View) => {
            let text = r.explain();
            if view.data.is_none() {
                view.phase = ReposPhase::Failed(text);
            } else {
                view.note(Severity::Error, text);
            }
            false
        }
        (Reply::Refused(r), Purpose::LinkStart) => {
            if let Some(link) = view.link.as_mut() {
                link.phase = LinkPhase::Failed(r.explain());
            }
            false
        }
        (Reply::Refused(r), _) => {
            let text = r.explain();
            // A refusal of what a form asked for is shown in that form, so the
            // member can change it — a policy refusal of an outside signer
            // most of all.
            if let Some(form) = view.add.as_mut() {
                form.error = Some(Status::error(text));
            } else if let ReposScreen::NewRepo(form) = &mut view.screen {
                form.error = Some(Status::error(text));
            } else {
                view.note(Severity::Error, text);
            }
            view.clear_progress();
            false
        }
        (other, _) => {
            view.note(Severity::Error, unexpected(&other));
            false
        }
    }
}

/// Whether a link URL may be shown and turned into a QR code: https, and on
/// the forge the attempt is for. Anything else would send the member, or their
/// phone, wherever the answer said.
pub(crate) fn link_url_ok(url: &str, forge: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some_and(|h| h.eq_ignore_ascii_case(forge))
            && u.username().is_empty()
            && u.password().is_none()
    })
}

fn unexpected(reply: &Reply) -> String {
    match reply {
        Reply::Unreadable { task, detail } => format!(
            "The community answered {task} in a shape this client cannot read ({detail}). \
             Client and VTC disagree on the git-ns contract — update openvtc, or tell the \
             community's operator."
        ),
        _ => "The community answered with something this view did not ask for.".into(),
    }
}

/// Expire what waited too long, and poll a link attempt that is due. Called
/// from the loop's five-second sweep: [`plan_tick`], then [`run_steps`].
pub(crate) async fn tick(lp: &mut Loop<'_>) {
    let steps = plan_tick(lp.state, Instant::now(), Utc::now());
    run_steps(lp, steps).await;
}

/// Plan the sweep at `now` (`wall` for the link's expiry). Pure: it ends the
/// waits past their windows and expires the link attempt, then returns the
/// due poll, the workspace probe and the did-git-sign read, in that order.
pub(crate) fn plan_tick(state: &mut State, now: Instant, wall: DateTime<Utc>) -> Vec<Step> {
    let mut poll = None;
    let mut lost = false;
    if let Some(view) = view_mut(state) {
        if view
            .pending
            .as_ref()
            .is_some_and(|p| now.duration_since(p.sent_at) > reply_window(&p.purpose))
            && let Some(p) = view.pending.take()
        {
            let secs = reply_window(&p.purpose).as_secs();
            match p.purpose {
                Purpose::View if view.data.is_none() => {
                    // Silence is not a refusal. A VTC that does not serve
                    // git namespaces still answers, with a refusal that is
                    // shown in words. So the only thing a timeout can mean is
                    // that the request or its answer was lost (R6.4).
                    view.phase = ReposPhase::Failed(format!(
                        "no reply within {secs}s. A community that does not serve git \
                         namespaces says so, so this is not that: the request or its answer \
                         was lost. Either the community's VTC is offline or unreachable, or it \
                         answered on a route this persona does not collect. Press r to try again."
                    ));
                }
                Purpose::View => {
                    view.note(
                        Severity::Error,
                        format!("no reply to the refresh within {secs}s"),
                    );
                }
                Purpose::Change(what) => {
                    let text = format!(
                        "No reply ({what}) within {secs}s. It may have been applied — refresh (r) \
                         to see before trying again."
                    );
                    // The form stays open with what was asked, marked, so a
                    // second press does not blindly repeat a change that may
                    // already have landed.
                    if let Some(form) = view.add.as_mut() {
                        form.error = Some(Status::warning(text.clone()));
                    } else if let ReposScreen::NewRepo(form) = &mut view.screen {
                        form.error = Some(Status::warning(text.clone()));
                    }
                    view.note(Severity::Error, text);
                }
                Purpose::LinkStart => {
                    if let Some(link) = view.link.as_mut() {
                        link.phase = LinkPhase::Failed(format!(
                            "no reply within {secs}s — the community's bridge may be offline"
                        ));
                    }
                }
                Purpose::LinkPoll => {}
            }
        }
        if let Some(link) = view.link.as_mut() {
            // A lost poll is retried once its backed-off interval passes.
            lost = link
                .poll
                .as_ref()
                .is_some_and(|p| now.duration_since(p.sent_at) > REPLY_WINDOW);
        }
    }
    if lost {
        link_poll_failed(
            state,
            now,
            format!(
                "no answer to the link check within {}s — the community's bridge may be offline",
                REPLY_WINDOW.as_secs()
            ),
        );
    }
    if let Some(link) = view_mut(state).and_then(|v| v.link.as_mut()) {
        if link.phase == LinkPhase::Waiting && link.expires_at.is_some_and(|e| wall >= e) {
            link.phase = LinkPhase::Expired;
        }
        if link.poll_due(now, wall)
            && let Some(link_id) = link.link_id.clone()
        {
            poll = Some(link_id);
        }
    }
    let mut steps: Vec<Step> = poll
        .and_then(|link_id| {
            plan_send(
                state,
                Request::LinkStatus { link_id },
                Purpose::LinkPoll,
                true,
                None,
            )
        })
        .into_iter()
        .collect();
    steps.push(Step::Probe);
    // The did-git-sign install as Help / Status and Settings show it: read off
    // the loop when it is due (a persona switch, a signing change made here,
    // either view opened), never in `sync_from_config`.
    steps.push(Step::CheckDidGitSign);
    steps
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::state_handler::background_dispatch::InFlight;
    use openvtc_core::git_ns::{Refusal, view};
    use openvtc_core::pending_replies::PendingReplies;
    use serde_json::json;

    const VTC: &str = "did:webvh:QmVtcScid7:acme-vtc.example";
    const BOB: &str = "did:webvh:QmBobScid2:acme-vtc.example:bob";
    const ALICE: &str = "did:webvh:QmAliceScid1:acme-vtc.example:alice";
    const DAN: &str = "did:webvh:QmDanScid4:dan.example";

    fn from_vtc(thid: &str, reply: Reply) -> InboundReply {
        InboundReply {
            from: VTC.into(),
            issuer: Some(VTC.into()),
            thid: thid.into(),
            reply,
        }
    }

    fn persona() -> PersonaId {
        PersonaId(uuid::Uuid::nil())
    }

    fn data() -> view::Response {
        serde_json::from_value(json!({
            "accounts": [],
            "namespaces": [{"id": "ns_1", "forge": "github.com", "owner": "acme",
                            "kind": "organization", "mode": "bridge", "state": "bound"}],
            "repos": [
                {"resource": "github.com/acme/gadgets", "forgeId": "1", "visibility": "public",
                 "state": "active", "owners": [BOB],
                 "bootstrap": {"workflow": true, "keyring": true, "variables": true, "requiredCheck": true},
                 "sync": {"state": "inSync", "drift": []}},
                {"resource": "github.com/acme/widgets", "forgeId": "2", "visibility": "public",
                 "state": "active", "owners": [ALICE],
                 "bootstrap": {"workflow": true, "keyring": true, "variables": true, "requiredCheck": true},
                 "sync": {"state": "drift", "drift": [{"type": "requiredCheckMissing",
                          "resource": "github.com/acme/widgets"}]}}
            ],
            "rights": [
                {"subject": BOB, "right": "git.repo.create", "resource": "github.com/acme",
                 "grantedBy": ALICE, "grantedAt": "2026-09-01T00:00:00Z"},
                {"subject": BOB, "right": "git.repo.own", "resource": "github.com/acme/gadgets",
                 "grantedBy": BOB, "grantedAt": "2026-09-02T00:00:00Z"},
                {"subject": DAN, "right": "git.commit.sign", "resource": "github.com/acme/gadgets",
                 "grantedBy": BOB, "grantedAt": "2026-09-03T00:00:00Z"},
                {"subject": BOB, "right": "git.commit.sign", "resource": "github.com/acme/widgets",
                 "grantedBy": ALICE, "grantedAt": "2026-09-04T00:00:00Z"}
            ]
        }))
        .unwrap()
    }

    fn open_state() -> State {
        let mut state = State::default();
        let mut view = ReposView::new(VTC.into(), persona(), BOB.into(), "Acme".into());
        view.data = Some(Arc::new(data()));
        view.phase = ReposPhase::Loaded;
        state.main_page.content_panel.repos.view = Some(view);
        state
    }

    fn view(state: &State) -> &ReposView {
        state.main_page.content_panel.repos.view.as_ref().unwrap()
    }

    fn pend(state: &mut State, thid: &str, purpose: Purpose) {
        view_mut(state).unwrap().pending = Some(Pending {
            thid: thid.into(),
            sent_at: Instant::now(),
            purpose,
        });
    }

    fn outcome(thid: &str, result: Result<(), String>, purpose: Purpose) -> ReposOutcome {
        ReposOutcome {
            vtc_did: VTC.into(),
            persona: persona(),
            thid: thid.into(),
            purpose,
            result,
        }
    }

    /// Arm as `Loop::send` does, before the send is spawned.
    fn sent(state: &mut State, thid: &str, purpose: Purpose) {
        arm(
            view_mut(state).unwrap(),
            thid.into(),
            purpose,
            Instant::now(),
        );
    }

    // --- navigation ---------------------------------------------------------

    #[test]
    fn enter_opens_the_highlighted_repo_and_esc_walks_back() {
        let mut state = open_state();
        assert!(reduce(&mut state, &Act::Select(1)));
        reduce(&mut state, &Act::OpenRepo);
        assert_eq!(
            view(&state).screen,
            ReposScreen::Repo {
                resource: "github.com/acme/widgets".into()
            }
        );
        reduce(&mut state, &Act::Back);
        assert_eq!(view(&state).screen, ReposScreen::List);
        reduce(&mut state, &Act::Back);
        assert!(state.main_page.content_panel.repos.view.is_none());
    }

    #[test]
    fn the_loop_services_what_sends() {
        let mut state = open_state();
        for a in [
            Act::Open(0),
            Act::Refresh,
            Act::NewSubmit,
            Act::AddSubmit,
            Act::Confirm,
            Act::LinkStart,
        ] {
            assert!(!reduce(&mut state, &a), "{a:?} must reach the loop");
        }
    }

    // --- new repository -----------------------------------------------------

    #[test]
    fn new_repo_opens_only_for_a_creator() {
        let mut state = open_state();
        reduce(&mut state, &Act::NewStart);
        assert!(matches!(view(&state).screen, ReposScreen::NewRepo(_)));

        let mut state = open_state();
        view_mut(&mut state).unwrap().me = DAN.into();
        reduce(&mut state, &Act::NewStart);
        assert_eq!(view(&state).screen, ReposScreen::List);
        assert!(view(&state).status_text().unwrap().contains("no right"));
    }

    #[test]
    fn the_new_repo_form_edits_its_fields() {
        let mut state = open_state();
        reduce(&mut state, &Act::NewStart);
        reduce(
            &mut state,
            &Act::NewInput {
                field: 1,
                value: "gizmos".into(),
            },
        );
        reduce(&mut state, &Act::NewVisibility);
        let ReposScreen::NewRepo(form) = &view(&state).screen else {
            panic!("form open");
        };
        assert_eq!(form.name, "gizmos");
        assert_eq!(form.visibility, git_ns::Visibility::Private);
    }

    #[test]
    fn the_owner_picker_adds_and_drops_owners() {
        let mut state = open_state();
        reduce(&mut state, &Act::NewStart);
        reduce(&mut state, &Act::NewOwnerQuery("dan.example".into()));
        reduce(&mut state, &Act::NewOwnerPick(0));
        reduce(&mut state, &Act::NewOwnerAdd);
        let ReposScreen::NewRepo(form) = &view(&state).screen else {
            panic!("form open");
        };
        assert_eq!(form.owners, [DAN.to_string()]);
        assert!(form.owner_query.is_empty(), "the query clears after adding");

        // Pasting a DID for someone not in the picker.
        reduce(&mut state, &Act::NewOwnerToggleExternal);
        reduce(
            &mut state,
            &Act::NewOwnerQuery("did:webvh:QmEveScid9:acme-vtc.example:eve".into()),
        );
        reduce(&mut state, &Act::NewOwnerAdd);
        let ReposScreen::NewRepo(form) = &view(&state).screen else {
            panic!("form open");
        };
        assert_eq!(form.owners.len(), 2);
        assert_eq!(form.owners[1], "did:webvh:QmEveScid9:acme-vtc.example:eve");

        // A chip-input backspace on an empty query drops the last one added.
        reduce(&mut state, &Act::NewOwnerRemoveLast);
        let ReposScreen::NewRepo(form) = &view(&state).screen else {
            panic!("form open");
        };
        assert_eq!(form.owners, [DAN.to_string()]);
    }

    #[test]
    fn naming_an_owner_arms_the_confirmation() {
        let mut state = open_state();
        reduce(&mut state, &Act::NewStart);
        reduce(&mut state, &Act::NewOwnerQuery("dan.example".into()));
        reduce(&mut state, &Act::NewOwnerAdd);
        let ReposScreen::NewRepo(form) = &view(&state).screen else {
            panic!("form open");
        };
        let owners = if form.owners.is_empty() {
            None
        } else {
            Some(form.owners.clone())
        };
        let request = Request::Create {
            namespace: "ns_1".into(),
            name: "sprockets".into(),
            visibility: git_ns::Visibility::Public,
            description: None,
            owners,
        };
        assert_eq!(request.consent_class(), git_ns::ConsentClass::Elevated);
    }

    #[test]
    fn self_grant_not_allowed_is_shown_on_the_new_repo_form() {
        let mut state = open_state();
        reduce(&mut state, &Act::NewStart);
        pend(&mut state, "t", Purpose::Change("creating".into()));
        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", refused("git-ns:selfGrantNotAllowed", None))],
        );
        let ReposScreen::NewRepo(form) = &view(&state).screen else {
            panic!("form open");
        };
        let text = form.error.as_ref().unwrap().text.clone();
        assert_eq!(
            text,
            "Separation of duties: nobody gives themselves an elevated right (own, repo.create \
             or ns.admin) on their own authority. Ask another community administrator to do \
             it. If nobody else can, break the glass (`cnm git break-glass`, or from the admin \
             console): it is announced to every administrator and flagged until another one \
             ratifies or revokes it."
        );
    }

    // --- add person ---------------------------------------------------------

    fn on_gadgets(state: &mut State) {
        view_mut(state).unwrap().screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
    }

    #[test]
    fn only_an_owner_may_add_people() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().screen = ReposScreen::Repo {
            resource: "github.com/acme/widgets".into(),
        };
        reduce(&mut state, &Act::AddStart);
        assert!(view(&state).add.is_none());

        on_gadgets(&mut state);
        reduce(&mut state, &Act::AddStart);
        assert!(view(&state).add.is_some());
    }

    #[test]
    fn the_picker_offers_known_people_but_not_me() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::AddStart);
        let v = view(&state);
        let all = v.candidates("");
        assert!(!all.contains(&BOB.to_string()));
        assert!(all.contains(&DAN.to_string()));
        assert_eq!(v.candidates("dan.example"), [DAN.to_string()]);
    }

    #[test]
    fn tab_switches_to_pasting_a_did() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::AddStart);
        reduce(
            &mut state,
            &Act::AddInput {
                field: 0,
                value: "dan".into(),
            },
        );
        reduce(&mut state, &Act::AddToggleExternal);
        let form = view(&state).add.as_ref().unwrap();
        assert!(form.external);
        assert!(form.query.is_empty(), "the filter does not become a DID");
    }

    // --- revoke / transfer / archive ---------------------------------------

    #[test]
    fn revoking_is_armed_before_it_is_sent() {
        let mut state = open_state();
        on_gadgets(&mut state);
        // People: Bob (owner) then Dan (committer).
        reduce(&mut state, &Act::Select(1));
        reduce(&mut state, &Act::RevokeArm);
        let armed = view(&state).confirm.clone().unwrap();
        assert_eq!(
            armed.request,
            Request::Revoke {
                subject: DAN.into(),
                right: GitRight::CommitSign,
                resource: "github.com/acme/gadgets".into(),
                reason: None,
            }
        );
        reduce(&mut state, &Act::Cancel);
        assert!(view(&state).confirm.is_none());
    }

    #[test]
    fn a_committer_cannot_revoke_someone_else() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().me = DAN.into();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::Select(0)); // Bob, the owner
        reduce(&mut state, &Act::RevokeArm);
        assert!(view(&state).confirm.is_none());
    }

    #[test]
    fn transfer_goes_to_the_highlighted_person_not_to_me() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::Select(0));
        reduce(&mut state, &Act::TransferArm);
        assert!(view(&state).confirm.is_none(), "not to myself");
        reduce(&mut state, &Act::Select(1));
        reduce(&mut state, &Act::TransferArm);
        assert_eq!(
            view(&state).confirm.as_ref().unwrap().request,
            Request::Transfer {
                resource: "github.com/acme/gadgets".into(),
                to: DAN.into()
            }
        );
    }

    #[test]
    fn archive_is_armed_as_an_elevated_change() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::ArchiveArm);
        let armed = view(&state).confirm.clone().unwrap();
        assert_eq!(
            armed.request.consent_class(),
            git_ns::ConsentClass::Elevated
        );
        assert!(armed.summary.contains("no unarchive"));
    }

    // --- drift --------------------------------------------------------------

    /// Bob owns `widgets`, which carries `drift`, in a namespace of `mode`.
    fn drifted(drift: serde_json::Value, mode: &str) -> State {
        let mut data = serde_json::to_value(data()).unwrap();
        data["namespaces"][0]["mode"] = json!(mode);
        data["repos"][1]["owners"] = json!([ALICE, BOB]);
        data["repos"][1]["sync"]["drift"] = drift;
        let mut state = open_state();
        let v = view_mut(&mut state).unwrap();
        v.data = Some(Arc::new(serde_json::from_value(data).unwrap()));
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/widgets".into(),
        };
        state
    }

    fn on_first_drift(state: &mut State) {
        let people = view(state).people("github.com/acme/widgets").len();
        reduce(state, &Act::Select(people));
    }

    fn role(observed: &str) -> serde_json::Value {
        json!([{"type": "roleAdded", "resource": "github.com/acme/widgets",
                "account": {"forge": "github.com", "id": "5550123", "login": "eve-dev"},
                "observed": observed}])
    }

    #[test]
    fn the_highlight_runs_on_from_the_people_into_the_drift() {
        let mut state = drifted(role("maintain"), "bridge");
        on_first_drift(&mut state);
        let (_, item) = view(&state).highlighted_drift().unwrap();
        assert_eq!(item.kind, "roleAdded");
        // Nothing past the last item.
        reduce(&mut state, &Act::Select(99));
        assert!(view(&state).highlighted_drift().is_some());
        // A person highlighted is not a drift item.
        reduce(&mut state, &Act::Select(0));
        assert!(view(&state).highlighted_drift().is_none());
        reduce(&mut state, &Act::DriftRevertArm);
        assert!(view(&state).confirm.is_none());
        assert!(
            view(&state)
                .status_text()
                .unwrap()
                .contains("Highlight a drift item")
        );
    }

    #[test]
    fn only_an_owner_resolves_drift() {
        // Bob only commits on widgets in the base data.
        let mut state = open_state();
        view_mut(&mut state).unwrap().screen = ReposScreen::Repo {
            resource: "github.com/acme/widgets".into(),
        };
        on_first_drift(&mut state);
        assert!(view(&state).highlighted_drift().is_some());
        reduce(&mut state, &Act::DriftRevertArm);
        assert!(view(&state).confirm.is_none());
        assert!(
            view(&state)
                .status_text()
                .unwrap()
                .contains("owner's decision")
        );
    }

    #[test]
    fn an_owner_arms_a_revert_of_the_highlighted_drift() {
        let mut state = drifted(
            json!([{"type": "requiredCheckMissing", "resource": "github.com/acme/widgets"}]),
            "bridge",
        );
        on_first_drift(&mut state);
        reduce(&mut state, &Act::DriftRevertArm);
        let armed = view(&state).confirm.clone().unwrap();
        assert_eq!(
            armed.request,
            Request::DriftResolve {
                resource: "github.com/acme/widgets".into(),
                action: git_ns::DriftAction::Revert,
                item: git_ns::DriftRef {
                    kind: "requiredCheckMissing".into(),
                    account: None,
                    observed: None,
                    expected: None,
                },
                reason: None,
                weighs_as: GitRight::RepoMaintain,
            }
        );
        assert_eq!(armed.request.consent_class(), git_ns::ConsentClass::Normal);
        assert!(
            armed.summary.contains("re-applies the ruleset"),
            "{}",
            armed.summary
        );
        // A ruleset item cannot be adopted.
        reduce(&mut state, &Act::Cancel);
        reduce(&mut state, &Act::DriftAdoptArm);
        assert!(view(&state).confirm.is_none());
        assert!(view(&state).status_text().unwrap().contains("Only a role"));
    }

    #[test]
    fn taking_an_admin_role_off_is_armed_as_elevated() {
        let mut state = drifted(role("admin"), "bridge");
        on_first_drift(&mut state);
        reduce(&mut state, &Act::DriftRevertArm);
        let armed = view(&state).confirm.clone().unwrap();
        assert_eq!(
            armed.request.consent_class(),
            git_ns::ConsentClass::Elevated
        );
        assert!(
            armed.summary.contains("community administrator"),
            "{}",
            armed.summary
        );
        assert!(armed.summary.contains("@eve-dev"));
    }

    #[test]
    fn adopting_is_not_offered_here_and_says_where_it_is() {
        // An adoptable role: nothing is armed, and the note says why and where.
        let mut state = drifted(role("maintain"), "bridge");
        on_first_drift(&mut state);
        reduce(&mut state, &Act::DriftAdoptArm);
        assert!(view(&state).confirm.is_none());
        let text = view(&state).status_text().unwrap();
        assert!(text.contains("maintainer"), "{text}");
        assert!(text.contains("only your own links"), "{text}");
        assert!(text.contains("--subject"), "{text}");
        // `write` projects nothing on an organisation: that reason first.
        let mut state = drifted(role("write"), "bridge");
        on_first_drift(&mut state);
        reduce(&mut state, &Act::DriftAdoptArm);
        assert!(view(&state).confirm.is_none());
        assert!(view(&state).status_text().unwrap().contains("No git right"));
    }

    #[test]
    fn a_manual_namespace_has_no_bridge_to_revert_with() {
        let mut state = drifted(role("maintain"), "manual");
        on_first_drift(&mut state);
        reduce(&mut state, &Act::DriftRevertArm);
        assert!(view(&state).confirm.is_none());
        assert!(view(&state).status_text().unwrap().contains("manual mode"));
    }

    #[test]
    fn a_resolved_drift_says_so_and_reads_again() {
        let mut state = drifted(role("maintain"), "bridge");
        pend(&mut state, "t", Purpose::Change("reverting drift".into()));
        let resolved = serde_json::from_value(
            json!({"action": "revert", "sync": {"state": "pending", "drift": []}}),
        )
        .unwrap();
        let refresh = apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", Reply::DriftResolved(Box::new(resolved)))],
        );
        assert!(refresh);
        let text = view(&state).status_text().unwrap();
        assert!(text.starts_with("Reverted"), "{text}");
    }

    // --- sends --------------------------------------------------------------

    #[test]
    fn a_sent_change_waits_for_its_reply() {
        let mut state = open_state();
        sent(&mut state, "thid-1", Purpose::Change("archiving x".into()));
        outcome("thid-1", Ok(()), Purpose::Change("archiving x".into())).apply(&mut state);
        let v = view(&state);
        assert_eq!(v.pending.as_ref().unwrap().thid, "thid-1");
        assert!(v.status_text().unwrap().contains("awaiting"));
    }

    #[test]
    fn a_first_read_that_never_left_fails_the_view() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().data = None;
        sent(&mut state, "thid-1", Purpose::View);
        outcome("thid-1", Err("peer unreachable".into()), Purpose::View).apply(&mut state);
        assert!(matches!(&view(&state).phase, ReposPhase::Failed(m) if m.contains("unreachable")));
        assert!(view(&state).pending.is_none());
    }

    #[test]
    fn an_outcome_for_another_community_is_dropped() {
        let mut state = open_state();
        sent(&mut state, "thid-1", Purpose::View);
        let mut o = outcome("thid-1", Err("peer unreachable".into()), Purpose::View);
        o.vtc_did = "did:webvh:other".into();
        o.apply(&mut state);
        assert!(view(&state).pending.is_some(), "still waiting");
        assert!(view(&state).status.is_none());
    }

    /// **The race.** The VTC can answer before the send's own outcome is
    /// applied — its answer comes in on the inbound channel, the outcome on the
    /// dispatch one. The view waits from before the send, so the answer is
    /// taken, and the outcome that follows changes nothing.
    #[test]
    fn a_reply_that_overtakes_the_send_is_still_matched() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().data = None;
        view_mut(&mut state).unwrap().phase = ReposPhase::Loading;
        sent(&mut state, "thid-1", Purpose::View);

        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("thid-1", Reply::View(Box::new(data())))],
        );
        outcome("thid-1", Ok(()), Purpose::View).apply(&mut state);

        let v = view(&state);
        assert_eq!(v.phase, ReposPhase::Loaded);
        assert!(v.pending.is_none(), "answered; not re-armed");
    }

    /// The same for a link poll, which waits in a slot of its own.
    #[test]
    fn a_poll_answer_that_overtakes_the_send_is_still_matched() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().link = Some(LinkFlow::starting("github.com".into()));
        sent(&mut state, "poll-1", Purpose::LinkPoll);

        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("poll-1", link_reply())],
        );
        outcome("poll-1", Ok(()), Purpose::LinkPoll).apply(&mut state);

        let link = view(&state).link.as_ref().unwrap();
        assert!(link.poll.is_none(), "answered; not re-armed");
        assert!(link.last_poll.is_some());
    }

    /// A send that fails after a newer request took the slot is for a question
    /// nobody waits on any more: the newer request's wait goes on.
    #[test]
    fn a_late_failure_for_a_superseded_request_keeps_the_current_wait() {
        let mut state = open_state();
        sent(&mut state, "grant-1", Purpose::Change("granting".into()));
        sent(&mut state, "view-2", Purpose::View);

        outcome(
            "grant-1",
            Err("peer unreachable".into()),
            Purpose::Change("granting".into()),
        )
        .apply(&mut state);

        let v = view(&state);
        assert_eq!(v.pending.as_ref().unwrap().thid, "view-2");
        assert!(
            !v.status_text().unwrap().contains("couldn't send"),
            "{:?}",
            v.status_text()
        );
    }

    /// A poll that did not leave frees its slot, so the next tick polls again.
    #[test]
    fn a_failed_poll_frees_its_slot() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().link = Some(LinkFlow::starting("github.com".into()));
        sent(&mut state, "poll-1", Purpose::LinkPoll);
        outcome("poll-1", Err("peer unreachable".into()), Purpose::LinkPoll).apply(&mut state);
        assert!(view(&state).link.as_ref().unwrap().poll.is_none());
    }

    // --- replies ------------------------------------------------------------

    fn config() -> Config {
        crate::state_handler::dispatch_util::test_config()
    }

    #[test]
    fn a_view_reply_loads_the_view() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().data = None;
        pend(&mut state, "t", Purpose::View);
        let refresh = apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", Reply::View(Box::new(data())))],
        );
        assert!(!refresh);
        let v = view(&state);
        assert_eq!(v.phase, ReposPhase::Loaded);
        assert_eq!(v.my_repos().len(), 2);
        assert!(v.pending.is_none());
    }

    #[test]
    fn an_uncorrelated_reply_is_dropped() {
        let mut state = open_state();
        pend(&mut state, "mine", Purpose::View);
        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("someone-elses", Reply::View(Box::new(data())))],
        );
        assert!(view(&state).pending.is_some(), "still waiting for its own");
    }

    fn refused(code: &str, message: Option<&str>) -> Reply {
        Reply::Refused(Refusal {
            code: code.into(),
            message: message.map(str::to_string),
        })
    }

    /// The community's policy refusing an outside signer is shown in the
    /// form, with its own reason, so the member can change the request.
    #[test]
    fn a_policy_refusal_is_shown_in_the_add_form() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::AddStart);
        pend(&mut state, "t", Purpose::Change("granting".into()));
        let refresh = apply_replies(
            &mut state,
            &config(),
            vec![from_vtc(
                "t",
                refused("git-ns:policyDenied", Some("no external signers")),
            )],
        );
        assert!(!refresh);
        let err = view(&state)
            .add
            .as_ref()
            .unwrap()
            .error
            .clone()
            .unwrap()
            .text;
        assert!(err.contains("no external signers"), "{err}");
        assert!(err.contains("policy"), "{err}");
    }

    #[test]
    fn a_grant_closes_the_form_and_reads_again() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::AddStart);
        pend(&mut state, "t", Purpose::Change("granting".into()));
        let granted = serde_json::from_value(json!({"right": {
            "subject": DAN, "right": "git.repo.maintain", "resource": "github.com/acme/gadgets",
            "grantedBy": BOB, "grantedAt": "2026-09-23T10:00:00Z"}}))
        .unwrap();
        let refresh = apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", Reply::Granted(Box::new(granted)))],
        );
        assert!(refresh);
        assert!(view(&state).add.is_none());
        assert!(
            view(&state)
                .status_text()
                .unwrap()
                .contains("Trust Registry")
        );
    }

    #[test]
    fn a_revoke_of_a_right_already_gone_is_success() {
        let mut state = open_state();
        pend(&mut state, "t", Purpose::Change("revoking".into()));
        let refresh = apply_replies(
            &mut state,
            &config(),
            vec![from_vtc(
                "t",
                refused("git-ns/right/revoke:notGranted", None),
            )],
        );
        assert!(refresh);
    }

    #[test]
    fn a_manual_create_shows_its_steps_on_the_repo() {
        let mut state = open_state();
        reduce(&mut state, &Act::NewStart);
        pend(&mut state, "t", Purpose::Change("creating".into()));
        let created = serde_json::from_value(json!({
            "repo": {"resource": "codeberg.org/acme/sprockets", "visibility": "public",
                     "state": "pendingCreate", "owners": [BOB],
                     "bootstrap": {"workflow": false, "keyring": false, "variables": false, "requiredCheck": false},
                     "sync": {"state": "unchecked", "drift": []}},
            "manualSteps": ["Create the repository.", "Run vgi repo init.", "Run cnm git adopt."]
        }))
        .unwrap();
        let refresh = apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", Reply::Created(Box::new(created)))],
        );
        assert!(refresh);
        let v = view(&state);
        assert_eq!(
            v.screen,
            ReposScreen::Repo {
                resource: "codeberg.org/acme/sprockets".into()
            }
        );
        assert_eq!(v.created.as_ref().unwrap().manual_steps.len(), 3);
    }

    /// The VTC admits elevated changes only from an administrator for now;
    /// that refusal reads as that.
    #[test]
    fn the_elevated_gate_is_explained() {
        let mut state = open_state();
        pend(&mut state, "t", Purpose::Change("archiving".into()));
        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc(
                "t",
                refused(
                    "permissionDenied",
                    Some(
                        "repo.archive is a elevated action ... (`[git_ns] elevated_requires_admin`)",
                    ),
                ),
            )],
        );
        assert!(
            view(&state)
                .status_text()
                .unwrap()
                .contains("community administrator")
        );
    }

    // --- linking ------------------------------------------------------------

    fn link_reply() -> Reply {
        Reply::LinkStarted(Box::new(
            serde_json::from_value(json!({
                "linkId": "lnk_1", "url": "https://github.com/login/device",
                "userCode": "WDJB-MJHT", "expiresAt": "2099-01-01T00:00:00Z"
            }))
            .unwrap(),
        ))
    }

    #[test]
    fn a_device_flow_shows_its_code_and_polls() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().link = Some(LinkFlow::starting("github.com".into()));
        pend(&mut state, "t", Purpose::LinkStart);
        apply_replies(&mut state, &config(), vec![from_vtc("t", link_reply())]);
        let link = view(&state).link.clone().unwrap();
        assert_eq!(link.phase, LinkPhase::Waiting);
        assert_eq!(link.user_code.as_deref(), Some("WDJB-MJHT"));
        assert!(link.poll_due(Instant::now(), Utc::now()));
    }

    #[test]
    fn polls_keep_to_the_five_second_floor() {
        let mut link = LinkFlow::starting("codeberg.org".into());
        link.phase = LinkPhase::Waiting;
        link.link_id = Some("lnk_1".into());
        let now = Instant::now();
        link.last_poll = Some(now);
        assert!(!link.poll_due(now, Utc::now()));
        assert!(link.poll_due(now + git_ns::LINK_POLL_INTERVAL, Utc::now()));
        link.expires_at = Some(Utc::now() - chrono::TimeDelta::seconds(1));
        assert!(
            !link.poll_due(now + git_ns::LINK_POLL_INTERVAL, Utc::now()),
            "not past the attempt's expiry"
        );
    }

    /// Each failed poll in a row doubles the interval, up to the cap; an
    /// answer brings it back to the floor.
    #[test]
    fn a_failing_poll_backs_off_to_a_cap_and_an_answer_resets_it() {
        let mut link = LinkFlow::starting("codeberg.org".into());
        link.phase = LinkPhase::Waiting;
        link.link_id = Some("lnk_1".into());
        let now = Instant::now();
        let mut seen = Vec::new();
        for _ in 0..6 {
            link.poll_failed(now, "unreachable");
            seen.push(link.poll_interval().as_secs());
        }
        assert_eq!(seen, vec![10, 20, 40, 60, 60, 60]);
        assert!(!link.poll_due(now + Duration::from_secs(59), Utc::now()));
        assert!(link.poll_due(now + Duration::from_secs(60), Utc::now()));
        link.poll_answered();
        assert_eq!(link.poll_interval(), git_ns::LINK_POLL_INTERVAL);
    }

    /// A failure is said once while it repeats; a different one is said, and
    /// so is the same one again after an answer.
    #[test]
    fn a_repeated_poll_failure_is_said_once() {
        let mut link = LinkFlow::starting("codeberg.org".into());
        let now = Instant::now();
        assert!(link.poll_failed(now, "unreachable"));
        assert!(!link.poll_failed(now, "unreachable"));
        assert!(link.poll_failed(now, "refused"));
        link.poll_answered();
        assert!(link.poll_failed(now, "refused"));
    }

    /// A poll lost past its reply window says so once and backs off; a second
    /// lost poll the same way says nothing more.
    #[test]
    fn a_lost_poll_is_said_once_and_backs_off() {
        let mut state = open_state();
        let mut link = LinkFlow::starting("github.com".into());
        link.phase = LinkPhase::Waiting;
        link.link_id = Some("lnk_1".into());
        view_mut(&mut state).unwrap().link = Some(link);
        let start = Instant::now();
        let later = start + REPLY_WINDOW + Duration::from_secs(1);
        let lose = |state: &mut State, sent_at: Instant| {
            view_mut(state).unwrap().link.as_mut().unwrap().poll = Some(Pending {
                thid: "poll-1".into(),
                sent_at,
                purpose: Purpose::LinkPoll,
            });
        };

        lose(&mut state, start);
        let steps = plan_tick(&mut state, later, Utc::now());
        assert!(
            !steps.iter().any(|s| matches!(s, Step::Send(_))),
            "not polled again at once"
        );
        let v = view(&state);
        let link = v.link.as_ref().unwrap();
        assert!(link.poll.is_none());
        assert_eq!(link.failures, 1);
        let said = v.status.as_ref().unwrap().text.clone();
        assert!(said.starts_with("no answer to the link check"), "{said}");

        view_mut(&mut state).unwrap().status = None;
        lose(&mut state, later);
        plan_tick(
            &mut state,
            later + REPLY_WINDOW + Duration::from_secs(1),
            Utc::now(),
        );
        let v = view(&state);
        assert_eq!(v.link.as_ref().unwrap().failures, 2);
        assert!(v.status.is_none(), "the same failure is not said again");
    }

    #[test]
    fn a_linked_answer_is_remembered_for_the_session() {
        let mut state = open_state();
        let mut link = LinkFlow::starting("github.com".into());
        link.phase = LinkPhase::Waiting;
        link.link_id = Some("lnk_1".into());
        link.poll = Some(Pending {
            thid: "poll-1".into(),
            sent_at: Instant::now(),
            purpose: Purpose::LinkPoll,
        });
        view_mut(&mut state).unwrap().link = Some(link);
        let status = serde_json::from_value(json!({"state": "linked",
            "account": {"forge": "github.com", "id": "9120045", "login": "bob-builds"}}))
        .unwrap();
        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("poll-1", Reply::LinkStatus(Box::new(status)))],
        );
        assert!(matches!(
            &view(&state).link.as_ref().unwrap().phase,
            LinkPhase::Linked { login, .. } if login == "bob-builds"
        ));
        let linked = &state.main_page.content_panel.repos.linked;
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].vtc_did, VTC);
    }

    /// A refresh pressed while a change awaits its answer does not take the
    /// pending slot — the change's answer would otherwise be dropped.
    #[tokio::test]
    async fn a_second_request_waits_for_the_first_answer() {
        let mut state = open_state();
        pend(
            &mut state,
            "grant-1",
            Purpose::Change("granting maintainer".into()),
        );
        let config = config();
        let tdk = crate::state_handler::dispatch_util::test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut in_flight = InFlight::default();
        refresh(
            &mut Loop {
                state: &mut state,
                config: &config,
                tdk: &tdk,
                vta: None,
                dispatch_tx: &tx,
                in_flight: &mut in_flight,
                pending_replies: &mut PendingReplies::default(),
            },
            false,
        )
        .await;
        let v = view(&state);
        assert_eq!(v.pending.as_ref().unwrap().thid, "grant-1");
        assert!(v.status_text().unwrap().contains("granting maintainer"));
        assert!(
            !in_flight.is_busy(DispatchDomain::GitNs),
            "nothing was sent"
        );
    }

    #[tokio::test]
    async fn a_reply_that_never_comes_times_out() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().pending = Some(Pending {
            thid: "t".into(),
            sent_at: Instant::now() - REPLY_WINDOW - Duration::from_secs(1),
            purpose: Purpose::Change("archiving gadgets".into()),
        });
        let config = config();
        let tdk = crate::state_handler::dispatch_util::test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut in_flight = InFlight::default();
        tick(&mut Loop {
            state: &mut state,
            config: &config,
            tdk: &tdk,
            vta: None,
            dispatch_tx: &tx,
            in_flight: &mut in_flight,
            pending_replies: &mut PendingReplies::default(),
        })
        .await;
        let v = view(&state);
        assert!(v.pending.is_none());
        assert!(v.status_text().unwrap().contains("within 30s"));
    }

    // --- review follow-ups -------------------------------------------------

    /// `l` on the panel, planned and run on the loop.
    async fn link_start(lp: &mut Loop<'_>) {
        let ReposEffect::Steps(steps) = plan(lp.state, lp.config, Act::LinkStart) else {
            panic!("a link start runs steps");
        };
        run_steps(lp, steps).await;
    }

    async fn with_loop<F>(state: &mut State, f: F)
    where
        F: for<'a> FnOnce(
            &'a mut Loop<'_>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>,
    {
        let config = config();
        let tdk = crate::state_handler::dispatch_util::test_tdk().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut in_flight = InFlight::default();
        let mut pending_replies = PendingReplies::default();
        let mut lp = Loop {
            state,
            config: &config,
            tdk: &tdk,
            vta: None,
            dispatch_tx: &tx,
            in_flight: &mut in_flight,
            pending_replies: &mut pending_replies,
        };
        f(&mut lp).await;
    }

    /// A reply correctly threaded but sent — or issued — by someone other than
    /// the community is dropped: a thread id is not a credential.
    #[test]
    fn a_threaded_reply_from_another_did_is_dropped() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().data = None;
        pend(&mut state, "t", Purpose::View);
        let mut forged = from_vtc("t", Reply::View(Box::new(data())));
        forged.from = "did:webvh:QmMallory:evil.example".into();
        apply_replies(&mut state, &config(), vec![forged]);
        assert!(view(&state).data.is_none());
        assert!(
            view(&state).pending.is_some(),
            "still waiting for the community"
        );

        let mut wrong_issuer = from_vtc("t", Reply::View(Box::new(data())));
        wrong_issuer.issuer = Some("did:webvh:QmMallory:evil.example".into());
        apply_replies(&mut state, &config(), vec![wrong_issuer]);
        assert!(view(&state).data.is_none());

        let mut no_issuer = from_vtc("t", Reply::View(Box::new(data())));
        no_issuer.issuer = None;
        apply_replies(&mut state, &config(), vec![no_issuer]);
        assert!(view(&state).data.is_none());

        // The community itself, from a key-qualified sender, is accepted.
        let mut ok = from_vtc("t", Reply::View(Box::new(data())));
        ok.from = format!("{VTC}#key-1");
        apply_replies(&mut state, &config(), vec![ok]);
        assert!(view(&state).data.is_some());
    }

    /// A link attempt is shown only once its request is on its way; a send
    /// refused before it leaves leaves no "starting…" behind.
    #[tokio::test]
    async fn a_link_that_never_left_is_not_left_starting() {
        // No messaging identity for the persona: the send is refused.
        let mut state = open_state();
        with_loop(&mut state, |lp| Box::pin(link_start(lp))).await;
        let v = view(&state);
        assert!(v.link.is_none(), "no attempt was started");
        assert_eq!(v.status.as_ref().unwrap().severity, Severity::Error);

        // Still waiting on another answer: likewise.
        let mut state = open_state();
        pend(&mut state, "grant-1", Purpose::Change("granting".into()));
        with_loop(&mut state, |lp| Box::pin(link_start(lp))).await;
        assert!(view(&state).link.is_none());
        assert!(
            view(&state)
                .status_text()
                .unwrap()
                .contains("Still waiting")
        );
    }

    /// `account/link` gets 60 s: the VTC waits up to 30 s on its bridge first.
    #[tokio::test]
    async fn a_link_start_waits_sixty_seconds() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().link = Some(LinkFlow::starting("github.com".into()));
        view_mut(&mut state).unwrap().pending = Some(Pending {
            thid: "t".into(),
            sent_at: Instant::now() - Duration::from_secs(45),
            purpose: Purpose::LinkStart,
        });
        with_loop(&mut state, |lp| Box::pin(tick(lp))).await;
        assert!(view(&state).pending.is_some(), "45 s is inside the window");

        view_mut(&mut state)
            .unwrap()
            .pending
            .as_mut()
            .unwrap()
            .sent_at = Instant::now() - LINK_START_WINDOW - Duration::from_secs(1);
        with_loop(&mut state, |lp| Box::pin(tick(lp))).await;
        assert!(matches!(
            view(&state).link.as_ref().unwrap().phase,
            LinkPhase::Failed(_)
        ));
        assert_eq!(reply_window(&Purpose::View), REPLY_WINDOW);
    }

    /// Only an https URL on the link's own forge is shown or made a QR code.
    #[test]
    fn a_link_url_off_the_forge_is_refused() {
        assert!(link_url_ok("https://github.com/login/device", "github.com"));
        assert!(!link_url_ok("http://github.com/login/device", "github.com"));
        assert!(!link_url_ok(
            "https://github.com.evil.example/x",
            "github.com"
        ));
        assert!(!link_url_ok(
            "https://evil.example/github.com",
            "github.com"
        ));
        assert!(!link_url_ok("https://user@github.com/x", "github.com"));
        assert!(!link_url_ok("javascript:alert(1)", "github.com"));

        let mut state = open_state();
        view_mut(&mut state).unwrap().link = Some(LinkFlow::starting("github.com".into()));
        pend(&mut state, "t", Purpose::LinkStart);
        let reply = Reply::LinkStarted(Box::new(
            serde_json::from_value(json!({
                "linkId": "lnk_1", "url": "https://evil.example/login/device",
                "userCode": "WDJB-MJHT", "expiresAt": "2099-01-01T00:00:00Z"
            }))
            .unwrap(),
        ));
        apply_replies(&mut state, &config(), vec![from_vtc("t", reply)]);
        let link = view(&state).link.clone().unwrap();
        assert!(matches!(link.phase, LinkPhase::Failed(_)));
        assert!(link.url.is_none(), "the address is not kept");
    }

    /// After a timeout the form stays, marked: the change may have landed.
    #[tokio::test]
    async fn a_timed_out_change_keeps_its_form_marked() {
        let mut state = open_state();
        on_gadgets(&mut state);
        reduce(&mut state, &Act::AddStart);
        view_mut(&mut state).unwrap().pending = Some(Pending {
            thid: "t".into(),
            sent_at: Instant::now() - REPLY_WINDOW - Duration::from_secs(1),
            purpose: Purpose::Change("granting maintainer".into()),
        });
        with_loop(&mut state, |lp| Box::pin(tick(lp))).await;
        let v = view(&state);
        let err = v
            .add
            .as_ref()
            .expect("the form stays")
            .error
            .clone()
            .unwrap();
        assert!(err.text.contains("may have been applied"), "{}", err.text);
        assert_eq!(err.severity, Severity::Warning);
        assert_eq!(v.status.as_ref().unwrap().severity, Severity::Error);
    }

    /// A create that lands after the member moved on does not pull them back.
    #[test]
    fn a_late_create_does_not_navigate() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().screen = ReposScreen::List;
        pend(&mut state, "t", Purpose::Change("creating".into()));
        let created = serde_json::from_value(json!({
            "repo": {"resource": "github.com/acme/gizmos", "visibility": "public",
                     "state": "pendingCreate", "owners": [BOB],
                     "bootstrap": {"workflow": false, "keyring": false, "variables": false, "requiredCheck": false},
                     "sync": {"state": "pending", "drift": []}},
            "manualSteps": ["Step \u{202E}one"]
        }))
        .unwrap();
        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", Reply::Created(Box::new(created)))],
        );
        let v = view(&state);
        assert_eq!(v.screen, ReposScreen::List);
        assert_eq!(v.status.as_ref().unwrap().severity, Severity::Success);
        assert_eq!(v.created.as_ref().unwrap().manual_steps, ["Step one"]);
    }

    /// Names are cleaned of bidi overrides and zero-width characters.
    #[test]
    fn a_did_is_named_sanitised() {
        let state = open_state();
        let v = view(&state);
        let name = v.name_of("did:webvh:Qm\u{202E}evil\u{200B}:x");
        assert_eq!(name, "did:webvh:Qmevil:x");
    }

    /// Refusals read as errors, by severity rather than wording.
    #[test]
    fn a_refusal_is_an_error() {
        let mut state = open_state();
        pend(&mut state, "t", Purpose::Change("archiving".into()));
        apply_replies(
            &mut state,
            &config(),
            vec![from_vtc("t", refused("git-ns:repoNotActive", None))],
        );
        assert_eq!(
            view(&state).status.as_ref().unwrap().severity,
            Severity::Error
        );
    }

    // --- the pure plan ------------------------------------------------------

    fn steps(effect: ReposEffect) -> Vec<Step> {
        match effect {
            ReposEffect::Steps(steps) => steps,
            _ => panic!("expected steps"),
        }
    }

    fn outbound(step: &Step) -> &Outbound {
        match step {
            Step::Send(outbound) => outbound,
            _ => panic!("expected a send"),
        }
    }

    /// A confirmation is spent by the plan; the change it armed is a send
    /// owed, and nothing says it is waiting until the send is claimed.
    #[test]
    fn a_confirmation_plans_its_change_and_is_spent() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().confirm = Some(ArmedChange {
            summary: "Archive?".into(),
            request: Request::Archive {
                resource: "github.com/acme/gadgets".into(),
            },
        });
        let planned = steps(plan(&mut state, &config(), Act::Confirm));
        assert_eq!(planned.len(), 1);
        let out = outbound(&planned[0]);
        assert_eq!(
            out.purpose,
            Purpose::Change("archiving acme/gadgets".into())
        );
        assert_eq!((out.vtc_did.as_str(), out.persona), (VTC, persona()));
        assert!(!out.quiet);
        assert_eq!(out.commit, None);
        let v = view(&state);
        assert!(v.confirm.is_none());
        assert!(
            v.pending.is_none() && v.status.is_none(),
            "armed only once claimed"
        );
    }

    /// While a request awaits its answer, a second is planned as the "still
    /// waiting" note — the confirmation still spent — and a quiet one as
    /// nothing at all.
    #[test]
    fn a_request_while_another_waits_plans_a_note_or_nothing_when_quiet() {
        let mut state = open_state();
        pend(
            &mut state,
            "g1",
            Purpose::Change("granting maintainer".into()),
        );
        view_mut(&mut state).unwrap().confirm = Some(ArmedChange {
            summary: "Archive?".into(),
            request: Request::Archive {
                resource: "github.com/acme/gadgets".into(),
            },
        });
        let planned = steps(plan(&mut state, &config(), Act::Confirm));
        assert!(matches!(
            planned.as_slice(),
            [Step::Note(Severity::Warning, text)]
                if text == "Still waiting for the community's answer (granting maintainer)."
        ));
        assert!(view(&state).confirm.is_none());
        assert!(view(&state).status.is_none(), "the runner says it");

        assert!(plan_read(&mut state, true).is_none());
        assert!(matches!(
            plan_read(&mut state, false),
            Some(Step::Note(_, text)) if text == "Still waiting for the community's answer (granting maintainer)."
        ));
    }

    /// A refresh wants a probe, then probes, shows the read starting and reads
    /// — in that order, so the read's cleared status line is what a refusal
    /// is written over.
    #[test]
    fn a_refresh_plans_probe_reading_then_the_read() {
        let mut state = open_state();
        let planned = steps(plan(&mut state, &config(), Act::Refresh));
        assert!(matches!(
            planned.as_slice(),
            [Step::Probe, Step::Reading, Step::Send(out)] if out.purpose == Purpose::View && !out.quiet
        ));
        assert_eq!(view(&state).workspace.probe_wanted, Some(true));

        pend(&mut state, "v1", Purpose::View);
        let planned = steps(plan(&mut state, &config(), Act::Refresh));
        assert!(matches!(
            planned.as_slice(),
            [Step::Probe, Step::Reading, Step::Note(Severity::Warning, _)]
        ));
    }

    /// Opening an index that names no Active community leaves the open view
    /// and still reads it, after the workspace is filled.
    #[test]
    fn opening_no_community_reads_the_open_view_after_the_workspace() {
        let mut state = open_state();
        let ReposEffect::Opened(planned) = plan(&mut state, &config(), Act::Open(7)) else {
            panic!("an open fills the workspace first");
        };
        assert!(matches!(
            planned.as_slice(),
            [Step::Reading, Step::Send(out)] if out.vtc_did == VTC
        ));
        assert_eq!(view(&state).vtc_did, VTC);
    }

    /// A new repository for the requester alone is a send owed; the form stays.
    #[test]
    fn a_new_repository_for_me_alone_plans_the_create() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().screen = ReposScreen::NewRepo(NewRepoForm {
            name: "gizmos".into(),
            ..NewRepoForm::default()
        });
        let planned = steps(plan(&mut state, &config(), Act::NewSubmit));
        assert_eq!(planned.len(), 1);
        assert_eq!(
            outbound(&planned[0]).purpose,
            Purpose::Change("creating gizmos".into())
        );
        assert!(view(&state).confirm.is_none());
    }

    /// A link start owes its "starting…" line to the claim; with no bridged
    /// forge it says so and plans nothing.
    #[test]
    fn a_link_start_owes_its_starting_line_to_the_claim() {
        let mut state = open_state();
        let planned = steps(plan(&mut state, &config(), Act::LinkStart));
        assert_eq!(planned.len(), 1);
        let out = outbound(&planned[0]);
        assert_eq!(out.purpose, Purpose::LinkStart);
        assert_eq!(out.commit, Some(Commit::LinkStarting("github.com".into())));
        assert!(view(&state).link.is_none());

        view_mut(&mut state).unwrap().data = None;
        assert!(steps(plan(&mut state, &config(), Act::LinkStart)).is_empty());
        assert_eq!(
            view(&state).status.as_ref().unwrap().severity,
            Severity::Warning
        );
    }

    /// The sweep plans a due poll — beside a pending change, quietly — then
    /// the probe and the did-git-sign read. The poll is armed only once sent.
    #[test]
    fn the_sweep_plans_a_due_poll_then_the_probe_and_did_git_sign() {
        let mut state = open_state();
        pend(&mut state, "g1", Purpose::Change("granting".into()));
        let mut link = LinkFlow::starting("github.com".into());
        link.phase = LinkPhase::Waiting;
        link.link_id = Some("lnk_1".into());
        view_mut(&mut state).unwrap().link = Some(link);
        let planned = plan_tick(&mut state, Instant::now(), Utc::now());
        assert!(matches!(
            planned.as_slice(),
            [Step::Send(out), Step::Probe, Step::CheckDidGitSign]
                if out.purpose == Purpose::LinkPoll && out.quiet
                    && out.request == Request::LinkStatus { link_id: "lnk_1".into() }
        ));
        let link = view(&state).link.as_ref().unwrap();
        assert!(link.poll.is_none() && link.last_poll.is_none());
    }

    /// The sweep ends a wait past its window at the time it is given.
    #[test]
    fn the_sweep_ends_a_wait_past_its_window() {
        let mut state = open_state();
        pend(&mut state, "t", Purpose::View);
        let sent = view(&state).pending.as_ref().unwrap().sent_at;
        let planned = plan_tick(&mut state, sent + REPLY_WINDOW, Utc::now());
        assert!(
            view(&state).pending.is_some(),
            "the window's edge is inside it"
        );
        assert!(matches!(
            planned.as_slice(),
            [Step::Probe, Step::CheckDidGitSign]
        ));

        plan_tick(
            &mut state,
            sent + REPLY_WINDOW + Duration::from_secs(1),
            Utc::now(),
        );
        assert!(view(&state).pending.is_none());
        assert!(view(&state).status_text().unwrap().contains("within 30s"));
    }
}
