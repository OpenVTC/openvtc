//! The Repos panel: a community's git repositories, from the member's side.
//!
//! Opened from Communities with `r`. Every read and change is one signed
//! `git-ns/*` task sent to the community's VTC ([`openvtc_core::git_ns`]),
//! off the loop thread in [`DispatchDomain::GitNs`], exactly as the
//! capabilities view sends its governance documents: the send returns a thread
//! id, the VTC's answer arrives later on the inbound channel, and
//! [`apply_replies`] matches it to what is pending. After any change the view
//! is read again — the VTC is the record, so nothing is patched locally.
//!
//! Changes above the `normal` consent class (design §6: owner, transfer,
//! archive), every removal and every drift resolution are armed first and
//! sent only on `y` ([`ArmedChange`]). The VTC may still refuse an elevated change from a
//! member who is not a community administrator — it cannot yet ask a member
//! to step up (VTI #1694, `[git_ns] elevated_requires_admin`) — and the
//! refusal says so ([`openvtc_core::git_ns::Refusal::explain`]).
//!
//! View-only changes go through [`reduce`], which both loops share.

use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_tdk::TDK;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::git_ns::{self, GitRight, Reply, Request};
use tokio::sync::mpsc::UnboundedSender;

use crate::state_handler::actions::ReposAction as Act;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::repos::{
    AddPersonForm, ArmedChange, CreatedRepo, EXPIRY_CHOICES, LinkFlow, LinkPhase, LinkedAccount,
    NewRepoForm, Pending, Purpose, ReposPhase, ReposScreen, ReposView, Severity, SigningHealth,
    Status,
};
use crate::state_handler::main_page::sanitize_display;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

const DOMAIN: DispatchDomain = DispatchDomain::GitNs;

/// How long a request waits for the community's answer (R1.2).
pub(crate) const REPLY_WINDOW: Duration = Duration::from_secs(30);

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

/// A `git-ns` answer as it arrived: who sent it and who the document says
/// issued it, besides the thread it answers.
pub(crate) struct InboundReply {
    /// The transport-authenticated sender.
    pub(crate) from: String,
    /// The document's `issuer`.
    pub(crate) issuer: Option<String>,
    pub(crate) thid: String,
    pub(crate) reply: Reply,
}

/// The DID part of a DID or DID URL.
fn did_part(did: &str) -> &str {
    did.split('#').next().unwrap_or(did)
}

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
    if view.confirm.take().is_some() || view.add.take().is_some() {
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

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

// ****************************************************************************
// Loop-side actions
// ****************************************************************************

/// Everything a send needs, resolved on the loop thread.
pub(crate) struct Sender {
    atm: ATM,
    profile: Arc<ATMProfile>,
    persona_did: String,
    mediator: String,
    signer: Box<Secret>,
}

/// Resolve the persona's messaging identity and signing key. The key comes
/// from the TDK secrets resolver, an in-memory store populated at startup —
/// not I/O — which is what lets the job own a plain `Secret`.
async fn sender(config: &Config, tdk: &TDK, persona: PersonaId) -> Result<Sender, String> {
    let id = config
        .identities
        .get(&persona)
        .ok_or_else(|| "this persona has no messaging identity".to_string())?;
    let atm = tdk
        .atm
        .as_ref()
        .ok_or_else(|| "messaging is unavailable".to_string())?
        .clone();
    let keys = config
        .get_persona_keys_for(persona, tdk)
        .await
        .map_err(|e| format!("couldn't read this persona's signing key: {e}"))?;
    Ok(Sender {
        atm,
        profile: id.profile().clone(),
        persona_did: id.persona_did().to_string(),
        mediator: id.mediator_did.clone().unwrap_or_default(),
        signer: Box::new(keys.signing.secret.clone()),
    })
}

/// One `git-ns/*` send, off the loop.
pub(crate) struct ReposJob {
    sender: Sender,
    vtc_did: String,
    persona: PersonaId,
    request: Request,
    purpose: Purpose,
    /// Also check did-git-sign's install and hook (on open and refresh).
    probe_signing: bool,
}

impl ReposJob {
    /// Build, sign and send. I/O only.
    pub(crate) async fn run(self) -> ReposOutcome {
        let signing = if self.probe_signing {
            let did = self.sender.persona_did.clone();
            tokio::task::spawn_blocking(move || super::signing_health::probe(&did))
                .await
                .ok()
        } else {
            None
        };
        let s = &self.sender;
        let result = async {
            let doc = git_ns::build_signed(&self.request, &s.persona_did, &self.vtc_did, &s.signer)
                .await?;
            openvtc_core::capabilities::send_capability_document(
                &s.atm,
                &s.profile,
                &s.persona_did,
                &self.vtc_did,
                &s.mediator,
                &doc,
            )
            .await
        }
        .await
        .map_err(|e| e.to_string());
        ReposOutcome {
            vtc_did: self.vtc_did,
            persona: self.persona,
            purpose: self.purpose,
            result,
            signing,
        }
    }
}

/// What a send did. Data only; applied on the loop thread.
pub(crate) struct ReposOutcome {
    vtc_did: String,
    persona: PersonaId,
    purpose: Purpose,
    /// The thread id to match the reply against, or why the send failed.
    result: Result<String, String>,
    signing: Option<SigningHealth>,
}

impl ReposOutcome {
    /// Arm the view to await the reply, or say the send never left.
    ///
    /// Dropped if the view has since closed or moved to another community: a
    /// thread id armed on the wrong community would match a reply to a question
    /// nobody asked there.
    pub(crate) fn apply(self, state: &mut State) {
        let Some(view) = view_mut(state) else {
            return;
        };
        if view.vtc_did != self.vtc_did || view.persona != self.persona {
            return;
        }
        if let Some(signing) = self.signing {
            view.signing = signing;
        }
        let now = Instant::now();
        match (self.result, self.purpose) {
            (Ok(thid), Purpose::LinkPoll) => {
                if let Some(link) = view.link.as_mut() {
                    link.last_poll = Some(now);
                    link.poll = Some(Pending {
                        thid,
                        sent_at: now,
                        purpose: Purpose::LinkPoll,
                    });
                }
            }
            (Ok(thid), purpose) => {
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
            (Err(e), Purpose::View) => {
                if view.data.is_none() {
                    view.phase = ReposPhase::Failed(format!(
                        "could not send the query to the community: {e}"
                    ));
                } else {
                    view.note(Severity::Error, format!("couldn't refresh: {e}"));
                }
            }
            (Err(e), Purpose::Change(what)) => {
                view.note(Severity::Error, format!("couldn't send ({what}): {e}"));
                tracing::error!("git-ns change failed to send: {e}");
            }
            (Err(e), Purpose::LinkStart) => {
                if let Some(link) = view.link.as_mut() {
                    link.phase = LinkPhase::Failed(format!("couldn't send: {e}"));
                }
            }
            // A poll that did not leave is retried on the next tick.
            (Err(e), Purpose::LinkPoll) => {
                if let Some(link) = view.link.as_mut() {
                    link.last_poll = Some(now);
                }
                tracing::debug!("git-ns link poll failed to send: {e}");
            }
        }
    }
}

/// The resources a send needs from the loop, borrowed. Both the action path
/// ([`ActionCtx`]) and the loop's own tick and reply arms build one.
pub(crate) struct Loop<'a> {
    pub(crate) state: &'a mut State,
    pub(crate) config: &'a Config,
    pub(crate) tdk: &'a TDK,
    pub(crate) dispatch_tx: &'a UnboundedSender<DispatchOutcome>,
    pub(crate) in_flight: &'a mut InFlight,
}

impl Loop<'_> {
    /// Send `request` for the open view. `quiet` suppresses the busy message,
    /// for sends nobody pressed a key for (polls, refresh after a change).
    /// Returns whether the send was dispatched; every early return says why
    /// in the view, unless `quiet`.
    async fn send(
        &mut self,
        request: Request,
        purpose: Purpose,
        probe_signing: bool,
        quiet: bool,
    ) -> bool {
        let Some((vtc_did, persona, waiting)) = self
            .state
            .main_page
            .content_panel
            .repos
            .view
            .as_ref()
            .map(|v| (v.vtc_did.clone(), v.persona, v.pending.clone()))
        else {
            return false;
        };
        // One request awaits its answer at a time. A second would take the
        // pending slot, and the first answer — a grant, say — would then match
        // nothing and be dropped unannounced. Polls have their own slot.
        if purpose != Purpose::LinkPoll
            && let Some(waiting) = waiting
        {
            if !quiet && let Some(view) = view_mut(self.state) {
                view.note(
                    Severity::Warning,
                    match waiting.purpose {
                        Purpose::Change(what) => {
                            format!("Still waiting for the community's answer ({what}).")
                        }
                        _ => "Still waiting for the community's answer.".into(),
                    },
                );
            }
            return false;
        }
        let sender = match sender(self.config, self.tdk, persona).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(view) = view_mut(self.state) {
                    if view.data.is_none() && purpose == Purpose::View {
                        view.phase = ReposPhase::Failed(e);
                    } else {
                        view.note(Severity::Error, e);
                    }
                }
                return false;
            }
        };
        if !self.in_flight.try_begin(DOMAIN) {
            if !quiet && let Some(view) = view_mut(self.state) {
                view.note(Severity::Warning, InFlight::busy_message(DOMAIN));
            }
            return false;
        }
        let job = ReposJob {
            sender,
            vtc_did,
            persona,
            request,
            purpose,
            probe_signing,
        };
        background_dispatch::spawn_dispatch(self.dispatch_tx.clone(), DOMAIN, async move {
            DispatchOutcome::Repos(job.run().await)
        });
        true
    }

    /// Read the view again.
    pub(crate) async fn refresh(&mut self, quiet: bool) {
        self.send(Request::View { resource: None }, Purpose::View, true, quiet)
            .await;
    }
}

/// Service an action that reads the config or sends a task.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: Act) {
    if let Act::Open(index) = action {
        open(ctx, index);
    }
    let mut lp = Loop {
        state: &mut *ctx.state,
        config: ctx.config,
        tdk: ctx.tdk,
        dispatch_tx: ctx.dispatch_tx,
        in_flight: &mut *ctx.in_flight,
    };
    match action {
        Act::Open(_) | Act::Refresh => {
            if let Some(view) = view_mut(lp.state) {
                if view.data.is_none() {
                    view.phase = ReposPhase::Loading;
                }
                view.status = None;
            }
            lp.refresh(false).await;
        }
        Act::NewSubmit => submit_new(&mut lp).await,
        Act::AddSubmit => submit_add(&mut lp).await,
        Act::Confirm => {
            let armed = view_mut(lp.state).and_then(|v| v.confirm.take());
            if let Some(armed) = armed {
                let what = describe(&armed.request);
                lp.send(armed.request, Purpose::Change(what), false, false)
                    .await;
            }
        }
        Act::LinkStart => start_link(&mut lp).await,
        // View-only: the shared reducer handled these before the loop saw them.
        _ => {}
    }
}

/// Open the panel for the Active community at a Communities display index.
fn open(ctx: &mut ActionCtx<'_>, index: usize) {
    let target = ctx
        .config
        .account
        .communities_for_display(ctx.state.main_page.content_panel.communities.show_archived)
        .get(index)
        .filter(|c| c.status.is_active())
        .map(|c| {
            (
                c.vtc_did.clone(),
                c.persona_ref,
                crate::state_handler::community_label(
                    ctx.config,
                    &c.vtc_did,
                    c.display_name.as_deref(),
                    256,
                ),
            )
        });
    let Some((vtc, persona, name)) = target else {
        return;
    };
    let me = ctx
        .config
        .identities
        .get(&persona)
        .map(|id| id.persona_did().to_string())
        .unwrap_or_default();
    ctx.state.main_page.content_panel.repos.view = Some(ReposView::new(vtc, persona, me, name));
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

async fn submit_new(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    let ReposScreen::NewRepo(form) = &view.screen else {
        return;
    };
    let creatable = view.creatable();
    let Some(ns) = creatable.get(form.namespace) else {
        return;
    };
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
        return;
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
        return;
    }
    let what = describe(&request);
    lp.send(request, Purpose::Change(what), false, false).await;
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

async fn submit_add(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
    let Some(form) = view.add.clone() else {
        return;
    };
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
                return;
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
        return;
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
        return;
    }
    let what = describe(&request);
    lp.send(request, Purpose::Change(what), false, false).await;
}

async fn start_link(lp: &mut Loop<'_>) {
    let Some(view) = view_mut(lp.state) else {
        return;
    };
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
        return;
    };
    // The attempt is shown only once its request is actually on its way: a
    // send refused here (still waiting, busy, no signing key) says why and
    // leaves no "starting…" line that nothing will ever answer.
    if lp
        .send(
            Request::Link {
                forge: forge.clone(),
            },
            Purpose::LinkStart,
            false,
            false,
        )
        .await
        && let Some(view) = view_mut(lp.state)
    {
        view.link = Some(LinkFlow::starting(forge));
    }
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
        let from_vtc = did_part(&inbound.from) == vtc;
        let issued_by_vtc = inbound.issuer.as_deref().map(did_part) == Some(vtc.as_str());
        if !(from_vtc && issued_by_vtc) {
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
            link.poll = None;
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
        // gave up on.
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
/// from the loop's five-second sweep.
pub(crate) async fn tick(lp: &mut Loop<'_>) {
    let now = Instant::now();
    let wall = Utc::now();
    let mut poll = None;
    if let Some(view) = view_mut(lp.state) {
        if view
            .pending
            .as_ref()
            .is_some_and(|p| now.duration_since(p.sent_at) > reply_window(&p.purpose))
            && let Some(p) = view.pending.take()
        {
            let secs = reply_window(&p.purpose).as_secs();
            match p.purpose {
                Purpose::View if view.data.is_none() => {
                    view.phase = ReposPhase::Failed(format!(
                        "no reply within {secs}s — the community's VTC may be offline, or may \
                         not serve git namespaces yet"
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
            // A lost poll is simply retried.
            if link
                .poll
                .as_ref()
                .is_some_and(|p| now.duration_since(p.sent_at) > REPLY_WINDOW)
            {
                link.poll = None;
            }
            if link.phase == LinkPhase::Waiting && link.expires_at.is_some_and(|e| wall >= e) {
                link.phase = LinkPhase::Expired;
            }
            if link.poll_due(now, wall)
                && let Some(link_id) = link.link_id.clone()
            {
                poll = Some(link_id);
            }
        }
    }
    if let Some(link_id) = poll {
        lp.send(
            Request::LinkStatus { link_id },
            Purpose::LinkPoll,
            false,
            true,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use openvtc_core::git_ns::{Refusal, view};
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

    fn outcome(result: Result<String, String>, purpose: Purpose) -> ReposOutcome {
        ReposOutcome {
            vtc_did: VTC.into(),
            persona: persona(),
            purpose,
            result,
            signing: None,
        }
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
        outcome(Ok("thid-1".into()), Purpose::Change("archiving x".into())).apply(&mut state);
        let v = view(&state);
        assert_eq!(v.pending.as_ref().unwrap().thid, "thid-1");
        assert!(v.status_text().unwrap().contains("awaiting"));
    }

    #[test]
    fn a_first_read_that_never_left_fails_the_view() {
        let mut state = open_state();
        view_mut(&mut state).unwrap().data = None;
        outcome(Err("peer unreachable".into()), Purpose::View).apply(&mut state);
        assert!(matches!(&view(&state).phase, ReposPhase::Failed(m) if m.contains("unreachable")));
    }

    #[test]
    fn an_outcome_for_another_community_is_dropped() {
        let mut state = open_state();
        let mut o = outcome(Ok("thid-1".into()), Purpose::View);
        o.vtc_did = "did:webvh:other".into();
        o.apply(&mut state);
        assert!(view(&state).pending.is_none());
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
        Loop {
            state: &mut state,
            config: &config,
            tdk: &tdk,
            dispatch_tx: &tx,
            in_flight: &mut in_flight,
        }
        .refresh(false)
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
            dispatch_tx: &tx,
            in_flight: &mut in_flight,
        })
        .await;
        let v = view(&state);
        assert!(v.pending.is_none());
        assert!(v.status_text().unwrap().contains("within 30s"));
    }

    // --- review follow-ups -------------------------------------------------

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
        let mut lp = Loop {
            state,
            config: &config,
            tdk: &tdk,
            dispatch_tx: &tx,
            in_flight: &mut in_flight,
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
        with_loop(&mut state, |lp| Box::pin(start_link(lp))).await;
        let v = view(&state);
        assert!(v.link.is_none(), "no attempt was started");
        assert_eq!(v.status.as_ref().unwrap().severity, Severity::Error);

        // Still waiting on another answer: likewise.
        let mut state = open_state();
        pend(&mut state, "grant-1", Purpose::Change("granting".into()));
        with_loop(&mut state, |lp| Box::pin(start_link(lp))).await;
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
}
