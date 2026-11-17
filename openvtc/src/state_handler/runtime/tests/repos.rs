//! Runtime-harness tests pinning the repos handlers: the busy, send-failure
//! and success paths (#612).
//!
//! The offline TDK holds an ATM, so a persona from [`fixtures::persona_with_keys`]
//! gets past the key lookup and the build to the claim. Its send then fails
//! off the loop (no mediator): that is the send-failure path, awaited on
//! `rt.dispatch_rx` and fed back through `rt.on_dispatch_outcome`.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::state_handler::actions::ReposAction as Act;
use crate::state_handler::actions::WorkspaceAction;
use crate::state_handler::background_dispatch::{DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::main_page::repos::{
    ArmedChange, LinkFlow, LinkPhase, NewRepoForm, Pending, Purpose, ReposPhase, ReposScreen,
    ReposView, Severity, WorkspaceChange, WorkspaceForm,
};
use crate::state_handler::repos_actions;
use openvtc_core::config::account::PersonaId;
use openvtc_core::git_ns::{self, Request};

const VTC: &str = "did:webvh:QmVtcScid7:acme-vtc.example";
const ME: &str = "did:webvh:QmBobScid2:acme-vtc.example:bob";
const GADGETS: &str = "github.com/acme/gadgets";

/// What the community governs: a bridged namespace `ME` may create in, and
/// one repository `ME` owns.
fn data() -> git_ns::view::Response {
    serde_json::from_value(serde_json::json!({
        "accounts": [],
        "namespaces": [{"id": "ns_1", "forge": "github.com", "owner": "acme",
                        "kind": "organization", "mode": "bridge", "state": "bound"}],
        "repos": [
            {"resource": GADGETS, "forgeId": "1", "visibility": "public",
             "state": "active", "owners": [ME],
             "bootstrap": {"workflow": true, "keyring": true, "variables": true, "requiredCheck": true},
             "sync": {"state": "inSync", "drift": []}}
        ],
        "rights": [
            {"subject": ME, "right": "git.repo.create", "resource": "github.com/acme",
             "grantedBy": ME, "grantedAt": "2026-09-01T00:00:00Z"},
            {"subject": ME, "right": "git.repo.own", "resource": GADGETS,
             "grantedBy": ME, "grantedAt": "2026-09-02T00:00:00Z"}
        ]
    }))
    .expect("a view response")
}

/// Open the panel on `VTC` as `persona`, loaded when `loaded`.
fn open_view(rt: &mut Runtime, persona: PersonaId, loaded: bool) {
    let mut view = ReposView::new(VTC.into(), persona, ME.into(), "Acme".into());
    if loaded {
        view.data = Some(Arc::new(data()));
        view.phase = ReposPhase::Loaded;
    }
    rt.state.main_page.content_panel.repos.view = Some(view);
}

/// A persona whose keys resolve, a member of `VTC`, with the panel open.
async fn ready(rt: &mut Runtime, loaded: bool) -> PersonaId {
    let persona = fixtures::persona_with_keys(rt, ME).await;
    fixtures::active_membership(rt, VTC, persona);
    open_view(rt, persona, loaded);
    persona
}

fn view(rt: &Runtime) -> &ReposView {
    rt.state
        .main_page
        .content_panel
        .repos
        .view
        .as_ref()
        .expect("the panel stays open")
}

fn view_mut(rt: &mut Runtime) -> &mut ReposView {
    rt.state
        .main_page
        .content_panel
        .repos
        .view
        .as_mut()
        .expect("the panel stays open")
}

fn status(rt: &Runtime) -> Option<(Severity, String)> {
    view(rt)
        .status
        .as_ref()
        .map(|s| (s.severity, s.text.clone()))
}

fn arm_archive(rt: &mut Runtime) {
    view_mut(rt).confirm = Some(ArmedChange {
        summary: "Archive gadgets?".into(),
        request: Request::Archive {
            resource: GADGETS.into(),
        },
    });
}

/// A link attempt the member is authorising, due its first poll.
fn waiting_link() -> LinkFlow {
    let mut link = LinkFlow::starting("github.com".into());
    link.phase = LinkPhase::Waiting;
    link.link_id = Some("lnk_1".into());
    link
}

/// The git-ns send's outcome, once the job reports back.
async fn git_ns_outcome(rt: &mut Runtime) -> DispatchOutcome {
    loop {
        let outcome = tokio::time::timeout(Duration::from_secs(30), rt.dispatch_rx.recv())
            .await
            .expect("the send reports back")
            .expect("the channel is open");
        if matches!(outcome, DispatchOutcome::Repos(_)) {
            return outcome;
        }
        rt.on_dispatch_outcome(outcome).await;
    }
}

fn busy() -> String {
    InFlight::busy_message(DispatchDomain::GitNs)
}

// ---- refusals before the claim ----

/// A confirmed change on a busy lane is refused: the confirmation is spent,
/// nothing is armed, and the busy message is shown.
#[tokio::test]
async fn a_confirmed_change_on_a_busy_lane_is_refused_and_arms_nothing() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    arm_archive(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::GitNs));

    rt.on_action(Action::Repos(Act::Confirm)).await;

    let v = view(&rt);
    assert!(v.confirm.is_none(), "a `y` answers one confirmation");
    assert!(v.pending.is_none(), "nothing is awaited");
    assert_eq!(status(&rt), Some((Severity::Warning, busy())));
    assert!(!rt.save.needs_flush());
}

/// The persona's key is looked up before the lane is claimed: with no
/// messaging identity, a busy lane is never reached and the lookup's reason
/// is what is shown.
#[tokio::test]
async fn the_key_lookup_comes_before_the_busy_lane() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    arm_archive(&mut rt);
    assert!(rt.in_flight.try_begin(DispatchDomain::GitNs));

    rt.on_action(Action::Repos(Act::Confirm)).await;

    assert!(view(&rt).confirm.is_none());
    assert!(view(&rt).pending.is_none());
    assert_eq!(
        status(&rt),
        Some((
            Severity::Error,
            "this persona has no messaging identity".into()
        ))
    );
}

/// One request awaits its answer at a time: a second is refused with what the
/// first is, before any key lookup or claim.
#[tokio::test]
async fn a_change_while_another_awaits_its_answer_says_still_waiting() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    arm_archive(&mut rt);
    view_mut(&mut rt).pending = Some(Pending {
        thid: "grant-1".into(),
        sent_at: Instant::now(),
        purpose: Purpose::Change("granting maintainer".into()),
    });

    rt.on_action(Action::Repos(Act::Confirm)).await;

    let v = view(&rt);
    assert!(v.confirm.is_none());
    assert_eq!(v.pending.as_ref().map(|p| p.thid.as_str()), Some("grant-1"));
    assert_eq!(
        status(&rt),
        Some((
            Severity::Warning,
            "Still waiting for the community's answer (granting maintainer).".into()
        ))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::GitNs));
}

/// A read refused while another waits names no purpose.
#[tokio::test]
async fn a_refresh_while_a_read_awaits_says_still_waiting() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    view_mut(&mut rt).pending = Some(Pending {
        thid: "view-1".into(),
        sent_at: Instant::now(),
        purpose: Purpose::View,
    });

    rt.on_action(Action::Repos(Act::Refresh)).await;

    assert_eq!(
        status(&rt),
        Some((
            Severity::Warning,
            "Still waiting for the community's answer.".into()
        ))
    );
}

/// A first read whose key lookup fails fails the view; a refresh of a loaded
/// view says it on the status line instead.
#[tokio::test]
async fn a_read_whose_key_lookup_fails_fails_an_empty_view_else_notes_it() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), false);
    rt.on_action(Action::Repos(Act::Refresh)).await;
    assert_eq!(
        view(&rt).phase,
        ReposPhase::Failed("this persona has no messaging identity".into())
    );
    assert!(
        view(&rt).status.is_none(),
        "a refresh clears the status first"
    );

    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    rt.on_action(Action::Repos(Act::Refresh)).await;
    assert_eq!(view(&rt).phase, ReposPhase::Loaded);
    assert_eq!(
        status(&rt),
        Some((
            Severity::Error,
            "this persona has no messaging identity".into()
        ))
    );
    assert!(!rt.in_flight.is_busy(DispatchDomain::GitNs));
}

/// A request the schema refuses is caught after the key lookup, before the
/// claim, and said with what it was for.
#[tokio::test]
async fn a_request_that_does_not_build_is_said_and_claims_nothing() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    view_mut(&mut rt).confirm = Some(ArmedChange {
        summary: "Archive?".into(),
        request: Request::Archive {
            resource: "not a resource".into(),
        },
    });

    rt.on_action(Action::Repos(Act::Confirm)).await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitNs));
    assert!(view(&rt).pending.is_none());
    let (severity, text) = status(&rt).expect("the refusal is shown");
    assert_eq!(severity, Severity::Error);
    assert!(text.starts_with("couldn't send (archiving "), "{text}");
}

/// A link attempt refused on a busy lane leaves no "starting…" behind.
#[tokio::test]
async fn a_link_start_on_a_busy_lane_starts_no_attempt() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    assert!(rt.in_flight.try_begin(DispatchDomain::GitNs));

    rt.on_action(Action::Repos(Act::LinkStart)).await;

    assert!(view(&rt).link.is_none());
    assert!(view(&rt).pending.is_none());
    assert_eq!(status(&rt), Some((Severity::Warning, busy())));
}

/// A refresh nobody pressed a key for (after a change landed) says nothing
/// when its lane is busy.
#[tokio::test]
async fn a_quiet_refresh_on_a_busy_lane_says_nothing() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    assert!(rt.in_flight.try_begin(DispatchDomain::GitNs));
    {
        let Runtime {
            state,
            config,
            tdk,
            admin_vta,
            dispatch_tx,
            in_flight,
            pending_replies,
            ..
        } = &mut rt;
        repos_actions::refresh(
            &mut repos_actions::Loop {
                state,
                config,
                tdk,
                vta: admin_vta.as_ref(),
                dispatch_tx,
                in_flight,
                pending_replies,
            },
            true,
        )
        .await;
    }
    assert!(view(&rt).status.is_none());
    assert!(view(&rt).pending.is_none());
}

// ---- the claim, and the send that then fails ----

/// A confirmed change that starts claims the lane, then arms the view on its
/// thread and says it is waiting; the send failing off the loop frees the
/// lane, ends the wait and says why. Nothing is persisted.
#[tokio::test]
async fn a_confirmed_change_claims_then_arms_and_a_failed_send_ends_the_wait() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    arm_archive(&mut rt);

    rt.on_action(Action::Repos(Act::Confirm)).await;

    assert!(rt.in_flight.is_busy(DispatchDomain::GitNs));
    let v = view(&rt);
    assert!(v.confirm.is_none());
    let pending = v.pending.as_ref().expect("armed once claimed");
    assert_eq!(
        pending.purpose,
        Purpose::Change("archiving acme/gadgets".into())
    );
    assert!(pending.thid.starts_with("urn:uuid:"), "{}", pending.thid);
    assert_eq!(
        status(&rt),
        Some((
            Severity::Progress,
            "archiving acme/gadgets… awaiting the community's reply".into()
        ))
    );

    let outcome = git_ns_outcome(&mut rt).await;
    rt.on_dispatch_outcome(outcome).await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitNs));
    assert!(view(&rt).pending.is_none());
    let (severity, text) = status(&rt).expect("the failure is shown");
    assert_eq!(severity, Severity::Error);
    assert!(
        text.starts_with("couldn't send (archiving acme/gadgets): "),
        "{text}"
    );
    assert!(!rt.save.needs_flush());
}

/// A first read: the view shows loading and awaits the answer; a send that
/// never left fails the view.
#[tokio::test]
async fn a_first_read_waits_and_a_failed_send_fails_the_view() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, false).await;
    view_mut(&mut rt).phase = ReposPhase::Failed("earlier".into());
    view_mut(&mut rt).status = Some(crate::state_handler::main_page::repos::Status::error("old"));

    rt.on_action(Action::Repos(Act::Refresh)).await;

    assert!(rt.in_flight.is_busy(DispatchDomain::GitNs));
    let v = view(&rt);
    assert_eq!(v.phase, ReposPhase::Loading);
    assert!(v.status.is_none(), "a read says nothing while it waits");
    assert_eq!(v.pending.as_ref().map(|p| &p.purpose), Some(&Purpose::View));

    let outcome = git_ns_outcome(&mut rt).await;
    rt.on_dispatch_outcome(outcome).await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitNs));
    assert!(matches!(
        &view(&rt).phase,
        ReposPhase::Failed(why) if why.starts_with("could not send the query to the community: ")
    ));
}

/// A new repository for the requester alone is sent at once.
#[tokio::test]
async fn a_new_repository_for_me_alone_is_sent_at_once() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    let form = NewRepoForm {
        name: "gizmos".into(),
        ..NewRepoForm::default()
    };
    view_mut(&mut rt).screen = ReposScreen::NewRepo(form);

    rt.on_action(Action::Repos(Act::NewSubmit)).await;

    assert!(rt.in_flight.is_busy(DispatchDomain::GitNs));
    let v = view(&rt);
    assert!(v.confirm.is_none());
    assert_eq!(
        v.pending.as_ref().map(|p| &p.purpose),
        Some(&Purpose::Change("creating gizmos".into()))
    );
    assert!(
        matches!(v.screen, ReposScreen::NewRepo(_)),
        "the form stays"
    );
}

/// A link attempt is shown once its request is on its way, and waits sixty
/// seconds; a send that never left fails it.
#[tokio::test]
async fn a_link_start_claims_then_shows_the_attempt() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;

    rt.on_action(Action::Repos(Act::LinkStart)).await;

    assert!(rt.in_flight.is_busy(DispatchDomain::GitNs));
    let v = view(&rt);
    assert_eq!(
        v.pending.as_ref().map(|p| &p.purpose),
        Some(&Purpose::LinkStart)
    );
    let link = v.link.as_ref().expect("the attempt is shown");
    assert_eq!(link.forge, "github.com");
    assert_eq!(link.phase, LinkPhase::Starting);
    assert!(v.status.is_none(), "a link start says nothing more");

    let outcome = git_ns_outcome(&mut rt).await;
    rt.on_dispatch_outcome(outcome).await;
    assert!(matches!(
        &view(&rt).link.as_ref().unwrap().phase,
        LinkPhase::Failed(why) if why.starts_with("couldn't send: ")
    ));
}

// ---- the sweep: reply windows and link polls ----

/// A due poll is sent on the sweep — even while a change awaits its answer,
/// polls having their own slot — and armed on the link once claimed. One that
/// never left frees its slot, says why once, and backs the next poll off.
#[tokio::test]
async fn a_due_link_poll_is_sent_on_the_sweep_beside_a_pending_change() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    view_mut(&mut rt).link = Some(waiting_link());
    view_mut(&mut rt).pending = Some(Pending {
        thid: "grant-1".into(),
        sent_at: Instant::now(),
        purpose: Purpose::Change("granting maintainer".into()),
    });

    rt.on_capabilities_sweep().await;

    assert!(rt.in_flight.is_busy(DispatchDomain::GitNs));
    let v = view(&rt);
    assert_eq!(v.pending.as_ref().map(|p| p.thid.as_str()), Some("grant-1"));
    let link = v.link.as_ref().unwrap();
    let poll = link.poll.as_ref().expect("the poll is awaited");
    assert_eq!(poll.purpose, Purpose::LinkPoll);
    assert!(link.last_poll.is_some());
    assert!(v.status.is_none(), "a poll says nothing");

    let outcome = git_ns_outcome(&mut rt).await;
    rt.on_dispatch_outcome(outcome).await;
    let v = view(&rt);
    let link = v.link.as_ref().unwrap();
    assert!(link.poll.is_none(), "retried once its interval passes");
    assert_eq!(link.failures, 1);
    assert!(link.poll_interval() > git_ns::LINK_POLL_INTERVAL);
    assert_eq!(v.pending.as_ref().map(|p| p.thid.as_str()), Some("grant-1"));
    let (severity, text) = status(&rt).expect("the failure is said");
    assert_eq!(severity, Severity::Error);
    assert!(
        text.starts_with("couldn't check the link with the community: "),
        "{text}"
    );
}

/// A due poll on a busy lane is quiet and leaves the link unpolled.
#[tokio::test]
async fn a_due_link_poll_on_a_busy_lane_is_quiet() {
    let (mut rt, _h) = runtime().await;
    ready(&mut rt, true).await;
    view_mut(&mut rt).link = Some(waiting_link());
    assert!(rt.in_flight.try_begin(DispatchDomain::GitNs));

    rt.on_capabilities_sweep().await;

    let v = view(&rt);
    let link = v.link.as_ref().unwrap();
    assert!(link.poll.is_none());
    assert!(link.last_poll.is_none());
    assert!(v.status.is_none());
}

/// A due poll whose key lookup fails says so, as an error on the status line,
/// once: the next sweep does not poll before the backed-off interval, and a
/// poll that fails the same way again does not say it again.
#[tokio::test]
async fn a_due_link_poll_whose_key_lookup_fails_says_so_once_and_backs_off() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    view_mut(&mut rt).link = Some(waiting_link());

    rt.on_capabilities_sweep().await;

    let link = view(&rt).link.clone().unwrap();
    assert!(link.poll.is_none());
    assert_eq!(link.failures, 1);
    assert_eq!(
        status(&rt),
        Some((
            Severity::Error,
            "this persona has no messaging identity".into()
        ))
    );

    // Not due again at once: the sweep does not retry it.
    view_mut(&mut rt).status = None;
    rt.on_capabilities_sweep().await;
    assert_eq!(view(&rt).link.as_ref().unwrap().failures, 1);
    assert!(status(&rt).is_none());

    // Once due, it fails the same way: backed off further, not said again.
    let interval = link.poll_interval();
    view_mut(&mut rt).link.as_mut().unwrap().last_poll =
        Some(Instant::now().checked_sub(interval).unwrap());
    rt.on_capabilities_sweep().await;
    let link = view(&rt).link.clone().unwrap();
    assert_eq!(link.failures, 2);
    assert!(link.poll_interval() > interval);
    assert!(status(&rt).is_none(), "the same failure is said once");
}

/// A change unanswered past its window ends on the sweep, saying it may have
/// landed.
#[tokio::test]
async fn an_unanswered_change_ends_on_the_sweep() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    view_mut(&mut rt).pending = Some(Pending {
        thid: "t".into(),
        sent_at: ago(repos_actions::REPLY_WINDOW.as_secs() + 1),
        purpose: Purpose::Change("archiving acme/gadgets".into()),
    });

    rt.on_capabilities_sweep().await;

    assert!(view(&rt).pending.is_none());
    let (severity, text) = status(&rt).unwrap();
    assert_eq!(severity, Severity::Error);
    assert!(text.contains("may have been applied"), "{text}");
}

// ---- the workspace: local jobs ----
//
// Set-up is the job pinned end to end: with the test config's keys held
// locally (no VTA), it fails at once inside the job without touching git,
// did-git-sign or the filesystem. Saving the settings form is a job too; its
// write is unit-tested in `repos_workspace`.

fn workspace(w: WorkspaceAction) -> Action {
    Action::Repos(Act::Workspace(w))
}

/// A job while another of the panel's own runs says what is running and
/// claims nothing.
#[tokio::test]
async fn a_workspace_job_while_one_runs_says_what_is_running() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    view_mut(&mut rt).workspace.busy = Some("cloning acme/gadgets".into());

    rt.on_action(workspace(WorkspaceAction::SetUp)).await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitWorkspace));
    assert_eq!(
        status(&rt),
        Some((
            Severity::Warning,
            "Still cloning acme/gadgets — please wait.".into()
        ))
    );
}

/// Saving the settings while a job runs is refused like any job: the job
/// may be writing the same settings file.
#[tokio::test]
async fn saving_the_settings_while_a_job_runs_is_refused() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    view_mut(&mut rt).workspace.busy = Some("cloning acme/gadgets".into());
    view_mut(&mut rt).workspace.form = Some(WorkspaceForm::Settings {
        root: "/srv/code".into(),
        protocol: None,
        error: None,
    });

    rt.on_action(workspace(WorkspaceAction::SettingsSubmit))
        .await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitWorkspace));
    assert_eq!(
        status(&rt),
        Some((
            Severity::Warning,
            "Still cloning acme/gadgets — please wait.".into()
        ))
    );
    assert!(view(&rt).workspace.form.is_some(), "the form stays");
}

/// A job refused for want of a target says so and claims nothing.
#[tokio::test]
async fn a_clone_with_nothing_highlighted_is_refused() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), false);

    rt.on_action(workspace(WorkspaceAction::Clone)).await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitWorkspace));
    assert!(view(&rt).workspace.busy.is_none());
    assert_eq!(
        status(&rt),
        Some((Severity::Warning, "Highlight a repository first.".into()))
    );
}

/// A job on a busy lane is refused with the busy message and marks nothing
/// running; a confirmed removal is spent all the same.
#[tokio::test]
async fn a_workspace_job_on_a_busy_lane_is_refused_and_marks_nothing() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);
    view_mut(&mut rt).workspace.confirm = Some(WorkspaceChange::RemoveIdentity);
    assert!(rt.in_flight.try_begin(DispatchDomain::GitWorkspace));

    rt.on_action(workspace(WorkspaceAction::Confirm)).await;

    let v = view(&rt);
    assert!(
        v.workspace.confirm.is_none(),
        "a `y` answers one confirmation"
    );
    assert!(v.workspace.busy.is_none());
    assert_eq!(
        status(&rt),
        Some((
            Severity::Warning,
            InFlight::busy_message(DispatchDomain::GitWorkspace)
        ))
    );
}

/// A job that starts claims the lane, then marks the workspace busy and says
/// so; its failure frees the lane, clears the mark, says why and wants a
/// probe. Nothing is persisted.
#[tokio::test]
async fn a_workspace_job_claims_then_marks_busy_and_its_failure_is_said() {
    let (mut rt, _h) = runtime().await;
    open_view(&mut rt, PersonaId::new(), true);

    rt.on_action(workspace(WorkspaceAction::SetUp)).await;

    assert!(rt.in_flight.is_busy(DispatchDomain::GitWorkspace));
    assert_eq!(
        view(&rt).workspace.busy.as_deref(),
        Some("setting did-git-sign up")
    );
    assert_eq!(
        status(&rt),
        Some((Severity::Progress, "Setting did-git-sign up…".into()))
    );

    let outcome = loop {
        let outcome = tokio::time::timeout(Duration::from_secs(30), rt.dispatch_rx.recv())
            .await
            .expect("the job reports back")
            .expect("the channel is open");
        if matches!(outcome, DispatchOutcome::Workspace(_)) {
            break outcome;
        }
        rt.on_dispatch_outcome(outcome).await;
    };
    rt.on_dispatch_outcome(outcome).await;

    assert!(!rt.in_flight.is_busy(DispatchDomain::GitWorkspace));
    let v = view(&rt);
    assert!(v.workspace.busy.is_none());
    assert_eq!(v.workspace.probe_wanted, Some(true));
    assert_eq!(
        status(&rt),
        Some((
            Severity::Error,
            "openvtc's keys are not held by a VTA, so there is no key for did-git-sign".into()
        ))
    );
    assert!(!rt.save.needs_flush());
}
