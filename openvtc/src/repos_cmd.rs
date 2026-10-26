//! `openvtc repo` — the Repos panel without the TUI.
//!
//! `list` sends one signed `git-ns/view` to the community's VTC and prints the
//! repositories the persona holds a right on; `clone` does the same, then
//! clones one of them as the panel's `c` does (without setting up signing).
//!
//! The request goes out exactly as the panel sends it; the answer is awaited
//! on a persona listener of our own, the way the TUI's state handler receives
//! it, and is taken only when it threads on our request, comes from the
//! community, and carries the community's valid signature.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use clap::{Arg, ArgMatches, Command};
use console::style;
use openvtc_core::capabilities::{correlation_thread, parse_envelope_document};
use openvtc_core::config::Config;
use openvtc_core::didcomm::{self, DIDCommEvent};
use openvtc_core::git_ns::{self, GitRight, Reply, Request};
use openvtc_core::git_workspace::{self, CLONE_TIMEOUT, RepoCoords, WorkspaceSettings};
use tokio::sync::mpsc;

use crate::colors::{CLI_ERROR, CLI_INFO, Themed};
use crate::headless::{self, Admin, Membership, progress, warn};
use crate::state_handler::{DeferredLoad, repos_actions};

/// How long a request waits for the community's answer (as the panel does).
const REPLY_WINDOW: Duration = Duration::from_secs(30);

/// How long the persona's mediator socket may take to come up.
const CONNECT_WINDOW: Duration = Duration::from_secs(30);

pub fn command() -> Command {
    let community = Arg::new("community")
        .long("community")
        .value_name("DID-OR-NAME")
        .help(
            "The community, by VTC DID or name. Optional when the account holds \
             exactly one active membership.",
        );
    Command::new("repo")
        .about("The Repos panel without the TUI: list, clone and sign repositories")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("list")
                .about("List the repositories you hold a right on, with that right")
                .arg(community.clone()),
        )
        .subcommand(
            Command::new("clone")
                .about("Clone one repository you hold a right on (signing is not set up)")
                .args([
                    Arg::new("resource")
                        .value_name("RESOURCE")
                        .required(true)
                        .help("The repository, e.g. gitlab.com/group/repo"),
                    Arg::new("dir")
                        .long("dir")
                        .value_name("PATH")
                        .help("Where to clone it (default: the workspace root's layout)"),
                    community,
                ]),
        )
        .subcommand(crate::signing_cmd::command())
}

pub async fn run(matches: &ArgMatches, deferred: DeferredLoad) -> Result<()> {
    match matches.subcommand() {
        Some(("list", args)) => list(args, deferred).await,
        Some(("clone", args)) => clone(args, deferred).await,
        Some(("sign", args)) => crate::signing_cmd::run(args, deferred).await,
        _ => bail!("unknown repo subcommand"),
    }
}

// ****************************************************************************
// Subcommands
// ****************************************************************************

async fn list(args: &ArgMatches, deferred: DeferredLoad) -> Result<()> {
    let profile = deferred.profile.clone();
    let (config, tdk) = load(deferred).await?;
    let target = pick(
        &config,
        args.get_one::<String>("community").map(String::as_str),
    )?;
    let rows = fetch_my_repos(&config, &tdk, &target).await?;
    let settings = workspace_settings(&profile);
    if rows.is_empty() {
        println!("You hold no right on any repository in {}.", target.label);
        return Ok(());
    }
    let width = rows.iter().map(|r| r.resource.len()).max().unwrap_or(0);
    println!(
        "{:width$}  {:16}  {:12}  LOCAL",
        "RESOURCE", "RIGHT", "STATUS"
    );
    for r in &rows {
        let local = RepoCoords::parse(&r.resource)
            .ok()
            .and_then(|c| settings.locate(&c))
            .map(|p| git_workspace::display_path(&p))
            .unwrap_or_else(|| "-".into());
        println!(
            "{:width$}  {:16}  {:12}  {local}",
            r.resource,
            r.right.label(),
            r.status
        );
    }
    Ok(())
}

async fn clone(args: &ArgMatches, deferred: DeferredLoad) -> Result<()> {
    let profile = deferred.profile.clone();
    let resource = args
        .get_one::<String>("resource")
        .map(String::as_str)
        .unwrap_or_default()
        .trim_end_matches('/');
    // Refused before anything is loaded or sent.
    let coords = RepoCoords::parse(resource)?;
    let dir = args
        .get_one::<String>("dir")
        .map(|d| git_workspace::expand_tilde(d));

    let (config, tdk) = load(deferred).await?;
    let target = pick(
        &config,
        args.get_one::<String>("community").map(String::as_str),
    )?;
    let rows = fetch_my_repos(&config, &tdk, &target).await?;
    let Some(row) = rows.iter().find(|r| r.resource == coords.resource()) else {
        bail!(
            "you hold no right on {} in {} (`openvtc repo list` shows the ones you do)",
            coords.resource(),
            target.label
        );
    };
    progress(format!(
        "You are {} on {}.",
        row.right.label(),
        row.resource
    ));

    let mut settings = workspace_settings(&profile);
    if dir.is_none()
        && let Some(path) = settings.locate(&coords)
    {
        println!(
            "{} is already checked out at {}.",
            row.resource,
            git_workspace::display_path(&path)
        );
        return Ok(());
    }
    let dest = dir
        .clone()
        .unwrap_or_else(|| coords.default_path(&settings.root));
    let credential = settings.credential_for(&target.vtc_did, &coords).credential;
    progress(format!(
        "Cloning into {} ({})…",
        git_workspace::display_path(&dest),
        credential.label()
    ));
    let (vtc, c, d, s) = (
        target.vtc_did.clone(),
        coords.clone(),
        dest.clone(),
        settings.clone(),
    );
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        // A missing key or a logged-out gh account, said before git runs.
        credential.check(&c.host)?;
        let gh = openvtc_core::forge_credential::forge_facts(&c.host).gh_protocol;
        let (protocol, _) = s.protocol_for(&vtc, &c, gh);
        let author = match credential.author(&c.host) {
            Some(Ok(a)) => Some(a),
            Some(Err(e)) => {
                eprintln!("note: commits keep your own git identity: {e}");
                None
            }
            None => None,
        };
        git_workspace::clone_repo(
            &c,
            protocol,
            &credential,
            author.as_ref(),
            &d,
            CLONE_TIMEOUT,
        )
    })
    .await
    .map_err(|e| anyhow!("the clone stopped unexpectedly: {e}"))?
    .map_err(|e| anyhow!(e))?;

    // A checkout outside the default layout is remembered, so the panel finds it.
    if let Some(path) = dir
        && path != coords.default_path(&settings.root)
    {
        let abs = std::path::absolute(&path).unwrap_or(path);
        settings.checkouts.insert(coords.resource(), abs);
        if let Err(e) = WorkspaceSettings::path(&profile).and_then(|p| settings.save_to(&p)) {
            warn(format!(
                "couldn't record the checkout in the workspace settings: {e}"
            ));
        }
    }
    println!(
        "{}",
        style(format!(
            "Cloned {} into {}. Commit signing is not set up: run `openvtc repo sign {}`.",
            row.resource,
            git_workspace::display_path(&dest),
            git_workspace::display_path(&dest)
        ))
        .themed(CLI_INFO)
    );
    Ok(())
}

// ****************************************************************************
// Account and community
// ****************************************************************************

/// The account, without an admin VTA session: this command never needs one.
async fn load(deferred: DeferredLoad) -> Result<(Config, affinidi_tdk::TDK)> {
    progress("Loading the account…");
    let (config, tdk, _) = headless::load_account(deferred, Admin::Drop).await?;
    Ok((config, tdk))
}

fn pick(config: &Config, wanted: Option<&str>) -> Result<Membership> {
    let m = headless::pick_community(config, wanted)?;
    progress(format!("Community: {} ({})", m.label, m.vtc_did));
    Ok(m)
}

fn workspace_settings(profile: &str) -> WorkspaceSettings {
    WorkspaceSettings::path(profile)
        .and_then(|p| WorkspaceSettings::load_from(&p))
        .unwrap_or_else(|e| {
            warn(format!(
                "couldn't read the workspace settings, using the defaults: {e}"
            ));
            WorkspaceSettings::default()
        })
}

// ****************************************************************************
// The git-ns exchange
// ****************************************************************************

/// One repository row: the strongest right held, and where it stands.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    resource: String,
    right: GitRight,
    status: String,
}

/// Ask the community for `git-ns/view` and read the persona's repositories.
async fn fetch_my_repos(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    target: &Membership,
) -> Result<Vec<Row>> {
    let (me, reply) = ask(config, tdk, target, Request::View { resource: None }).await?;
    match reply {
        Reply::View(data) => Ok(git_ns::my_repos(&data, &me)
            .into_iter()
            .map(|r| Row {
                resource: r.resource,
                right: r.right,
                status: r.status.label(),
            })
            .collect()),
        Reply::Refused(r) => {
            eprintln!("{}", style(r.explain()).themed(CLI_ERROR));
            bail!("the community refused the request ({})", r.code)
        }
        Reply::Unreadable { task, detail } => {
            bail!("the community's {task} answer is unreadable: {detail}")
        }
        other => bail!("the community answered with something unexpected: {other:?}"),
    }
}

/// Send `request` as the persona, as the Repos panel does, and wait for the
/// community's answer. Returns the persona DID it was asked as, and the answer.
async fn ask(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    target: &Membership,
    request: Request,
) -> Result<(String, Reply)> {
    // Listen first, so a fast answer is not stored unread at the mediator.
    let (service, mut event_rx) = headless::start_messaging(config).await;
    let result = async {
        // Outbound TSP must share the listener's relationship store.
        let tdk = service
            .tsp_store()
            .adopt_into(tdk.clone())
            .await
            .unwrap_or_else(|_| tdk.clone());
        progress("Connecting to the mediator…");
        headless::connect_persona(&service, config, &tdk, target.persona, CONNECT_WINDOW).await?;

        let sender = repos_actions::sender(config, &tdk, target.persona, &target.vtc_did)
            .await
            .map_err(|e| anyhow!(e))?;
        let mut doc = git_ns::build(&request, &sender.persona_did, &target.vtc_did)?;
        let thid = correlation_thread(&doc).to_string();
        progress(format!(
            "Asking the community ({} over {})…",
            request.type_uri().trim_start_matches(git_ns::TYPE_PREFIX),
            if sender.over_tsp { "TSP" } else { "DIDComm" }
        ));
        repos_actions::sign_and_send(&sender, &target.vtc_did, &mut doc)
            .await
            .map_err(|e| anyhow!("couldn't send the request: {e}"))?;

        let reply = await_reply(
            &mut event_rx,
            &tdk,
            &target.vtc_did,
            &sender.persona_did,
            &thid,
        )
        .await?;
        Ok((sender.persona_did, reply))
    }
    .await;
    service.shutdown().await;
    result
}

/// Wait out [`REPLY_WINDOW`] for the answer threaded on `thid`.
async fn await_reply(
    event_rx: &mut mpsc::UnboundedReceiver<DIDCommEvent>,
    tdk: &affinidi_tdk::TDK,
    vtc_did: &str,
    persona_did: &str,
    thid: &str,
) -> Result<Reply> {
    let deadline = tokio::time::Instant::now() + REPLY_WINDOW;
    // Why a reply on our thread was not taken, for the timeout message.
    let mut rejected: Option<String> = None;
    loop {
        let event = match tokio::time::timeout_at(deadline, event_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => bail!("the messaging runtime stopped before the community answered"),
            Err(_) => {
                return Err(match rejected {
                    Some(why) => anyhow!(
                        "no acceptable answer within {}s: a reply arrived but was refused ({why})",
                        REPLY_WINDOW.as_secs()
                    ),
                    None => anyhow!(
                        "the community did not answer within {}s; check `openvtc health`",
                        REPLY_WINDOW.as_secs()
                    ),
                });
            }
        };
        let DIDCommEvent::InboundMessage { message, .. } = event else {
            continue;
        };
        match take_reply(&message, tdk, vtc_did, persona_did, thid).await {
            Some(Ok(reply)) => return Ok(reply),
            Some(Err(why)) => {
                tracing::warn!("git-ns reply on our thread refused: {why}");
                rejected = Some(why);
            }
            None => {}
        }
    }
}

/// The answer to our request, if `message` is it. `Some(Err)` is a reply on
/// our thread that failed a check; `None` is anything else.
async fn take_reply(
    message: &affinidi_tdk::didcomm::Message,
    tdk: &affinidi_tdk::TDK,
    vtc_did: &str,
    persona_did: &str,
    thid: &str,
) -> Option<Result<Reply, String>> {
    let opened = didcomm::open_didcomm_envelope(message);
    let message = opened.as_ref().unwrap_or(message);
    if !git_ns::is_reply_type(&message.typ) {
        return None;
    }
    let (_, doc) = parse_envelope_document(&message.body)?;
    let (reply_thid, reply) = git_ns::parse_reply(&doc)?;
    if reply_thid != thid {
        return None;
    }
    let from = message.from.as_deref().unwrap_or_default();
    if !repos_actions::answered_by(vtc_did, from, doc.issuer.as_deref()) {
        return Some(Err(format!(
            "sent by {from}, not the community it was asked of"
        )));
    }
    if let Err(e) = openvtc_core::operational::verify_operational(
        &message.body,
        from,
        &[persona_did],
        &message.typ,
        tdk.did_resolver(),
        &openvtc_core::operational::SeenDocuments::default(),
        chrono::Utc::now(),
    )
    .await
    {
        return Some(Err(format!("signature or envelope check failed: {e}")));
    }
    Some(Ok(reply))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[test]
    fn repos_subcommands_parse() {
        let m = crate::cli::cli()
            .try_get_matches_from([
                "openvtc",
                "repo",
                "clone",
                "gitlab.com/group/sub/repo",
                "--dir",
                "/tmp/x",
                "--community",
                "Alpha",
            ])
            .unwrap();
        let (_, repos) = m.subcommand().unwrap();
        let (sub, clone) = repos.subcommand().unwrap();
        assert_eq!(sub, "clone");
        assert_eq!(
            clone.get_one::<String>("resource").map(String::as_str),
            Some("gitlab.com/group/sub/repo")
        );
        assert!(
            crate::cli::cli()
                .try_get_matches_from(["openvtc", "repo", "list"])
                .is_ok()
        );
        assert!(
            crate::cli::cli()
                .try_get_matches_from(["openvtc", "repo", "clone"])
                .is_err(),
            "clone needs a resource"
        );
        let m = crate::cli::cli()
            .try_get_matches_from(["openvtc", "repo", "sign", "/tmp/x", "--persona", "alice"])
            .unwrap();
        let (_, repo) = m.subcommand().unwrap();
        let (sub, sign) = repo.subcommand().unwrap();
        assert_eq!(sub, "sign");
        assert_eq!(
            sign.get_one::<String>("path").map(String::as_str),
            Some("/tmp/x")
        );
    }
}
