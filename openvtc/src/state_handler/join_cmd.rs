//! `openvtc community join` — join a community without the TUI.
//!
//! Covers the two ways in that need no questions answered: presenting an
//! invitation, or sending an open request. The submit mirrors
//! `join_flow::run_join_sequence` for an existing persona; the wait reuses the
//! TUI's inbound dispatch and join status poll, so a verdict is applied exactly
//! as the runtime loop would apply it.

use std::time::Duration;

use affinidi_tdk::TDK;
use affinidi_tdk::didcomm::Message;
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use openvtc_core::config::{
    Config, PeerTransports,
    account::{CommunityRecord, CommunityStatus, PersonaId},
    community_context,
};
use openvtc_core::didcomm::{DIDCommEvent, Messaging, MessagingTransport};
use openvtc_core::logs::LogFamily;
use openvtc_core::messaging::SeenMessages;
use openvtc_core::vetting::disclosure::DirectoryStatement;
use openvtc_core::vetting::protocol::JoinProtocol;
use serde_json::Value;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, warn};
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::did_management::create::WebvhPathMode;

use crate::headless::{self, Admin, progress, save, step};

use super::main_page::shorten_did;
use super::message_dispatch::{Arrival, InboundEffects, process_inbound_message};
use super::{DeferredLoad, create_persona, join_flow, join_status_poll};

/// Bound on resolving the community's DID (same as the TUI's).
/// How long the submit waits for the persona's mediator socket.
const PERSONA_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// First status poll after the submit, then how often the pacer is asked.
const POLL_FIRST: Duration = Duration::from_secs(30);
const POLL_EVERY: Duration = Duration::from_secs(20);
/// Label for a persona created when the account has none.
const DEFAULT_PERSONA_LABEL: &str = "member";

/// The `community join` subcommand's definition.
pub fn command() -> Command {
    Command::new("join")
        .about("Join a community without the TUI, then wait for the verdict")
        .long_about(
            "Send a join request to a community and wait, headless, for an \
             administrator's verdict.\n\n\
             With --invitation (before or after `join`) the invitation credential \
             (VIC) is presented; without one this is an open request the community's moderators decide. The \
             persona is --persona, else the only persona in the account, else a new \
             one (named by --new-persona). On admission the membership credentials \
             are stored and the account saved. Exits non-zero on rejection, timeout \
             or any failure.",
        )
        .args([
            Arg::new("vtc")
                .required(true)
                .value_name("COMMUNITY_DID")
                .help("The community's VTC DID"),
            Arg::new("persona")
                .long("persona")
                .value_name("NAME")
                .conflicts_with("new-persona")
                .help("Join as this persona: its DID, label or agent name"),
            Arg::new("new-persona")
                .long("new-persona")
                .value_name("NAME")
                .help("Create a new persona with this label and join as it"),
            Arg::new("wait")
                .long("wait")
                .value_name("DURATION")
                .default_value("30m")
                .value_parser(headless::parse_wait)
                .help("How long to wait for the verdict, e.g. 90s, 30m, 2h"),
        ])
}

/// Run `openvtc community join`. `vic` is the global `--invitation`, already verified
/// by `main`.
pub async fn run(args: &ArgMatches, deferred: DeferredLoad, vic: Option<Value>) -> Result<()> {
    let vtc_did = args
        .get_one::<String>("vtc")
        .expect("required")
        .trim()
        .to_string();
    let wait = *args.get_one::<Duration>("wait").expect("defaulted");
    let profile = deferred.profile.clone();

    step(format!("Loading account `{profile}`"));
    let (mut config, tdk, admin) = headless::load_account(deferred, Admin::Open).await?;
    let admin = admin.context("no VTA session: joining needs the account's VTA")?;
    if tdk.atm.is_none() {
        bail!("messaging is unavailable, so the join request cannot be sent");
    }
    let (messaging, mut events) = headless::start_messaging(&config).await;

    let job = Job {
        tdk: &tdk,
        admin: &admin,
        messaging: &messaging,
        profile: &profile,
        vtc_did: &vtc_did,
    };
    let result = job
        .join(
            &mut config,
            &mut events,
            vic,
            args.get_one::<String>("persona").map(String::as_str),
            args.get_one::<String>("new-persona").map(String::as_str),
            wait,
        )
        .await;

    messaging.shutdown().await;
    admin.shutdown().await;
    result
}

/// What a join needs that does not change while it runs.
struct Job<'a> {
    tdk: &'a TDK,
    admin: &'a VtaClient,
    messaging: &'a Messaging,
    profile: &'a str,
    vtc_did: &'a str,
}

impl Job<'_> {
    async fn join(
        &self,
        config: &mut Config,
        events: &mut UnboundedReceiver<DIDCommEvent>,
        vic: Option<Value>,
        persona_arg: Option<&str>,
        new_persona: Option<&str>,
        wait: Duration,
    ) -> Result<()> {
        let vtc_did = self.vtc_did;
        step(format!("Reading {vtc_did}'s requirements"));
        self.learn_requirements(config).await?;

        let persona_id = self
            .pick_persona(config, vic.as_ref(), persona_arg, new_persona)
            .await?;
        let persona_did = config
            .account
            .personas
            .get(&persona_id)
            .map(|p| p.did.clone())
            .ok_or_else(|| anyhow!("the chosen persona is not in the account"))?;
        step(format!("Persona {persona_did}"));

        let status = config
            .account
            .membership(vtc_did, persona_id)
            .map(|r| r.status.clone());
        match status {
            Some(CommunityStatus::Active) => {
                println!("membership: Active (already a member of {vtc_did} as {persona_did})");
                return Ok(());
            }
            Some(CommunityStatus::Pending { .. }) => {
                progress("a join request is already pending as this persona; waiting on it");
                self.start_listener(config, persona_id).await;
            }
            // One record per (community, persona): a finished one would be
            // read in place of the new request's.
            Some(other) => bail!(
                "this persona's earlier membership of {vtc_did} is {other:?}; join as another \
                 persona (--new-persona <name>)"
            ),
            None => self.submit(config, persona_id, &persona_did, vic).await?,
        }

        println!("waiting for an administrator to admit {persona_did}");
        self.wait_for_verdict(config, events, persona_id, &persona_did, wait)
            .await
    }

    /// Read the manifest over HTTP and refuse what this command cannot answer.
    async fn learn_requirements(&self, config: &mut Config) -> Result<()> {
        let vtc_did = self.vtc_did;
        match join_flow::learn_over_http(config, self.tdk, vtc_did).await {
            Ok(()) => {}
            Err(e) if !e.resolvable() => bail!("{vtc_did}: {}", e.reason()),
            Err(e) => progress(format!(
                "requirements not read ({}); continuing without them",
                e.reason()
            )),
        }
        if let Some(DirectoryStatement::Malformed(why)) = config.private.vetting.directory(vtc_did)
        {
            bail!(
                "the community's member-directory statement could not be read ({why}); \
                 nothing was sent"
            );
        }
        let asked = config.private.vetting.requested_attributes(vtc_did);
        let required: Vec<&str> = asked
            .iter()
            .filter(|a| a.required)
            .map(|a| a.claim_type.as_str())
            .collect();
        if !required.is_empty() {
            bail!(
                "the community requires answers this command cannot give: {}. Join from the \
                 TUI to answer them.",
                required.join(", ")
            );
        }
        if !asked.is_empty() {
            progress("the community's optional questions are left unanswered");
        }
        Ok(())
    }

    /// `--persona`, else the invitation's subject, else the only persona, else
    /// a new one.
    async fn pick_persona(
        &self,
        config: &mut Config,
        vic: Option<&Value>,
        persona_arg: Option<&str>,
        new_persona: Option<&str>,
    ) -> Result<PersonaId> {
        if let Some(label) = new_persona {
            return self.mint_persona(config, label).await;
        }
        if let Some(name) = persona_arg {
            return headless::find_persona(config, name);
        }
        if let Some(subject) = vic.and_then(openvtc_core::join::invitation_subject) {
            return config.account.persona_id_for_did(subject).ok_or_else(|| {
                anyhow!(
                    "the invitation names {subject}, which is not one of your personas; \
                     only that DID can present it"
                )
            });
        }
        let mut ids = config.account.personas.keys().copied();
        match (ids.next(), ids.next()) {
            (Some(only), None) => Ok(only),
            (None, _) => {
                progress("no persona yet; creating one");
                self.mint_persona(config, DEFAULT_PERSONA_LABEL).await
            }
            (Some(_), Some(_)) => bail!(
                "this account has several personas; choose one with --persona. {}",
                headless::persona_listing(config)
            ),
        }
    }

    /// The TUI's create-persona overlay, headless: a context of its own, a
    /// server-assigned path.
    async fn mint_persona(&self, config: &mut Config, label: &str) -> Result<PersonaId> {
        let label = label.trim();
        if label.is_empty() {
            bail!("a persona label cannot be empty");
        }
        if config.account.top_context_id.is_empty() {
            bail!("no account context yet; finish setup before creating a persona");
        }
        let context_id = create_persona::auto_context(config, label).map_err(|e| anyhow!(e))?;
        step(format!("Creating persona “{label}” in {context_id}"));
        let inputs = create_persona::MintInputs::from_config(
            config,
            context_id,
            WebvhPathMode::AutoAssign,
            None,
        );
        let minted = create_persona::mint_standalone_persona(
            self.admin,
            self.tdk,
            inputs,
            label.to_string(),
            |line: &str| progress(line),
        )
        .await?;
        let persona_id = minted
            .persist(config, self.tdk, self.profile)
            .await
            .with_context(|| format!("persona {} minted but not saved", minted.did))?;
        save(config, self.profile)?;
        progress(format!("persona created: {}", minted.did));
        Ok(persona_id)
    }

    /// Bring the persona's mediator socket up so the verdict is streamed;
    /// without it the status poll still collects the reply.
    async fn start_listener(&self, config: &Config, persona_id: PersonaId) {
        match headless::connect_persona(
            self.messaging,
            config,
            self.tdk,
            persona_id,
            PERSONA_CONNECT_TIMEOUT,
        )
        .await
        {
            Ok(()) => progress("persona connected to its mediator"),
            Err(e) => {
                debug!(error = %e, "persona not connected");
                progress(format!("{e}; the reply is collected by polling"));
            }
        }
    }

    /// `run_join_sequence` for an existing persona: context, listener,
    /// presentation, transport, submit, pending record.
    async fn submit(
        &self,
        config: &mut Config,
        persona_id: PersonaId,
        persona_did: &str,
        vic: Option<Value>,
    ) -> Result<()> {
        let vtc_did = self.vtc_did;
        let display_name =
            openvtc_core::agent_name::resolve_verified_name(self.tdk.did_resolver(), vtc_did).await;
        config.set_cached_agent_name(vtc_did, display_name.clone(), Utc::now());

        let transports = openvtc_core::config::peer_messaging_transports(vtc_did).await;
        let Some(preferred) = transports.preferred() else {
            bail!("the community advertises no messaging transport (neither TSP nor DIDComm)");
        };
        progress(format!("community reachable over {preferred}"));

        let context_id = self
            .prepare_context(config, persona_id, display_name.as_deref())
            .await?;
        self.start_listener(config, persona_id).await;

        let presentation = self
            .build_presentation(config, persona_id, persona_did, vic.as_ref())
            .await?;
        let (request_id, submit_transport) = self
            .send(config, persona_id, persona_did, &transports, presentation)
            .await?;

        let mut record = CommunityRecord::new_pending(
            vtc_did.to_string(),
            display_name,
            context_id,
            persona_id,
            request_id,
            Utc::now(),
        );
        record.submit_transport = Some(submit_transport);
        config.account.add_membership(record);
        config.public.logs.insert(
            LogFamily::Community,
            format!(
                "Join request sent to ({vtc_did}) as persona ({persona_did}) over \
                 {submit_transport} from the command line — Pending."
            ),
        );
        save(config, self.profile)?;
        step(format!(
            "Join request sent over {submit_transport} (request {request_id})"
        ));
        Ok(())
    }

    /// Sign and send the join request as the persona, over TSP when both
    /// ends carry it. Returns the request id and the transport used.
    async fn send(
        &self,
        config: &Config,
        persona_id: PersonaId,
        persona_did: &str,
        transports: &PeerTransports,
        presentation: openvtc_core::join::JoinPresentation,
    ) -> Result<(uuid::Uuid, MessagingTransport)> {
        let vtc_did = self.vtc_did;
        let (profile, mediator) = match config.identities.get(&persona_id) {
            Some(ident) => (
                ident.profile().clone(),
                ident.mediator_did.clone().unwrap_or_default(),
            ),
            None => bail!("the persona has no messaging identity"),
        };
        let tsp_mediator =
            tsp_mediator(vtc_did, &mediator, transports.didcomm_mediator.is_some()).await;
        let submit_transport = if tsp_mediator.is_some() {
            MessagingTransport::Tsp
        } else {
            MessagingTransport::DidComm
        };

        let signer = config
            .get_persona_keys_for(persona_id, self.tdk)
            .await
            .context("couldn't read the persona's signing key")?
            .authentication
            .secret
            .clone();
        let route = openvtc_core::join::Applicant {
            atm: self.tdk.atm.as_ref().expect("checked at load"),
            profile: &profile,
            persona_did,
            signer: &signer,
            vtc_did,
            mediator_did: &mediator,
            tsp_mediator_did: tsp_mediator.as_deref(),
        };
        let request_id = openvtc_core::join::submit_join_request(&route, presentation)
            .await
            .context("failed to submit the join request")?;

        Ok((request_id, submit_transport))
    }

    /// The membership's context: the persona's own, or a new one named after
    /// the community (the TUI's default choice).
    async fn prepare_context(
        &self,
        config: &Config,
        persona_id: PersonaId,
        display_name: Option<&str>,
    ) -> Result<String> {
        let vtc_did = self.vtc_did;
        let top = config.account.top_context_id.clone();
        let suggested = join_flow::suggested_context(config, vtc_did);
        let context_id = community_context::context_options(
            &config.account,
            config.account.personas.get(&persona_id),
            &suggested,
        )
        .into_iter()
        .next()
        .map(|o| o.context_id)
        .unwrap_or(suggested);
        let context_name = display_name.map_or_else(|| shorten_did(vtc_did, 48), str::to_string);
        match community_context::ensure_context(self.admin, &top, &context_id, &context_name).await
        {
            Ok(true) => progress(format!("created context {context_id}")),
            Ok(false) => progress(format!("using context {context_id}")),
            Err(e) => bail!("couldn't prepare context {context_id}: {e}"),
        }
        Ok(context_id)
    }

    /// The join presentation: the invitation if any, then the vetting
    /// statements gathered for this community.
    async fn build_presentation(
        &self,
        config: &mut Config,
        persona_id: PersonaId,
        persona_did: &str,
        vic: Option<&Value>,
    ) -> Result<openvtc_core::join::JoinPresentation> {
        let (admin, vtc_did) = (self.admin, self.vtc_did);
        // The invitation, if any. Explicit, so a mismatch is an error rather
        // than the TUI's quiet fall-back to an open request.
        let mut linkage = None;
        if let Some(vic) = vic {
            if let Err(e) = admin.cred_vault_receive(vic.clone(), None).await {
                debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
            }
            if !openvtc_core::join::invitation_matches_community(vic, vtc_did) {
                bail!("the invitation was issued by another community, not {vtc_did}");
            }
            if openvtc_core::join::invitation_is_expired(vic, Utc::now()) {
                bail!("the invitation has expired");
            }
            let subject = openvtc_core::join::invitation_subject(vic)
                .ok_or_else(|| anyhow!("the invitation names no subject"))?;
            if subject != persona_did {
                if config.account.persona_id_for_did(subject).is_none() {
                    bail!("the invitation names {subject}, which is not one of your personas");
                }
                let vic_id = openvtc_core::join::invitation_id(vic)
                    .ok_or_else(|| anyhow!("the invitation has no id"))?;
                linkage = Some(
                    config
                        .build_subject_linkage(subject, Some(admin), vic_id, persona_did)
                        .await
                        .context("couldn't link the invited persona to this one")?,
                );
                progress(format!(
                    "the invitation names {subject}; the community will see the two linked"
                ));
            }
            progress("presenting the invitation credential");
        } else {
            progress("no invitation: sending an open request for the moderators to decide");
        }
        let mut vp = openvtc_core::join::build_join_vp(persona_did, vic, linkage.as_ref());

        // Vetting statements this persona gathered for the community go with
        // it, as in the TUI. A hidden-vetting proof needs the TUI.
        let protocol = config.private.vetting.protocol_for(vtc_did);
        let presentation = match config
            .private
            .vetting
            .application(vtc_did, persona_id)
            .filter(|a| a.join_did == persona_did)
        {
            Some(application) if application.hidden.is_some() => {
                bail!("this community hides its vetters; join from the TUI to build the proof")
            }
            Some(application) => {
                let statements = application.presentable_statements(Utc::now());
                if !statements.is_empty() {
                    progress(format!(
                        "presenting {} vetting statement(s)",
                        statements.len()
                    ));
                }
                openvtc_core::join::attach_credentials(&mut vp, statements);
                openvtc_core::join::JoinPresentation {
                    vp,
                    extensions: application.join_extensions(protocol),
                    attributes: Vec::new(),
                    protocol,
                    criterion: application.requirements_digest.clone(),
                    registry_consent: false,
                }
            }
            None => openvtc_core::join::JoinPresentation {
                protocol,
                ..vp.into()
            },
        };
        Ok(presentation)
    }

    /// Apply inbound messages and poll the community until the membership
    /// leaves `Pending`, or `wait` runs out.
    async fn wait_for_verdict(
        &self,
        config: &mut Config,
        events: &mut UnboundedReceiver<DIDCommEvent>,
        persona_id: PersonaId,
        persona_did: &str,
        wait: Duration,
    ) -> Result<()> {
        let vtc_did = self.vtc_did;
        let deadline = tokio::time::Instant::now() + wait;
        let mut seen = SeenMessages::new();
        let mut pacer = join_status_poll::PollPacer::default();
        let mut poll =
            tokio::time::interval_at(tokio::time::Instant::now() + POLL_FIRST, POLL_EVERY);
        let tsp_dirty = self.messaging.tsp_store().dirty();
        let mut acknowledged = receipt_seen(config, vtc_did, persona_id);

        loop {
            match config
                .account
                .membership(vtc_did, persona_id)
                .map(|r| (r.status.clone(), r.decision.clone()))
            {
                Some((CommunityStatus::Active, _)) => break,
                Some((CommunityStatus::Pending { .. }, _)) => {}
                Some((status, decision)) => {
                    let why = decision
                        .and_then(|d| d.reason.or(d.code))
                        .map(|r| format!(": {r}"))
                        .unwrap_or_default();
                    println!("membership: {status:?}{why}");
                    bail!("the join did not succeed ({status:?})");
                }
                None => bail!("the membership record disappeared while waiting"),
            }
            if !acknowledged && receipt_seen(config, vtc_did, persona_id) {
                acknowledged = true;
                progress("the community acknowledged the request");
            }

            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    println!("membership: Pending (no verdict within {}s)", wait.as_secs());
                    bail!("timed out waiting for the verdict; the request stays Pending");
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("membership: Pending (interrupted)");
                    bail!("interrupted; the request stays Pending");
                }
                Some(event) = events.recv() => {
                    if let DIDCommEvent::InboundMessage { message, .. } = event {
                        note_verdict(&message);
                        if self.dispatch(config, &mut seen, &message).await {
                            save(config, self.profile)?;
                        }
                    }
                }
                _ = poll.tick() => {
                    let due: Vec<_> = config
                        .account
                        .pollable_pending(Utc::now())
                        .into_iter()
                        .filter(|p| p.vtc_did == vtc_did && p.persona_ref == persona_id)
                        .collect();
                    let due = pacer.due(due, std::time::Instant::now());
                    if !due.is_empty()
                        && let Some(atm) = self.tdk.atm.clone()
                    {
                        let polls = join_status_poll::build(config, self.tdk, due).await;
                        join_status_poll::send_all(atm, polls).await;
                    }
                }
                _ = tsp_dirty.notified() => {
                    config.private.tsp_relationships = self.messaging.tsp_store().snapshot().await;
                    save(config, self.profile)?;
                }
            }
        }

        step("Admitted. Storing membership credentials at the VTA");
        let report = openvtc_core::credential_sync::sync_membership_credentials(
            config,
            self.admin,
            self.tdk.did_resolver(),
        )
        .await;
        progress(format!(
            "stored {}, already held {}, failed {}, unverified {}",
            report.stored, report.already_held, report.failed, report.unverified
        ));
        save(config, self.profile)?;
        println!("membership: Active in {vtc_did} as {persona_did}");
        Ok(())
    }

    /// The runtime loop's inbound handling: dispatch, run any deferred check
    /// inline, dispatch again with its result. `true` when the config changed.
    async fn dispatch(
        &self,
        config: &mut Config,
        seen: &mut SeenMessages,
        message: &Message,
    ) -> bool {
        let nobody = |_: &str| false;
        let mut arrival = Arrival::New { waiting: &nobody };
        let mut message = message.clone();
        let mut changed = false;
        // Bounded: a returning message is handled, not set aside again.
        for _ in 0..3 {
            let mut effects = InboundEffects::default();
            match process_inbound_message(
                config,
                self.tdk,
                self.messaging,
                seen,
                &message,
                &mut effects,
                arrival,
            )
            .await
            {
                Ok(c) => changed |= c,
                Err(e) => warn!(error = %e, "inbound message not handled"),
            }
            let Some(deferred) = effects.deferred else {
                break;
            };
            arrival = Arrival::Returning(deferred.job.run(self.tdk.clone()).await);
            message = deferred.message;
        }
        changed
    }
}

/// TSP only when both ends carry it, as the TUI decides.
async fn tsp_mediator(vtc_did: &str, mediator: &str, didcomm_fallback: bool) -> Option<String> {
    let peer = openvtc_core::config::peer_tsp_mediator(vtc_did).await?;
    match openvtc_core::config::our_mediator_carries_tsp(mediator).await {
        Some(true) => Some(peer),
        Some(false) | None if didcomm_fallback => None,
        _ => Some(peer),
    }
}

/// Whether the community has acknowledged the pending request.
fn receipt_seen(config: &Config, vtc_did: &str, persona_id: PersonaId) -> bool {
    config
        .account
        .membership(vtc_did, persona_id)
        .is_some_and(|r| r.receipt_at.is_some())
}

/// Say what a `requestMore` verdict asks for; nothing else needs a line.
fn note_verdict(message: &Message) {
    if !JoinProtocol::is_submit_response(&message.typ) {
        return;
    }
    if let Some(needs) = openvtc_core::messaging::join_verdict_needs(message) {
        progress(format!(
            "the community has not decided yet: {}",
            openvtc_core::messaging::describe_join_needs(&needs, false)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_command_parses() {
        let m = command()
            .try_get_matches_from([
                "join",
                "did:webvh:x:y",
                "--persona",
                "alice",
                "--wait",
                "5m",
            ])
            .expect("valid");
        assert_eq!(
            m.get_one::<Duration>("wait"),
            Some(&Duration::from_secs(300))
        );
        assert!(
            command()
                .try_get_matches_from([
                    "join",
                    "did:webvh:x:y",
                    "--persona",
                    "a",
                    "--new-persona",
                    "b"
                ])
                .is_err(),
            "--persona and --new-persona conflict"
        );
        let m = crate::cli::cli()
            .try_get_matches_from(["openvtc", "community", "join", "did:webvh:x:y"])
            .expect("valid");
        assert_eq!(
            m.subcommand().and_then(|(_, c)| c.subcommand_name()),
            Some("join")
        );
    }
}
