//! The join flow, driven by the loop that owns it (#529).
//!
//! The join is a state machine: [`JoinDriver`] holds the open join (a
//! [`JoinSession`]) and each of its methods does one step and returns, so
//! while the join screen is up every other arm of the runtime — saves, VTA
//! supervision, inbound messages, timers — keeps running.
//!
//! - **Actions** reach [`JoinDriver::on_action`] from the owning loop's action
//!   arm. The pure page logic runs there, on the loop.
//! - **Long network work** runs as an off-loop job on
//!   [`DispatchDomain::Join`], one at a time. Its result comes back as
//!   [`DispatchOutcome::Join`] carrying the job's generation, which
//!   [`JoinDriver::on_outcome`] matches against the job it is waiting for (an
//!   aborted or superseded job's result is ignored), and its progress lines as
//!   [`ProgressUpdate::Join`], applied by [`JoinDriver::on_progress`].
//! - **While a job is in flight** the join actions are queued and replayed, in
//!   order, once it has finished — except the ways out: `JoinCancel` and
//!   `Exit` abort the job at once.
//! - **A launch** is a saga ([`JoinSaga`]): off-loop stages with on-loop
//!   applies between them, each recording what it did. Every way a launch can
//!   stop short — a failed stage, a cancel, an interrupt — undoes it from
//!   [`JoinSaga::compensations`], so what is rolled back does not depend on
//!   where an `.await` happened to be when a future was dropped.
//!
//! Short, bounded sends (a manifest or challenge question, a wallet-session
//! request) and the VTA reads behind the Answers page stay inline awaits on
//! the loop, as they are everywhere else in the runtime.
//!
//! Everything that touches the network, the disk or a live messaging account
//! goes through [`JoinIo`], so a test can drive a whole launch offline and fail
//! it at any stage.

use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc};

use affinidi_tdk::{did_resolver::DIDCacheClient, secrets_resolver::secrets::Secret};
use openvtc_core::config::{PeerTransports, PersonaDIDKeys, keys::SubjectSigner};
use openvtc_core::didcomm::{ListenerSpec, MessagingTransport};
use openvtc_core::errors::OpenVTCError;
use openvtc_core::join::{
    SubjectLinkage,
    saga::{Compensation, JoinSaga},
    sequence::{NotLearned, OverHttp, PreparedSubmit, SubmitError},
};
use openvtc_core::persona::join_answers::Asked;
use openvtc_core::vetting::hidden::HiddenParams;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    watch,
};
use tracing::error;
use vta_sdk::protocols::join_requests::JoinRequestAttribute;

use super::*;
use crate::state_handler::{
    background_dispatch::{DispatchDomain, DispatchOutcome, InFlight, ProgressUpdate},
    save_coalesce::SaveScheduler,
    setup_sequence::SetupState,
};

#[cfg(test)]
mod tests;

/// A boxed future, as [`JoinIo`] returns them.
pub(crate) type IoFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything a join step acts on, lent by the loop that owns the join.
///
/// The runtime loop lends its own; the State-A loop lends what it has, with
/// `messaging` its listener-less service.
pub(crate) struct JoinCtx<'a> {
    pub state: &'a mut State,
    pub config: &'a mut Config,
    pub tdk: &'a TDK,
    pub admin_vta: Option<&'a VtaClient>,
    pub messaging: Option<&'a Messaging>,
    pub profile: &'a str,
    pub save: &'a mut SaveScheduler,
    pub dispatch_tx: &'a UnboundedSender<DispatchOutcome>,
    pub in_flight: &'a mut InFlight,
    pub state_tx: &'a watch::Sender<Arc<State>>,
}

/// What a join step asks of the loop that owns it.
pub(crate) enum JoinStep {
    /// The join goes on: nothing for the loop to do.
    Continue,
    /// User cancelled / finished — return to the main page and resume the
    /// caller's loop. Carries the just-joined session when a join succeeded, so
    /// the runtime loop can register it + start its listener live (R-B-5).
    Returned(Option<JoinedSession>),
    /// The community was asked what it requires. The caller keeps the join
    /// screen up, waits for the answer, and enters the flow again
    /// ([`AwaitingRequirements`]).
    AwaitRequirements(AwaitingRequirements),
    /// The launch is parked on the challenge its hidden-vetting proof binds;
    /// the caller hears the answer and enters the flow again
    /// ([`AwaitingChallenge`]).
    AwaitChallenge(AwaitingChallenge),
    /// The launch is parked on a wallet session ([`AwaitingWallet`]).
    AwaitWallet(AwaitingWallet),
    /// Application is exiting (Exit / interrupt).
    Exit(Interrupted),
}

/// A finished off-loop join job, as it comes back over the dispatch channel.
pub(crate) struct JoinOutcome {
    generation: u64,
    result: JobResult,
}

/// What a job brought back.
enum JobResult {
    Resolved(Result<String, String>),
    Discovered(Box<Discovered>),
    Reached(Reached),
    Context(Result<bool, String>),
    Minted(Box<MintedParts>),
    Invited(Invited),
    Presented(Presented),
    Submitted(Submitted),
    /// The job panicked and brought back nothing.
    Panicked,
}

/// Where a running job says what it is doing: the join page's log, as it
/// happens rather than when the job ends.
#[derive(Clone)]
pub(crate) struct Progress {
    tx: UnboundedSender<DispatchOutcome>,
    generation: u64,
}

impl Progress {
    /// Say `line` on the join page.
    pub(crate) fn say(&self, line: impl Into<String>) {
        let _ = self
            .tx
            .send(DispatchOutcome::Progress(ProgressUpdate::Join {
                generation: self.generation,
                line: line.into(),
            }));
    }
}

// ---------------------------------------------------------------------------
// The I/O seam
// ---------------------------------------------------------------------------

/// What reading a community needs: its invitations, its manifest, its DID
/// document — any of them.
pub(crate) struct DiscoverReq {
    pub resolver: DIDCacheClient,
    pub admin_vta: Option<VtaClient>,
    pub vtc_did: String,
    /// Collect the community's usable invitations, with the one loaded by hand
    /// (if any). `None` when they are already collected.
    pub invitations: Option<Option<serde_json::Value>>,
    /// Read the manifest from the community's REST endpoint.
    pub manifest: bool,
    pub document: DocumentWhen,
}

/// When to resolve a community's DID document, to learn how it signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DocumentWhen {
    Never,
    Always,
    /// Only when the manifest could not be read: a read manifest records it.
    IfManifestFails,
}

/// What reading a community found.
#[derive(Default)]
pub(crate) struct Discovered {
    pub invitations: Option<Vec<AvailableVic>>,
    pub manifest: Option<Result<OverHttp, NotLearned>>,
    pub document: Option<affinidi_tdk::did_common::Document>,
}

/// A launch's first stage: how the community is named, and what it offers.
pub(crate) struct ReachReq {
    pub resolver: DIDCacheClient,
    pub vtc_did: String,
}

pub(crate) struct Reached {
    pub display_name: Option<String>,
    pub transports: PeerTransports,
}

/// The community's context at the VTA, made if it is missing.
pub(crate) struct ContextReq {
    pub admin_vta: VtaClient,
    pub top_context_id: String,
    pub context_id: String,
    pub name: String,
}

/// The four VTA calls that mint a persona.
pub(crate) struct MintReq {
    pub admin_vta: VtaClient,
    pub tdk: TDK,
    pub context_id: String,
    pub presentation: vta_sdk::client::DidPresentation,
}

/// What the mint got as far as making, and why it stopped if it did.
#[derive(Default)]
pub(crate) struct MintedParts {
    pub keys: Option<PersonaDIDKeys>,
    pub update: Option<(Secret, Secret)>,
    pub did: Option<vta::MintedDid>,
    pub failure: Option<String>,
}

/// Bring the applicant online and settle the invitation to present.
pub(crate) struct InviteReq {
    pub messaging: Option<Messaging>,
    /// The listener to install — `None` when there is none to install (no
    /// service, or one already serving this persona).
    pub listener: Option<ListenerSpec>,
    pub admin_vta: VtaClient,
    pub resolver: DIDCacheClient,
    pub vtc_did: String,
    /// The person chose to present an invitation.
    pub present: bool,
    /// The invitation loaded by hand, if any.
    pub loaded: Option<serde_json::Value>,
    /// The loaded invitation's subject when it is none of our personas.
    pub foreign: Option<String>,
}

pub(crate) struct Invited {
    /// Whether the listener came up; `None` when none was installed.
    pub listener_up: Option<bool>,
    /// The invitation to present, verified.
    pub presentable: Option<serde_json::Value>,
}

/// The VTA work of presenting: the subject-linkage proof, the answers from a
/// face, the hidden-vetting proof.
pub(crate) struct PresentReq {
    pub admin_vta: VtaClient,
    pub linkage: Option<LinkagePlan>,
    pub answers: Option<AnswersPlan>,
    pub hidden: Option<HiddenPlan>,
}

pub(crate) struct LinkagePlan {
    pub signer: SubjectSigner,
    pub subject: String,
    pub vic_id: String,
    pub presenter: String,
    /// What the join page says once the proof is built.
    pub said: String,
}

pub(crate) struct AnswersPlan {
    pub context_id: String,
    pub persona_did: String,
    pub community_did: String,
    pub asked: Vec<Asked>,
    pub face_id: String,
    pub approved: Vec<(String, serde_json::Value)>,
}

/// A hidden-vetting launch's proof: refused before the VTA is asked, or asked
/// for.
pub(crate) enum HiddenPlan {
    Refuse(String),
    Prove {
        application_id: String,
        params: Box<HiddenParams>,
        digest: String,
        challenge: String,
    },
}

pub(crate) struct Presented {
    pub linkage: Option<SubjectLinkage>,
    pub attributes: Vec<JoinRequestAttribute>,
    pub proof: Option<serde_json::Value>,
    /// Why the join stops here; nothing was sent.
    pub failure: Option<String>,
}

/// The send.
pub(crate) struct SubmitReq {
    pub messaging: Option<Messaging>,
    pub vtc_did: String,
    pub applicant_did: String,
    pub mediator: String,
    pub transports: PeerTransports,
    /// What the send needs from the config, or why it could not be read —
    /// said only after the wire is settled, as it always was.
    pub prepared: Result<Option<PreparedSubmit>, SubmitError>,
    pub presentation: openvtc_core::join::JoinPresentation,
}

pub(crate) struct Submitted {
    pub transport: MessagingTransport,
    pub online: bool,
    pub request: Result<uuid::Uuid, SubmitError>,
}

/// Everything the join does that touches the network, the disk or a live
/// messaging account. [`LiveIo`] in production; a test supplies its own.
///
/// The `'static` methods are the off-loop jobs. The borrowing ones run on the
/// loop, where they always did: they are here only because they need an ATM,
/// a keyring or a mediator that a test does not have.
pub(crate) trait JoinIo: Send + Sync {
    fn resolve(
        &self,
        resolver: DIDCacheClient,
        name: String,
    ) -> IoFuture<'static, Result<String, String>>;
    fn discover(&self, req: DiscoverReq) -> IoFuture<'static, Discovered>;
    fn reach(&self, req: ReachReq, progress: Progress) -> IoFuture<'static, Reached>;
    fn context(&self, req: ContextReq) -> IoFuture<'static, Result<bool, String>>;
    fn mint(&self, req: MintReq, progress: Progress) -> IoFuture<'static, MintedParts>;
    fn invite(&self, req: InviteReq, progress: Progress) -> IoFuture<'static, Invited>;
    fn present(&self, req: PresentReq, progress: Progress) -> IoFuture<'static, Presented>;
    fn submit(&self, req: SubmitReq, progress: Progress) -> IoFuture<'static, Submitted>;

    /// Write a just-minted persona into the account (and save it).
    fn persist_mint<'a>(
        &'a self,
        config: &'a mut Config,
        setup: &'a SetupState,
        tdk: &'a TDK,
        profile: &'a str,
    ) -> IoFuture<'a, anyhow::Result<PersonaId>>;
    /// Whether an ATM is up to send with.
    fn can_message(&self, tdk: &TDK) -> bool;
    /// A persona's messaging identity: the DID it sends as and its mediator.
    fn identity(&self, config: &Config, persona: PersonaId) -> Option<(String, String)>;
    /// The listener to install for the applicant, when there is one to install.
    fn listener_spec<'a>(
        &'a self,
        messaging: Option<&'a Messaging>,
        config: &'a Config,
        tdk: &'a TDK,
        persona: PersonaId,
        did: &'a str,
    ) -> IoFuture<'a, Option<ListenerSpec>>;
    /// Read what the send needs out of the config.
    fn prepare_submit<'a>(
        &'a self,
        config: &'a Config,
        tdk: &'a TDK,
        persona: PersonaId,
    ) -> IoFuture<'a, Result<Option<PreparedSubmit>, SubmitError>>;
    fn remove_listener<'a>(&'a self, messaging: &'a Messaging, id: &'a str) -> IoFuture<'a, ()>;
    /// Persist the config now.
    fn save<'a>(
        &'a self,
        save: &'a mut SaveScheduler,
        config: &'a Config,
    ) -> IoFuture<'a, Result<(), OpenVTCError>>;
}

/// The join's I/O, for real.
pub(crate) struct LiveIo;

impl JoinIo for LiveIo {
    fn resolve(
        &self,
        resolver: DIDCacheClient,
        name: String,
    ) -> IoFuture<'static, Result<String, String>> {
        Box::pin(async move {
            openvtc_core::agent_name::resolve_identifier(&resolver, &name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn discover(&self, req: DiscoverReq) -> IoFuture<'static, Discovered> {
        Box::pin(async move {
            let DiscoverReq {
                resolver,
                admin_vta,
                vtc_did,
                invitations,
                manifest,
                document,
            } = req;
            let invitations = match invitations {
                Some(loaded) => Some(
                    collect_available_vics(
                        loaded.as_ref(),
                        admin_vta.as_ref(),
                        &resolver,
                        &vtc_did,
                    )
                    .await,
                ),
                None => None,
            };
            let manifest = if manifest {
                Some(sequence::fetch_over_http(&resolver, &vtc_did).await)
            } else {
                None
            };
            let resolve = match document {
                DocumentWhen::Never => false,
                DocumentWhen::Always => true,
                DocumentWhen::IfManifestFails => matches!(manifest, Some(Err(_))),
            };
            let document = if resolve {
                sequence::resolve_document(&resolver, &vtc_did).await
            } else {
                None
            };
            Discovered {
                invitations,
                manifest,
                document,
            }
        })
    }

    fn reach(&self, req: ReachReq, _progress: Progress) -> IoFuture<'static, Reached> {
        Box::pin(async move {
            // Resolve the community's verified agent name for display
            // (best-effort). A verified name (`example.com/@acme`) is the
            // community's human-readable handle; `None` when it has no
            // verifiable name, so the sub-context derivation falls back to the
            // DID-derived token (D9).
            let display_name =
                openvtc_core::agent_name::resolve_verified_name(&req.resolver, &req.vtc_did).await;
            // Preflight the community's transports, before anything is minted.
            let transports = openvtc_core::config::peer_messaging_transports(&req.vtc_did).await;
            Reached {
                display_name,
                transports,
            }
        })
    }

    fn context(&self, req: ContextReq) -> IoFuture<'static, Result<bool, String>> {
        Box::pin(async move {
            community_context::ensure_context(
                &req.admin_vta,
                &req.top_context_id,
                &req.context_id,
                &req.name,
            )
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn mint(&self, req: MintReq, progress: Progress) -> IoFuture<'static, MintedParts> {
        Box::pin(async move {
            let MintReq {
                admin_vta,
                tdk,
                context_id,
                presentation,
            } = req;
            let mut parts = MintedParts::default();
            // Every key and the DID in the community's context.
            match vta::create_persona_keys(&admin_vta, Some(&context_id)).await {
                Ok(keys) => parts.keys = Some(keys),
                Err(e) => {
                    parts.failure = Some(format!("Failed to create persona keys: {e}"));
                    return parts;
                }
            }
            // WebVH update keys.
            progress.say("Creating DID update keys…");
            match vta::create_update_keys(&admin_vta, Some(&context_id)).await {
                Ok(update) => parts.update = Some(update),
                Err(e) => {
                    parts.failure = Some(format!("Failed to create update keys: {e}"));
                    return parts;
                }
            }
            // Pick the first WebVH server. Serverless mint is a deliberate follow-up.
            progress.say("Finding a DID hosting server…");
            let server_id = match vta::list_webvh_servers(&admin_vta).await {
                Ok(servers) => match servers.into_iter().next() {
                    Some(s) => s.id,
                    None => {
                        parts.failure = Some(
                            "No WebVH server available from the VTA (serverless mint not yet supported)."
                                .to_string(),
                        );
                        return parts;
                    }
                },
                Err(e) => {
                    parts.failure = Some(format!("Failed to list WebVH servers: {e}"));
                    return parts;
                }
            };
            // Create the persona did:webvh via the server (auto-assigned path).
            progress.say(format!("Creating persona DID via {server_id}…"));
            match vta::create_did_via_server(
                &admin_vta,
                &tdk,
                &context_id,
                &server_id,
                WebvhPathMode::AutoAssign,
                presentation,
            )
            .await
            {
                Ok(minted) => parts.did = Some(minted),
                Err(e) => parts.failure = Some(format!("Failed to create persona DID: {e}")),
            }
            parts
        })
    }

    fn invite(&self, req: InviteReq, progress: Progress) -> IoFuture<'static, Invited> {
        Box::pin(async move {
            let InviteReq {
                messaging,
                listener,
                admin_vta,
                resolver,
                vtc_did,
                present,
                loaded,
                foreign,
            } = req;
            // Open the applicant's mailbox before knocking on the door. The VTC
            // decides a well-formed invited join in under a second and pushes
            // the VMC + role VEC straight back, and a mediator only
            // *live-streams* a message whose recipient is connected at the
            // instant it lands. Connecting first closes that window at the only
            // end we control; the submit waits, bounded, for the socket
            // (`applicant_online`).
            //
            // Failure is never fatal. A join whose applicant could not connect
            // is still a valid join: the reply waits in the mailbox for the
            // persona's listener to pick up (R6.4: the operator is told what
            // happened, not handed one generic hint).
            let listener_up = match (messaging.as_ref(), listener.as_ref()) {
                (Some(service), Some(spec)) => Some(
                    match openvtc_core::didcomm::add_listener(service, spec).await {
                        Err(e) => {
                            progress.say(format!(
                                "Couldn't open this persona's mediator session ({e}) — submitting \
                                 anyway; the community's reply will be collected when it connects."
                            ));
                            false
                        }
                        Ok(()) => {
                            progress.say("Connecting the new persona to its mediator…");
                            true
                        }
                    },
                ),
                _ => None,
            };
            // #2: resolve the VIC to present for THIS community. A VIC's issuer
            // is the community's VTC DID, so a presentable invitation must
            // match `vtc_did` and be unexpired. An explicitly loaded VIC is
            // still stored in the vault regardless (its durable home), but only
            // *presented* when it matches; otherwise fall back to a
            // community-matched VIC the vault already holds, else submit as an
            // open request. All vault calls are best-effort.
            let mut presentable: Option<serde_json::Value> = None;
            if present {
                if let Some(vic) = loaded {
                    if let Err(e) = admin_vta.cred_vault_receive(vic.clone(), None).await {
                        debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
                    }
                    if !openvtc_core::join::invitation_matches_community(&vic, &vtc_did) {
                        progress.say(
                            "Loaded invitation is for a different community — \
                             looking for one that matches…",
                        );
                    } else if openvtc_core::join::invitation_is_expired(&vic, Utc::now()) {
                        progress.say("Loaded invitation has expired — looking for a valid one…");
                    } else {
                        presentable = Some(vic);
                    }
                }
                if presentable.is_none() {
                    presentable = load_invitation_from_vault(&admin_vta, &vtc_did).await;
                }
            } else if let Some(vic) = loaded {
                // The operator chose to join *without* an invitation. Still
                // store a loaded VIC in the vault but present nothing — this is
                // what honours the choice over the vault fallback above.
                if let Err(e) = admin_vta.cred_vault_receive(vic, None).await {
                    debug!(error = %e, "storing invitation in the VTA vault failed (continuing)");
                }
                match foreign {
                    // Not a choice the operator made: say what stopped the invitation.
                    Some(subject) => progress.say(format!(
                        "Your invitation names {}, which is not one of your personas — \
                         the community accepts it only from that DID, so this is an open \
                         request (awaiting approval).",
                        shorten_did(&sanitize_display(&subject, 256), 48)
                    )),
                    None => progress.say(
                        "Joining without an invitation — submitting an open request (awaiting approval).",
                    ),
                }
            }
            // Completeness gate before presenting: a VIC resolved from the vault
            // may predate the ingest-time validation. An incomplete VIC is
            // unusable — the VTC can't extract it and silently refers the join to
            // a moderator — so drop it and fall to an open request with a reason.
            if let Some(vic) = &presentable
                && let Err(why) =
                    openvtc_core::join::verify_invitation_credential(vic, &resolver, Utc::now())
                        .await
            {
                progress.say(format!(
                    "Resolved invitation is not usable ({why}) — submitting as an open request instead."
                ));
                presentable = None;
            }
            Invited {
                listener_up,
                presentable,
            }
        })
    }

    fn present(&self, req: PresentReq, progress: Progress) -> IoFuture<'static, Presented> {
        Box::pin(async move {
            let PresentReq {
                admin_vta,
                linkage,
                answers,
                hidden,
            } = req;
            let refused = |linkage, attributes, why: String| Presented {
                linkage,
                attributes,
                proof: None,
                failure: Some(why),
            };
            // Subject-linkage (#1b): when the presenting DID differs from the
            // VIC subject, prove the subject authorized this presenter (signed
            // with the subject persona's key). Best-effort: a signing failure is
            // logged and the join presents without it.
            let linkage = match linkage {
                None => None,
                Some(plan) => match plan
                    .signer
                    .sign(Some(&admin_vta), &plan.vic_id, &plan.presenter)
                    .await
                {
                    Ok(linkage) => {
                        // Presenting through another persona is a disclosure:
                        // the community learns that the persona it invited
                        // vouches for this one.
                        progress.say(plan.said);
                        Some(linkage)
                    }
                    Err(e) => {
                        debug!(subject = %plan.subject, error = %e, "subject-linkage proof unavailable");
                        None
                    }
                },
            };
            // The community's questions, answered from the face the holder chose
            // on the Answers page — through a disclosure, so the holder's own
            // history records what they told the community.
            let attributes = match answers {
                None => Vec::new(),
                Some(a) => {
                    progress.say("Answering the community's questions from your face…");
                    match answer_from_face(
                        &admin_vta,
                        &a.context_id,
                        &a.persona_did,
                        &a.community_did,
                        &a.asked,
                        &a.face_id,
                        &a.approved,
                    )
                    .await
                    {
                        Ok(attributes) => attributes,
                        Err(e) => return refused(linkage, Vec::new(), e),
                    }
                }
            };
            // Under a hidden-vetting criterion the proof is built here, bound to
            // a challenge of this submission's own (design §8). Every way the
            // proof can be missing stops the join: submitting without it sends no
            // vetting at all.
            let proof = match hidden {
                None => None,
                Some(HiddenPlan::Refuse(why)) => return refused(linkage, attributes, why),
                Some(HiddenPlan::Prove {
                    application_id,
                    params,
                    digest,
                    challenge,
                }) => {
                    progress.say("Proving that enough vetters vetted you, without naming them…");
                    match openvtc_core::vetting::pcs_vta::prove(
                        &admin_vta,
                        &application_id,
                        &params,
                        &digest,
                        &challenge,
                    )
                    .await
                    {
                        Ok(proof) => Some(proof),
                        Err(e)
                            if e.is(openvtc_core::vetting::pcs_vta::tasks::prove::v0_1::error_codes::NO_USABLE_ATTESTATION) =>
                        {
                            return refused(linkage, attributes, NO_ATTESTATION.to_string());
                        }
                        Err(e) => {
                            return refused(
                                linkage,
                                attributes,
                                format!(
                                    "The zero-knowledge proof of your vetting could not be built \
                                     ({e}). Nothing was sent — joining without it would present \
                                     no vetting at all."
                                ),
                            );
                        }
                    }
                }
            };
            Presented {
                linkage,
                attributes,
                proof,
                failure: None,
            }
        })
    }

    fn submit(&self, req: SubmitReq, progress: Progress) -> IoFuture<'static, Submitted> {
        Box::pin(async move {
            let SubmitReq {
                messaging,
                vtc_did,
                applicant_did,
                mediator,
                transports,
                prepared,
                presentation,
            } = req;
            // Settle the wire (TSP needs both legs; `choose_submit_route` says why).
            let route = sequence::choose_submit_route(&vtc_did, &mediator, &transports).await;
            if let Some(note) = route.note {
                progress.say(note.describe());
            }
            let transport = route.transport();
            // Last gate before the request goes out: the socket started earlier
            // has had the invitation + VP work to come up, so this is normally
            // already true.
            let online = applicant_online(messaging.as_ref(), &applicant_did, &progress).await;
            let request = match prepared {
                Ok(Some(prepared)) => {
                    sequence::submit_prepared(&prepared, &vtc_did, &route, presentation).await
                }
                Ok(None) => Err(SubmitError::NoMessaging),
                Err(e) => Err(e),
            };
            Submitted {
                transport,
                online,
                request,
            }
        })
    }

    fn persist_mint<'a>(
        &'a self,
        config: &'a mut Config,
        setup: &'a SetupState,
        tdk: &'a TDK,
        profile: &'a str,
    ) -> IoFuture<'a, anyhow::Result<PersonaId>> {
        Box::pin(<Config as ConfigExtension>::mint_persona_into(
            config, setup, tdk, profile,
        ))
    }

    fn can_message(&self, tdk: &TDK) -> bool {
        tdk.atm.is_some()
    }

    fn identity(&self, config: &Config, persona: PersonaId) -> Option<(String, String)> {
        config.identities.get(&persona).map(|ident| {
            (
                ident.persona_did().to_string(),
                ident.mediator_did.clone().unwrap_or_default(),
            )
        })
    }

    fn listener_spec<'a>(
        &'a self,
        messaging: Option<&'a Messaging>,
        config: &'a Config,
        tdk: &'a TDK,
        persona: PersonaId,
        did: &'a str,
    ) -> IoFuture<'a, Option<ListenerSpec>> {
        Box::pin(applicant_listener(messaging, config, tdk, persona, did))
    }

    fn prepare_submit<'a>(
        &'a self,
        config: &'a Config,
        tdk: &'a TDK,
        persona: PersonaId,
    ) -> IoFuture<'a, Result<Option<PreparedSubmit>, SubmitError>> {
        Box::pin(async move {
            sequence::prepare_submit(config, tdk, persona)
                .await
                .map(Some)
        })
    }

    fn remove_listener<'a>(&'a self, messaging: &'a Messaging, id: &'a str) -> IoFuture<'a, ()> {
        Box::pin(messaging.remove_listener(id))
    }

    fn save<'a>(
        &'a self,
        save: &'a mut SaveScheduler,
        config: &'a Config,
    ) -> IoFuture<'a, Result<(), OpenVTCError>> {
        Box::pin(save.flush(config))
    }
}

/// The listener to install for the applicant persona, so its socket is coming
/// up while the rest of the launch runs.
///
/// `Some` **only when the launch should install one** — that is the launch's
/// claim on it, recorded in its saga so a failure or cancel tears it down.
/// `None` covers every case where there is nothing to install, and so nothing
/// to undo: no messaging service (State A with none), a reused persona that is
/// already live (one identity, one listener — D1/D11; tearing it down on a
/// cancelled join would take another community's session with it), or a
/// persona with no listener config.
pub(super) async fn applicant_listener(
    messaging: Option<&Messaging>,
    config: &Config,
    tdk: &TDK,
    persona_id: PersonaId,
    applicant_did: &str,
) -> Option<ListenerSpec> {
    let service = messaging?;
    let listener_id = openvtc_core::didcomm::persona_listener_id(applicant_did);
    if service.has_listener(&listener_id).await {
        return None;
    }
    let spec = openvtc_core::didcomm::persona_listener_config_for(config, tdk, persona_id).await;
    if spec.is_none() {
        // The mint wrote this identity moments ago, so this is unexpected — but
        // it costs the join nothing, so log it and carry on.
        debug!(
            persona = %applicant_did,
            "no listener config for the applicant persona; submitting without a live session"
        );
    }
    spec
}

/// Wait — bounded by [`PERSONA_CONNECT_TIMEOUT`] — for the applicant persona's
/// socket to be live, immediately before the join request goes out.
///
/// Returns whether the applicant was live at the moment of the submit — which
/// the durable join record then states, because "sent while offline" is the one
/// fact that explains a join taking the slow (collect-on-connect) path. A
/// persona with no listener at all is nothing to wait for.
async fn applicant_online(
    messaging: Option<&Messaging>,
    applicant_did: &str,
    progress: &Progress,
) -> bool {
    let Some(service) = messaging else {
        return false;
    };
    let listener_id = openvtc_core::didcomm::persona_listener_id(applicant_did);
    if !service.has_listener(&listener_id).await {
        return false;
    }
    match service
        .wait_connected(&listener_id, PERSONA_CONNECT_TIMEOUT)
        .await
    {
        Ok(()) => {
            progress.say("Persona connected — ready to receive the community's reply.");
            true
        }
        Err(e) => {
            // Installed but not up yet. The listener's own restart policy keeps
            // working on it, so this is a slow connect, not a dead one.
            debug!(listener = %listener_id, error = %e, "applicant persona not connected before submit");
            progress.say(
                "The persona's mediator session is still connecting — submitting now; the \
                 community's reply will be collected once it is up.",
            );
            false
        }
    }
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// The join flow, as a state machine its owning loop drives.
pub(crate) struct JoinDriver {
    /// Whether the owning loop hears inbound messages, and so can wait for a
    /// community's answer.
    hears_replies: bool,
    /// Bumped for every job, so a result is matched to the job that asked.
    generation: u64,
    session: Option<JoinSession>,
    /// Actions queued during a job that are now due, for the loop to take
    /// before reading its channel again.
    leftover: VecDeque<Action>,
    io: Arc<dyn JoinIo>,
}

/// An open join.
struct JoinSession {
    hears_replies: bool,
    job: Option<Job>,
    launch: Option<Launch>,
    /// Join actions that arrived while a job was in flight.
    queued: VecDeque<Action>,
}

/// The job in flight, and what its result is for.
struct Job {
    generation: u64,
    abort: tokio::task::AbortHandle,
    then: Then,
    /// The submit stage: the request may already be on the wire, so the job
    /// is past the point where cancelling can undo it.
    submitting: bool,
}

enum Then {
    /// An agent name was resolved: enter the community it names.
    Enter,
    /// A community was read.
    Discovered { vtc_did: String, purpose: Purpose },
    /// A launch stage finished.
    Stage,
}

/// Why a community was read.
enum Purpose {
    /// Entering it: decide which page answers it. `knew` is what the book knew
    /// before the manifest was read again.
    Enter { knew: Option<bool> },
    /// Back from waiting for its requirements.
    Resume(RequirementsOutcome),
    /// Only its invitations were missing: go on with the join.
    ContinueJoin,
    /// Only its invitations were missing: open the invitation step.
    InvitationChoice(PersonaId),
}

/// A launch in progress: what was chosen, what it has done, and what it has
/// learned on the way.
struct Launch {
    vtc_did: String,
    choice: IdentityPick,
    context_id: String,
    admin: VtaClient,
    saga: JoinSaga,
    /// `mint_persona_into` may overwrite `public.friendly_name`; a rollback
    /// restores it.
    prior_friendly_name: String,
    registry_consent: bool,
    directory_statement_digest: Option<String>,
    display_name: Option<String>,
    transports: PeerTransports,
    /// The keys a minted persona was made with, for its rollback.
    minted_keys: Option<PersonaDIDKeys>,
    /// The persona presented, and its DID.
    persona: Option<(PersonaId, String)>,
    /// The applicant's messaging DID and mediator.
    applicant: Option<(String, String)>,
}

impl JoinDriver {
    /// A driver for a loop that hears inbound messages (`hears_replies`), or
    /// does not (State A).
    pub(crate) fn new(hears_replies: bool) -> Self {
        Self::with_io(hears_replies, Arc::new(LiveIo))
    }

    pub(crate) fn with_io(hears_replies: bool, io: Arc<dyn JoinIo>) -> Self {
        Self {
            hears_replies,
            generation: 0,
            session: None,
            leftover: VecDeque::new(),
            io,
        }
    }

    /// Whether a join is open — its screen up and its actions this driver's.
    pub(crate) fn is_active(&self) -> bool {
        self.session.is_some()
    }

    /// The next action for the owning loop: one queued during a join job that
    /// is now due, else the next from the channel.
    pub(crate) async fn next_action(
        &mut self,
        action_rx: &mut UnboundedReceiver<Action>,
    ) -> Option<Action> {
        if let Some(action) = self.leftover.pop_front() {
            return Some(action);
        }
        action_rx.recv().await
    }

    /// Open the join flow.
    pub(crate) async fn enter(&mut self, ctx: &mut JoinCtx<'_>, entry: JoinEntry) -> JoinStep {
        if self.session.is_some() {
            debug!("a join was entered while one was open; the open one is cancelled");
            self.cancel(ctx).await;
        }
        let state = &mut *ctx.state;
        // Enter the flow on a fresh EnterDid page — unless this is a launch
        // coming back with its challenge, which must find everything the person
        // chose on the way to it exactly as they left it.
        // Whichever way a parked wait ends, it has ended: Esc is no longer
        // the cheap way out once the launch carries on.
        state.join.waiting_on_challenge = false;
        if !matches!(
            entry,
            JoinEntry::Challenge { .. } | JoinEntry::Wallet { .. }
        ) {
            state.join.reset();
            // Surface the launch-supplied invitation on the entry page (reset
            // clears the transient join sub-state, so mirror the flag back in
            // afterwards).
            state.join.has_invitation = state.invitation_credential.is_some();
            state.join.invitation_foreign_subject = state
                .invitation_credential
                .as_ref()
                .and_then(|vic| foreign_invitation_subject(ctx.config, vic));
        }
        state.active_page = ActivePage::Join;
        let hears_replies = match &entry {
            JoinEntry::Fresh | JoinEntry::ForCommunity { .. } => self.hears_replies,
            // Only the runtime loop waits on an answer, so only it resumes.
            JoinEntry::Resume { .. } | JoinEntry::Challenge { .. } | JoinEntry::Wallet { .. } => {
                true
            }
        };
        state.join.hears_replies = hears_replies;
        self.session = Some(JoinSession {
            hears_replies,
            job: None,
            launch: None,
            queued: VecDeque::new(),
        });
        let step = match entry {
            JoinEntry::Fresh => JoinStep::Continue,
            // The community is already chosen, so the flow opens where the DID
            // entry page would have led.
            JoinEntry::ForCommunity { vtc_did } => {
                self.enter_community(ctx, vtc_did);
                JoinStep::Continue
            }
            JoinEntry::Resume { vtc_did, outcome } => {
                // `reset` above cleared what the asking pass collected, and the
                // routes cannot be drawn without it. The manifest came over
                // DIDComm, which never resolved the community's DID document.
                let document = if matches!(outcome, RequirementsOutcome::Learned)
                    && ctx
                        .config
                        .private
                        .vetting
                        .post_quantum_key(&vtc_did)
                        .is_none()
                {
                    DocumentWhen::Always
                } else {
                    DocumentWhen::Never
                };
                self.discover(ctx, vtc_did, Purpose::Resume(outcome), false, document);
                JoinStep::Continue
            }
            JoinEntry::Challenge { awaiting, outcome } => {
                match outcome {
                    ChallengeOutcome::Issued => {
                        // The stored challenge is the one this launch asked for;
                        // the launch takes the flag, so it serves exactly one submit.
                        ctx.state.join.challenge_fresh = true;
                        self.launch(ctx, awaiting.choice, awaiting.vtc_did, awaiting.context_id)
                            .await;
                    }
                    ChallengeOutcome::Unanswered(reason) => {
                        let name =
                            vetting_actions::community_display(ctx.config, &awaiting.vtc_did);
                        ctx.state.join.page = JoinPage::Progress;
                        ctx.state.join.fail(challenge_failed_words(&name, &reason));
                    }
                }
                JoinStep::Continue
            }
            JoinEntry::Wallet { end } => {
                ctx.state.join.processing = false;
                match end {
                    WalletEnd::Presented => {
                        let join = &mut ctx.state.join;
                        let parked = join.wallet.as_mut().and_then(|w| {
                            join.wallet_outcome =
                                Some(WalletOutcome::Presented(w.requirements_digest.clone()));
                            w.parked.take()
                        });
                        join.wallet = None;
                        if let Some((pick, vtc_did, context_id)) = parked {
                            self.launch(ctx, pick, vtc_did, context_id).await;
                        }
                    }
                    WalletEnd::Unfinished(why) => {
                        ctx.state.join.page = JoinPage::Wallet;
                        if let Some(wallet) = ctx.state.join.wallet.as_mut() {
                            wallet.phase = WalletPhase::Offered { note: Some(why) };
                        }
                    }
                }
                JoinStep::Continue
            }
        };
        self.settle(ctx, step)
    }

    /// A UI action, while the join is open.
    pub(crate) async fn on_action(&mut self, ctx: &mut JoinCtx<'_>, action: Action) -> JoinStep {
        let Some(session) = self.session.as_mut() else {
            return JoinStep::Continue;
        };
        if session.job.as_ref().is_some_and(|job| job.submitting)
            && matches!(action, Action::Exit | Action::JoinCancel)
        {
            // The request may already be on the wire. Cancelling now would
            // forget the persona the community is about to answer, with no
            // record of the request: let the submit finish and be recorded,
            // then take this way out.
            session.queued.push_back(action);
            ctx.state
                .join
                .info("Sending the join request — stopping once it has been sent.");
            return JoinStep::Continue;
        }
        if session.job.is_some() {
            // The ways out take effect now, whatever the job is waiting on;
            // everything else waits its turn.
            let step = match action {
                Action::Exit => JoinStep::Exit(Interrupted::UserInt),
                Action::JoinCancel => JoinStep::Returned(None),
                action => {
                    session.queued.push_back(action);
                    return JoinStep::Continue;
                }
            };
            self.interrupt(ctx).await;
            if let JoinStep::Returned(_) = step {
                ctx.state.active_page = ActivePage::Main;
                return self.settle(ctx, JoinStep::Returned(joined_session(&ctx.state.join)));
            }
            return self.settle(ctx, step);
        }
        let step = self.act(ctx, action).await;
        self.settle(ctx, step)
    }

    /// A join job finished.
    pub(crate) async fn on_outcome(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        outcome: JoinOutcome,
    ) -> JoinStep {
        let JoinOutcome { generation, result } = outcome;
        // Stale — aborted, or from a session that is over: the domain it held
        // was freed when it was abandoned.
        let Some(job) = self
            .session
            .as_mut()
            .and_then(|s| s.job.take_if(|j| j.generation == generation))
        else {
            return JoinStep::Continue;
        };
        ctx.in_flight.finish(DispatchDomain::Join);
        let step = match (job.then, result) {
            (Then::Stage, JobResult::Panicked) => {
                self.fail_and_undo(ctx, JOB_LOST).await;
                JoinStep::Continue
            }
            (_, JobResult::Panicked) => {
                ctx.state.join.fail(JOB_LOST);
                JoinStep::Continue
            }
            (Then::Enter, JobResult::Resolved(resolved)) => {
                match resolved {
                    Ok(did) => self.enter_community(ctx, did),
                    Err(e) => ctx.state.join.fail(e),
                }
                JoinStep::Continue
            }
            (Then::Discovered { vtc_did, purpose }, JobResult::Discovered(found)) => {
                self.discovered(ctx, vtc_did, purpose, *found).await
            }
            (Then::Stage, JobResult::Reached(reached)) => {
                self.on_reached(ctx, reached);
                JoinStep::Continue
            }
            (Then::Stage, JobResult::Context(context)) => {
                self.on_context(ctx, context).await;
                JoinStep::Continue
            }
            (Then::Stage, JobResult::Minted(parts)) => {
                self.on_minted(ctx, *parts).await;
                JoinStep::Continue
            }
            (Then::Stage, JobResult::Invited(invited)) => {
                self.on_invited(ctx, invited).await;
                JoinStep::Continue
            }
            (Then::Stage, JobResult::Presented(presented)) => {
                self.on_presented(ctx, presented).await;
                JoinStep::Continue
            }
            (Then::Stage, JobResult::Submitted(submitted)) => {
                self.on_submitted(ctx, submitted).await;
                JoinStep::Continue
            }
            _ => {
                debug!("a join job's result did not match what it was started for");
                JoinStep::Continue
            }
        };
        self.settle(ctx, step)
    }

    /// A running join job said what it is doing.
    pub(crate) fn on_progress(&mut self, state: &mut State, generation: u64, line: String) {
        if self
            .session
            .as_ref()
            .and_then(|s| s.job.as_ref())
            .is_some_and(|j| j.generation == generation)
        {
            state.join.info(line);
        }
    }

    /// End the open join now — Exit, an interrupt, the loop stopping. A job in
    /// flight is aborted and a launch undone; the session is over.
    pub(crate) async fn cancel(&mut self, ctx: &mut JoinCtx<'_>) {
        if self.session.is_none() {
            return;
        }
        self.interrupt(ctx).await;
        self.end_session();
    }

    /// A persona the join's create-persona overlay minted was just persisted
    /// (through the loop's ordinary dispatch path).
    ///
    /// It is brought online here — in the background: the join is about to
    /// offer it as a way in, and a persona that cannot send is not one. The
    /// submit waits, bounded, for the socket right before the request goes
    /// out, which is where being online matters. A no-op without a service.
    pub(crate) async fn on_persona_minted(&mut self, ctx: &mut JoinCtx<'_>, persona_id: PersonaId) {
        ctx.state.join.minted_persona = Some(persona_id);
        if let Some(did) = ctx
            .config
            .identities
            .get(&persona_id)
            .map(|ident| ident.did.clone())
        {
            spawn_persona_listener(ctx.messaging, ctx.config, ctx.tdk, persona_id, &did).await;
        }
        ctx.state
            .join
            .info("Connecting the new persona to its mediator…".to_string());
    }

    // ---- session bookkeeping ----

    /// Finish a step: hand a parked launch to the loop that can hear its
    /// answer, release the actions a finished job held back, and close the
    /// session when the step leaves the flow.
    fn settle(&mut self, ctx: &mut JoinCtx<'_>, step: JoinStep) -> JoinStep {
        let Some(session) = self.session.as_mut() else {
            return step;
        };
        let idle = session.job.is_none();
        let step = match step {
            // A launch that stopped to ask a hidden-vetting community for its
            // challenge leaves the flow here, whichever page or entry started
            // it: only the caller's loop hears the answer. Likewise a wallet
            // session.
            JoinStep::Continue if idle => {
                if let Some(awaiting) = ctx.state.join.challenge_wait.take() {
                    JoinStep::AwaitChallenge(awaiting)
                } else if let Some(awaiting) = ctx.state.join.wallet_wait.take() {
                    JoinStep::AwaitWallet(awaiting)
                } else {
                    JoinStep::Continue
                }
            }
            step => step,
        };
        match step {
            JoinStep::Continue => {
                if idle {
                    let queued = std::mem::take(&mut session.queued);
                    for action in queued.into_iter().rev() {
                        self.leftover.push_front(action);
                    }
                }
            }
            _ => {
                if let Some(job) = session.job.take() {
                    job.abort.abort();
                    ctx.in_flight.finish(DispatchDomain::Join);
                }
                self.end_session();
            }
        }
        step
    }

    fn end_session(&mut self) {
        if let Some(session) = self.session.take() {
            for action in session.queued.into_iter().rev() {
                self.leftover.push_front(action);
            }
        }
    }

    fn hears_replies(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.hears_replies)
    }

    /// Abort the job in flight, and undo a launch that was under way.
    async fn interrupt(&mut self, ctx: &mut JoinCtx<'_>) {
        let mut submitting = false;
        if let Some(job) = self.session.as_mut().and_then(|s| s.job.take()) {
            submitting = job.submitting;
            job.abort.abort();
            ctx.in_flight.finish(DispatchDomain::Join);
        }
        if submitting && self.session.as_ref().is_some_and(|s| s.launch.is_some()) {
            // Interrupted mid-submit (the app is stopping): the request may
            // have gone out, so the persona and its listener are kept rather
            // than forgotten — deleting a DID the community may now hold is
            // worse than leaving one unused.
            self.end_launch(ctx);
            ctx.state.join.completed = Completion::CompletedFail;
            ctx.state.join.info(
                "Stopped while sending the join request. It may have been sent; the persona was kept. Check the community's status from Communities.",
            );
            ctx.state
                .main_page
                .log("Join stopped while its request was being sent; persona kept.");
            return;
        }
        if self.session.as_ref().is_some_and(|s| s.launch.is_some()) {
            self.compensate(ctx).await;
            self.end_launch(ctx);
            ctx.state.join.completed = Completion::CompletedFail;
            ctx.state.join.info(
                "Join cancelled. Any partially-minted persona was rolled back; a sub-context may remain at the VTA.",
            );
            ctx.state.main_page.log("Join cancelled by user.");
        }
    }

    /// Start a job off the loop. `make` builds its future from the I/O seam;
    /// `wrap` says which result it is.
    fn start<T: Send + 'static>(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        then: Then,
        make: impl FnOnce(&dyn JoinIo, Progress) -> IoFuture<'static, T>,
        wrap: fn(T) -> JobResult,
    ) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.generation += 1;
        let generation = self.generation;
        let progress = Progress {
            tx: ctx.dispatch_tx.clone(),
            generation,
        };
        let work = make(self.io.as_ref(), progress);
        if !ctx.in_flight.try_begin(DispatchDomain::Join) {
            debug!("the join domain was still claimed when a join job started");
        }
        let task = tokio::spawn(async move { wrap(work.await) });
        let abort = task.abort_handle();
        let tx = ctx.dispatch_tx.clone();
        tokio::spawn(async move {
            let result = match task.await {
                Ok(result) => result,
                // Aborted: whoever aborted it has moved on and freed the domain.
                Err(e) if e.is_cancelled() => return,
                Err(e) => {
                    error!(error = %e, "join job panicked");
                    JobResult::Panicked
                }
            };
            let _ = tx.send(DispatchOutcome::Join(Box::new(JoinOutcome {
                generation,
                result,
            })));
        });
        session.job = Some(Job {
            generation,
            abort,
            then,
            submitting: false,
        });
    }

    fn launch_mut(&mut self) -> Option<&mut Launch> {
        self.session.as_mut().and_then(|s| s.launch.as_mut())
    }

    // ---- the pages ----

    /// One action on an idle join.
    async fn act(&mut self, ctx: &mut JoinCtx<'_>, action: Action) -> JoinStep {
        match action {
            Action::Exit => return JoinStep::Exit(Interrupted::UserInt),
            Action::JoinCancel => {
                // Leave the flow; the caller restores the main page. Hand back
                // the joined session (if any) so the runtime loop can bring its
                // live session up (R-B-5).
                ctx.state.active_page = ActivePage::Main;
                return JoinStep::Returned(joined_session(&ctx.state.join));
            }
            Action::JoinPasteVic(text) => {
                // #3: a pasted invitation credential — validate it is a VIC and
                // stash it so the join presents it (mirrors the `--invitation
                // <file>` launch flag). On the entry page the community isn't
                // chosen yet, so only the credential shape is checked; on the
                // invitation step it is, so the paste is also matched against it.
                let vtc = if ctx.state.join.page == JoinPage::InvitationChoice {
                    ctx.state.join.pending_vtc.clone()
                } else {
                    None
                };
                ctx.state.join.messages.clear();
                load_pasted_vic(ctx.state, ctx.tdk.did_resolver(), &text, vtc.as_deref()).await;
                ctx.state.join.invitation_foreign_subject = ctx
                    .state
                    .invitation_credential
                    .as_ref()
                    .and_then(|vic| foreign_invitation_subject(ctx.config, vic));
            }
            Action::JoinClipboardFailed(why) => {
                // Only the failure reaches the loop: `[Ctrl+V]` reads and applies
                // the text where the input lives, so a pasted DID never takes a
                // trip through here to be mistaken for an invitation.
                ctx.state.join.messages.clear();
                ctx.state.join.messages.push(MessageType::Error(format!(
                    "Could not read the clipboard ({why}). Paste directly into \
                     this screen instead — that works over SSH, where reading \
                     the clipboard cannot."
                )));
            }
            Action::JoinClearVic => {
                // Explicit "proceed without a VIC": drop the loaded invitation so
                // it isn't presented, and flag the clear so the entry page shows
                // "joining without an invitation".
                ctx.state.invitation_credential = None;
                ctx.state.join.has_invitation = false;
                ctx.state.join.invitation_issuer = None;
                ctx.state.join.invitation_foreign_subject = None;
                ctx.state.join.vic_cleared = true;
                ctx.state.join.messages.clear();
            }
            Action::JoinSubmitVtc(vtc_did) => {
                let vtc_did = match validate_join_input(&vtc_did) {
                    Ok(did) => did,
                    // Say why nothing happened. A keypress that cannot proceed
                    // must not be a silent no-op — that reads as a frozen screen
                    // (issue #29).
                    Err(why) => {
                        ctx.state.join.messages.push(MessageType::Error(why));
                        return JoinStep::Continue;
                    }
                };
                // Accept an agent name (`example.com/@acme`) in place of the VTC
                // DID. Only resolve when the input actually looks like a name,
                // so pasting a DID keeps its existing (no-extra-round-trip)
                // path; the resolved DID is what everything downstream persists.
                if openvtc_core::agent_name::looks_like_agent_name(&vtc_did) {
                    // Say what the wait is for: a name costs a redirect, a
                    // resolve and a check (bounded by IDENTIFIER_RESOLVE_TIMEOUT).
                    // Off the loop, so Esc and F10 are heard while it runs.
                    ctx.state
                        .join
                        .messages
                        .push(MessageType::Info(format!("Resolving {vtc_did}…")));
                    let resolver = ctx.tdk.did_resolver().clone();
                    self.start(
                        ctx,
                        Then::Enter,
                        |io, _| io.resolve(resolver, vtc_did),
                        JobResult::Resolved,
                    );
                } else {
                    self.enter_community(ctx, vtc_did);
                }
            }
            Action::JoinIdentitySelect(i) => {
                // Clamp to the reuse rows plus the trailing "mint" row.
                ctx.state.join.identity_selected = i.min(ctx.state.join.mint_row());
                // Moving the highlight dismisses any armed warning.
                ctx.state.join.reuse_confirm = None;
            }
            Action::JoinNewPersonaMethodCycle => {
                ctx.state.join.new_persona_did_method =
                    next_did_method(ctx.state.join.new_persona_did_method);
            }
            Action::JoinIdentityChoose => {
                if ctx.state.join.mint_row_selected() {
                    let Some(vtc_did) = ctx.state.join.pending_vtc.clone() else {
                        return JoinStep::Continue;
                    };
                    ctx.state.join.present_invitation =
                        mint_can_present(ctx.config, ctx.state, &vtc_did);
                    if let Some(context_id) =
                        offer_contexts(ctx.state, ctx.config, IdentityPick::Mint, &vtc_did)
                    {
                        self.launch(ctx, IdentityPick::Mint, vtc_did, context_id)
                            .await;
                    }
                } else if let Some(opt) = ctx
                    .state
                    .join
                    .persona_options
                    .get(ctx.state.join.identity_selected)
                {
                    // Arm the cross-community linkage warning (D1).
                    ctx.state.join.reuse_confirm = Some(opt.id);
                }
            }
            Action::JoinReuseConfirm => {
                let Some(persona_id) = ctx.state.join.reuse_confirm else {
                    return JoinStep::Continue;
                };
                // The community DID stays parked in `pending_vtc`; the
                // invitation step is what launches the join now.
                if ctx.state.join.pending_vtc.is_none() {
                    return JoinStep::Continue;
                }
                ctx.state.join.reuse_confirm = None;
                open_invitation_choice(ctx.state, ctx.config, persona_id);
            }
            Action::JoinReuseCancel => {
                ctx.state.join.reuse_confirm = None;
            }
            Action::JoinInvitationSelect(i) => {
                // Rows: 0..len an invitation, len = paste, len+1 = without.
                let max = ctx.state.join.invitation_without_row();
                ctx.state.join.invitation_use_selected = i.min(max);
            }
            Action::JoinInvitationChoose => {
                let Some(vtc_did) = ctx.state.join.pending_vtc.clone() else {
                    return JoinStep::Continue;
                };
                let Some(persona_id) = ctx.state.join.invitation_for_persona else {
                    return JoinStep::Continue;
                };
                // The paste row loads a VIC instead of launching: it is the
                // answer to "I have one, it just isn't in the vault". Read the OS
                // clipboard as a convenience; the portable path is the
                // terminal's own bracketed paste, which arrives as
                // `JoinPasteVic` from anywhere on this page. Either way we stay
                // on the step so the operator sees the loaded invitation before
                // committing to it.
                if ctx.state.join.invitation_use_selected == ctx.state.join.invitation_paste_row() {
                    ctx.state.join.messages.clear();
                    match crate::clipboard::read_clipboard() {
                        Ok(text) => {
                            load_pasted_vic(
                                ctx.state,
                                ctx.tdk.did_resolver(),
                                &text,
                                Some(&vtc_did),
                            )
                            .await;
                        }
                        Err(why) => {
                            ctx.state.join.messages.push(MessageType::Error(format!(
                                "Could not read the clipboard ({why}). Paste the \
                                 invitation JSON directly into this screen instead."
                            )));
                        }
                    }
                    return JoinStep::Continue;
                }
                // A selected invitation row presents that VIC; the trailing row
                // joins without one.
                let sel = ctx.state.join.invitation_use_selected;
                if let Some(av) = ctx.state.join.invitation_options.get(sel) {
                    ctx.state.invitation_credential = Some(av.body.clone());
                    ctx.state.join.present_invitation = true;
                } else {
                    ctx.state.invitation_credential = None;
                    ctx.state.join.present_invitation = false;
                }
                let pick = IdentityPick::Reuse(persona_id);
                if let Some(context_id) = offer_contexts(ctx.state, ctx.config, pick, &vtc_did) {
                    self.launch(ctx, pick, vtc_did, context_id).await;
                }
            }
            Action::JoinAnswersSelect(i) => {
                if let (Some(answers), Some(client)) =
                    (ctx.state.join.answers.as_mut(), ctx.admin_vta)
                {
                    answers.selected = i.min(answers.faces.len().saturating_sub(1));
                    load_shown(answers, client).await;
                }
            }
            Action::JoinAnswersChoose => {
                let Some(answers) = ctx.state.join.answers.as_mut() else {
                    return JoinStep::Continue;
                };
                let Some((face_id, face_name)) = answers.faces.get(answers.selected).cloned()
                else {
                    answers.error = Some(
                        "You have no face to answer with. Make one under Identity, \
                         then join again."
                            .into(),
                    );
                    return JoinStep::Continue;
                };
                let missing = answers.unanswered();
                if !missing.is_empty() {
                    answers.error = Some(format!(
                        "{face_name} does not show {} — the community requires it. \
                         Pick another face, or add it to this one under Identity.",
                        missing.join(", ")
                    ));
                    return JoinStep::Continue;
                }
                // What the holder approves is these values, exactly.
                let approved = answers
                    .shown
                    .iter()
                    .filter_map(|(t, v)| v.clone().map(|v| (t.clone(), v)))
                    .collect();
                answers.approved = Some((face_id, approved));
                let Some((pick, vtc_did, context_id)) = answers.parked.take() else {
                    return JoinStep::Continue;
                };
                self.launch(ctx, pick, vtc_did, context_id).await;
            }
            Action::JoinWalletStart => {
                let Some(wallet) = ctx.state.join.wallet.as_ref() else {
                    return JoinStep::Continue;
                };
                if !matches!(wallet.phase, WalletPhase::Offered { .. }) {
                    return JoinStep::Continue;
                }
                let Some((IdentityPick::Reuse(persona), vtc_did, _)) = wallet.parked.clone() else {
                    return JoinStep::Continue;
                };
                let digest = wallet.requirements_digest.clone();
                match ask_wallet_start(
                    ctx.config,
                    ctx.tdk,
                    ctx.messaging,
                    &vtc_did,
                    persona,
                    &digest,
                )
                .await
                {
                    Ok(awaiting) => {
                        if let Some(wallet) = ctx.state.join.wallet.as_mut() {
                            wallet.phase = WalletPhase::Opening;
                        }
                        ctx.state.join.wallet_wait = Some(awaiting);
                    }
                    Err(why) => {
                        if let Some(wallet) = ctx.state.join.wallet.as_mut() {
                            wallet.phase = WalletPhase::Offered { note: Some(why) };
                        }
                    }
                }
            }
            Action::JoinWalletSkip => {
                let parked = ctx.state.join.wallet.as_mut().and_then(|w| {
                    matches!(w.phase, WalletPhase::Offered { .. })
                        .then(|| w.parked.take())
                        .flatten()
                });
                let Some((pick, vtc_did, context_id)) = parked else {
                    return JoinStep::Continue;
                };
                ctx.state.join.wallet = None;
                ctx.state.join.wallet_outcome = Some(WalletOutcome::Skipped);
                self.launch(ctx, pick, vtc_did, context_id).await;
            }
            Action::JoinRegistryToggle => {
                if let Some(registry) = ctx.state.join.registry.as_mut() {
                    registry.publish = !registry.publish;
                }
            }
            Action::JoinRegistryConfirm => {
                // Either answer is an answer. What is sent is the box as it
                // stands now — read again by the launch via
                // `RegistryChoice::consent_for`, never cached apart from the
                // page that showed it.
                let Some(registry) = ctx.state.join.registry.as_mut() else {
                    return JoinStep::Continue;
                };
                registry.confirmed = true;
                let Some((pick, vtc_did, context_id)) = registry.parked.take() else {
                    return JoinStep::Continue;
                };
                self.launch(ctx, pick, vtc_did, context_id).await;
            }
            Action::JoinContextSelect(i) => {
                let last = ctx.state.join.context_options.len().saturating_sub(1);
                ctx.state.join.context_selected = i.min(last);
                ctx.state.join.messages.clear();
            }
            Action::JoinContextSlug(slug) => {
                ctx.state.join.context_slug = slug;
                ctx.state.join.messages.clear();
            }
            Action::JoinContextChoose => {
                let (Some(vtc_did), Some(pick)) = (
                    ctx.state.join.pending_vtc.clone(),
                    ctx.state.join.picked_identity,
                ) else {
                    return JoinStep::Continue;
                };
                let Some(option) = ctx
                    .state
                    .join
                    .context_options
                    .get(ctx.state.join.context_selected)
                    .cloned()
                else {
                    return JoinStep::Continue;
                };
                let context_id = if option.kind == ContextKind::New {
                    match community_context::new_context_id(
                        &ctx.config.account.top_context_id,
                        &ctx.state.join.context_slug,
                        |id| sequence::context_taken(ctx.config, id),
                    ) {
                        Ok(id) => id,
                        Err(e) => {
                            ctx.state.join.messages.clear();
                            ctx.state
                                .join
                                .messages
                                .push(MessageType::Error(e.to_string()));
                            return JoinStep::Continue;
                        }
                    }
                } else {
                    option.context_id
                };
                self.launch(ctx, pick, vtc_did, context_id).await;
            }
            Action::JoinVettingRow(forward) => {
                if let Some(known) = known_vetting(ctx.state) {
                    known.step(forward);
                }
            }
            Action::JoinVettingTake => {
                // Enter on the routes list. A route the page drew as blocked must
                // say why rather than do nothing — a keypress that cannot proceed
                // reads as a frozen screen (issue #29).
                let Some(option) =
                    known_vetting(ctx.state).and_then(|known| known.selected_route().cloned())
                else {
                    return JoinStep::Continue;
                };
                if !option.available() {
                    let why = option.blocked().unwrap_or_default();
                    ctx.state.join.messages.clear();
                    ctx.state
                        .join
                        .messages
                        .push(MessageType::Error(format!("{}: {why}", option.label)));
                    return JoinStep::Continue;
                }
                // A route that starts with the join doing something: do it, and
                // remember what it was on the way to. That is the difference
                // between being guided and being told to go and configure
                // something elsewhere.
                //
                // A step that is merely the next page needs none of this —
                // taking the route reaches it.
                if option.first_step_kind() == Some(FirstStepKind::CreatePersona) {
                    ctx.state.join.messages.clear();
                    ctx.state.join.resume_route = Some(option.route);
                    crate::state_handler::handle_nav_action(ctx.state, &Action::StartCreatePersona);
                    return JoinStep::Continue;
                }
                return self.take_route(ctx, option.route, option.applicant).await;
            }
            Action::JoinVettingApply => {
                // `a`: read the highlighted row's own application.
                let Some(vtc_did) = ctx.state.join.pending_vtc.clone() else {
                    return JoinStep::Continue;
                };
                let Some(persona) = known_vetting(ctx.state).and_then(|k| k.selected_persona())
                else {
                    return JoinStep::Continue;
                };
                ctx.state.join.messages.clear();
                match apply_for_vetting(
                    ctx.state,
                    ctx.config,
                    self.io.as_ref(),
                    ctx.save,
                    &vtc_did,
                    persona,
                )
                .await
                {
                    Ok(()) => {
                        ctx.state.active_page = ActivePage::Main;
                        return JoinStep::Returned(None);
                    }
                    Err(why) => ctx.state.join.messages.push(MessageType::Error(why)),
                }
            }
            Action::JoinVettingJoin => {
                // `j`, offered only while the community is being asked or could
                // not be: there are no rows yet, so no persona has been chosen
                // and none of its statements are presumed. The identity step
                // asks, and the submit attaches the chosen persona's own.
                let Some(vtc_did) = ctx.state.join.pending_vtc.clone() else {
                    return JoinStep::Continue;
                };
                ctx.state.join.messages.clear();
                self.continue_join(ctx, vtc_did).await;
            }
            // The create-persona overlay, hosted here rather than on the main
            // page. Everything except the mint is the shared pure reducer, so
            // the phases and keys cannot drift from the ones the main page
            // shows.
            action if crate::state_handler::handle_nav_action(ctx.state, &action) => {
                // A persona minted behind this page changes what the routes say,
                // so they are re-derived once the overlay is gone. Cheap,
                // idempotent, and it means the row that was blocked on having no
                // persona unblocks itself rather than waiting for a re-entry.
                if ctx.state.join.page == JoinPage::Vetting
                    && ctx.state.main_page.create_persona.is_none()
                    && let Some(vtc_did) = ctx.state.join.pending_vtc.clone()
                {
                    show_vetting(ctx.state, ctx.config, &vtc_did);
                    // And carry on where the step interrupted — as the persona
                    // the step made, on that persona's own row. Only when the
                    // step actually produced one: an overlay closed with Esc
                    // leaves the page as it was, with the "new persona" row
                    // still saying what it starts with.
                    let minted = ctx.state.join.minted_persona;
                    let resumable = ctx.state.join.resume_route.and_then(|route| {
                        let known = known_vetting(ctx.state)?;
                        let row = match route {
                            JoinRoute::Vetting => known.row_for(Applicant::Persona(minted?))?,
                            other => known.row_of(other)?,
                        };
                        let option = known.routes.get(row)?;
                        (option.first_step().is_none() && option.available()).then_some((
                            row,
                            option.route,
                            option.applicant,
                        ))
                    });
                    if let Some((row, route, applicant)) = resumable {
                        ctx.state.join.resume_route = None;
                        if let Some(known) = known_vetting(ctx.state) {
                            known.row = row;
                        }
                        return self.take_route(ctx, route, applicant).await;
                    }
                }
            }
            // The mint itself goes through the loop's ordinary dispatch path;
            // when it settles, the loop hands the persona back to
            // [`JoinDriver::on_persona_minted`] while this join is open.
            Action::CreatePersonaSubmit => {
                crate::state_handler::spawn_persona_mint(
                    ctx.dispatch_tx,
                    ctx.in_flight,
                    ctx.state,
                    ctx.config,
                    ctx.tdk,
                    ctx.admin_vta,
                );
            }
            Action::CreatePersonaCopy => {
                if let Some(did) = ctx
                    .state
                    .main_page
                    .create_persona
                    .as_ref()
                    .and_then(|o| o.did.clone())
                {
                    let copied = crate::clipboard::copy_to_clipboard(&did).is_ok();
                    if let Some(o) = ctx.state.main_page.create_persona.as_mut() {
                        o.copied = copied;
                    }
                }
            }
            Action::JoinVettingAskAgain => {
                let Some(vtc_did) = ctx.state.join.pending_vtc.clone() else {
                    return JoinStep::Continue;
                };
                if self.hears_replies()
                    && let Ok(awaiting) =
                        ask_requirements(ctx.state, ctx.config, ctx.tdk, ctx.messaging, &vtc_did)
                            .await
                {
                    return JoinStep::AwaitRequirements(awaiting);
                }
            }
            _ => {}
        }
        JoinStep::Continue
    }

    /// Enter `vtc_did` into the flow: learn what it asks of the people who
    /// join, and put up the page that answers it.
    ///
    /// Shared by the DID entry page and by a join started for a community
    /// already chosen (a vetting application's), so both get the same
    /// discovery rather than the entry page's alone. The reading runs off the
    /// loop; [`Self::entered`] decides on it.
    fn enter_community(&mut self, ctx: &mut JoinCtx<'_>, vtc_did: String) {
        // Known before is not known now. A community changes what it asks, and
        // a join decided on the last visit's copy shows the person a community
        // that no longer exists. So the manifest is read again on every join,
        // over the endpoint that needs nothing of us (bounded, R1.2). Only when
        // the community cannot be reached does the stored copy stand in.
        let knew = knowledge_of(ctx.config, &vtc_did);
        // The re-read records how it signs; if it cannot be made, the DID
        // document may still resolve on its own.
        let document = if knew == Some(true)
            && ctx
                .config
                .private
                .vetting
                .post_quantum_key(&vtc_did)
                .is_none()
        {
            DocumentWhen::IfManifestFails
        } else {
            DocumentWhen::Never
        };
        self.discover(ctx, vtc_did, Purpose::Enter { knew }, true, document);
    }

    /// Read a community off the loop: its invitations when they are not
    /// collected yet (whether presenting one is a way in is a fact about this
    /// account, and the vetting page cannot say what the options are without
    /// it), its manifest, its DID document.
    fn discover(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        vtc_did: String,
        purpose: Purpose,
        manifest: bool,
        document: DocumentWhen,
    ) {
        let invitations = (ctx.state.join.invitations_for.as_deref() != Some(vtc_did.as_str()))
            .then(|| ctx.state.invitation_credential.clone());
        let req = DiscoverReq {
            resolver: ctx.tdk.did_resolver().clone(),
            admin_vta: ctx.admin_vta.cloned(),
            vtc_did: vtc_did.clone(),
            invitations,
            manifest,
            document,
        };
        self.start(
            ctx,
            Then::Discovered { vtc_did, purpose },
            |io, _| io.discover(req),
            |found| JobResult::Discovered(Box::new(found)),
        );
    }

    /// A community was read: take in what was found and carry on with what it
    /// was read for.
    async fn discovered(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        vtc_did: String,
        purpose: Purpose,
        found: Discovered,
    ) -> JoinStep {
        let Discovered {
            invitations,
            manifest,
            document,
        } = found;
        if let Some(vics) = invitations {
            ctx.state.join.available_vics = vics;
            ctx.state.join.invitations_for = Some(vtc_did.clone());
        }
        match purpose {
            Purpose::Enter { knew } => {
                return self.entered(ctx, vtc_did, knew, manifest, document).await;
            }
            Purpose::Resume(outcome) => match outcome {
                RequirementsOutcome::Unanswered(reason) => {
                    // We got here by sending the question, so the DID resolved:
                    // it is the answer that never came.
                    show_unknown(ctx.state, ctx.config, &vtc_did, reason, true, true);
                }
                outcome => {
                    let learned = matches!(outcome, RequirementsOutcome::Learned);
                    if learned
                        && ctx
                            .config
                            .private
                            .vetting
                            .post_quantum_key(&vtc_did)
                            .is_none()
                        && let Some(doc) = document
                    {
                        sequence::note_signing(ctx.config, &vtc_did, &doc);
                    }
                    let shown = learned && show_vetting(ctx.state, ctx.config, &vtc_did);
                    if !shown {
                        self.continue_join(ctx, vtc_did).await;
                    }
                }
            },
            Purpose::ContinueJoin => self.continue_with_invitations(ctx, vtc_did).await,
            Purpose::InvitationChoice(persona) => {
                open_invitation_choice(ctx.state, ctx.config, persona);
            }
        }
        JoinStep::Continue
    }

    /// Decide which page answers a community just read.
    ///
    /// Peer identity vetting: a community that vets says what it requires
    /// before anything about the applicant is sent (vetting-process.md §6.1).
    /// What the book knows decides at once. Otherwise the community is asked,
    /// and the wait happens in the caller's loop — the one that hears the
    /// answer — which enters this flow again.
    async fn entered(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        vtc_did: String,
        knew: Option<bool>,
        mut manifest: Option<Result<OverHttp, NotLearned>>,
        document: Option<affinidi_tdk::did_common::Document>,
    ) -> JoinStep {
        let mut knowledge = knew;
        if knowledge.is_some() {
            match manifest.take() {
                Some(Ok(fetched)) => {
                    sequence::learn_fetched(ctx.config, &vtc_did, fetched);
                    knowledge = knowledge_of(ctx.config, &vtc_did);
                }
                Some(Err(why)) => {
                    debug!(community = %vtc_did, reason = %why.reason(), "manifest not re-read");
                    ctx.state.main_page.log(format!(
                        "Could not read {}'s current requirements ({}); showing what it said \
                         last time.",
                        vetting_actions::community_display(ctx.config, &vtc_did),
                        why.reason()
                    ));
                }
                None => {}
            }
        }
        match knowledge {
            Some(true) => {
                // The re-read above records how it signs; if it could not be
                // made, the DID document may still have resolved on its own.
                if ctx
                    .config
                    .private
                    .vetting
                    .post_quantum_key(&vtc_did)
                    .is_none()
                    && let Some(doc) = document
                {
                    sequence::note_signing(ctx.config, &vtc_did, &doc);
                }
                show_vetting(ctx.state, ctx.config, &vtc_did);
            }
            // Known before, and not after reading it again: read it as a first
            // visit would.
            None if knew.is_some() => self.enter_community(ctx, vtc_did),
            None => match manifest {
                // The community's own endpoint first. It needs no mediator, no
                // persona and no loop that can hear a reply, so it answers on a
                // first join — where the DIDComm question cannot be asked at
                // all — and it answers in one round trip everywhere else.
                Some(Ok(fetched)) => {
                    sequence::learn_fetched(ctx.config, &vtc_did, fetched);
                    if !show_vetting(ctx.state, ctx.config, &vtc_did) {
                        // It answered, and the answer is that it does not vet.
                        self.continue_join(ctx, vtc_did).await;
                    }
                }
                // Nothing resolved, so there is nobody to ask by any route: a
                // DIDComm question needs an endpoint the document would have
                // named. Stop here rather than send a request into the dark.
                Some(Err(why)) if !why.resolvable() => {
                    show_unknown(
                        ctx.state,
                        ctx.config,
                        &vtc_did,
                        why.reason().to_string(),
                        false,
                        false,
                    );
                }
                Some(Err(why)) if self.hears_replies() => {
                    debug!(community = %vtc_did, reason = %why.reason(), "manifest not read over REST");
                    if let Ok(awaiting) =
                        ask_requirements(ctx.state, ctx.config, ctx.tdk, ctx.messaging, &vtc_did)
                            .await
                    {
                        return JoinStep::AwaitRequirements(awaiting);
                    }
                    // The page now says why the question could not be sent.
                }
                Some(Err(why)) => {
                    // Both ways of asking are shut: its endpoint did not answer,
                    // and this loop has no inbound arm to hear a message on. Say
                    // so rather than sending an open request on the quiet — a
                    // community that vets refers that request to its moderators,
                    // and the applicant would never learn there was a way in they
                    // could have taken.
                    show_unknown(
                        ctx.state,
                        ctx.config,
                        &vtc_did,
                        why.reason().to_string(),
                        false,
                        true,
                    );
                }
                None => {}
            },
            Some(false) => self.continue_join(ctx, vtc_did).await,
        }
        JoinStep::Continue
    }

    /// Take one of the community's ways in, as `applicant` when it is a
    /// vetting row.
    ///
    /// Split out of the keypress so the join can also take a route it had to
    /// interrupt: a route whose first step was creating a persona resumes here
    /// once that persona exists, rather than putting the person back on the
    /// list to press the same key again.
    ///
    /// Which persona presents statements is decided here and nowhere else on
    /// this page, and only from the row's own persona: its application, ready
    /// or not. The invitation and open-request rows name no persona, so they go
    /// to the identity step, and the submit attaches whatever the persona
    /// chosen there gathered for this community — its own, matched on its DID,
    /// which the review page shows before it is sent.
    async fn take_route(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        route: JoinRoute,
        applicant: Option<Applicant>,
    ) -> JoinStep {
        let Some(vtc_did) = ctx.state.join.pending_vtc.clone() else {
            return JoinStep::Continue;
        };
        ctx.state.join.messages.clear();
        match route {
            // The invitation is chosen further on, once the persona it is bound
            // to is known: the invitation step lists this community's VICs for
            // that persona and is where one is picked.
            JoinRoute::Invitation | JoinRoute::OpenRequest => {
                self.continue_join(ctx, vtc_did).await;
            }
            JoinRoute::Vetting => {
                let ready = known_vetting(ctx.state).and_then(|k| k.ready_as(applicant));
                match (ready, applicant) {
                    // This persona's own statements meet the requirements:
                    // joining is what presents them, and they fix the persona —
                    // so the identity step has nothing left to ask and the flow
                    // goes straight to the invitation choice.
                    (Some(persona), _) => {
                        if ctx.state.join.invitations_for.as_deref() == Some(vtc_did.as_str()) {
                            open_invitation_choice(ctx.state, ctx.config, persona);
                        } else {
                            self.discover(
                                ctx,
                                vtc_did,
                                Purpose::InvitationChoice(persona),
                                false,
                                DocumentWhen::Never,
                            );
                        }
                    }
                    // Anything else is taken by working on this persona's own
                    // application — carrying it on, or starting it.
                    (None, Some(Applicant::Persona(persona))) => {
                        match apply_for_vetting(
                            ctx.state,
                            ctx.config,
                            self.io.as_ref(),
                            ctx.save,
                            &vtc_did,
                            persona,
                        )
                        .await
                        {
                            Ok(()) => {
                                ctx.state.active_page = ActivePage::Main;
                                return JoinStep::Returned(None);
                            }
                            Err(why) => ctx.state.join.messages.push(MessageType::Error(why)),
                        }
                    }
                    // A new persona's row starts by making it (its first step is
                    // taken before this is reached) and comes back on that
                    // persona's own row. Reaching here without one is a page out
                    // of step with itself; say so rather than guess.
                    (None, Some(Applicant::NewPersona) | None) => {
                        ctx.state.join.messages.push(MessageType::Error(
                            "Applying as a new persona starts by making it — press Enter on \
                             \"Apply for vetting as a new persona\"."
                                .to_string(),
                        ));
                    }
                }
            }
        }
        JoinStep::Continue
    }

    /// Go on with a join once any vetting has been dealt with: collect the
    /// community's invitations, then choose the identity to present, or mint
    /// one on a first join.
    async fn continue_join(&mut self, ctx: &mut JoinCtx<'_>, vtc_did: String) {
        ctx.state.join.vetting = None;
        // Identity first: collect the invitations available for this community
        // so each persona can be badged with its usable-invitation count, then
        // let the operator pick the identity to present (the invitation choice,
        // if any, follows for the chosen persona).
        if ctx.state.join.invitations_for.as_deref() == Some(vtc_did.as_str()) {
            self.continue_with_invitations(ctx, vtc_did).await;
        } else {
            self.discover(
                ctx,
                vtc_did,
                Purpose::ContinueJoin,
                false,
                DocumentWhen::Never,
            );
        }
    }

    async fn continue_with_invitations(&mut self, ctx: &mut JoinCtx<'_>, vtc_did: String) {
        // Idempotency is per-persona (R-B-9): a community may be joined as more
        // than one persona, so the duplicate check happens once the identity is
        // chosen (in the launch) rather than at the community level here.
        let options = build_persona_options(ctx.config, &ctx.state.join.available_vics);
        if options.is_empty() {
            // First join — nothing to reuse; mint a fresh identity. With no
            // persona to vouch for it, the new one cannot present an invitation
            // (`mint_can_present` is false); the loaded one is kept so the launch
            // stores it in the vault and says why it went unused.
            ctx.state.join.present_invitation = mint_can_present(ctx.config, ctx.state, &vtc_did);
            ctx.state.join.pending_vtc = Some(vtc_did.clone());
            if let Some(context_id) =
                offer_contexts(ctx.state, ctx.config, IdentityPick::Mint, &vtc_did)
            {
                self.launch(ctx, IdentityPick::Mint, vtc_did, context_id)
                    .await;
            }
        } else {
            ctx.state.join.pending_vtc = Some(vtc_did);
            ctx.state.join.persona_options = options;
            ctx.state.join.identity_selected = 0;
            ctx.state.join.reuse_confirm = None;
            ctx.state.join.page = JoinPage::IdentityChoice;
        }
    }

    // ---- the launch ----

    /// Launch the join for the chosen identity, unless something must be asked
    /// first: the community's questions, an unreadable directory statement,
    /// the trust-registry consent, a wallet, a hidden-vetting challenge. Every
    /// way to submit passes through here, so none can skip them.
    async fn launch(
        &mut self,
        ctx: &mut JoinCtx<'_>,
        choice: IdentityPick,
        vtc_did: String,
        context_id: String,
    ) {
        // A community that asks the applicant to tell it about themselves is
        // answered before anything else happens: which face, and exactly what it
        // would send. The launch waits on the Answers page and resumes from
        // `JoinAnswersChoose`.
        let asked = ctx.config.private.vetting.requested_attributes(&vtc_did);
        let answered = ctx
            .state
            .join
            .answers
            .as_ref()
            .is_some_and(|a| a.approved.is_some());
        if !asked.is_empty() && !answered {
            open_answers(
                ctx.state,
                ctx.admin_vta,
                asked,
                (choice, vtc_did, context_id),
            )
            .await;
            return;
        }

        // A directory statement the community published but this client could
        // not read stops the join: the person would otherwise apply without
        // seeing what joining makes visible about them (`manifest/0.4`).
        if let Some(DirectoryStatement::Malformed(why)) =
            ctx.config.private.vetting.directory(&vtc_did)
        {
            let name = vetting_actions::community_display(ctx.config, &vtc_did);
            ctx.state.join.page = JoinPage::Progress;
            ctx.state.join.messages.clear();
            ctx.state.join.fail(format!(
                "{name} published a statement of what its member directory would show about you, and it could not be read ({}). Nothing has been sent: joining without seeing it is not offered. Ask the community to fix it, then try again.",
                sanitize_display(why, 200)
            ));
            return;
        }

        // Then the trust-registry question, last, so it is the final thing the
        // person sees before the request goes out — and on every join, because
        // there is no right answer to assume.
        let registry_answered = ctx
            .state
            .join
            .registry
            .as_ref()
            .is_some_and(|r| r.answered_for(&vtc_did));
        if !registry_answered {
            let community_name = ctx.config.agent_name_for(&vtc_did).map(str::to_string);
            let review = join_review(ctx.config, ctx.state, &vtc_did, &choice);
            let directory = match ctx.config.private.vetting.directory(&vtc_did) {
                Some(DirectoryStatement::Stated(d)) => {
                    Some(crate::state_handler::join::DirectoryReview {
                        sentences: d.describe(|label| sanitize_display(label, 64)),
                        statement_digest: d.statement_digest.to_string(),
                    })
                }
                _ => None,
            };
            open_registry_choice(ctx.state, community_name, (choice, vtc_did, context_id));
            if let Some(registry) = ctx.state.join.registry.as_mut() {
                registry.review = Some(review);
                registry.directory = directory;
            }
            return;
        }

        // A criterion asking for a credential a wallet presents: offer to
        // collect it now, before the request goes out, so the submit can name
        // the criterion and the community counts the evidence it already holds.
        if let Some(offer) = wallet_offer(ctx.config, ctx.state, &vtc_did, &choice) {
            ctx.state.join.wallet = Some(WalletStep {
                parked: Some((choice, vtc_did, context_id)),
                ..offer
            });
            ctx.state.join.page = JoinPage::Wallet;
            ctx.state.join.processing = false;
            return;
        }

        // A community that hides its vetters takes a proof bound to a challenge
        // it issues — once, and fresh for each attempt (see `challenge_step`).
        // Asked for here, after every question the person answers, so the
        // challenge is as young as it can be when the proof is built over it.
        // The flow hands the wait to the loop that can hear the answer and comes
        // back through `JoinEntry::Challenge`, which lands here again.
        let fresh = std::mem::take(&mut ctx.state.join.challenge_fresh);
        let step = challenge_step(
            presented_application(ctx.config, &vtc_did, &choice),
            ctx.state.join.hears_replies,
            fresh,
        );
        if step == ChallengeStep::Ask
            && let IdentityPick::Reuse(persona) = choice
        {
            ctx.state.join.page = JoinPage::Progress;
            ctx.state.join.completed = Completion::NotFinished;
            ctx.state.join.messages.clear();
            let _ = ctx.state_tx.publish(ctx.state);
            let name = vetting_actions::community_display(ctx.config, &vtc_did);
            match ask_challenge(ctx.config, ctx.tdk, ctx.messaging, &vtc_did, persona).await {
                Ok(document_id) => {
                    // Locked while the answer is awaited: the wait is bounded
                    // (`CHALLENGE_WAIT`), and nothing on this page can usefully
                    // be done in the meantime.
                    ctx.state.join.processing = true;
                    ctx.state.join.waiting_on_challenge = true;
                    ctx.state.join.info(format!(
                        "This community hides its vetters. Asking {name} for a fresh challenge \
                         to bind your proof to — this gives up after {} seconds. Nothing has \
                         been sent yet; Esc stops waiting.",
                        CHALLENGE_WAIT.as_secs()
                    ));
                    ctx.state.join.challenge_wait = Some(AwaitingChallenge {
                        vtc_did,
                        document_id,
                        asked_at: std::time::Instant::now(),
                        choice,
                        context_id,
                    });
                }
                Err(reason) => ctx.state.join.fail(challenge_failed_words(&name, &reason)),
            }
            return;
        }

        // Move to the progress page and lock input.
        ctx.state.join.page = JoinPage::Progress;
        ctx.state.join.processing = true;
        ctx.state.join.completed = Completion::NotFinished;
        ctx.state.join.messages.clear();
        ctx.state.join.info(format!("Joining {vtc_did}…"));

        // Captured before the mint so a rollback (cancel or failure) can
        // restore it — `mint_persona_into` may overwrite `public.friendly_name`.
        let prior_friendly_name = ctx.config.public.friendly_name.clone();
        // The person's trust-registry answer, consumed by this one submit.
        // Taken, not read: a later join from the same open flow — another
        // community, or a retry after a failure — asks again rather than
        // inheriting it.
        let registry = ctx.state.join.registry.take();
        let registry_consent = registry.as_ref().is_some_and(|r| r.consent_for(&vtc_did));
        // The directory statement the person was shown, named by its digest,
        // kept with the join so a later change to the terms can be told apart.
        let directory_statement_digest = registry
            .filter(|r| r.community == vtc_did)
            .and_then(|r| r.directory)
            .map(|d| d.statement_digest);

        // The mint + join sequence needs the admin VTA session.
        let Some(admin) = ctx.admin_vta.cloned() else {
            ctx.state
                .join
                .fail("VTA session unavailable — cannot join right now.");
            return;
        };
        let resolver = ctx.tdk.did_resolver().clone();
        if let Some(session) = self.session.as_mut() {
            session.launch = Some(Launch {
                vtc_did: vtc_did.clone(),
                choice,
                context_id,
                admin,
                saga: JoinSaga::default(),
                prior_friendly_name,
                registry_consent,
                directory_statement_digest,
                display_name: None,
                transports: PeerTransports::default(),
                minted_keys: None,
                persona: None,
                applicant: None,
            });
        }
        self.start(
            ctx,
            Then::Stage,
            |io, progress| io.reach(ReachReq { resolver, vtc_did }, progress),
            JobResult::Reached,
        );
    }

    /// Stage 1 came back: the community's name and what it offers.
    fn on_reached(&mut self, ctx: &mut JoinCtx<'_>, reached: Reached) {
        let Some(launch) = self.launch_mut() else {
            return;
        };
        // Seeded into the persisted cache so the communities list shows it
        // without waiting for the background sweep.
        ctx.config
            .set_cached_agent_name(&launch.vtc_did, reached.display_name.clone(), Utc::now());
        ctx.state.join.display_name = reached.display_name.clone();
        launch.display_name = reached.display_name;
        launch.transports = reached.transports;
        // A peer that advertises no messaging service cannot be joined at all,
        // and discovering that after the persona mint leaves an orphaned
        // identity attached to a request nobody could receive. This is a check
        // on what the document *offers*.
        let Some(peer_preferred) = launch.transports.preferred() else {
            let message = format!(
                "This community advertises no messaging transport ({}). Its DID \
                 document offers neither a TSP nor a DIDComm service, so a join \
                 request cannot reach it. Nothing was created.",
                ctx.state
                    .join
                    .display_name
                    .as_deref()
                    .unwrap_or(&launch.vtc_did)
            );
            ctx.state.join.fail(message);
            self.end_launch(ctx);
            return;
        };
        // What the community *offers* — not yet the wire the submit goes out
        // on. That needs our own leg too, settled at the submit.
        ctx.state
            .join
            .info(format!("Community reachable over {peer_preferred}."));
        // The community's context exists before anything is minted into it. A
        // retried join reuses a context an interrupted one left behind.
        let req = ContextReq {
            admin_vta: launch.admin.clone(),
            top_context_id: ctx.config.account.top_context_id.clone(),
            context_id: launch.context_id.clone(),
            name: launch
                .display_name
                .clone()
                .unwrap_or_else(|| shorten_did(&launch.vtc_did, 48)),
        };
        self.start(
            ctx,
            Then::Stage,
            |io, _| io.context(req),
            JobResult::Context,
        );
    }

    /// Stage 1 done: the context is there. Choose the persona — reuse one, or
    /// start minting.
    async fn on_context(&mut self, ctx: &mut JoinCtx<'_>, context: Result<bool, String>) {
        let io = Arc::clone(&self.io);
        let Some(launch) = self.launch_mut() else {
            return;
        };
        let context_id = launch.context_id.clone();
        match context {
            Ok(true) => ctx
                .state
                .join
                .info(format!("Created context {context_id}.")),
            Ok(false) => ctx.state.join.info(format!("Using context {context_id}.")),
            Err(e) => {
                ctx.state.join.fail(format!(
                    "Could not prepare context {context_id}: {e}. Nothing was created."
                ));
                self.end_launch(ctx);
                return;
            }
        }
        launch.saga.context_registered(context_id.clone());
        let top_context_id = ctx.config.account.top_context_id.clone();
        // Reuse an existing account persona (R-B-3) or mint a fresh,
        // self-contained one (D6). Only a *minted* persona is recorded in the
        // saga — a reused persona pre-exists and is never rolled back.
        match launch.choice {
            IdentityPick::Reuse(persona_id) => {
                let Some((did, _)) = io.identity(ctx.config, persona_id) else {
                    ctx.state
                        .join
                        .fail("Selected persona is unavailable — cannot reuse it.");
                    self.end_launch(ctx);
                    return;
                };
                // Per-persona idempotency (R-B-9): block a second live
                // membership as the *same* persona, while still allowing other
                // personas.
                if is_duplicate_membership(ctx.config, &launch.vtc_did, persona_id) {
                    ctx.state.join.fail(
                        "Already a member of (or have a pending request for) this community as this persona.",
                    );
                    self.end_launch(ctx);
                    return;
                }
                // A persona's keys live in one context; one minted into a
                // sub-context is only ever presented from it.
                if let Some(record) = ctx.config.account.personas.get(&persona_id) {
                    let home = community_context::persona_context(record, &top_context_id);
                    if community_context::is_sub_context(home, &top_context_id)
                        && home != context_id
                    {
                        let message = format!(
                            "This persona's keys live in {home}, so it can only join from there."
                        );
                        ctx.state.join.fail(message);
                        self.end_launch(ctx);
                        return;
                    }
                }
                ctx.state.join.info(format!("Reusing persona {did}…"));
                launch.persona = Some((persona_id, did));
                self.connect(ctx).await;
            }
            IdentityPick::Mint => {
                // The persona's mediator is the account's VTA mediator: the DID
                // minted via the VTA's webvh server advertises that mediator in
                // its DIDComm service, so the persona listener must use the same
                // one. A VTA that advertised no mediator refuses the mint here,
                // before any key or DID is created at the VTA.
                let Some(mediator) = setup_config::vta_mediator(ctx.config) else {
                    ctx.state.join.fail(setup_config::NO_VTA_MEDIATOR);
                    self.end_launch(ctx);
                    return;
                };
                ctx.state.setup.custom_mediator = Some(mediator);
                ctx.state
                    .join
                    .info("Creating persona keys (signing, authentication, encryption)…");
                // How the new persona is presented: the operator's choice on the
                // identity page, else the account's preference (VTI-VTA-036).
                let req = MintReq {
                    admin_vta: launch.admin.clone(),
                    tdk: ctx.tdk.clone(),
                    context_id,
                    presentation: openvtc_core::config::account::persona_presentation(
                        &ctx.config.account,
                        ctx.state.join.new_persona_did_method,
                    ),
                };
                self.start(
                    ctx,
                    Then::Stage,
                    |io, progress| io.mint(req, progress),
                    |parts| JobResult::Minted(Box::new(parts)),
                );
            }
        }
    }

    /// Stage 2 came back: what the VTA minted. Persist the persona.
    async fn on_minted(&mut self, ctx: &mut JoinCtx<'_>, parts: MintedParts) {
        let MintedParts {
            keys,
            update,
            did,
            failure,
        } = parts;
        if let Some(keys) = keys {
            ctx.state.setup.did_keys = Some(keys);
        }
        if let Some((update, next_update)) = update {
            ctx.state.setup.vta.update_secret = Some(update);
            ctx.state.setup.vta.next_update_secret = Some(next_update);
        }
        if let Some(vta::MintedDid {
            keys,
            did,
            document,
            locator,
        }) = did
        {
            // A persona the VTA minted without `#tsp` can never reach a
            // TSP-only community — and this join may be to one. Say so here
            // rather than letting it surface later as a request that goes out
            // and is never answered.
            if let Some(warning) = openvtc_core::config::did::tsp_advertisement_warning(&document) {
                ctx.state.join.info(warning);
            }
            ctx.state.setup.did_keys = Some(keys);
            ctx.state.setup.webvh_address.did = did;
            ctx.state.setup.webvh_address.document = document;
            ctx.state.setup.webvh_address.locator = locator;
        }
        if let Some(failure) = failure {
            ctx.state.join.fail(failure);
            self.end_launch(ctx);
            return;
        }
        // A join mints the persona *unlabelled*: the community's name is not
        // the persona's. Its community binding is recorded on the membership
        // record and shown beside it; the label is for a name the operator
        // chose.
        ctx.state.setup.username = String::new();
        // `mint_persona_into` writes the persona record + runtime identity + key
        // info to disk *immediately*, so from here until the community record is
        // persisted the account holds a persona with no community. The saga
        // records it so a cancel or later failure rolls it back.
        let persona_id = match self
            .io
            .persist_mint(ctx.config, &ctx.state.setup, ctx.tdk, ctx.profile)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                ctx.state.join.fail(format!("Failed to save persona: {e}"));
                self.end_launch(ctx);
                return;
            }
        };
        let minted_keys = ctx.state.setup.did_keys.clone();
        let Some(launch) = self.launch_mut() else {
            return;
        };
        launch.saga.minted(persona_id);
        launch.minted_keys = minted_keys;
        // Where its keys live, which decides every context it can join from.
        if let Some(record) = ctx.config.account.personas.get_mut(&persona_id) {
            record.origin_context_id = launch.context_id.clone();
        }
        let persona_did = ctx.state.setup.webvh_address.did.clone();
        ctx.state
            .join
            .info(format!("Persona created: {persona_did}"));
        launch.persona = Some((persona_id, persona_did));
        self.connect(ctx).await;
    }

    /// Stage 3, on the loop: the applicant can send, and its listener is
    /// claimed — recorded in the saga *before* it is installed, so a cancel
    /// while it connects still removes it. Then off the loop: install it and
    /// settle the invitation.
    async fn connect(&mut self, ctx: &mut JoinCtx<'_>) {
        let io = Arc::clone(&self.io);
        let Some(persona_id) = self
            .launch_mut()
            .and_then(|l| l.persona.as_ref().map(|(id, _)| *id))
        else {
            return;
        };
        // Submit the join request to the VTC. The persona is the sender (the
        // VTC reads the applicant from the envelope). The VTC's submit-receipt
        // returns asynchronously to the persona's mediator; until it does, the
        // request message id is the correlation handle stored on the Pending
        // record.
        ctx.state.join.info("Submitting join request…");
        if !io.can_message(ctx.tdk) {
            self.fail_and_undo(
                ctx,
                "Messaging (ATM) unavailable — cannot submit the join request.",
            )
            .await;
            return;
        }
        let Some((applicant_did, mediator)) = io.identity(ctx.config, persona_id) else {
            self.fail_and_undo(
                ctx,
                "Persona identity unavailable after mint — cannot submit.",
            )
            .await;
            return;
        };
        let listener = io
            .listener_spec(
                ctx.messaging,
                ctx.config,
                ctx.tdk,
                persona_id,
                &applicant_did,
            )
            .await;
        let present = ctx.state.join.present_invitation;
        let loaded = ctx.state.invitation_credential.take();
        let foreign = if present {
            None
        } else {
            loaded
                .as_ref()
                .and_then(|vic| foreign_invitation_subject(ctx.config, vic))
        };
        let resolver = ctx.tdk.did_resolver().clone();
        let messaging = ctx.messaging.cloned();
        let Some(launch) = self.launch_mut() else {
            return;
        };
        if let Some(spec) = &listener {
            launch.saga.listener_up(spec.id.clone());
        }
        launch.applicant = Some((applicant_did, mediator));
        let req = InviteReq {
            messaging,
            listener,
            admin_vta: launch.admin.clone(),
            resolver,
            vtc_did: launch.vtc_did.clone(),
            present,
            loaded,
            foreign,
        };
        self.start(
            ctx,
            Then::Stage,
            |io, progress| io.invite(req, progress),
            JobResult::Invited,
        );
    }

    /// Stage 3 came back: the listener's fate and the invitation to present.
    /// Plan the presenting — the linkage proof's signer, the answers, the
    /// hidden-vetting proof — on the loop, and run it off.
    async fn on_invited(&mut self, ctx: &mut JoinCtx<'_>, invited: Invited) {
        let Some(launch) = self.launch_mut() else {
            return;
        };
        if invited.listener_up == Some(false) {
            launch.saga.listener_failed();
        }
        // Setting the presented invitation to the resolved VIC keeps the VP,
        // the linkage proof, and the summary all consistent with what is
        // actually presented.
        let state = &mut *ctx.state;
        let config = &*ctx.config;
        state.invitation_credential = invited.presentable;
        state.join.has_invitation = state.invitation_credential.is_some();
        state.join.presented_invitation = state.invitation_credential.as_ref().map(|vic| {
            let subject = openvtc_core::join::invitation_subject(vic).map(str::to_string);
            PresentedInvitation {
                id: openvtc_core::join::invitation_id(vic)
                    .unwrap_or_default()
                    .to_string(),
                // Verified-only, from the persisted cache: the subject is one of
                // our own personas, so the sweep normally has a name for it.
                subject_agent_name: subject
                    .as_deref()
                    .and_then(|s| config.agent_name_for(s))
                    .map(|n| sanitize_display(n, 256)),
                subject,
            }
        });
        // Present the holder VP. When a matching, unexpired invitation (VIC) is
        // resolved it rides in the VP's `verifiableCredential` array; the VTC
        // verifies it and auto-admits on a valid, trusted, unconsumed
        // invitation. With none the join is an open request the community
        // reviews.
        if state.invitation_credential.is_some() {
            state
                .join
                .info("Presenting your invitation credential to the community…");
        } else if state.join.present_invitation {
            // Wanted to present one, but none resolved to a usable VIC.
            state.join.info(
                "No valid invitation for this community — \
                 submitting as an open request (awaiting approval).",
            );
        }
        let Some((persona_id, _)) = launch.persona.clone() else {
            self.fail_and_undo(ctx, "The join lost track of its persona part-way through and was undone. Please try again.").await;
            return;
        };
        let Some((applicant_did, _)) = launch.applicant.clone() else {
            self.fail_and_undo(ctx, "The join lost track of its persona part-way through and was undone. Please try again.").await;
            return;
        };
        let linkage = plan_linkage(config, state, &applicant_did);
        let answers = state.join.answers.as_ref().and_then(|a| {
            a.approved.clone().map(|(face_id, approved)| AnswersPlan {
                context_id: launch.context_id.clone(),
                persona_did: applicant_did.clone(),
                community_did: launch.vtc_did.clone(),
                asked: a.asked.clone(),
                face_id,
                approved,
            })
        });
        // Peer identity vetting: present the statements gathered for this
        // community under this persona. Under a hidden-vetting criterion the
        // proof is built off the loop; everything that stops it before the VTA
        // is asked is decided here, and said after the answers, as it always
        // was.
        let hidden = config
            .private
            .vetting
            .application(&launch.vtc_did, persona_id)
            .filter(|a| a.join_did == applicant_did && a.hidden.is_some())
            .map(hidden_plan);
        let req = PresentReq {
            admin_vta: launch.admin.clone(),
            linkage,
            answers,
            hidden,
        };
        self.start(
            ctx,
            Then::Stage,
            |io, progress| io.present(req, progress),
            JobResult::Presented,
        );
    }

    /// Stage 4 came back: build the presentation and read the signer, then
    /// send it off the loop.
    async fn on_presented(&mut self, ctx: &mut JoinCtx<'_>, presented: Presented) {
        let Presented {
            linkage,
            attributes,
            proof,
            failure,
        } = presented;
        if let Some(failure) = failure {
            self.fail_and_undo(ctx, failure).await;
            return;
        }
        let io = Arc::clone(&self.io);
        let Some(launch) = self.launch_mut() else {
            return;
        };
        let (Some((persona_id, _)), Some((applicant_did, mediator))) =
            (launch.persona.clone(), launch.applicant.clone())
        else {
            self.fail_and_undo(ctx, "The join lost track of its persona part-way through and was undone. Please try again.").await;
            return;
        };
        let vtc_did = launch.vtc_did.clone();
        if let Some(proof) = proof
            && let Some(application) = ctx
                .config
                .private
                .vetting
                .application_mut(&vtc_did, persona_id)
                .filter(|a| a.join_did == applicant_did && a.hidden.is_some())
        {
            application.set_hidden_submission(proof);
        }
        let mut vp = openvtc_core::join::build_join_vp(
            &applicant_did,
            ctx.state.invitation_credential.as_ref(),
            linkage.as_ref(),
        );
        let registry_consent = launch.registry_consent;
        let protocol = ctx.config.private.vetting.protocol_for(&vtc_did);
        let presentation = match ctx.config.private.vetting.application(&vtc_did, persona_id) {
            Some(application) if application.join_did == applicant_did => {
                let statements = application.presentable_statements(Utc::now());
                if !statements.is_empty() {
                    ctx.state.join.info(format!(
                        "Presenting {} vetting statement(s) to the community…",
                        statements.len()
                    ));
                }
                openvtc_core::join::attach_credentials(&mut vp, statements);
                openvtc_core::join::JoinPresentation {
                    vp,
                    extensions: application.join_extensions(),
                    attributes,
                    protocol,
                    // The vetting criterion this application was made under.
                    criterion: application.requirements_digest.clone(),
                    registry_consent,
                }
            }
            // No application: the community decides under the first criterion
            // this submission meets — an invitation, a credential it recognises,
            // or review — which is the route the person chose. With wallet
            // evidence, under the criterion it was collected for: the community
            // counts it only there.
            _ => openvtc_core::join::JoinPresentation {
                attributes,
                protocol,
                registry_consent,
                criterion: match &ctx.state.join.wallet_outcome {
                    Some(WalletOutcome::Presented(digest)) => Some(digest.clone()),
                    _ => None,
                },
                ..vp.into()
            },
        };
        let prepared = io.prepare_submit(ctx.config, ctx.tdk, persona_id).await;
        let req = SubmitReq {
            messaging: ctx.messaging.cloned(),
            vtc_did,
            applicant_did,
            mediator,
            transports: launch.transports.clone(),
            prepared,
            presentation,
        };
        self.start(
            ctx,
            Then::Stage,
            |io, progress| io.submit(req, progress),
            JobResult::Submitted,
        );
        if let Some(job) = self.session.as_mut().and_then(|s| s.job.as_mut()) {
            job.submitting = true;
        }
    }

    /// The community a join request is being sent to right now, if one is.
    /// The runtime holds that community's messages until the request has
    /// been recorded, so a fast answer is not processed before the pending
    /// record it answers exists.
    pub(crate) fn submitting_to(&self) -> Option<&str> {
        let session = self.session.as_ref()?;
        session
            .job
            .as_ref()
            .filter(|job| job.submitting)
            .and(session.launch.as_ref())
            .map(|launch| launch.vtc_did.as_str())
    }

    /// Stage 5 came back: the request went out, or why not. Record the
    /// pending membership.
    async fn on_submitted(&mut self, ctx: &mut JoinCtx<'_>, submitted: Submitted) {
        let Submitted {
            transport: submit_transport,
            online: applicant_online,
            request,
        } = submitted;
        let request_id = match request {
            Ok(id) => id,
            // A persona whose key cannot be read cannot apply. Nothing was sent;
            // the persona and its listener are kept, as they always were on
            // this path.
            Err(SubmitError::Signer(e)) => {
                ctx.state
                    .join
                    .fail(format!("Couldn't sign the application: {e}"));
                self.end_launch(ctx);
                return;
            }
            // Nothing was submitted, so nothing will reply — release the socket
            // opened for this attempt and roll back a persona minted for it.
            Err(e) => {
                self.fail_and_undo(ctx, format!("Failed to submit join request: {e}"))
                    .await;
                return;
            }
        };
        let io = Arc::clone(&self.io);
        let Some(launch) = self.launch_mut() else {
            return;
        };
        launch.saga.submitted();
        let (Some((persona_id, persona_did)), Some((applicant_did, _))) =
            (launch.persona.clone(), launch.applicant.clone())
        else {
            self.fail_and_undo(ctx, "The join lost track of its persona part-way through and was undone. Please try again.").await;
            return;
        };
        let vtc_did = launch.vtc_did.clone();
        // The challenge a hidden proof was bound to is spent now: the community
        // consumes it the moment it reads the proof, whatever it then decides.
        // Kept, it would be bound into the next attempt's proof and refused
        // there. Saved with the membership below.
        if let Some(application) = ctx
            .config
            .private
            .vetting
            .application_mut(&vtc_did, persona_id)
            .filter(|a| a.join_did == applicant_did)
        {
            application.hidden_submission_sent();
        }
        // Record the pending membership and persist.
        let record = sequence::pending_record(
            vtc_did.clone(),
            launch.display_name.clone(),
            launch.context_id.clone(),
            persona_id,
            request_id,
            Utc::now(),
            submit_transport,
        );
        let record = CommunityRecord {
            directory_statement_digest: launch.directory_statement_digest.clone(),
            ..record
        };
        ctx.config.account.add_membership(record.clone());
        launch.saga.persisted();
        let registry_consent = launch.registry_consent;
        if let Err(e) = io.save(ctx.save, ctx.config).await {
            ctx.state
                .join
                .fail(format!("Failed to save community record: {e}"));
            self.end_launch(ctx);
            return;
        }

        // Sent — refresh the communities panel and surface the relaunch prompt.
        //
        // "Sent", not "delivered": the send resolves `Ok` when *our own
        // mediator* accepts the frame, which says nothing about whether the
        // community received it (R1.1). The acknowledgement is asynchronous;
        // `pending_unacknowledged` flags the record in the communities panel if
        // nothing arrives within `PENDING_ACK_GRACE_SECS`, so the honest thing to
        // do here is name what is still outstanding and point at where the
        // answer will show up.
        ctx.state.main_page.sync_from_config(ctx.config);
        // Durable, unlike the ceremony commentary in `state.join`, which is
        // transient UI. Whether the applicant was connected is part of that
        // record: a join submitted from an unconnected persona takes the slow
        // path, and an operator reading this log later cannot otherwise tell
        // that from a community that never answered.
        ctx.config.private.logs.insert(
            LogFamily::Community,
            format!(
                "Join request sent to ({}) as persona ({}) over {} — Pending, not yet acknowledged.{}",
                ctx.state.join.display_name.as_deref().unwrap_or(&vtc_did),
                persona_did,
                submit_transport,
                if applicant_online {
                    ""
                } else {
                    " The applicant was not connected at submit; a reply that arrives before it \
                     connects is collected from the mediator rather than streamed."
                }
            ),
        );
        ctx.state.main_page.log(format!(
            "Join request sent over {submit_transport} — Pending in your Communities list, awaiting \
             the community's acknowledgement."
        ));
        ctx.state.join.created_community = Some(record);
        ctx.state.join.created_persona_did = Some(persona_did);
        ctx.state.join.registry_consent_sent = Some(registry_consent);
        ctx.state.join.completed = Completion::CompletedOK;
        ctx.state.join.info(format!(
            "Join request sent over {submit_transport}. Waiting for the community to acknowledge it — \
             it's Pending in your Communities list, which will flag it if no response arrives."
        ));
        self.end_launch(ctx);
    }

    /// The launch failed: say why, undo what it did, and end it.
    async fn fail_and_undo(&mut self, ctx: &mut JoinCtx<'_>, why: impl Into<String>) {
        ctx.state.join.fail(why);
        self.compensate(ctx).await;
        self.end_launch(ctx);
    }

    /// Undo the launch from its saga: remove the listener it installed, and
    /// forget the persona it minted unless something already references it.
    async fn compensate(&mut self, ctx: &mut JoinCtx<'_>) {
        let Some(launch) = self.session.as_ref().and_then(|s| s.launch.as_ref()) else {
            return;
        };
        let mut forgot = false;
        for compensation in launch.saga.compensations() {
            match compensation {
                Compensation::RemoveListener(id) => {
                    if let Some(messaging) = ctx.messaging {
                        self.io.remove_listener(messaging, &id).await;
                    }
                }
                Compensation::ForgetPersona(persona_id) => {
                    if !ctx.config.account.persona_referenced(&persona_id) {
                        sequence::forget_minted_persona(
                            ctx.config,
                            persona_id,
                            launch.minted_keys.as_ref(),
                            &launch.prior_friendly_name,
                        );
                        forgot = true;
                    }
                }
            }
        }
        if forgot && let Err(e) = self.io.save(ctx.save, ctx.config).await {
            debug!("persona rollback re-save failed after a failed join: {e}");
        }
    }

    /// The launch is over, however it ended: input unlocks.
    fn end_launch(&mut self, ctx: &mut JoinCtx<'_>) {
        if let Some(session) = self.session.as_mut() {
            session.launch = None;
        }
        ctx.state.join.processing = false;
    }

    /// The saga of the launch in progress — for tests.
    #[cfg(test)]
    fn saga(&self) -> Option<&JoinSaga> {
        self.session
            .as_ref()
            .and_then(|s| s.launch.as_ref())
            .map(|l| &l.saga)
    }
}

/// What a job that panicked leaves on the join page.
const JOB_LOST: &str = "Joining a community failed (internal error).";

/// What the book knows about whether `vtc_did` vets.
fn knowledge_of(config: &Config, vtc_did: &str) -> Option<bool> {
    match config.private.vetting.knowledge(vtc_did) {
        Knowledge::Vetting(_) => Some(true),
        Knowledge::NoVetting => Some(false),
        Knowledge::Unknown => None,
    }
}

/// #1b: the subject-linkage proof to build when the presenting DID differs
/// from the presented VIC's subject — the invited persona authorizes the
/// presenter. `None` on the join-as-subject path (presenter == subject), when
/// no invitation is presented, or when the subject's signer cannot be read
/// (it isn't one of our personas: we can't sign for a key we don't hold, and
/// the VTC then refuses the mismatched binding).
fn plan_linkage(config: &Config, state: &State, presenter_did: &str) -> Option<LinkagePlan> {
    let vic = state.invitation_credential.as_ref()?;
    let subject = openvtc_core::join::invitation_subject(vic)?;
    if subject == presenter_did {
        return None; // join-as-subject — no linkage needed
    }
    let vic_id = openvtc_core::join::invitation_id(vic)?;
    let signer = match config.subject_signer(subject) {
        Ok(signer) => signer,
        Err(e) => {
            debug!(subject = %subject, error = %e, "subject-linkage proof unavailable");
            return None;
        }
    };
    let name = config
        .agent_name_for(subject)
        .map(|n| sanitize_display(n, 256))
        .unwrap_or_else(|| shorten_did(subject, 48));
    Some(LinkagePlan {
        signer,
        subject: subject.to_string(),
        vic_id: vic_id.to_string(),
        presenter: presenter_did.to_string(),
        said: format!(
            "The invitation names {name}, which signs for this persona — the community \
             will see that the two are linked."
        ),
    })
}

/// What a hidden-vetting application's launch does about its proof: refuse
/// with the sentence the progress page fails with, or ask the VTA for it.
fn hidden_plan(application: &Application) -> HiddenPlan {
    let challenge = match hidden_proof_precheck(application) {
        Ok(challenge) => challenge,
        Err(refusal) => return HiddenPlan::Refuse(refusal),
    };
    // Hidden parameters but no application at the VTA: no vetter's attestation
    // has arrived.
    let (Some(params), Some(app)) = (application.hidden.clone(), application.hidden_app.clone())
    else {
        return HiddenPlan::Refuse(NO_ATTESTATION.to_string());
    };
    HiddenPlan::Prove {
        application_id: app.application_id,
        params: Box::new(params),
        digest: application.requirements_digest.clone().unwrap_or_default(),
        challenge,
    }
}
