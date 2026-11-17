//! State-B "join a community" orchestration (R-A-5 Stage 4).
//!
//! The join is driven by the loop that owns it — the runtime loop, or the
//! State-A loop — through [`driver::JoinDriver`], a state machine with no event
//! loop of its own (#529). Its long network work runs off the loop as jobs on
//! `DispatchDomain::Join`; the launch is a saga whose steps a failure or a
//! cancel undoes (`openvtc_core::join::saga`). See [`driver`] for the shape.
//!
//! This module holds what the driver decides with: the pure page logic (which
//! routes a community offers, how a vetting row reads, which contexts a persona
//! can join from), the bounded sends a join makes while it waits on a
//! community (its requirements, a challenge, a wallet session), and the hand-off
//! types the runtime loop uses to hear those answers ([`AwaitingRequirements`],
//! [`AwaitingChallenge`], [`AwaitingWallet`]). Every failure is surfaced into
//! the join log as a [`MessageType::Error`] — nothing `?`-bubbles a join error
//! in a way that would kill the app.

pub(crate) mod driver;

pub(crate) use driver::{JoinCtx, JoinDriver, JoinOutcome, JoinStep};

#[allow(unused_imports)]
use crate::state_handler::state::PublishState;
use std::time::Duration;

use affinidi_tdk::TDK;
use chrono::Utc;
use openvtc_core::config::{
    Config,
    account::{CommunityRecord, PersonaId, VtcDid},
    community_context::{self, ContextKind, ContextOption},
    context_path::parse_sub_context_id,
};
use openvtc_core::didcomm::Messaging;
use openvtc_core::join::sequence;
use openvtc_core::logs::LogFamily;
use openvtc_core::vetting::applicant::Application;
use openvtc_core::vetting::book::Knowledge;
use openvtc_core::vetting::disclosure::{Describe, DirectoryStatement};
use openvtc_core::vetting::guide::describe_requirements;
use openvtc_core::vetting::queries::{CommunityAnswer, CommunityQuery, QueryKind};
use openvtc_core::vetting::wire;
use tracing::{debug, warn};
use vta_sdk::{
    client::VtaClient,
    protocols::did_management::create::WebvhPathMode,
    protocols::vetting::{VettingRequirements, VettingRequirementsInvitation},
};

use crate::{
    Interrupted,
    state_handler::{
        actions::Action,
        join::{
            Applicant, ApplyAs, AvailableVic, FirstStepKind, IdentityPick, JoinAnswers,
            JoinApplication, JoinPage, JoinRoute, JoinState, JoinVettingView, KnownVetting,
            PersonaOption, PresentedInvitation, RegistryChoice, RouteOption, RouteState,
            VettingPhase, WalletOutcome, WalletPhase, WalletStep,
        },
        main_page::content::{VicLifecycle, VicSummary},
        main_page::{sanitize_display, shorten_did},
        setup_sequence::{
            Completion, MessageType,
            config::{self as setup_config, ConfigExtension},
            vta,
        },
        state::{ActivePage, State},
        vetting_actions,
    },
};
use driver::JoinIo;

/// How the join flow is entered.
///
/// Whether the flow can ask a community for its requirements and hand the
/// wait for the answer to the calling loop is the [`JoinDriver`]'s: only a
/// loop that reads inbound messages can.
pub(crate) enum JoinEntry {
    /// From the Communities panel.
    Fresh,
    /// For a community already chosen elsewhere — `j` on a vetting application,
    /// which is the join that application was made for. The DID entry page is
    /// skipped: an application names its community, and making someone find and
    /// retype that DID is what turned "go and get vetted" into a dead end.
    ForCommunity { vtc_did: String },
    /// Back from waiting for a community's requirements.
    Resume {
        vtc_did: String,
        outcome: RequirementsOutcome,
    },
    /// Back from waiting for the challenge a hidden-vetting proof binds. The
    /// launch that asked is taken up again exactly where it parked: everything
    /// the person chose on the way to it — persona, invitation, answers, the
    /// trust-registry box — is still on the join state, which this entry does
    /// not reset.
    Challenge {
        awaiting: AwaitingChallenge,
        outcome: ChallengeOutcome,
    },
    /// Back from a wallet session. Like [`JoinEntry::Challenge`], the join
    /// state is kept: the launch it parked is on [`WalletStep::parked`].
    Wallet { end: WalletEnd },
}

/// How a wallet session ended, for the launch waiting on it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WalletEnd {
    /// The wallet presented and the community verified it.
    Presented,
    /// No evidence, and why — the page offers to try again or go on.
    Unfinished(String),
}

/// A join parked on a wallet session.
///
/// The applicant's agent opens the session and polls it; the wallet answers
/// the community directly. Both answers arrive on the runtime loop's inbound
/// arm, so — like [`AwaitingChallenge`] — the flow hands the wait to that loop,
/// which keeps the wallet page up, polls on its sweep tick ([`wallet_tick`]),
/// reads each answer ([`wallet_answer`]) and enters the flow again with
/// [`JoinEntry::Wallet`].
#[derive(Clone, Debug)]
pub(crate) struct AwaitingWallet {
    pub vtc_did: String,
    /// The persona that opened the session — the one that will submit, since
    /// the evidence is bound to the applicant who opened it.
    pub persona: PersonaId,
    pub applicant_did: String,
    /// The question in flight (start, then each status poll), if any.
    pub asking: Option<String>,
    pub asked_at: std::time::Instant,
    /// The session, once the community opened it.
    pub session_id: Option<String>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

/// How long one wallet-session question waits for its answer.
pub(crate) const WALLET_ANSWER_WAIT: Duration = REQUIREMENTS_WAIT;

/// How a wait for a community's requirements ended.
pub(crate) enum RequirementsOutcome {
    /// Its manifest arrived; the book knows whether it vets.
    Learned,
    /// No usable answer, and why.
    Unanswered(String),
    /// The person chose to join without waiting.
    Skipped,
}

/// A join waiting for a community's manifest. The answer arrives on the
/// runtime loop's inbound arm, not as a join action, so the flow asks, returns
/// this ([`JoinStep::AwaitRequirements`]), and the runtime loop keeps the join
/// screen up, hears the answer — or gives up after [`REQUIREMENTS_WAIT`] — and
/// enters the flow again.
pub(crate) struct AwaitingRequirements {
    pub vtc_did: String,
    /// The manifest request's document id.
    pub document_id: String,
    pub asked_at: std::time::Instant,
}

/// How long the join screen waits for a community's requirements before
/// offering to go on without them.
pub(crate) const REQUIREMENTS_WAIT: Duration = Duration::from_secs(15);

/// A join parked on the challenge its hidden-vetting proof must bind.
///
/// A community that hides its vetters accepts a proof only over a challenge it
/// issued itself, once (`vtc/vetting/pcs-challenge/0.1`). The launch asks for
/// one and then, like [`AwaitingRequirements`], hands the wait to the runtime
/// loop, which is the only loop that hears the answer: the join driver takes
/// actions and its own jobs' results, nothing inbound. When the answer
/// arrives — or [`CHALLENGE_WAIT`] passes without one — that loop enters the
/// flow again with [`JoinEntry::Challenge`], and the launch carries on from
/// where it stopped rather than sending the person off to ask for it themselves.
#[derive(Clone, Debug)]
pub(crate) struct AwaitingChallenge {
    pub vtc_did: String,
    /// The challenge request's document id — what the answer threads on.
    pub document_id: String,
    pub asked_at: std::time::Instant,
    /// The launch to take up again: what `launch_join_sequence` was called
    /// with when it stopped to ask.
    pub choice: IdentityPick,
    pub context_id: String,
}

/// How a wait for a community's challenge ended.
#[derive(Debug)]
pub(crate) enum ChallengeOutcome {
    /// The challenge is on the application; the launch can build its proof.
    Issued,
    /// No usable challenge, and why — worded so the operator can tell a
    /// community that refused from one that never answered (R6.4).
    Unanswered(String),
}

/// How long a join waits for a community's challenge before it says none came.
/// The same wait as for its requirements: both are one round trip to the same
/// service, and a person watching the screen should not have to learn two.
pub(crate) const CHALLENGE_WAIT: Duration = REQUIREMENTS_WAIT;

/// How long sending the question may take before the page says so.
const ASK_TIMEOUT: Duration = Duration::from_secs(15);

/// The entry a community's answer makes for the join waiting on it, if the
/// answer is about that community's requirements.
pub(crate) fn resume_for(
    awaiting: &AwaitingRequirements,
    answer: &CommunityAnswer,
) -> Option<JoinEntry> {
    if answer.community() != awaiting.vtc_did {
        return None;
    }
    let outcome = match answer {
        CommunityAnswer::Manifest { .. } => RequirementsOutcome::Learned,
        CommunityAnswer::Refused {
            kind: QueryKind::Manifest,
            code,
            ..
        } => RequirementsOutcome::Unanswered(format!("it refused to say ({code})")),
        CommunityAnswer::Unreadable {
            kind: QueryKind::Manifest,
            detail,
            ..
        } => RequirementsOutcome::Unanswered(format!(
            "its answer is in a form this client cannot read ({detail})"
        )),
        _ => return None,
    };
    Some(JoinEntry::Resume {
        vtc_did: awaiting.vtc_did.clone(),
        outcome,
    })
}

/// The entry a community's answer makes for the join waiting on its challenge,
/// if the answer is to that join's own question.
///
/// Matched on the request's document id, not only the community: the Vetting
/// page asks for challenges too, and an answer to one of those is not the
/// answer this launch is waiting for.
pub(crate) fn challenge_resume_for(
    awaiting: &AwaitingChallenge,
    answer: &CommunityAnswer,
) -> Option<JoinEntry> {
    if answer.community() != awaiting.vtc_did {
        return None;
    }
    let outcome = match answer {
        CommunityAnswer::Challenge { query, .. } if *query == awaiting.document_id => {
            ChallengeOutcome::Issued
        }
        CommunityAnswer::Refused {
            query,
            kind: QueryKind::PcsChallenge,
            code,
            message,
            ..
        } if *query == awaiting.document_id => {
            let mut why = format!("it refused ({})", sanitize_display(code, 120));
            if let Some(note) = message {
                why.push_str(&format!(", saying: {}", sanitize_display(note, 300)));
            }
            ChallengeOutcome::Unanswered(why)
        }
        CommunityAnswer::Unreadable {
            query,
            kind: QueryKind::PcsChallenge,
            detail,
            ..
        } if *query == awaiting.document_id => ChallengeOutcome::Unanswered(format!(
            "it answered in a form this client cannot read — the two disagree about the task; \
             it is not a refusal ({})",
            sanitize_display(detail, 200)
        )),
        _ => return None,
    };
    Some(JoinEntry::Challenge {
        awaiting: awaiting.clone(),
        outcome,
    })
}

/// What a launch does about the challenge its hidden-vetting proof binds.
#[derive(Debug, PartialEq, Eq)]
enum ChallengeStep {
    /// Go on: nothing hidden to prove, a challenge was just issued for this
    /// launch, or this loop cannot hear an answer anyway (and
    /// [`hidden_proof_precheck`] says what to do when none is held).
    Proceed,
    /// Ask the community for a fresh challenge, and wait for it.
    Ask,
}

/// Decide [`ChallengeStep`] for a launch presenting `application`.
///
/// A fresh challenge is asked for on **every** hidden-vetting launch that can
/// hear the answer, even when one is already stored. The community keeps one
/// open challenge per applicant, replaces it whenever it is asked again, lets
/// it lapse after fifteen minutes, and spends it on any submission that
/// carries a proof — counted or refused. A stored one may be any of those
/// without this client knowing, and a proof over a dead challenge is refused
/// only after the request has gone out. One round trip at join time is the
/// price of never sending that.
///
/// Nothing is asked when there is nothing to prove: with no vetter's
/// attestation held there is no proof, and the refusal that follows says so —
/// asking first would only make the person wait to be told it.
fn challenge_step(
    application: Option<&Application>,
    hears_replies: bool,
    fresh: bool,
) -> ChallengeStep {
    let Some(application) = application.filter(|a| a.hidden.is_some()) else {
        return ChallengeStep::Proceed;
    };
    // An attestation the community will refuse is nothing to prove either, and the refusal
    // that follows says why — asking for a challenge first would only spend it.
    if fresh || !hears_replies || !application.holds_current_hidden_attestation() {
        return ChallengeStep::Proceed;
    }
    ChallengeStep::Ask
}

/// The vetting application a join as `pick` to `vtc_did` presents: the one
/// made under that persona, and only while it was made for that persona's DID
/// — the statements and proof it holds name the DID they were gathered for.
/// The same match the launch makes when it attaches them.
fn presented_application<'a>(
    config: &'a Config,
    vtc_did: &str,
    pick: &IdentityPick,
) -> Option<&'a Application> {
    let IdentityPick::Reuse(id) = pick else {
        return None;
    };
    let persona = config.account.personas.get(id)?;
    config
        .private
        .vetting
        .application(vtc_did, persona.persona_id)
        .filter(|a| a.join_did == persona.did)
}

/// Ask `vtc_did` for the challenge `persona`'s hidden proof must bind. `Ok` is
/// the request's document id; `Err` is why it could not be put on the wire.
///
/// The send is bounded (R1.2) and its failure is worded as *ours* — the
/// question never left — so it is not mistaken for a community that refused or
/// one that never answered (R6.4). The stored challenge is dropped once the
/// request is out: the community replaces it on receipt, so it can no longer
/// bind anything.
async fn ask_challenge(
    config: &mut Config,
    tdk: &TDK,
    messaging: Option<&Messaging>,
    vtc_did: &str,
    persona: PersonaId,
) -> Result<String, String> {
    let service = messaging.ok_or_else(|| {
        "messaging is not running, so the community's answer could not be heard".to_string()
    })?;
    let join_did = config
        .private
        .vetting
        .application(vtc_did, persona)
        .map(|a| a.join_did.clone())
        .ok_or_else(|| "the vetting application for this persona is gone".to_string())?;
    let document = wire::pcs_challenge_request(&join_did, vtc_did, None)
        .map_err(|e| format!("the request could not be built: {e}"))?;
    let document_id = match tokio::time::timeout(
        ASK_TIMEOUT,
        wire::sign_and_send(config, tdk, service, persona, document),
    )
    .await
    {
        Ok(Ok(document_id)) => document_id,
        Ok(Err(e)) => return Err(format!("the request could not be sent: {e}")),
        Err(_) => {
            return Err(format!(
                "the request was not sent within {} seconds — your mediator may be unreachable",
                ASK_TIMEOUT.as_secs()
            ));
        }
    };
    config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: vtc_did.to_string(),
        persona,
        kind: QueryKind::PcsChallenge,
        sent_at: Utc::now(),
    });
    if let Some(application) = config.private.vetting.application_mut(vtc_did, persona) {
        application.hidden_challenge = None;
    }
    Ok(document_id)
}

/// The wallet step a launch offers, if it offers one: the community has a
/// criterion a wallet can answer, the person has not answered the offer on
/// this join, the loop can hear the community's answers, and the join presents
/// an existing persona with no vetting application — the persona must exist to
/// sign the session open (the evidence is bound to the applicant who opened
/// it), and a vetting application submits under its own criterion.
fn wallet_offer(
    config: &Config,
    state: &State,
    vtc_did: &str,
    choice: &IdentityPick,
) -> Option<WalletStep> {
    if !state.join.hears_replies
        || state.join.wallet_outcome.is_some()
        || !matches!(choice, IdentityPick::Reuse(_))
        || presented_application(config, vtc_did, choice).is_some()
    {
        return None;
    }
    let criterion = config.private.vetting.wallet_criterion(vtc_did)?;
    Some(WalletStep {
        community: vetting_actions::community_display(config, vtc_did),
        requirements_digest: criterion.requirements_digest.clone()?,
        description: criterion.description.clone(),
        types: criterion.wallet_types.clone(),
        phase: WalletPhase::Offered { note: None },
        parked: None,
    })
}

/// Send one wallet-session question as `persona`, bounded (R1.2), and record
/// it so the answer is claimed. `Ok` is the document id.
async fn ask_wallet(
    config: &mut Config,
    tdk: &TDK,
    messaging: Option<&Messaging>,
    vtc_did: &str,
    persona: PersonaId,
    document: wire::Document,
    kind: QueryKind,
) -> Result<String, String> {
    let service = messaging.ok_or_else(|| {
        "messaging is not running, so the community's answer could not be heard".to_string()
    })?;
    let document_id = match tokio::time::timeout(
        ASK_TIMEOUT,
        wire::sign_and_send(config, tdk, service, persona, document),
    )
    .await
    {
        Ok(Ok(document_id)) => document_id,
        Ok(Err(e)) => return Err(format!("the request could not be sent: {e}")),
        Err(_) => {
            return Err(format!(
                "the request was not sent within {} seconds — your mediator may be unreachable",
                ASK_TIMEOUT.as_secs()
            ));
        }
    };
    config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: vtc_did.to_string(),
        persona,
        kind,
        sent_at: Utc::now(),
    });
    Ok(document_id)
}

/// Ask `vtc_did` to open a wallet session for the criterion
/// `requirements_digest`, as `persona`.
async fn ask_wallet_start(
    config: &mut Config,
    tdk: &TDK,
    messaging: Option<&Messaging>,
    vtc_did: &str,
    persona: PersonaId,
    requirements_digest: &str,
) -> Result<AwaitingWallet, String> {
    let applicant_did = config
        .identities
        .get(&persona)
        .map(|i| i.persona_did().to_string())
        .ok_or_else(|| "this persona's identity is not loaded".to_string())?;
    let document = wire::wallet_session_start_request(&applicant_did, vtc_did, requirements_digest)
        .map_err(|e| format!("the request could not be built: {e}"))?;
    let document_id = ask_wallet(
        config,
        tdk,
        messaging,
        vtc_did,
        persona,
        document,
        QueryKind::WalletSessionStart,
    )
    .await?;
    Ok(AwaitingWallet {
        vtc_did: vtc_did.to_string(),
        persona,
        applicant_did,
        asking: Some(document_id),
        asked_at: std::time::Instant::now(),
        session_id: None,
        expires_at: None,
    })
}

/// What an answer does to the wallet session waiting on it: `None` when it is
/// not this session's, `Some(None)` when the session goes on, and
/// `Some(Some(entry))` when it has ended.
pub(crate) fn wallet_answer(
    awaiting: &mut AwaitingWallet,
    answer: &CommunityAnswer,
    state: &mut State,
) -> Option<Option<JoinEntry>> {
    use openvtc_core::vetting::queries::wallet_session::status::v0_1 as status;
    if answer.community() != awaiting.vtc_did {
        return None;
    }
    let ours = |query: &str| awaiting.asking.as_deref() == Some(query);
    let end = |why: String| {
        Some(Some(JoinEntry::Wallet {
            end: WalletEnd::Unfinished(why),
        }))
    };
    match answer {
        CommunityAnswer::WalletSessionStarted { query, session, .. } if ours(query) => {
            awaiting.asking = None;
            awaiting.session_id = Some(session.session_id.to_string());
            awaiting.expires_at = Some(session.expires_at);
            if let Some(wallet) = state.join.wallet.as_mut() {
                wallet.phase = WalletPhase::Scan {
                    wallet_uri: session.wallet_uri.clone(),
                    expires_at: session.expires_at,
                    retrieved: false,
                };
            }
            Some(None)
        }
        CommunityAnswer::WalletSessionStatus {
            query, status: s, ..
        } if ours(query) => {
            awaiting.asking = None;
            match s.state {
                status::ResponseState::Presented => {
                    Some(Some(JoinEntry::Wallet { end: WalletEnd::Presented }))
                }
                status::ResponseState::Refused => end(match s.reason {
                    Some(reason) => wallet_refusal_words(reason),
                    None => "The community refused what the wallet presented.".to_string(),
                }),
                status::ResponseState::Expired => end(
                    "The session expired before the wallet answered. Try again when your wallet is to hand."
                        .to_string(),
                ),
                status::ResponseState::RequestRetrieved => {
                    if let Some(WalletPhase::Scan { retrieved, .. }) =
                        state.join.wallet.as_mut().map(|w| &mut w.phase)
                    {
                        *retrieved = true;
                    }
                    Some(None)
                }
                _ => Some(None),
            }
        }
        CommunityAnswer::Refused {
            query,
            kind: QueryKind::WalletSessionStart | QueryKind::WalletSessionStatus,
            code,
            message,
            ..
        } if ours(query) => {
            let mut why = format!(
                "The community refused the wallet session ({})",
                sanitize_display(code, 120)
            );
            if let Some(note) = message {
                why.push_str(&format!(": {}", sanitize_display(note, 300)));
            }
            end(why)
        }
        CommunityAnswer::Unreadable {
            query,
            kind: QueryKind::WalletSessionStart | QueryKind::WalletSessionStatus,
            detail,
            ..
        } if ours(query) => end(format!(
            "The community answered in a form this client cannot read — the two disagree about the task; it is not a refusal ({})",
            sanitize_display(detail, 200)
        )),
        _ => None,
    }
}

/// What a wallet presentation the community refused was refused for.
fn wallet_refusal_words(
    reason: openvtc_core::vetting::queries::wallet_session::status::v0_1::ResponseReason,
) -> String {
    use openvtc_core::vetting::queries::wallet_session::status::v0_1::ResponseReason as R;
    match reason {
        R::PresentationInvalid => {
            "The community could not verify what the wallet presented.".to_string()
        }
        R::QueryNotSatisfied => {
            "The wallet's credential does not have what the community asks for.".to_string()
        }
        R::IssuerNotTrusted => {
            "The community does not accept credentials from that credential's issuer.".to_string()
        }
        R::StatusNotValid => "The wallet's credential has been revoked or suspended.".to_string(),
        R::WalletDeclined => "The wallet declined to present.".to_string(),
        #[allow(unreachable_patterns)]
        _ => "The community refused what the wallet presented.".to_string(),
    }
}

/// One sweep tick of a wallet session: poll where it stands when nothing is in
/// flight, and end the wait when an answer has been owed too long (R1.2).
/// `Some` when the wait has ended.
pub(crate) async fn wallet_tick(
    awaiting: &mut AwaitingWallet,
    config: &mut Config,
    tdk: &TDK,
    messaging: Option<&Messaging>,
) -> Option<JoinEntry> {
    let unanswered = |what: &str| {
        Some(JoinEntry::Wallet {
            end: WalletEnd::Unfinished(format!(
                "The community did not answer {what} within {} seconds — its service may be offline or unreachable.",
                WALLET_ANSWER_WAIT.as_secs()
            )),
        })
    };
    // Past its expiry with no answer saying so: the community has stopped
    // answering, or this client could not ask.
    if awaiting
        .expires_at
        .is_some_and(|e| Utc::now() > e + chrono::Duration::seconds(30))
    {
        if let Some(query) = awaiting.asking.take() {
            config.private.vetting.forget_query(&query);
        }
        return unanswered("where the wallet session stands");
    }
    if let Some(query) = awaiting.asking.clone() {
        if awaiting.asked_at.elapsed() < WALLET_ANSWER_WAIT {
            return None;
        }
        // An unanswered status poll: the session may still be open, so ask
        // again below.
        config.private.vetting.forget_query(&query);
        awaiting.asking = None;
        if awaiting.session_id.is_none() {
            return unanswered("the request for a wallet session");
        }
    }
    let session_id = awaiting.session_id.clone()?;
    let document = match wire::wallet_session_status_request(
        &awaiting.applicant_did,
        &awaiting.vtc_did,
        &session_id,
    ) {
        Ok(d) => d,
        Err(e) => {
            return Some(JoinEntry::Wallet {
                end: WalletEnd::Unfinished(format!("The status request could not be built: {e}")),
            });
        }
    };
    match ask_wallet(
        config,
        tdk,
        messaging,
        &awaiting.vtc_did,
        awaiting.persona,
        document,
        QueryKind::WalletSessionStatus,
    )
    .await
    {
        Ok(query) => {
            awaiting.asking = Some(query);
            awaiting.asked_at = std::time::Instant::now();
            None
        }
        // Not sent: try again on the next tick, until the session runs out.
        Err(why) => {
            warn!(reason = %why, "wallet session status not sent");
            awaiting.asked_at = std::time::Instant::now();
            None
        }
    }
}

/// The sentence a hidden-vetting join stops on when the community's challenge
/// did not come. `reason` says which way it failed: not sent, refused,
/// unreadable, or no answer at all.
fn challenge_failed_words(community: &str, reason: &str) -> String {
    format!(
        "This community hides its vetters, so joining sends a zero-knowledge proof bound to a \
         challenge the community issues for each attempt. Asking {community} for one failed: \
         {reason}. Nothing was sent — join again to ask once more."
    )
}

/// The contexts a new application by `persona` to `vtc_did` can use.
fn application_contexts(
    config: &Config,
    vtc_did: &str,
    persona: Option<PersonaId>,
) -> Vec<ContextOption> {
    let record = persona.and_then(|p| config.account.personas.get(&p));
    community_context::context_options(
        &config.account,
        record,
        &sequence::suggested_context(config, vtc_did),
    )
}

/// The invitation row's detail: how many are held, and when the longest-lived
/// one runs out. Dates are shown as the credential writes them — an invitation
/// is someone else's document, and reformatting its `validUntil` would put a
/// date on screen that is not in the thing being presented.
fn invitations_held(invitations: &[AvailableVic]) -> String {
    let n = invitations.len();
    let latest = invitations
        .iter()
        .map(|v| v.valid_until.as_str())
        .filter(|u| !u.is_empty())
        .max();
    match latest {
        Some(until) => format!("{n} held, valid until {}", sanitize_display(until, 40)),
        None => format!("{n} held"),
    }
}

/// The ways in to `vtc_did`, in the order they are drawn.
///
/// Being vetted comes first, one row per persona and one for a new persona,
/// each a complete choice: which persona is the row's own, so nothing else on
/// the page has to be set first, and no row can act on behalf of a persona it
/// does not name. Within that group the personas are ordered by how close each
/// is to joining — statements ready, then an application under way, then none
/// — with a new persona last. The other ways in follow: an invitation, then an
/// open request, which only puts the applicant in front of the community's
/// moderators. Blocked rows keep their place rather than sinking to the
/// bottom, so the list reads the same way twice running.
fn build_routes(
    community: &str,
    requirements: &VettingRequirements,
    applications: &[JoinApplication],
    personas: &[ApplyAs],
    invitations: &[AvailableVic],
) -> Vec<RouteOption> {
    let held = invitations.len();
    let mut routes = Vec::new();

    let application_of = |persona: PersonaId| applications.iter().find(|a| a.persona == persona);
    let standing = |persona: PersonaId| match application_of(persona) {
        Some(app) if app.satisfied => 0,
        Some(_) => 1,
        None => 2,
    };
    let mut ordered: Vec<&ApplyAs> = personas.iter().collect();
    // Stable, so personas that stand alike keep the order they came in (by
    // label).
    ordered.sort_by_key(|p| standing(p.persona));
    for persona in ordered {
        let application = application_of(persona.persona);
        let (label, detail) = vetting_row_words(Some(&persona.label), application);
        routes.push(RouteOption {
            route: JoinRoute::Vetting,
            applicant: Some(Applicant::Persona(persona.persona)),
            label,
            detail,
            state: RouteState::Ready,
        });
    }
    let (label, detail) = vetting_row_words(None, None);
    routes.push(RouteOption {
        route: JoinRoute::Vetting,
        applicant: Some(Applicant::NewPersona),
        label,
        detail,
        state: new_persona_route_state(personas.is_empty()),
    });

    // An invitation the community requires is not an alternative to being
    // vetted — it is a second thing asked for on top. Offering it as its own
    // row would read as a way around the statements, so it is left to the
    // requirement bullets (`describe_requirements` already names it) and to the
    // note beside the vetting heading.
    let invitation_required = matches!(
        requirements.invitation,
        Some(VettingRequirementsInvitation::Required)
    );
    if !invitation_required {
        let refuses = matches!(
            requirements.invitation,
            Some(VettingRequirementsInvitation::None)
        );
        routes.push(RouteOption {
            route: JoinRoute::Invitation,
            applicant: None,
            label: "Use an invitation".to_string(),
            detail: if held == 0 {
                "admits you without being vetted".to_string()
            } else {
                invitations_held(invitations)
            },
            // Holding none is two different situations, and the difference is
            // provable rather than a guess. A VIC must name a
            // `credentialSubject.id` — `validate_invitation_credential` refuses
            // one without it, so there is no such thing as a bearer invitation
            // — and that subject is a persona DID. With no personas, no valid
            // invitation can be *for* you, and the row is genuinely shut. With
            // personas, one may well exist that this vault has not seen, and
            // pasting it is a step the join can walk you through.
            state: if refuses {
                RouteState::Blocked(format!("{community} does not admit anyone by invitation"))
            } else if held > 0 {
                RouteState::Ready
            } else if personas.is_empty() {
                RouteState::Blocked(
                    "an invitation is issued to one of your personas, and you have none yet"
                        .to_string(),
                )
            } else {
                RouteState::FirstStep {
                    note: "none is in your vault, so this starts by asking you to paste one — \
                           if you have none, the step offers to join without it"
                        .to_string(),
                    kind: FirstStepKind::OnTheWay,
                }
            },
        });
    }

    routes.push(RouteOption {
        route: JoinRoute::OpenRequest,
        applicant: None,
        label: "Send an open request".to_string(),
        // The persona is chosen on the next page, and the submit attaches that
        // persona's own statements whenever it has gathered any here — never
        // another persona's. Saying so keeps this row from reading as a way to
        // hold them back, without promising statements a persona lacks.
        detail: if applications.iter().any(|a| a.statements > 0) {
            format!(
                "{community}'s moderators decide — a persona with statements here presents them"
            )
        } else {
            format!("{community} refers it to its moderators to decide")
        },
        state: RouteState::Ready,
    });
    routes
}

/// Correct what the rows promise against what the community's criteria say
/// meeting them does (`manifest/0.3` `admission`).
///
/// [`build_routes`] words the invitation row as admitting and the vetting rows
/// as the applications they are, which is what a 0.2 community meant. A 0.3
/// community says per criterion whether meeting it admits or only submits for
/// review, and a row that said "admits you" over a `review` criterion would
/// tell someone they are in when an administrator has yet to decide. A 0.2
/// community says nothing, and its rows are left as they are.
fn word_routes_by_admission(
    routes: &mut [RouteOption],
    criteria: &[openvtc_core::vetting::book::CommunityCriterion],
) {
    use openvtc_core::vetting::protocol::Admission;
    let review = |c: Option<&openvtc_core::vetting::book::CommunityCriterion>| {
        c.and_then(|c| c.admission) == Some(Admission::Review)
    };
    let invitation = criteria
        .iter()
        .find(|c| c.invitation_required == Some(true));
    let vetting = criteria.iter().find(|c| c.vetting);
    for row in routes.iter_mut() {
        match row.route {
            JoinRoute::Invitation if review(invitation) => {
                if row.detail == "admits you without being vetted" {
                    row.detail = "goes to its administrators without being vetted".to_string();
                }
            }
            JoinRoute::Vetting if review(vetting) => {
                row.detail.push_str(" — then an administrator decides");
            }
            _ => {}
        }
    }
}

/// The longest a persona's label runs inside a row's label before it is
/// shortened, so one long name cannot push every row's detail off the screen.
const ROW_PERSONA_WIDTH: usize = 24;

/// What a vetting row says: `persona` is the persona's label, `None` for a new
/// persona, and `application` is that persona's own application here.
///
/// The label names the persona because the row *is* the choice of persona —
/// "Present your vetting statements" on its own left the reader to work out
/// whose statements, which is exactly the question that went wrong.
fn vetting_row_words(
    persona: Option<&str>,
    application: Option<&JoinApplication>,
) -> (String, String) {
    let Some(persona) = persona else {
        return (
            "Apply for vetting as a new persona".to_string(),
            "a new DID — vetting starts from scratch".to_string(),
        );
    };
    let who = openvtc_core::display::shorten_for_display(persona, ROW_PERSONA_WIDTH);
    match application {
        // Hidden vetting presents a proof, not statements: what it shows the
        // community is that enough vetters vetted you, never who.
        Some(app) if app.satisfied && app.attestations > 0 => (
            format!("Present your PCS ZKP proof as {who}"),
            format!(
                "ready — proves {} vetter{} vetted you, without naming them",
                app.attestations,
                if app.attestations == 1 { "" } else { "s" }
            ),
        ),
        Some(app) if app.satisfied => (
            format!("Present your vetting statements as {who}"),
            format!(
                "{} statement{} ready to present",
                app.statements,
                if app.statements == 1 { "" } else { "s" }
            ),
        ),
        Some(app) => (
            format!("Carry on with your application as {who}"),
            app.progress
                .clone()
                .unwrap_or_else(|| "under way".to_string()),
        ),
        None => (
            format!("Apply for vetting as {who}"),
            "no application yet".to_string(),
        ),
    }
}

/// What the "new persona" vetting row starts with. A persona is something this
/// join can make, so needing one is the row's first step rather than a reason
/// it is shut — greyed out, the one route the community is actually telling
/// you about read as the one you could not use.
fn new_persona_route_state(no_personas_yet: bool) -> RouteState {
    RouteState::FirstStep {
        note: if no_personas_yet {
            "you have no persona yet, so this starts by creating one — every card is signed by \
             the DID you join with"
                .to_string()
        } else {
            "this starts by creating the persona, then its own application — statements made \
             for another of your personas name that persona's DID, and do not carry over"
                .to_string()
        },
        kind: FirstStepKind::CreatePersona,
    }
}

/// What to do next on an application, worded for the join page.
///
/// The Vetting panel's words ([`vetting_actions::next_step_words`]) lead with
/// that panel's key — `j` to join, `f` for a face — and none of those keys mean
/// anything here. On this page every step is taken from the persona's own row,
/// so the hint names the row.
fn join_page_next_step(step: &openvtc_core::vetting::applicant::NextStep, row: &str) -> String {
    use openvtc_core::vetting::applicant::NextStep;
    let what = match step {
        NextStep::Join => return format!("join — Enter on \"{row}\""),
        NextStep::SendCard { .. } => {
            "a vetter opened a session: read the code together, then send your card"
        }
        NextStep::LearnRequirements => "ask the community what it requires",
        NextStep::ChooseFace => "choose the face you show vetters, then ask a vetter",
        NextStep::AskVetter => "ask a vetter with their ticket",
        NextStep::WaitForVetters => "wait for your vetters — you are told when one answers",
    };
    format!("{what} — Enter on \"{row}\" opens it")
}

/// The note beside the vetting heading: that this community also asks for an
/// invitation, on top of the statements.
fn vetting_detail_suffix(
    community: &str,
    requirements: &VettingRequirements,
    held: usize,
) -> Option<String> {
    matches!(
        requirements.invitation,
        Some(VettingRequirementsInvitation::Required)
    )
    .then(|| format!("{community} also asks for an invitation ({held} held)"))
}

/// The row the page opens on.
///
/// In order: the persona just made from this page (making it was the decision
/// about who applies); a persona whose statements are ready (the common
/// rejoin, which then takes no keystrokes); an invitation in hand (it admits
/// without vetting); an application under way; and otherwise the first row
/// that can be taken, so Enter on arrival never lands on one that refuses.
fn opening_row(known: &KnownVetting, prefer: Option<PersonaId>) -> usize {
    let vetting_row = |pick: &dyn Fn(PersonaId) -> bool| {
        known
            .routes
            .iter()
            .position(|r| matches!(r.applicant, Some(Applicant::Persona(p)) if pick(p)))
    };
    prefer
        .and_then(|p| known.row_for(Applicant::Persona(p)))
        .or_else(|| vetting_row(&|p| known.ready_as(Some(Applicant::Persona(p))).is_some()))
        .or_else(|| {
            known
                .routes
                .iter()
                .position(|r| r.route == JoinRoute::Invitation && r.state == RouteState::Ready)
        })
        .or_else(|| vetting_row(&|p| known.application_for(p).is_some()))
        .or_else(|| known.routes.iter().position(RouteOption::available))
        .unwrap_or(0)
}

/// What the join flow shows for `vtc_did`, when the book knows it vets.
///
/// `invitations` are this community's usable VICs, already collected — the
/// routes cannot be drawn without them, because whether an invitation is a way
/// in is a fact about this account, not about the community.
pub(crate) fn vetting_view(
    config: &Config,
    vtc_did: &str,
    invitations: &[AvailableVic],
    prefer: Option<PersonaId>,
    now: chrono::DateTime<Utc>,
) -> Option<JoinVettingView> {
    let book = &config.private.vetting;
    let Knowledge::Vetting(criterion) = book.knowledge(vtc_did) else {
        return None;
    };
    let label =
        |persona: PersonaId| sanitize_display(&config.persona_profile_label_for(persona), 128);
    let mut personas: Vec<ApplyAs> = config
        .identities
        .iter()
        .map(|(id, identity)| ApplyAs {
            persona: *id,
            label: label(*id),
            did: identity.persona_did().to_string(),
        })
        .collect();
    personas.sort_by(|a, b| a.label.cmp(&b.label));
    // Every one, not the first: a community can hold an application from each
    // of this account's personas, and each has a row of its own.
    let mut joins: Vec<JoinApplication> = book
        .applications
        .iter()
        .filter(|a| a.community == vtc_did)
        .map(|app| {
            let evaluation = app.checklist(now);
            // The statements name the DID the application was made for, and
            // the join attaches them only when that is the DID joining
            // (the launch's presenting stage). A persona whose DID has moved on since
            // cannot present them, so the page must not call them ready.
            let current_did = personas
                .iter()
                .find(|p| p.persona == app.persona)
                .map(|p| p.did.as_str());
            let stale = current_did.is_some_and(|did| did != app.join_did);
            JoinApplication {
                id: app.id.clone(),
                persona: app.persona,
                persona_label: label(app.persona),
                statements: app.presentable_statements(now).len(),
                attestations: app.hidden_held(),
                progress: if stale {
                    Some(
                        "made for an earlier DID of this persona — its statements cannot be \
                         presented as it is now"
                            .to_string(),
                    )
                } else {
                    evaluation.as_ref().map(vetting_actions::progress_line)
                },
                satisfied: !stale && evaluation.as_ref().is_some_and(|e| e.satisfied()),
                next_step: String::new(),
            }
        })
        .collect();
    let name = vetting_actions::community_display(config, vtc_did);
    let mut routes = build_routes(
        &name,
        &criterion.requirements,
        &joins,
        &personas,
        invitations,
    );
    word_routes_by_admission(&mut routes, book.routes(vtc_did));
    // The next step names the row it is taken from, so it is worded once the
    // rows exist.
    for join in &mut joins {
        let Some(app) = book.applications.iter().find(|a| a.id == join.id) else {
            continue;
        };
        let row = routes
            .iter()
            .find(|r| r.applicant == Some(Applicant::Persona(join.persona)))
            .map(|r| r.label.clone());
        join.next_step = match row {
            Some(row) => join_page_next_step(&app.next_step(now), &row),
            // A persona this account no longer holds: nothing on this page can
            // act for it, so the panel's words are the useful ones.
            None => vetting_actions::next_step_words(&app.next_step(now)),
        };
    }
    let mut known = KnownVetting {
        pcs_zkp: book.pcs_zkp(vtc_did),
        post_quantum: book.post_quantum_key(vtc_did),
        requirements: describe_requirements(&criterion.requirements)
            .iter()
            .map(|line| sanitize_display(line, 300))
            .collect(),
        governance_url: criterion
            .requirements
            .governance_framework_url
            .as_deref()
            .map(|u| sanitize_display(u, 300)),
        applications: joins,
        vetting_note: vetting_detail_suffix(&name, &criterion.requirements, invitations.len()),
        routes,
        personas,
        row: 0,
    };
    known.row = opening_row(&known, prefer);
    Some(JoinVettingView {
        community: vtc_did.to_string(),
        name,
        accent: book.branding(vtc_did).and_then(|b| b.accent_rgb()),
        phase: VettingPhase::Known(Box::new(known)),
    })
}

/// Open the vetting page for `vtc_did` when the book knows it vets. Returns
/// whether it did.
fn show_vetting(state: &mut State, config: &Config, vtc_did: &str) -> bool {
    let Some(view) = vetting_view(
        config,
        vtc_did,
        &state.join.available_vics,
        state.join.minted_persona,
        Utc::now(),
    ) else {
        return false;
    };
    state.join.pending_vtc = Some(vtc_did.to_string());
    state.join.vetting = Some(view);
    state.join.messages.clear();
    state.join.page = JoinPage::Vetting;
    true
}

/// Open the vetting page saying the requirements could not be learned.
///
/// `can_retry` is whether the calling loop can hear an answer at all: the
/// State-A loop cannot, and offering it "ask again" there would be a key that
/// can only ever fail. `resolvable` is whether the DID names anything — when it
/// does not, "join anyway" is withdrawn too, for the same reason.
fn show_unknown(
    state: &mut State,
    config: &Config,
    vtc_did: &str,
    reason: String,
    can_retry: bool,
    resolvable: bool,
) {
    state.join.pending_vtc = Some(vtc_did.to_string());
    state.join.vetting = Some(JoinVettingView {
        community: vtc_did.to_string(),
        name: vetting_actions::community_display(config, vtc_did),
        accent: config
            .private
            .vetting
            .branding(vtc_did)
            .and_then(|b| b.accent_rgb()),
        phase: VettingPhase::Unknown {
            reason: sanitize_display(&reason, 300),
            can_retry,
            resolvable,
        },
    });
    state.join.page = JoinPage::Vetting;
}

/// Ask `vtc_did` for its manifest, as the active persona, and show the page
/// that waits for the answer. The answer reaches the caller's loop, not this
/// one. `Err` means the page now says why the question could not be asked.
async fn ask_requirements(
    state: &mut State,
    config: &mut Config,
    tdk: &TDK,
    messaging: Option<&Messaging>,
    vtc_did: &str,
) -> Result<AwaitingRequirements, ()> {
    let sent: Result<(PersonaId, String), String> = async {
        let service = messaging.ok_or_else(|| {
            "messaging is not running, so its answer could not be heard".to_string()
        })?;
        let identity = config.active_identity().ok_or_else(|| {
            "there is no persona to ask as — create one under My Identity".to_string()
        })?;
        let persona = identity.persona_id;
        let protocol = config.private.vetting.protocol_for(vtc_did);
        let document = wire::manifest_request(identity.persona_did(), vtc_did, protocol)
            .map_err(|e| e.to_string())?;
        match tokio::time::timeout(
            ASK_TIMEOUT,
            wire::sign_and_send(config, tdk, service, persona, document),
        )
        .await
        {
            Ok(Ok(document_id)) => Ok((persona, document_id)),
            Ok(Err(e)) => Err(format!("the question could not be sent: {e}")),
            Err(_) => Err(format!(
                "the question was not sent within {} seconds — your mediator may be unreachable",
                ASK_TIMEOUT.as_secs()
            )),
        }
    }
    .await;
    match sent {
        Ok((persona, document_id)) => {
            config.private.vetting.ask(CommunityQuery {
                document_id: document_id.clone(),
                community: vtc_did.to_string(),
                persona,
                kind: QueryKind::Manifest,
                sent_at: Utc::now(),
            });
            state.join.pending_vtc = Some(vtc_did.to_string());
            state.join.vetting = Some(JoinVettingView {
                community: vtc_did.to_string(),
                name: vetting_actions::community_display(config, vtc_did),
                accent: None,
                phase: VettingPhase::Asking,
            });
            state.join.messages.clear();
            state.join.page = JoinPage::Vetting;
            Ok(AwaitingRequirements {
                vtc_did: vtc_did.to_string(),
                document_id,
                asked_at: std::time::Instant::now(),
            })
        }
        Err(reason) => {
            // Our side failed, not theirs: the community resolved, we could not
            // put the question on the wire. Joining anyway still reaches it.
            show_unknown(state, config, vtc_did, reason, true, true);
            Err(())
        }
    }
}

fn known_vetting(state: &mut State) -> Option<&mut KnownVetting> {
    match state.join.vetting.as_mut().map(|v| &mut v.phase) {
        Some(VettingPhase::Known(known)) => Some(known),
        _ => None,
    }
}

/// Start (or continue) `persona`'s vetting application to `vtc_did` from the
/// join page, then show it on the Vetting page with its next step.
///
/// The persona is the row's own, passed in: what this does follows from
/// whether *that* persona has an application here, never from whether any
/// other persona does.
///
/// A new application is saved at once (`io.save`, a flush of the loop's
/// scheduler): the Vetting page it opens is where the person goes next, and the
/// application must survive whatever they do there.
async fn apply_for_vetting(
    state: &mut State,
    config: &mut Config,
    io: &dyn JoinIo,
    save: &mut crate::state_handler::save_coalesce::SaveScheduler,
    vtc_did: &str,
    persona: PersonaId,
) -> Result<(), String> {
    let Some(JoinVettingView {
        name,
        phase: VettingPhase::Known(known),
        ..
    }) = state.join.vetting.clone()
    else {
        return Err("The community's requirements are not known yet.".to_string());
    };
    if let Some(app) = known.application_for(persona) {
        // Said on the Vetting page, so in that page's words and keys — the
        // join page's own wording names rows that are not there.
        let next = config
            .private
            .vetting
            .applications
            .iter()
            .find(|a| a.id == app.id)
            .map(|a| vetting_actions::next_step_words(&a.next_step(Utc::now())))
            .unwrap_or_default();
        let message = format!(
            "Your application to {name}, as {}. Next: {next}. Press j here when you are ready \
             to join — the join picks up where you left it.",
            app.persona_label,
        );
        vetting_actions::focus_application(state, config, &app.id, message);
        return Ok(());
    }
    let Some(applicant) = known
        .personas
        .iter()
        .find(|p| p.persona == persona)
        .cloned()
    else {
        return Err(
            "That persona is no longer in this account. Choose another row, or \"Apply for \
             vetting as a new persona\" to make one."
                .to_string(),
        );
    };
    // Where the application's face is worn: the first context this persona
    // can use, which is a sub-context of the application's own unless the
    // persona's keys already live somewhere — then it is that one.
    let context = application_contexts(config, vtc_did, Some(persona))
        .into_iter()
        .next()
        .map(|o| o.context_id);
    let now = Utc::now();
    let book = &mut config.private.vetting;
    let id = match book.start_application(vtc_did, applicant.persona, &applicant.did, now) {
        Ok(app) => {
            if app.context_id.is_none() {
                app.context_id = context;
            }
            app.id.clone()
        }
        Err(e) => return Err(format!("Could not start the application: {e}")),
    };
    // Said, not dropped (R6.4): a criterion this build cannot honour is the one thing that
    // makes the application below gather evidence the community will not count.
    let unadopted = book
        .adopt_known_requirements(&id)
        .err()
        .map(|e| format!(" Its requirements could not be taken up: {e}."))
        .unwrap_or_default();
    let next = book
        .applications
        .iter()
        .find(|a| a.id == id)
        .map(|a| vetting_actions::next_step_words(&a.next_step(now)))
        .unwrap_or_default();
    io.save(save, config)
        .await
        .map_err(|e| format!("Could not save the application: {e}"))?;
    vetting_actions::focus_application(
        state,
        config,
        &id,
        format!(
            "Application to {name} started as {}. Next: {next}. The join to {name} is not lost — \
             press j here to take it up again, without finding that DID a second time.{unadopted}",
            applicant.label
        ),
    );
    Ok(())
}

/// The persona + community of a just-completed join, handed back to the runtime
/// loop so it can bring a live session up immediately (R-B-5 / D11) rather than
/// only on the next launch.
pub(crate) struct JoinedSession {
    pub persona_id: PersonaId,
    pub persona_did: String,
    pub vtc_did: VtcDid,
}

/// Extract the [`JoinedSession`] from a finished join's state — `Some` only when
/// the sequence persisted a community (i.e. the join succeeded).
fn joined_session(js: &JoinState) -> Option<JoinedSession> {
    let record = js.created_community.as_ref()?;
    Some(JoinedSession {
        persona_id: record.persona_ref,
        persona_did: js.created_persona_did.clone().unwrap_or_default(),
        vtc_did: record.vtc_did.clone(),
    })
}

/// Open the invitation step for a join as `persona_id`: this community's valid
/// invitations bound to that persona, plus one loaded by hand.
fn open_invitation_choice(state: &mut State, config: &Config, persona_id: PersonaId) {
    // Invitations already known for the chosen persona:
    // this community's valid VICs whose subject is that
    // persona's DID.
    let persona_did = config
        .account
        .personas
        .get(&persona_id)
        .map(|p| p.did.clone());
    // …plus one the operator loaded for this join by hand
    // (`--invitation` / a paste on the entry page) whatever
    // its subject. Filtering that by subject too was how a
    // deliberately supplied invitation could disappear
    // between the entry page and the submit; a subject that
    // is not the presenting persona is what
    // drop it. A subject that is none of our personas is: no
    // persona here can sign the linkage, the community
    // refuses it, and the entry page has already said the
    // join will be an open request (#373).
    let loaded = state
        .invitation_credential
        .as_ref()
        .filter(|v| foreign_invitation_subject(config, v).is_none())
        .and_then(|v| openvtc_core::join::invitation_id(v))
        .map(str::to_string);
    let invitations: Vec<AvailableVic> = state
        .join
        .available_vics
        .iter()
        .filter(|v| {
            (persona_did.is_some() && v.subject == persona_did)
                || loaded.as_deref() == Some(v.id.as_str())
        })
        .cloned()
        .collect();
    // Always offer the choice, including with none found.
    // The step carries a paste row, so an empty list is a
    // question ("do you have one?") rather than a reason
    // to skip. Launching straight into an open request
    // here would never ask an operator holding an
    // invitation for it.
    state.join.invitation_options = invitations;
    state.join.vetting_in_hand = state
        .join
        .pending_vtc
        .as_deref()
        .and_then(|vtc| vetting_in_hand(config, vtc, persona_id));
    state.join.invitation_for_persona = Some(persona_id);
    state.join.invitation_persona_did = persona_did;
    state.join.invitation_use_selected = 0;
    state.join.messages.clear();
    state.join.page = JoinPage::InvitationChoice;
}

/// Offer the contexts `pick` can join `vtc_did` in.
///
/// Returns the context when there is nothing to ask — a persona whose keys
/// live in a sub-context, or one whose vetting application already chose where
/// its face is worn — and otherwise opens the context-choice page and returns
/// `None`.
fn offer_contexts(
    state: &mut State,
    config: &Config,
    pick: IdentityPick,
    vtc_did: &str,
) -> Option<String> {
    let persona = match pick {
        IdentityPick::Reuse(id) => {
            if let Some(context) = config
                .private
                .vetting
                .application(vtc_did, id)
                .and_then(|a| a.context_id.clone())
            {
                return Some(context);
            }
            config.account.personas.get(&id)
        }
        IdentityPick::Mint => None,
    };
    let suggested = sequence::suggested_context(config, vtc_did);
    let options = community_context::context_options(&config.account, persona, &suggested);
    if options.len() == 1 {
        return options.into_iter().next().map(|o| o.context_id);
    }
    state.join.context_slug = parse_sub_context_id(&suggested)
        .map(|(_, slug)| slug.to_string())
        .unwrap_or_default();
    state.join.context_community_names = options
        .iter()
        .flat_map(|o| o.communities.iter())
        .map(|did| {
            let display = config
                .account
                .memberships()
                .find(|m| &m.vtc_did == did)
                .and_then(|m| m.display_name.as_deref());
            (
                did.clone(),
                crate::state_handler::community_label(config, did, display, 40),
            )
        })
        .collect();
    state.join.context_options = options;
    state.join.context_selected = 0;
    state.join.picked_identity = Some(pick);
    state.join.messages.clear();
    state.join.page = JoinPage::ContextChoice;
    None
}

/// The DID `vic` names, when no persona in this account is that DID.
///
/// `None` for an invitation that names one of our personas, and for one that
/// names no subject at all (validation refuses those before they get here).
fn foreign_invitation_subject(config: &Config, vic: &serde_json::Value) -> Option<String> {
    let subject = openvtc_core::join::invitation_subject(vic)?;
    (!config.account.personas.values().any(|p| p.did == subject)).then(|| subject.to_string())
}

/// Whether a persona minted for this join can present the loaded invitation.
///
/// A new persona is never the invitation's subject, so the community accepts
/// the invitation from it only with a subject-linkage proof, signed by the
/// subject (`build_linkage_proof`). That is possible exactly when the subject
/// is one of our personas. The invitation must also be for this community and
/// unexpired: otherwise the sequence would fall back to whichever vault
/// invitation matches, which a new persona was never meant to present.
///
/// Answering `false` whatever the invitation would throw a pasted invitation
/// away and send the join out as an open request, with no word until the
/// progress page (#373).
fn mint_can_present(config: &Config, state: &State, vtc_did: &str) -> bool {
    state.invitation_credential.as_ref().is_some_and(|vic| {
        openvtc_core::join::invitation_subject(vic).is_some()
            && foreign_invitation_subject(config, vic).is_none()
            && openvtc_core::join::invitation_matches_community(vic, vtc_did)
            && !openvtc_core::join::invitation_is_expired(vic, Utc::now())
    })
}

/// Build the reuse options for the identity-choice page (R-B-3): every existing
/// persona, labelled, with the communities it is already presented to (the
/// linkage-warning detail) and the count of `vics` bound to it (the available
/// invitations for the community being joined). Sorted by label for a stable
/// list.
fn build_persona_options(config: &Config, vics: &[AvailableVic]) -> Vec<PersonaOption> {
    let mut options: Vec<PersonaOption> = config
        .account
        .personas
        .values()
        .map(|p| {
            let mut linked_communities: Vec<String> = config
                .account
                .memberships()
                .filter(|c| c.persona_ref == p.persona_id)
                .map(|c| {
                    crate::state_handler::community_label(
                        config,
                        &c.vtc_did,
                        c.display_name.as_deref(),
                        40,
                    )
                })
                .collect();
            linked_communities.sort();
            let valid_vic_count = vics
                .iter()
                .filter(|v| v.subject.as_deref() == Some(p.did.as_str()))
                .count();
            PersonaOption {
                id: p.persona_id,
                // Explicit label, then the persona's verified agent name, then
                // the DID — matching what the communities panel already does
                // for the same personas.
                label: p
                    .label
                    .clone()
                    .or_else(|| config.agent_name_for(&p.did).map(str::to_owned))
                    .unwrap_or_else(|| shorten_did(&p.did, 32)),
                did: p.did.clone(),
                linked_communities,
                valid_vic_count,
            }
        })
        .collect();
    options.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.did.cmp(&b.did)));
    options
}

/// Collect the valid invitations (VICs) available for the community `vtc_did`,
/// across all personas: `loaded` — an `--invitation`/pasted VIC — when it
/// matches, plus the community-matched, valid, active VICs the vault holds. Each
/// is validated (complete + unexpired + verified) so the identity badges and the
/// invitation list only ever show usable invitations. Best-effort: with no admin
/// VTA only a loaded VIC is considered.
///
/// Two screens need them — the vetting page, to say whether presenting one is
/// a way in, and the identity step, to badge each persona with its count — and
/// the collection is a vault listing plus a fetch per descriptor, so it runs off
/// the loop and once per community: `JoinState::invitations_for`, rather than
/// the emptiness of the list, is what says it has been done (holding none is a
/// legitimate answer).
async fn collect_available_vics(
    loaded: Option<&serde_json::Value>,
    admin_vta: Option<&VtaClient>,
    resolver: &affinidi_tdk::did_resolver::DIDCacheClient,
    vtc_did: &str,
) -> Vec<AvailableVic> {
    let now = Utc::now();
    // Usable = for this community, unexpired, complete, and genuinely signed by
    // it (proof, window and revocation status verified). The vault's own
    // `status` is not taken on trust.
    let usable = async |vic: &serde_json::Value| {
        openvtc_core::join::invitation_matches_community(vic, vtc_did)
            && !openvtc_core::join::invitation_is_expired(vic, now)
            && openvtc_core::join::verify_invitation_credential(vic, resolver, now)
                .await
                .is_ok()
    };
    let mut out: Vec<AvailableVic> = Vec::new();

    // Vault: only fetch bodies for this community's active, valid descriptors.
    if let Some(vta) = admin_vta
        && let Ok(listing) = vta
            .cred_vault_query(serde_json::json!({ "purpose": "invite" }))
            .await
        && let Some(arr) = listing.get("credentials").and_then(|c| c.as_array())
    {
        for d in arr {
            let summ = VicSummary::from_descriptor(d);
            if summ.issuer != vtc_did
                || summ.status != "valid"
                || summ.lifecycle != VicLifecycle::Active
            {
                continue;
            }
            if let Ok(got) = vta.cred_vault_get(&summ.id).await
                && let Some(body) = serde_json::to_value(got)
                    .ok()
                    .and_then(|v| v.get("credential").cloned())
                && usable(&body).await
                && let Some(av) = to_available_vic(&body)
            {
                out.push(av);
            }
        }
    }

    // A loaded VIC (--invitation / paste) that matches this community, if not
    // already surfaced from the vault.
    if let Some(vic) = loaded
        && usable(vic).await
        && let Some(av) = to_available_vic(vic)
        && !out.iter().any(|o| o.id == av.id)
    {
        out.push(av);
    }
    out
}

/// Map a signed VIC body to the display+present record. `None` if it lacks an id.
fn to_available_vic(body: &serde_json::Value) -> Option<AvailableVic> {
    Some(AvailableVic {
        id: openvtc_core::join::invitation_id(body)?.to_string(),
        subject: openvtc_core::join::invitation_subject(body).map(str::to_string),
        valid_from: openvtc_core::join::invitation_valid_from(body)
            .unwrap_or_default()
            .to_string(),
        valid_until: openvtc_core::join::invitation_valid_until(body)
            .unwrap_or_default()
            .to_string(),
        body: body.clone(),
    })
}

/// Accept a pasted / clipboard-read invitation credential (VIC).
///
/// `vtc_did` is `Some` only on the invitation step, where the community is
/// already chosen: there the paste is additionally required to be *for* that
/// community and unexpired, and lands as a new row on the step (selected, so the
/// next Enter presents it). On the entry page the community is still unknown, so
/// only the credential shape is checked and the VIC is stashed for
/// [`collect_available_vics`] to match once a DID is entered.
///
/// Every rejection is reported into `join.messages` with its reason. An
/// invitation that silently fails to load reads exactly like one that was never
/// pasted, and the operator then submits an open request believing they
/// presented a credential — which is the same failure, in miniature, as skipping
/// the step altogether.
async fn load_pasted_vic(
    state: &mut State,
    resolver: &affinidi_tdk::did_resolver::DIDCacheClient,
    text: &str,
    vtc_did: Option<&str>,
) {
    let candidates = match pasted_vic_candidates(text) {
        Ok(candidates) => candidates,
        Err(why) => {
            state.join.messages.push(MessageType::Error(why));
            return;
        }
    };
    // Verified before anything is read out of it: the issuer it names is
    // shown as the community and prefills the DID input, and anyone can write
    // an invitation naming any community. A paste mended from a wrapped
    // terminal is held to the same proof — the mending is only a guess at
    // what was copied, and the proof is what says whether it guessed right.
    let mut first_failure = None;
    for (mended, vic) in candidates {
        match openvtc_core::join::verify_invitation_credential(&vic, resolver, Utc::now()).await {
            Ok(()) => {
                if mended {
                    state.join.messages.push(MessageType::Info(
                        "The pasted invitation had been broken across lines; it was \
                         joined back together and its proof verified."
                            .to_string(),
                    ));
                }
                stash_verified_vic(state, vic, vtc_did);
                return;
            }
            Err(why) => {
                first_failure.get_or_insert(why);
            }
        }
    }
    if let Some(why) = first_failure {
        state.join.messages.push(MessageType::Error(format!(
            "Pasted invitation is not usable: {why}"
        )));
    }
}

/// Every reading of the pasted text that is a well-formed invitation, as given
/// first and then mended from terminal line-wrapping
/// ([`openvtc_core::join::pasted_json_readings`]), each flagged with whether it
/// was mended. `Err` carries the reason for the reading as given when none is.
fn pasted_vic_candidates(text: &str) -> Result<Vec<(bool, serde_json::Value)>, String> {
    let mut candidates = Vec::new();
    let mut first_error = None;
    for (i, reading) in openvtc_core::join::pasted_json_readings(text)
        .into_iter()
        .enumerate()
    {
        let checked = serde_json::from_str::<serde_json::Value>(&reading)
            .map_err(|e| format!("Pasted text is not valid JSON: {e}"))
            .and_then(|vic| {
                openvtc_core::join::validate_invitation_credential(&vic)
                    .map(|()| vic)
                    .map_err(|why| format!("Pasted invitation is not usable: {why}"))
            });
        match checked {
            Ok(vic) => candidates.push((i > 0, vic)),
            Err(why) => {
                first_error.get_or_insert(why);
            }
        }
    }
    if candidates.is_empty() {
        Err(first_error.unwrap_or_else(|| "Nothing was pasted.".to_string()))
    } else {
        Ok(candidates)
    }
}

/// The pasted text as a complete invitation, or `None` with the reason pushed.
#[cfg(test)]
fn parse_pasted_vic(state: &mut State, text: &str) -> Option<serde_json::Value> {
    match pasted_vic_candidates(text) {
        Ok(mut candidates) => Some(candidates.remove(0).1),
        Err(why) => {
            state.join.messages.push(MessageType::Error(why));
            None
        }
    }
}

/// Keep an invitation whose proof has **already verified**
/// ([`openvtc_core::join::verify_invitation_credential`]). Only
/// [`load_pasted_vic`] calls this, after that check.
fn stash_verified_vic(state: &mut State, vic: serde_json::Value, vtc_did: Option<&str>) {
    let Some(vtc_did) = vtc_did else {
        // Entry page: no community to match against yet. The VIC's issuer *is*
        // the community — its proof has just verified against that issuer's
        // DID document — so record it: the page shows it and prefills the DID
        // input from it instead of asking for a DID the credential carries.
        state.join.invitation_issuer =
            openvtc_core::join::invitation_issuer(&vic).map(str::to_string);
        state.invitation_credential = Some(vic);
        state.join.has_invitation = true;
        state.join.vic_cleared = false;
        return;
    };
    if !openvtc_core::join::invitation_matches_community(&vic, vtc_did) {
        state.join.messages.push(MessageType::Error(
            "That invitation was issued by a different community, so this one will \
             not accept it."
                .to_string(),
        ));
        return;
    }
    if openvtc_core::join::invitation_is_expired(&vic, Utc::now()) {
        state.join.messages.push(MessageType::Error(
            "That invitation has expired. Ask the community for a new one, or join \
             without it."
                .to_string(),
        ));
        return;
    }
    let Some(av) = to_available_vic(&vic) else {
        state.join.messages.push(MessageType::Error(
            "That invitation has no `id`, so it cannot be presented.".to_string(),
        ));
        return;
    };
    // Re-pasting one already listed re-selects it rather than duplicating it.
    let row = match state
        .join
        .invitation_options
        .iter()
        .position(|o| o.id == av.id)
    {
        Some(existing) => existing,
        None => {
            state.join.invitation_options.push(av);
            state.join.invitation_options.len() - 1
        }
    };
    state.join.invitation_use_selected = row;
    state.join.has_invitation = true;
    state.join.vic_cleared = false;
}

/// Validate the raw VTC DID the operator submitted on the EnterDid page.
///
/// Pure decision peeled out of the `JoinSubmitVtc` arm: trims surrounding
/// whitespace, then checks that what is left could be an identifier at all —
/// an agent name (`example.com/@acme`), or a DID (`did:<method>:<id>`). `Err`
/// is the sentence the page shows, and the loop `continue`s on it, staying on
/// the EnterDid page with the field intact.
///
/// The syntax check is here rather than downstream because of what downstream
/// does with a string it cannot resolve: it cannot tell "this community does
/// not answer" from "this is not a community", so it offers to join anyway —
/// a request to a DID that does not exist, which nothing will ever answer.
/// Typing `asdasd` produced exactly that offer. A resolver failure on a
/// well-formed DID still reaches that screen, because then joining anyway is a
/// real option; a string that is not an identifier never had one.
fn validate_join_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(
            "Enter the community's DID or agent name first — or paste an invitation \
                    credential (VIC) to fill it in."
                .to_string(),
        );
    }
    if openvtc_core::agent_name::looks_like_agent_name(trimmed) {
        return Ok(trimmed.to_string());
    }
    // Deliberately shallow: a DID's method-specific id is the method's business,
    // and refusing one this build does not recognise would refuse a community
    // OpenVTC can reach perfectly well. This rejects what is not a DID at all.
    let well_formed = trimmed
        .strip_prefix("did:")
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(method, id)| {
            !method.is_empty()
                && !id.is_empty()
                && method
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    if well_formed {
        return Ok(trimmed.to_string());
    }
    Err(format!(
        "\u{201c}{}\u{201d} is not a community identifier. A community is a DID \
         (did:webvh:\u{2026}) or an agent name (example.com/@acme) — check what you pasted, \
         or paste an invitation credential (VIC) to fill it in.",
        openvtc_core::display::shorten_for_display(trimmed, 40)
    ))
}
/// #2: load a *presentable* invitation the VTA already holds for the community
/// being joined (`vtc_did`). Queries the credential vault for `purpose = invite`
/// and selects an active, vault-valid (not expired / revoked) VIC whose issuer is
/// this community — preferring the one that stays valid longest — then fetches
/// its body. The first-match grab this replaced could present a VIC for the wrong
/// community (or an expired one), which the VTC then rejected. Best-effort: any
/// error / no match yields `None`, and the join proceeds as an open request.
async fn load_invitation_from_vault(
    admin_vta: &VtaClient,
    vtc_did: &str,
) -> Option<serde_json::Value> {
    let listing = admin_vta
        .cred_vault_query(serde_json::json!({ "purpose": "invite" }))
        .await
        .ok()?;
    let descriptors = listing.get("credentials").and_then(|c| c.as_array())?;
    // Community-matched, active, vault-valid candidates; prefer the latest
    // `validUntil` (longest-lived). RFC 3339 timestamps sort lexicographically.
    let best = descriptors
        .iter()
        .map(VicSummary::from_descriptor)
        .filter(|v| {
            v.issuer == vtc_did && v.status == "valid" && v.lifecycle == VicLifecycle::Active
        })
        .max_by(|a, b| a.valid_until.cmp(&b.valid_until))?;
    let got = admin_vta.cred_vault_get(&best.id).await.ok()?;
    serde_json::to_value(got).ok()?.get("credential").cloned()
}

/// Idempotency decision (R-B-9): is there already a *live* (Active/Pending)
/// membership for this VTC?
///
/// Whether a *live* (Active/Pending) membership already exists for this community
/// **as this persona** — the per-persona join idempotency gate (R-B-9). A
/// community may be joined more than once, but not twice as the same persona, so
/// the check is keyed on `(vtc, persona)` and only blocks the reuse path (a
/// freshly minted persona can never collide).
fn is_duplicate_membership(config: &Config, vtc_did: &str, persona: PersonaId) -> bool {
    config.account.has_live_membership(vtc_did, persona)
}

/// How long the join sequence waits for the applicant persona's mediator socket
/// before submitting anyway (R1.2: the wait is finite).
///
/// The connect is an authenticate + websocket upgrade + live-delivery toggle
/// against a mediator that is, by definition, reachable — the same mediator this
/// process is already talking to for the admin session. Ten seconds is generous
/// for that and short enough that a mediator having a bad minute costs the
/// operator a pause, not the join: the submit goes out either way.
const PERSONA_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Start `persona_id`'s listener without waiting for it to connect.
///
/// The connect runs on its own task, so the page that made the persona keeps
/// answering keys meanwhile. What it needs from the config is read here, before
/// the task starts; the task only connects. A failure is logged — the submit's
/// own wait for the socket (bounded by [`PERSONA_CONNECT_TIMEOUT`]) is what tells the person
/// whether the request went out live.
async fn spawn_persona_listener(
    messaging: Option<&Messaging>,
    config: &Config,
    tdk: &TDK,
    persona_id: PersonaId,
    did: &str,
) {
    let Some(service) = messaging else {
        return;
    };
    let listener_id = openvtc_core::didcomm::persona_listener_id(did);
    if service.has_listener(&listener_id).await {
        return;
    }
    let Some(spec) =
        openvtc_core::didcomm::persona_listener_config_for(config, tdk, persona_id).await
    else {
        debug!(persona = %did, "no listener config for the new persona");
        return;
    };
    let service = service.clone();
    tokio::spawn(async move {
        if let Err(e) = openvtc_core::didcomm::add_listener(&service, &spec).await {
            tracing::warn!(listener = %spec.id, error = %e, "the new persona's mediator session did not open");
        }
    });
}

/// Everything that stops a hidden-vetting join before the VTA is asked for a proof: the
/// community's challenge it must bind, or the sentence the join fails with.
fn hidden_proof_precheck(
    application: &openvtc_core::vetting::applicant::Application,
) -> Result<String, String> {
    // Nothing to prove is said first: with no attestation held, a missing challenge is beside
    // the point, and naming it would send the person after the wrong thing.
    if application.hidden.is_some() && !application.holds_hidden_attestation() {
        return Err(NO_ATTESTATION.to_string());
    }
    // Every attestation held is one the community will refuse. A proof built from them
    // verifies, and counts nothing: the join would come back "needs more vetting" while this
    // client called it satisfied. Said here, with what to do, instead.
    if application.hidden.is_some() && !application.holds_current_hidden_attestation() {
        return Err(stale_attestations_refusal(
            &application.stale_hidden_attestations(),
        ));
    }
    // The challenge is the COMMUNITY's, asked for over `vtc/vetting/pcs-challenge/0.1` and
    // recorded on the application when it arrives. A proof over one we minted ourselves
    // verifies and is refused, which is the whole point of the exchange: the community
    // accepts each challenge exactly once, so a submission cannot be replayed.
    //
    // A launch that can hear the answer has already asked for a fresh one (`challenge_step`),
    // so this is reached without one only from a loop that cannot — and the way out is a loop
    // that can, not a key on a page this screen cannot reach.
    application.hidden_challenge.clone().ok_or_else(|| {
        "This community hides its vetters, so joining sends a zero-knowledge proof bound to \
         a challenge the community issues — and none is held. Nothing was sent. This screen \
         cannot hear the community's answer, so it could not ask for one: start the join \
         again once messaging is running, and it asks for the challenge itself."
            .to_string()
    })
}

/// Why a hidden-vetting join stops when every attestation held is one the community refuses.
fn stale_attestations_refusal(
    stale: &[openvtc_core::vetting::applicant::StaleAttestation],
) -> String {
    let mut why: Vec<String> = stale.iter().map(ToString::to_string).collect();
    why.dedup();
    let why = if why.is_empty() {
        "it no longer matches what the community publishes".to_string()
    } else {
        why.join("; ")
    };
    format!(
        "The community would not count your PCS ZKP proof: the vetter attestation you hold \
         cannot count there any more — {why}. Nothing was sent. Ask your vetter to attest \
         again under the community's current criterion (send them a new vetting request), then \
         join again."
    )
}

/// Why a hidden-vetting join stops when no vetter has attested yet.
const NO_ATTESTATION: &str = "This community hides its vetters, and no vetter's attestation has \
                              reached this application yet, so there is nothing to prove. \
                              Nothing was sent.";

/// Wear `face_id` in the community's context, preview the disclosure of what
/// it asks, refuse if that differs from what the holder approved, and release
/// it. `Err` is the sentence the progress page shows; nothing was sent.
async fn answer_from_face(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
    community_did: &str,
    asked: &[openvtc_core::persona::join_answers::Asked],
    face_id: &str,
    approved: &[(String, serde_json::Value)],
) -> Result<Vec<vta_sdk::protocols::join_requests::JoinRequestAttribute>, String> {
    use openvtc_core::persona::join_answers;
    openvtc_core::persona::binding::set(client, context_id, persona_did, Some(face_id))
        .await
        .map_err(|e| format!("Could not put your face on this persona: {e}"))?;
    let preview = join_answers::preview(client, context_id, persona_did, community_did, asked)
        .await
        .map_err(|e| e.to_string())?;
    if !join_answers::preview_matches(&preview, approved) {
        return Err(
            "What your face would send changed after you approved it, so nothing was \
                    sent. Join again to see the current values."
                .into(),
        );
    }
    join_answers::present(client, context_id, &preview.preview_id)
        .await
        .map_err(|e| e.to_string())
}

/// Open the Answers page for `asked`, parking the launch until a face is
/// chosen.
async fn open_answers(
    state: &mut State,
    admin_vta: Option<&VtaClient>,
    asked: Vec<openvtc_core::persona::join_answers::Asked>,
    parked: (IdentityPick, String, String),
) {
    let mut answers = JoinAnswers {
        asked,
        parked: Some(parked),
        ..JoinAnswers::default()
    };
    match admin_vta {
        None => {
            answers.error = Some(
                "Your VTA is not connected, so your faces cannot be read. Reconnect and join \
                 again."
                    .into(),
            );
        }
        Some(client) => {
            match openvtc_core::persona::profile::list(client).await {
                Ok(faces) => {
                    answers.faces = faces
                        .into_iter()
                        .map(|f| (f.profile_id.clone(), f.display_name().to_string()))
                        .collect();
                }
                Err(e) => answers.error = Some(format!("Your faces could not be read: {e}")),
            }
            load_shown(&mut answers, client).await;
        }
    }
    state.join.answers = Some(answers);
    state.join.page = JoinPage::Answers;
    state.join.processing = false;
}

/// What the join request for `vtc_did` as `pick` will carry, read from the
/// same records the launch builds it from: the persona's DID, the
/// invitation chosen, the application's statements or hidden proof, and the
/// face's approved answers.
fn join_review(
    config: &Config,
    state: &State,
    vtc_did: &str,
    pick: &IdentityPick,
) -> crate::state_handler::join::JoinReview {
    use crate::state_handler::join::{JoinReview, ReviewVetting};
    use openvtc_core::vetting::guide::{claim_words, method_words};
    let now = Utc::now();
    let persona = match pick {
        IdentityPick::Reuse(id) => config.account.personas.get(id),
        IdentityPick::Mint => None,
    };
    let persona_line = persona.map_or_else(
        || "a new persona — its DID is made when you send".to_string(),
        |p| sanitize_display(&p.did, 256),
    );
    let invitation = state
        .join
        .present_invitation
        .then_some(state.invitation_credential.as_ref())
        .flatten()
        .map(|vic| {
            let issuer = vic
                .get("issuer")
                .and_then(|i| i.as_str().or_else(|| i.get("id").and_then(|x| x.as_str())))
                .unwrap_or("the community");
            // Issued to a different DID from the one joining: the join adds a
            // proof that links the two, which the community sees.
            let linked = vic
                .pointer("/credentialSubject/id")
                .and_then(|v| v.as_str())
                .zip(persona.map(|p| p.did.as_str()))
                .is_some_and(|(issued_to, joining)| issued_to != joining);
            format!(
                "an invitation issued by {}{}",
                sanitize_display(issuer, 128),
                if linked {
                    ", issued to another of your personas and linked to this one with a proof"
                } else {
                    ""
                }
            )
        });
    let application = presented_application(config, vtc_did, pick);
    let vetting = match application {
        None => ReviewVetting::None,
        Some(app) if app.hidden.is_some() => ReviewVetting::Hidden {
            attestations: app.hidden_held(),
        },
        Some(app) => ReviewVetting::Named(
            app.statements
                .iter()
                .filter(|s| s.valid_until > now)
                .map(|s| {
                    let checked: Vec<String> =
                        s.claims_verified.iter().map(|c| claim_words(c)).collect();
                    format!(
                        "{} — vetted you {}{}, valid until {}",
                        openvtc_core::display::display_identifier(
                            config.agent_name_for(&s.vetter),
                            &s.vetter,
                            64
                        ),
                        method_words(s.method),
                        if checked.is_empty() {
                            String::new()
                        } else {
                            format!(", checking your {}", checked.join(", "))
                        },
                        s.valid_until.format("%-d %b %Y")
                    )
                })
                .collect(),
        ),
    };
    let face = state
        .join
        .answers
        .as_ref()
        .and_then(|a| a.approved.as_ref())
        .map(|(_, values)| {
            values
                .iter()
                .map(|(claim, value)| {
                    let shown = match value {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (sanitize_display(claim, 64), sanitize_display(&shown, 256))
                })
                .collect()
        })
        .unwrap_or_default();
    let decision = application
        .and_then(|app| vetting_decision(config, vtc_did, app))
        .or_else(|| {
            (application.is_none() && invitation.is_none()).then(|| {
                "with no invitation or vetting, the request goes to its moderators to decide"
                    .to_string()
            })
        });
    JoinReview {
        persona: persona_line,
        invitation,
        vetting,
        face,
        decision,
    }
}

/// How the community decides on a request carrying this application's
/// vetting, when its manifest says. The criterion an application names is the
/// one the community decides under.
fn vetting_decision(config: &Config, vtc_did: &str, app: &Application) -> Option<String> {
    let digest = app.requirements_digest.as_deref()?;
    let route = config
        .private
        .vetting
        .routes(vtc_did)
        .iter()
        .find(|r| r.requirements_digest.as_deref() == Some(digest))?;
    Some(match route.admission? {
        openvtc_core::vetting::protocol::Admission::Automatic => {
            "meeting its vetting requirements admits you automatically".to_string()
        }
        _ => "meeting its vetting requirements sends you to an administrator, who decides"
            .to_string(),
    })
}

/// The vetting a join by `persona_id` to `vtc_did` will present, whatever is
/// chosen on the invitation page — the launch attaches it either way.
fn vetting_in_hand(
    config: &Config,
    vtc_did: &str,
    persona_id: PersonaId,
) -> Option<crate::state_handler::join::VettingInHand> {
    let did = &config.account.personas.get(&persona_id)?.did;
    let app = config
        .private
        .vetting
        .application(vtc_did, persona_id)
        .filter(|a| &a.join_did == did)?;
    let (count, hidden) = match &app.hidden {
        Some(_) => (app.hidden_held(), true),
        None => (app.presentable_statements(Utc::now()).len(), false),
    };
    (count > 0).then(|| crate::state_handler::join::VettingInHand {
        count,
        hidden,
        decision: vetting_decision(config, vtc_did, app),
    })
}

/// Open the trust-registry page for the parked launch, with the box unticked.
///
/// A fresh [`RegistryChoice`] every time — never one carried over from an
/// earlier question — because consent given for one community, or on one
/// attempt, is not consent to the next. `community_name` is display only, and
/// only ever a verified agent name (the cached, round-tripped one), so the page
/// never puts an unverified claim beside a privacy decision.
fn open_registry_choice(
    state: &mut State,
    community_name: Option<String>,
    parked: (IdentityPick, String, String),
) {
    state.join.registry = Some(RegistryChoice {
        publish: false,
        community: parked.1.clone(),
        community_name,
        confirmed: false,
        parked: Some(parked),
        review: None,
        directory: None,
    });
    state.join.page = JoinPage::RegistryConsent;
    state.join.processing = false;
}

/// Read what the highlighted face would answer. A holder-scoped resolved read
/// — the values a disclosure from it would carry.
async fn load_shown(answers: &mut JoinAnswers, client: &VtaClient) {
    answers.error = None;
    answers.shown = answers
        .asked
        .iter()
        .map(|a| (a.claim_type.clone(), None))
        .collect();
    let Some((face_id, _)) = answers.faces.get(answers.selected) else {
        return;
    };
    match openvtc_core::persona::profile::get(client, face_id, true).await {
        Ok(detail) => {
            answers.shown =
                openvtc_core::persona::join_answers::shown_by(&answers.asked, &detail.resolved);
        }
        Err(e) => answers.error = Some(format!("That face could not be read: {e}")),
    }
}

#[cfg(test)]
mod tests {
    //! The join's pure page logic and its bounded helpers. Cancel safety — a
    //! Ctrl-C or F10 mid-launch undoing what the launch made (R15) — is the
    //! driver's, and is tested there against injected failures
    //! (`driver::tests`).

    /// A community that asks the applicant about themselves stops the join on
    /// the Answers page before anything is minted or sent, with the launch
    /// parked for Enter to resume. Without a connected VTA the page still
    /// opens, and says why no face can be offered — rather than joining
    /// without the answers the community requires and being refused.
    #[tokio::test]
    async fn a_community_that_asks_opens_the_answers_page_and_parks_the_launch() {
        use crate::state_handler::State;
        use crate::state_handler::join::{IdentityPick, JoinPage};
        use openvtc_core::persona::join_answers::Asked;
        let mut state = State::default();
        super::open_answers(
            &mut state,
            None,
            vec![Asked {
                claim_type: "name.display".into(),
                required: true,
                purpose: None,
            }],
            (
                IdentityPick::Mint,
                "did:web:vtc.example".into(),
                "acct/co-op".into(),
            ),
        )
        .await;
        assert_eq!(state.join.page, JoinPage::Answers);
        assert!(!state.join.processing, "the page must take keys");
        let answers = state.join.answers.expect("answers state");
        assert_eq!(
            answers.parked,
            Some((
                IdentityPick::Mint,
                "did:web:vtc.example".into(),
                "acct/co-op".into()
            ))
        );
        assert!(
            answers.approved.is_none(),
            "nothing is approved by opening the page"
        );
        assert!(
            answers
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not connected"))
        );
        assert_eq!(answers.unanswered(), vec!["name.display".to_string()]);
    }

    /// Every join stops on the trust-registry page before anything is sent,
    /// with the box unticked and the launch parked for Enter to resume.
    #[test]
    fn the_registry_question_opens_unticked_and_parks_the_launch() {
        use crate::state_handler::State;
        use crate::state_handler::join::{IdentityPick, JoinPage};
        let mut state = State::default();
        let parked = (
            IdentityPick::Mint,
            "did:web:vtc.example".to_string(),
            "acct/co-op".to_string(),
        );
        super::open_registry_choice(&mut state, None, parked.clone());
        assert_eq!(state.join.page, JoinPage::RegistryConsent);
        assert!(!state.join.processing, "the page must take keys");
        let registry = state.join.registry.expect("registry state");
        assert!(!registry.publish, "never pre-ticked");
        assert!(!registry.confirmed, "opening the page answers nothing");
        assert_eq!(registry.parked, Some(parked));
        assert!(
            !registry.answered_for("did:web:vtc.example"),
            "the launch must wait for an answer"
        );
    }

    /// A re-opened page starts unticked again, even when the last answer for
    /// the same community was yes: consent is given per request, not
    /// remembered.
    #[test]
    fn a_previous_yes_does_not_pre_tick_the_next_question() {
        use crate::state_handler::State;
        use crate::state_handler::join::IdentityPick;
        let mut state = State::default();
        let parked = (
            IdentityPick::Mint,
            "did:web:vtc.example".to_string(),
            "acct".to_string(),
        );
        super::open_registry_choice(&mut state, None, parked.clone());
        let r = state.join.registry.as_mut().unwrap();
        r.publish = true;
        r.confirmed = true;
        super::open_registry_choice(&mut state, None, parked);
        assert!(!state.join.registry.unwrap().publish);
    }

    /// What is sent as `registryConsent`: yes only for an answered, ticked
    /// question about this very community.
    #[test]
    fn consent_is_sent_only_when_given_for_this_community() {
        use crate::state_handler::join::RegistryChoice;
        let vtc = "did:web:vtc.example";
        let base = RegistryChoice {
            community: vtc.to_string(),
            ..RegistryChoice::default()
        };
        // Not answered: unticked or ticked, nothing is consented.
        assert!(!base.consent_for(vtc));
        let ticked_unanswered = RegistryChoice {
            publish: true,
            ..base.clone()
        };
        assert!(!ticked_unanswered.consent_for(vtc));
        // Answered no.
        let declined = RegistryChoice {
            confirmed: true,
            ..base.clone()
        };
        assert!(declined.answered_for(vtc));
        assert!(!declined.consent_for(vtc));
        // Answered yes — for this community only.
        let given = RegistryChoice {
            publish: true,
            confirmed: true,
            ..base
        };
        assert!(given.consent_for(vtc));
        assert!(!given.consent_for("did:web:another.example"));
        assert!(!given.answered_for("did:web:another.example"));
    }
    use super::driver::applicant_listener;
    use super::{
        is_duplicate_membership, joined_session, load_pasted_vic, parse_pasted_vic,
        stash_verified_vic, validate_join_input,
    };
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::join::JoinState;
    use crate::state_handler::setup_sequence::MessageType;
    use crate::state_handler::state::State;
    use affinidi_tdk::{TDK, common::config::TDKConfig};
    use openvtc_core::config::account::{CommunityRecord, CommunityStatus, PersonaId};
    use openvtc_core::didcomm::Messaging;
    use serde_json::json;

    // ---- Pure-decision tests (peeled out of the join sequence) ----

    /// A persona whose keys live in a sub-context is presented from it, so
    /// nothing is asked; a new persona is asked, with a context of its own
    /// offered first.
    #[test]
    fn a_persona_bound_to_a_context_skips_the_choice_and_a_new_one_is_asked() {
        use super::offer_contexts;
        use crate::state_handler::join::{IdentityPick, JoinPage};
        use openvtc_core::config::account::PersonaRecord;
        use openvtc_core::config::community_context::ContextKind;

        let mut config = test_config();
        config.account.top_context_id = "openvtc".into();
        let persona_id = PersonaId::new();
        config.account.personas.insert(
            persona_id,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id,
                did: "did:webvh:scid:example.com:alice".into(),
                did_document: None,
                did_locator: None,
                key_refs: vec![],
                mediator_did: None,
                origin_context_id: "openvtc/work".into(),
                created_at: chrono::Utc::now(),
                label: None,
            },
        );
        let vtc = "did:webvh:QmCommunityScid:vtc.example.com";
        let mut state = State::default();

        assert_eq!(
            offer_contexts(&mut state, &config, IdentityPick::Reuse(persona_id), vtc).as_deref(),
            Some("openvtc/work")
        );
        assert_ne!(state.join.page, JoinPage::ContextChoice);

        assert!(offer_contexts(&mut state, &config, IdentityPick::Mint, vtc).is_none());
        assert_eq!(state.join.page, JoinPage::ContextChoice);
        let kinds: Vec<_> = state.join.context_options.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [ContextKind::New, ContextKind::Existing, ContextKind::Top]
        );
        assert!(!state.join.context_slug.is_empty());
        assert_eq!(state.join.picked_identity, Some(IdentityPick::Mint));
    }

    /// `validate_join_input` trims, and accepts only something that could be a
    /// community: a DID or an agent name. Garbage is refused here, on the page
    /// that can still be corrected — downstream, an unresolvable string reached
    /// the "join anyway" offer, which for `asdasd` meant offering to send a
    /// join request to nothing.
    #[test]
    fn validate_join_input_table() {
        let cases: &[(&str, bool)] = &[
            ("", false),
            ("   ", false),
            ("\t\n", false),
            // The one from the report.
            ("asdasd", false),
            // Looks close, but is not an identifier.
            ("did:", false),
            ("did:webvh", false),
            ("did:webvh:", false),
            ("did::abc", false),
            ("https://vtc.example.com", false),
            // DIDs, including methods this build has never heard of — which
            // method-specific ids are legal is the method's business, not ours.
            ("did:webvh:example", true),
            ("  did:webvh:example  ", true),
            ("\tdid:peer:abc\n", true),
            ("did:futuremethod:whatever", true),
            // Agent names.
            ("vtc.example.com/@acme", true),
        ];
        for (raw, accepted) in cases {
            let got = validate_join_input(raw);
            assert_eq!(
                got.is_ok(),
                *accepted,
                "validate_join_input({raw:?}) = {got:?}"
            );
            if let Ok(did) = got {
                assert_eq!(did, raw.trim(), "the cleaned value is the trimmed input");
            }
        }
        // The refusal names what was typed, so it is about *this* input rather
        // than a rule the reader has to apply themselves.
        let why = validate_join_input("asdasd").unwrap_err();
        assert!(why.contains("asdasd"), "{why}");
        assert!(why.contains("did:webvh"), "and what one looks like: {why}");
    }
    /// `is_duplicate_membership` mirrors `Account::has_live_membership`: live
    /// (Active/Pending) memberships are duplicates; inactive ones and unknown
    /// DIDs are not. Table-driven over the membership status.
    #[test]
    fn is_duplicate_membership_table() {
        // (status to register for "did:vtc:known", is_duplicate?)
        let cases: &[(Option<CommunityStatus>, bool)] = &[
            (None, false),
            (
                Some(CommunityStatus::Pending {
                    request_id: uuid::Uuid::new_v4(),
                }),
                true,
            ),
            (Some(CommunityStatus::Active), true),
            (Some(CommunityStatus::Left), false),
            (Some(CommunityStatus::Rejected), false),
            (Some(CommunityStatus::Removed), false),
            (Some(CommunityStatus::Expired), false),
        ];
        let vtc = "did:vtc:known";
        let persona = PersonaId::new();
        for (status, expected) in cases {
            let mut config = test_config();
            if let Some(status) = status {
                let mut rec = CommunityRecord::new_pending(
                    vtc.to_string(),
                    None,
                    "ctx/slug".to_string(),
                    persona,
                    uuid::Uuid::new_v4(),
                    chrono::Utc::now(),
                );
                rec.status = status.clone();
                config.account.add_membership(rec);
            }
            assert_eq!(
                is_duplicate_membership(&config, vtc, persona),
                *expected,
                "is_duplicate_membership for status {status:?}"
            );
            // An unrelated DID is never a duplicate regardless of registered state.
            assert!(
                !is_duplicate_membership(&config, "did:vtc:other", persona),
                "unknown DID is not a duplicate (status {status:?})"
            );
            // The same community as a *different* persona is not a duplicate.
            assert!(
                !is_duplicate_membership(&config, vtc, PersonaId::new()),
                "different persona is not a duplicate (status {status:?})"
            );
        }
    }

    /// `build_pending_record` produces a `Pending` record carrying the submit
    /// inputs (vtc/display name/sub-context/persona/request id/requested_at).
    #[test]
    fn build_pending_record_carries_inputs() {
        let persona = PersonaId::new();
        let request_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let rec = openvtc_core::join::sequence::pending_record(
            "did:vtc:c".to_string(),
            Some("Community".to_string()),
            "top/slug".to_string(),
            persona,
            request_id,
            now,
            openvtc_core::didcomm::MessagingTransport::Tsp,
        );
        assert_eq!(rec.vtc_did, "did:vtc:c");
        assert_eq!(rec.display_name.as_deref(), Some("Community"));
        assert_eq!(rec.sub_context_id, "top/slug");
        assert_eq!(rec.persona_ref, persona);
        assert_eq!(rec.requested_at, Some(now));
        assert_eq!(
            rec.submit_transport,
            Some(openvtc_core::didcomm::MessagingTransport::Tsp),
            "the record remembers which transport carried the submit"
        );
        assert!(rec.is_live(), "a fresh Pending record is live");
        match rec.status {
            CommunityStatus::Pending { request_id: got } => {
                assert_eq!(got, request_id, "request id is carried into the status");
            }
            other => panic!("expected Pending status, got {other:?}"),
        }
    }

    #[test]
    fn joined_session_extracted_only_on_success() {
        // No persisted community → nothing for the runtime loop to register (R-B-5).
        let mut js = JoinState::default();
        assert!(joined_session(&js).is_none());

        // A successful sequence leaves the record + persona did → a session.
        let persona = PersonaId::new();
        let rec = openvtc_core::join::sequence::pending_record(
            "did:vtc:c".to_string(),
            None,
            "top/slug".to_string(),
            persona,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            openvtc_core::didcomm::MessagingTransport::DidComm,
        );
        js.created_community = Some(rec);
        js.created_persona_did = Some("did:webvh:persona".to_string());

        let joined = joined_session(&js).expect("a persisted community yields a session");
        assert_eq!(joined.persona_id, persona);
        assert_eq!(joined.persona_did, "did:webvh:persona");
        assert_eq!(joined.vtc_did, "did:vtc:c");
    }

    // ---- `load_pasted_vic`: the paste row on the invitation step ----

    const COMMUNITY: &str = "did:webvh:example.com:community";

    /// A complete, presentable VIC — every field `validate_invitation_credential`
    /// requires, issued by [`COMMUNITY`] and not yet expired.
    fn pasteable_vic(id: &str) -> serde_json::Value {
        json!({
            // The DTG wire form, as `dtg-credentials` mints it — both required
            // contexts and the `DTGCredential` base type. A fixture that omits
            // them is not a VIC a community could have issued.
            "@context": [
                openvtc_core::join::W3C_VC_V2_CONTEXT,
                openvtc_core::join::DTG_CONTEXT
            ],
            "id": id,
            "type": ["VerifiableCredential", "DTGCredential", "InvitationCredential"],
            "issuer": COMMUNITY,
            "issuerScope": "public",
            "credentialSubject": { "id": "did:webvh:example.com:alice" },
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2099-01-01T00:00:00Z",
            "credentialStatus": { "type": "BitstringStatusListEntry" },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    /// A config holding one persona, `did`.
    fn config_with_persona(did: &str) -> openvtc_core::config::Config {
        use openvtc_core::config::account::PersonaRecord;
        let mut config = test_config();
        let persona_id = PersonaId::new();
        config.account.personas.insert(
            persona_id,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id,
                did: did.into(),
                did_document: None,
                did_locator: None,
                key_refs: vec![],
                mediator_did: None,
                origin_context_id: "openvtc".into(),
                created_at: chrono::Utc::now(),
                label: None,
            },
        );
        config
    }

    // ---- An invitation on a join that mints a persona (#373) ----

    /// A first join: no persona can vouch for a new one, so the invitation is
    /// not presented — but it is kept (the sequence vaults it and says why), and
    /// its subject is named on the entry page before anything is sent.
    #[test]
    fn a_first_join_names_the_invitation_it_cannot_present() {
        let config = test_config();
        let vic = pasteable_vic("urn:uuid:first");
        let state = State {
            invitation_credential: Some(vic.clone()),
            ..State::default()
        };

        assert_eq!(
            super::foreign_invitation_subject(&config, &vic).as_deref(),
            Some("did:webvh:example.com:alice")
        );
        assert!(!super::mint_can_present(&config, &state, COMMUNITY));
        assert!(state.invitation_credential.is_some(), "kept, not discarded");
    }

    /// "Be someone new" with an invitation naming one of our personas: the new
    /// persona presents it through a subject-linkage proof, as a reused persona
    /// already could.
    #[test]
    fn a_new_persona_presents_an_invitation_one_of_ours_can_vouch_for() {
        let config = config_with_persona("did:webvh:example.com:alice");
        let vic = pasteable_vic("urn:uuid:ours");
        let state = State {
            invitation_credential: Some(vic.clone()),
            ..State::default()
        };

        assert_eq!(super::foreign_invitation_subject(&config, &vic), None);
        assert!(super::mint_can_present(&config, &state, COMMUNITY));
        // Not for this community: presenting would fall back to whatever the
        // vault holds, which a new persona was never meant to present.
        assert!(!super::mint_can_present(
            &config,
            &state,
            "did:webvh:example.com:elsewhere"
        ));
    }

    /// An invitation naming a stranger stays unpresentable however many
    /// personas the account holds.
    #[test]
    fn an_invitation_for_a_stranger_is_foreign_to_every_persona() {
        let config = config_with_persona("did:webvh:example.com:bob");
        let state = State {
            invitation_credential: Some(pasteable_vic("urn:uuid:stranger")),
            ..State::default()
        };
        assert!(!super::mint_can_present(&config, &state, COMMUNITY));
    }

    /// Paste as `load_pasted_vic` does once the proof has verified: parse,
    /// shape-check, stash. The proof step itself needs the network (the
    /// invitation's status list) and is covered in `openvtc-core::join` and by
    /// [`an_unsigned_paste_is_refused_and_prefills_nothing`].
    fn paste_verified(state: &mut State, text: &str, vtc_did: Option<&str>) {
        if let Some(vic) = parse_pasted_vic(state, text) {
            stash_verified_vic(state, vic, vtc_did);
        }
    }

    /// An invitation copied out of a wrapped terminal — broken mid-string, with
    /// panel borders — is mended back into one that parses and shape-checks.
    #[test]
    fn a_wrapped_invitation_paste_is_mended() {
        let vic = serde_json::to_string(&pasteable_vic("urn:uuid:wrapped")).unwrap();
        let wrapped: String = vic
            .as_bytes()
            .chunks(37)
            .map(|c| format!("│ {} │\n", std::str::from_utf8(c).unwrap()))
            .collect();
        let mut state = State::default();
        let got = parse_pasted_vic(&mut state, &wrapped);
        assert!(state.join.messages.is_empty(), "{:?}", state.join.messages);
        assert_eq!(got, Some(pasteable_vic("urn:uuid:wrapped")));
    }

    /// A paste whose proof does not verify is refused, and leaves no issuer
    /// behind to prefill the community DID from.
    #[tokio::test]
    async fn an_unsigned_paste_is_refused_and_prefills_nothing() {
        let resolver = affinidi_tdk::did_resolver::DIDCacheClient::new(
            affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        for vtc in [None, Some(COMMUNITY)] {
            let mut state = State::default();
            load_pasted_vic(
                &mut state,
                &resolver,
                &pasteable_vic("urn:uuid:one").to_string(),
                vtc,
            )
            .await;
            assert!(first_error(&state).is_some_and(|e| e.contains("did not verify")));
            assert!(state.join.invitation_issuer.is_none());
            assert!(state.invitation_credential.is_none());
            assert!(state.join.invitation_options.is_empty());
        }
    }

    fn first_error(state: &State) -> Option<&str> {
        state.join.messages.iter().find_map(|m| match m {
            MessageType::Error(e) => Some(e.as_str()),
            _ => None,
        })
    }

    #[test]
    fn a_matching_paste_becomes_the_selected_invitation() {
        let mut state = State::default();
        paste_verified(
            &mut state,
            &pasteable_vic("urn:uuid:one").to_string(),
            Some(COMMUNITY),
        );
        assert_eq!(state.join.invitation_options.len(), 1);
        assert_eq!(state.join.invitation_options[0].id, "urn:uuid:one");
        // Selected, so the next Enter presents it rather than needing an arrow.
        assert_eq!(state.join.invitation_use_selected, 0);
        assert!(state.join.has_invitation);
        assert_eq!(first_error(&state), None);
    }

    #[test]
    fn re_pasting_the_same_invitation_reselects_rather_than_duplicates() {
        let mut state = State::default();
        let vic = pasteable_vic("urn:uuid:one").to_string();
        paste_verified(&mut state, &vic, Some(COMMUNITY));
        paste_verified(&mut state, &vic, Some(COMMUNITY));
        assert_eq!(state.join.invitation_options.len(), 1);
        assert_eq!(state.join.invitation_use_selected, 0);
    }

    /// Each rejection has to say *why*. A paste that silently fails to load is
    /// indistinguishable from one that was never made, and the operator then
    /// sends an open request believing they presented a credential.
    #[test]
    fn every_rejection_reports_its_reason() {
        // Wrong community.
        let mut other = pasteable_vic("urn:uuid:one");
        other["issuer"] = json!("did:webvh:example.com:elsewhere");
        // Expired.
        let mut expired = pasteable_vic("urn:uuid:one");
        expired["validUntil"] = json!("2000-01-01T00:00:00Z");
        // Right shape, wrong document — not an InvitationCredential.
        let not_a_vic = json!({ "id": "urn:uuid:one", "type": ["VerifiableCredential"] });

        let cases: &[(&str, String, &str)] = &[
            ("not JSON", "}{ not json".to_string(), "not valid JSON"),
            ("not a VIC", not_a_vic.to_string(), "not usable"),
            ("wrong community", other.to_string(), "different community"),
            ("expired", expired.to_string(), "expired"),
        ];
        for (name, text, expect) in cases {
            let mut state = State::default();
            paste_verified(&mut state, text, Some(COMMUNITY));
            let err =
                first_error(&state).unwrap_or_else(|| panic!("{name}: expected a reported reason"));
            assert!(
                err.contains(expect),
                "{name}: reason should mention {expect:?}, got {err:?}"
            );
            assert!(
                state.join.invitation_options.is_empty(),
                "{name}: a rejected paste must not become a presentable row"
            );
        }
    }

    /// On the entry page the community is not chosen yet, so the paste is only
    /// shape-checked and stashed — `collect_available_vics` matches it later.
    #[test]
    fn an_entry_page_paste_is_stashed_without_a_community_check() {
        let mut state = State::default();
        let mut elsewhere = pasteable_vic("urn:uuid:one");
        elsewhere["issuer"] = json!("did:webvh:example.com:elsewhere");
        paste_verified(&mut state, &elsewhere.to_string(), None);
        assert!(state.invitation_credential.is_some());
        assert!(state.join.has_invitation);
        assert!(!state.join.vic_cleared);
        // No row is added: the invitation step has not been reached.
        assert!(state.join.invitation_options.is_empty());
        assert_eq!(first_error(&state), None);
    }

    /// The entry-page paste records the VIC's issuer, which *is* the community
    /// being joined. The entry page prefills its DID input from this, so an
    /// operator holding an invitation never has to find and retype a DID the
    /// credential already carries (#29).
    #[test]
    fn an_entry_page_paste_records_the_issuing_community() {
        let mut state = State::default();
        paste_verified(&mut state, &pasteable_vic("urn:uuid:one").to_string(), None);
        assert_eq!(state.join.invitation_issuer.as_deref(), Some(COMMUNITY));
    }

    /// A DTG credential names its issuer as a DID string. The W3C object form
    /// is not one `dtg-credentials` parses, so a pasted invitation carrying it
    /// is refused rather than half-read — and leaves no issuer behind.
    #[test]
    fn an_object_form_issuer_is_refused() {
        let mut state = State::default();
        let mut vic = pasteable_vic("urn:uuid:one");
        vic["issuer"] = json!({ "id": COMMUNITY, "name": "Example Community" });
        paste_verified(&mut state, &vic.to_string(), None);
        assert_eq!(state.join.invitation_issuer, None);
    }

    /// A rejected paste must not leave an issuer behind: the entry page would
    /// prefill a community DID from a credential it refused to load, and the
    /// operator would join without the invitation they thought they presented.
    #[test]
    fn a_rejected_entry_page_paste_records_no_issuer() {
        let not_a_vic = json!({ "id": "urn:uuid:one", "type": ["VerifiableCredential"] });
        for text in ["}{ not json", &not_a_vic.to_string()] {
            let mut state = State::default();
            paste_verified(&mut state, text, None);
            assert_eq!(state.join.invitation_issuer, None, "for paste {text:?}");
            assert!(!state.join.has_invitation);
        }
    }

    // ---- Pre-submit persona connect ----
    //
    // What `applicant_listener` returns is an *ownership claim*: the launch's
    // saga records it, and a cancel or failure removes whatever it recorded, so
    // handing back one the launch should not install would tear down a socket
    // serving something else. Both no-op paths are covered here; the install-and-connect
    // path needs a live mediator and is covered by the messaging e2e suite.

    /// Offline TDK — no environment load, no network.
    async fn test_tdk() -> TDK {
        TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .expect("TDK config builds"),
            None,
        )
        .await
        .expect("TDK builds")
    }

    /// State-A runs with no messaging service at all. Nothing is installed, so
    /// nothing is claimed — and a cancel has nothing to remove.
    #[tokio::test]
    async fn without_a_messaging_service_nothing_is_claimed() {
        let config = test_config();
        let tdk = test_tdk().await;

        let claimed = applicant_listener(
            None,
            &config,
            &tdk,
            PersonaId::new(),
            "did:webvh:example.com:applicant",
        )
        .await;

        assert!(claimed.is_none(), "no service means no listener to own");
    }

    /// A persona the config cannot resolve to an identity yields no listener
    /// config, so no listener is installed and none is claimed. The join carries
    /// on regardless — an applicant that cannot connect still gets admitted.
    #[tokio::test]
    async fn an_unresolvable_persona_is_not_claimed() {
        // `test_config` has no identities, so any persona id is unresolvable.
        let config = test_config();
        let tdk = test_tdk().await;
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = Messaging::start(event_tx);

        let claimed = applicant_listener(
            Some(&service),
            &config,
            &tdk,
            PersonaId::new(),
            "did:webvh:example.com:applicant",
        )
        .await;

        assert!(
            claimed.is_none(),
            "an uninstalled listener must never be claimed"
        );
        service.shutdown().await;
    }
}

#[cfg(test)]
mod vetting_tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use vta_sdk::protocols::join_requests::manifest;

    /// A hidden-vetting join with no proof to send stops, and says what to do
    /// — never a submit that presents no vetting at all.
    #[test]
    fn a_hidden_join_without_its_proof_stops_and_says_why() {
        let mut app = openvtc_core::vetting::applicant::Application::new(
            VTC,
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();

        // Reached without a challenge only from a loop that cannot hear one,
        // so the way out it names is a join that can — not a key to press.
        let no_challenge = hidden_proof_precheck(&app).expect_err("refused");
        assert!(
            no_challenge.contains("cannot hear the community's answer"),
            "{no_challenge}"
        );
        assert!(!no_challenge.contains("press m"), "{no_challenge}");
        assert!(no_challenge.contains("Nothing was sent"), "{no_challenge}");

        // With the challenge held, what is left is the VTA's: it builds the proof, or finds no
        // attestation to build it from.
        app.hidden_challenge = Some("nonce".into());
        assert_eq!(hidden_proof_precheck(&app), Ok("nonce".to_string()));
    }

    /// An application under a hidden-vetting criterion, holding one vetter's
    /// attestation when `attested`. The values are placeholders: nothing here
    /// builds a proof, only decides whether one could be asked for.
    fn hidden_application(attested: bool) -> Application {
        use vta_sdk::protocols::vetting::{VettingMethod, VettingRelationship};
        let mut app =
            Application::new(VTC, PersonaId::new(), "did:key:zApplicant", Utc::now()).unwrap();
        app.hidden = Some(
            serde_json::from_value(serde_json::json!({
                "suite": "placeholder",
                "helperKey": "z1",
                "tokenKey": "z2",
                "vetterLabels": ["vetter/2026-10"],
                "tokenLabels": ["token/2026-10"],
            }))
            .unwrap(),
        );
        let held = serde_json::json!({
                "community": VTC,
                "requirementsDigest": DIGEST,
                "method": serde_json::to_value(VettingMethod::InPerson).unwrap(),
                "claimsVerified": [],
                "livenessConfirmed": false,
                "declaredRelationship": serde_json::to_value(VettingRelationship::None).unwrap(),
                "identityCommitment": "z4",
                "cardDigestMultibase": "z5",
                "validFrom": "2026-10-01",
                "validUntil": "2027-01-01",
                "tokenLabel": "token/2026-10",
                "tokenSerial": "z6",
        });
        app.hidden_app = Some(
            serde_json::from_value(serde_json::json!({
                "applicationId": "app-1",
                "id": "z9",
                "attestations": if attested { vec![held] } else { vec![] },
            }))
            .unwrap(),
        );
        app
    }

    /// An attestation made before the community changed its published
    /// hidden-vetting parameters cannot count there: the criterion's digest
    /// moved, or the token's label is no longer live. The join stops before it
    /// spends a challenge, and says so — not "needs more vetting" from the
    /// community with no reason, after this client called the join satisfied.
    #[test]
    fn a_hidden_join_holding_only_stale_attestations_stops_and_says_why() {
        // Current: asks for its challenge as before.
        let mut app = hidden_application(true);
        app.requirements_digest = Some(DIGEST.to_string());
        assert!(app.holds_current_hidden_attestation());
        assert_eq!(challenge_step(Some(&app), true, false), ChallengeStep::Ask);

        // The criterion moved on (its drip rate changed, say): the digest the
        // attestation binds is not the one the join will cite.
        app.requirements_digest = Some("zQmTheCriterionSinceItChanged".to_string());
        assert!(!app.holds_current_hidden_attestation());
        assert_eq!(
            challenge_step(Some(&app), true, false),
            ChallengeStep::Proceed,
            "no challenge is spent on a proof that cannot count"
        );
        app.hidden_challenge = Some("nonce".into());
        let refusal = hidden_proof_precheck(&app).expect_err("refused");
        assert!(refusal.contains("PCS ZKP proof"), "{refusal}");
        assert!(refusal.contains("earlier version"), "{refusal}");
        assert!(refusal.contains("attest again"), "{refusal}");
        assert!(refusal.contains("Nothing was sent"), "{refusal}");

        // The month rolled over: the token's label is no longer published.
        let mut app = hidden_application(true);
        app.requirements_digest = Some(DIGEST.to_string());
        if let Some(params) = app.hidden.as_mut() {
            params.token_labels = vec!["token/2026-11".into()];
        }
        app.hidden_challenge = Some("nonce".into());
        let refusal = hidden_proof_precheck(&app).expect_err("refused");
        assert!(refusal.contains("token/2026-10"), "{refusal}");
        assert!(refusal.contains("no longer accepts"), "{refusal}");
    }

    /// With nothing to prove, that is what the join says — not that a
    /// challenge is missing, which would send the person after the wrong thing.
    #[test]
    fn a_hidden_join_with_no_attestation_says_so_before_the_challenge() {
        let app = hidden_application(false);
        let refusal = hidden_proof_precheck(&app).expect_err("refused");
        assert!(refusal.contains("no vetter's attestation"), "{refusal}");
    }

    /// A hidden-vetting launch that can hear the answer asks for a challenge
    /// instead of failing — every time, because a stored one may have been
    /// replaced, lapsed or spent without this client knowing.
    #[test]
    fn a_hidden_launch_asks_for_its_challenge_rather_than_failing() {
        let mut app = hidden_application(true);
        assert_eq!(
            challenge_step(Some(&app), true, false),
            ChallengeStep::Ask,
            "no challenge held: ask, don't fail"
        );
        app.hidden_challenge = Some("an older one".into());
        assert_eq!(
            challenge_step(Some(&app), true, false),
            ChallengeStep::Ask,
            "a stored challenge is not trusted to be live"
        );
        assert_eq!(
            challenge_step(Some(&app), true, true),
            ChallengeStep::Proceed,
            "the challenge just issued for this launch is used"
        );
        assert_eq!(
            challenge_step(Some(&app), false, false),
            ChallengeStep::Proceed,
            "a loop that cannot hear the answer does not ask and wait forever"
        );
    }

    /// Nothing is asked when there is nothing hidden to prove.
    #[test]
    fn only_a_hidden_launch_with_an_attestation_asks() {
        assert_eq!(challenge_step(None, true, false), ChallengeStep::Proceed);
        let named =
            Application::new(VTC, PersonaId::new(), "did:key:zApplicant", Utc::now()).unwrap();
        assert_eq!(
            challenge_step(Some(&named), true, false),
            ChallengeStep::Proceed
        );
        assert_eq!(
            challenge_step(Some(&hidden_application(false)), true, false),
            ChallengeStep::Proceed,
            "no attestation: the refusal says so without a wait first"
        );
    }

    fn awaiting_challenge() -> AwaitingChallenge {
        AwaitingChallenge {
            vtc_did: VTC.into(),
            document_id: "urn:uuid:c1".into(),
            asked_at: std::time::Instant::now(),
            choice: IdentityPick::Reuse(PersonaId::new()),
            context_id: "ctx".into(),
        }
    }

    /// Only the answer to the launch's own question resumes it, and a failed
    /// one says which way it failed (R6.4).
    #[test]
    fn only_the_awaited_challenge_resumes_the_launch() {
        let waiting = awaiting_challenge();
        assert!(matches!(
            challenge_resume_for(
                &waiting,
                &CommunityAnswer::Challenge {
                    query: "urn:uuid:c1".into(),
                    community: VTC.into(),
                }
            ),
            Some(JoinEntry::Challenge {
                outcome: ChallengeOutcome::Issued,
                ..
            })
        ));
        assert!(
            challenge_resume_for(
                &waiting,
                &CommunityAnswer::Challenge {
                    query: "urn:uuid:asked-from-the-vetting-page".into(),
                    community: VTC.into(),
                }
            )
            .is_none(),
            "another question's challenge is not this launch's"
        );
        assert!(
            challenge_resume_for(
                &waiting,
                &CommunityAnswer::Challenge {
                    query: "urn:uuid:c1".into(),
                    community: "did:web:other".into(),
                }
            )
            .is_none()
        );
        assert!(matches!(
            challenge_resume_for(
                &waiting,
                &CommunityAnswer::Refused {
                    query: "urn:uuid:c1".into(),
                    community: VTC.into(),
                    kind: QueryKind::PcsChallenge,
                    code: "vtc/vetting/pcs-challenge:notHiddenVetting".into(),
                    message: None,
                }
            ),
            Some(JoinEntry::Challenge { outcome: ChallengeOutcome::Unanswered(why), .. })
                if why.contains("refused") && why.contains("notHiddenVetting")
        ));
        assert!(matches!(
            challenge_resume_for(
                &waiting,
                &CommunityAnswer::Unreadable {
                    query: "urn:uuid:c1".into(),
                    community: VTC.into(),
                    kind: QueryKind::PcsChallenge,
                    detail: "missing field `challenge`".into(),
                }
            ),
            Some(JoinEntry::Challenge { outcome: ChallengeOutcome::Unanswered(why), .. })
                if why.contains("cannot read") && why.contains("not a refusal")
        ));
        assert!(
            challenge_resume_for(
                &waiting,
                &CommunityAnswer::Manifest {
                    community: VTC.into()
                }
            )
            .is_none(),
            "a manifest is not a challenge"
        );
    }

    /// The failure names what to do next and that nothing went out.
    #[test]
    fn a_challenge_that_did_not_come_stops_the_join_and_says_why() {
        let words = challenge_failed_words("Kernel", "it refused (notHiddenVetting)");
        assert!(words.contains("Asking Kernel for one failed"), "{words}");
        assert!(words.contains("notHiddenVetting"), "{words}");
        assert!(words.contains("Nothing was sent"), "{words}");
    }

    const VTC: &str = "did:web:kernel.example";
    /// Base58btc and at least 16 characters, as the published criterion asks.
    const DIGEST: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";

    fn manifest(vets: bool) -> openvtc_core::vetting::protocol::Manifest {
        let requirements = serde_json::from_value(serde_json::json!({
            "version": "0.1",
            "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
            "minStatements": 2,
            "acceptedMethods": ["inPerson", "video"],
            "requiredClaims": ["name.legal"],
            "maxStatementAge": "P120D",
            "eligibleVetters": { "role": "vetter" }
        }))
        .unwrap();
        let criterion = manifest::v0_4::Criterion::try_from(
            manifest::v0_4::Criterion::builder()
                .id("vetted")
                .presentation_definition(serde_json::Map::new())
                .vetting(vets.then_some(requirements))
                .admission(manifest::v0_4::CriterionAdmission::Review)
                .requirements_digest(manifest::v0_4::DigestMultibase::try_from(DIGEST).unwrap()),
        )
        .unwrap();
        openvtc_core::vetting::protocol::Manifest::try_from(
            openvtc_core::vetting::protocol::Manifest::builder()
                .community_did(VTC)
                .criteria(vec![criterion]),
        )
        .unwrap()
    }

    fn awaiting() -> AwaitingRequirements {
        AwaitingRequirements {
            vtc_did: VTC.into(),
            document_id: "urn:uuid:m1".into(),
            asked_at: std::time::Instant::now(),
        }
    }

    /// Only an answer about the community being joined, and about its
    /// requirements, resumes the join.
    #[test]
    fn only_the_awaited_manifest_resumes_the_join() {
        let waiting = awaiting();
        assert!(matches!(
            resume_for(
                &waiting,
                &CommunityAnswer::Manifest {
                    community: VTC.into()
                }
            ),
            Some(JoinEntry::Resume {
                outcome: RequirementsOutcome::Learned,
                ..
            })
        ));
        assert!(
            resume_for(
                &waiting,
                &CommunityAnswer::Manifest {
                    community: "did:web:other".into()
                }
            )
            .is_none()
        );
        assert!(matches!(
            resume_for(
                &waiting,
                &CommunityAnswer::Refused {
                    query: "urn:uuid:m1".into(),
                    community: VTC.into(),
                    kind: QueryKind::Manifest,
                    code: "permissionDenied".into(),
                    message: None,
                }
            ),
            Some(JoinEntry::Resume { outcome: RequirementsOutcome::Unanswered(reason), .. })
                if reason.contains("permissionDenied")
        ));
        assert!(
            resume_for(
                &waiting,
                &CommunityAnswer::Refused {
                    query: "q".into(),
                    community: VTC.into(),
                    kind: QueryKind::VetterList,
                    code: "permissionDenied".into(),
                    message: None,
                }
            )
            .is_none(),
            "a directory refusal is not about joining"
        );
    }

    /// A new persona with no invitation and no application sends no vetting,
    /// and its request goes to the community's moderators — and the review
    /// says so rather than leaving the lines blank.
    #[test]
    fn a_bare_join_reviews_as_a_new_persona_with_nothing_to_present() {
        use crate::state_handler::join::ReviewVetting;
        let config = test_config();
        let state = State::default();
        let review = join_review(&config, &state, VTC, &IdentityPick::Mint);
        assert!(review.persona.contains("a new persona"), "{review:?}");
        assert_eq!(review.invitation, None);
        assert_eq!(review.vetting, ReviewVetting::None);
        assert!(review.face.is_empty());
        assert!(
            review
                .decision
                .as_deref()
                .is_some_and(|d| d.contains("moderators")),
            "{review:?}"
        );
    }

    /// A persona just made from this page is the one the page re-opens on,
    /// whichever persona its own rules would otherwise have picked.
    #[test]
    fn the_page_reopens_on_the_persona_just_made() {
        use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
        let mut config = test_config();
        let now = Utc::now();
        config
            .private
            .vetting
            .learn_manifest(VTC, &manifest(true), now);
        let mut add = |did: &str| {
            let pid = PersonaId::new();
            config.identities.insert(
                pid,
                openvtc_core::identity::IdentityContext {
                    persona_id: pid,
                    did: did.to_string(),
                    document: serde_json::from_value(serde_json::json!({ "id": did }))
                        .expect("minimal DID document"),
                    profile: std::sync::Arc::new(ATMProfile {
                        inner: std::sync::Arc::new(ATMProfileInner {
                            did: did.to_string(),
                            alias: did.to_string(),
                            mediator: std::sync::Arc::new(None),
                        }),
                    }),
                    mediator_did: None,
                },
            );
            pid
        };
        let first = add("did:key:zFirst");
        let second = add("did:key:zSecond");
        let opened_on = |prefer| {
            let view = vetting_view(&config, VTC, &[], prefer, now).unwrap();
            let VettingPhase::Known(known) = view.phase else {
                panic!("known");
            };
            known.selected_persona().expect("opens on a persona's row")
        };
        let unpreferred = opened_on(None);
        let other = if unpreferred == first { second } else { first };
        assert_eq!(opened_on(Some(other)), other);
    }

    /// The page says what the community requires in words, and shows the
    /// application under way with its next step.
    #[test]
    fn a_vetting_community_is_explained_before_joining() {
        let mut config = test_config();
        let now = Utc::now();
        assert!(
            vetting_view(&config, VTC, &[], None, now).is_none(),
            "not known yet"
        );

        config
            .private
            .vetting
            .learn_manifest(VTC, &manifest(false), now);
        assert!(
            vetting_view(&config, VTC, &[], None, now).is_none(),
            "does not vet"
        );

        config
            .private
            .vetting
            .learn_manifest(VTC, &manifest(true), now);
        let view = vetting_view(&config, VTC, &[], None, now).unwrap();
        let VettingPhase::Known(known) = &view.phase else {
            panic!("known");
        };
        assert!(known.requirements[0].starts_with("2 vetting statements"));
        assert!(known.requirements.iter().any(|l| l.contains("120 days")));
        assert!(known.applications.is_empty());

        let persona = PersonaId::new();
        let id = config
            .private
            .vetting
            .start_application(VTC, persona, "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        config
            .private
            .vetting
            .adopt_known_requirements(&id)
            .unwrap();
        let view = vetting_view(&config, VTC, &[], None, now).unwrap();
        let VettingPhase::Known(known) = &view.phase else {
            panic!("known");
        };
        let app = known
            .applications
            .first()
            .expect("the application under way");
        assert_eq!(app.persona, persona);
        assert!(!app.satisfied);
        assert!(app.next_step.starts_with("f —"), "{}", app.next_step);
    }

    /// A community can hold an application from each of this account's
    /// personas — they are keyed on `(community, persona)`. The join page used
    /// to show only the first and hide the chooser, so a second persona could
    /// never apply from here at all.
    #[test]
    fn every_persona_with_an_application_is_reachable_from_the_join() {
        let mut config = test_config();
        let now = Utc::now();
        config
            .private
            .vetting
            .learn_manifest(VTC, &manifest(true), now);

        let alice = PersonaId::new();
        let bob = PersonaId::new();
        for persona in [alice, bob] {
            let id = config
                .private
                .vetting
                .start_application(VTC, persona, "did:key:zA", now)
                .unwrap()
                .id
                .clone();
            config
                .private
                .vetting
                .adopt_known_requirements(&id)
                .unwrap();
        }

        let view = vetting_view(&config, VTC, &[], None, now).unwrap();
        let VettingPhase::Known(known) = &view.phase else {
            panic!("known");
        };
        assert_eq!(known.applications.len(), 2, "both must be on the page");
    }

    /// A vetting row names the persona it is taken as, and its words follow
    /// from that persona's own application — none, under way, or ready. A row
    /// that said "Present your vetting statements" without saying whose left
    /// the reader to work out which persona's statements would go.
    #[test]
    fn the_vetting_row_names_its_persona_and_that_persona_s_standing() {
        let (label, detail) = vetting_row_words(Some("alice"), None);
        assert_eq!(label, "Apply for vetting as alice");
        assert_eq!(detail, "no application yet");

        let under_way = JoinApplication {
            id: "a1".into(),
            persona: PersonaId::new(),
            persona_label: "alice".into(),
            statements: 0,
            attestations: 0,
            progress: Some("0 of 2".into()),
            next_step: String::new(),
            satisfied: false,
        };
        let (label, detail) = vetting_row_words(Some("alice"), Some(&under_way));
        assert_eq!(label, "Carry on with your application as alice");
        assert_eq!(detail, "0 of 2");

        let ready = JoinApplication {
            statements: 2,
            attestations: 0,
            satisfied: true,
            ..under_way
        };
        let (label, detail) = vetting_row_words(Some("alice"), Some(&ready));
        assert_eq!(label, "Present your vetting statements as alice");
        assert_eq!(detail, "2 statements ready to present");

        // Hidden vetting: no named statements, and a proof ready all the same.
        let proof = JoinApplication {
            statements: 0,
            attestations: 2,
            satisfied: true,
            ..ready.clone()
        };
        let (label, detail) = vetting_row_words(Some("alice"), Some(&proof));
        assert_eq!(label, "Present your PCS ZKP proof as alice");
        assert_eq!(
            detail,
            "ready — proves 2 vetters vetted you, without naming them"
        );
        assert!(!detail.contains("0 statements"));

        let (label, detail) = vetting_row_words(None, None);
        assert_eq!(label, "Apply for vetting as a new persona");
        assert!(detail.contains("starts from scratch"), "{detail}");
    }

    /// The join page's next step names the row it is taken from; the Vetting
    /// panel's words lead with that panel's keys, and `j` does nothing on the
    /// join page.
    #[test]
    fn the_join_page_names_the_row_for_the_next_step() {
        use openvtc_core::vetting::applicant::NextStep;
        let row = "Present your vetting statements as alice";
        assert_eq!(
            join_page_next_step(&NextStep::Join, row),
            "join — Enter on \"Present your vetting statements as alice\""
        );
        let face = join_page_next_step(
            &NextStep::ChooseFace,
            "Carry on with your application as alice",
        );
        assert!(face.starts_with("choose the face"), "{face}");
        assert!(face.ends_with("opens it"), "{face}");
        // The panel keeps its keys.
        assert!(vetting_actions::next_step_words(&NextStep::Join).starts_with("j —"));
    }

    fn requirements(invitation: Option<&str>) -> VettingRequirements {
        let mut value = serde_json::json!({
            "version": "0.1",
            "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
            "minStatements": 2,
            "acceptedMethods": ["inPerson"],
            "eligibleVetters": { "role": "vetter" }
        });
        if let Some(invitation) = invitation {
            value["invitation"] = serde_json::json!(invitation);
        }
        serde_json::from_value(value).unwrap()
    }

    fn a_persona() -> ApplyAs {
        ApplyAs {
            persona: PersonaId::new(),
            label: "alice".into(),
            did: "did:webvh:alice".into(),
        }
    }

    fn a_vic() -> AvailableVic {
        AvailableVic {
            id: "urn:uuid:vic".into(),
            subject: None,
            valid_from: String::new(),
            valid_until: "2026-12-01T00:00:00Z".into(),
            body: serde_json::Value::Null,
        }
    }

    fn option_for(routes: &[RouteOption], route: JoinRoute) -> Option<&RouteOption> {
        routes.iter().find(|r| r.route == route)
    }

    /// An invitation in hand is a way in that does not go through vetting, and
    /// with no statements ready it is where the page opens.
    #[test]
    fn an_invitation_in_hand_is_where_the_page_opens_when_nothing_is_ready() {
        let personas = [a_persona()];
        let held = [a_vic()];
        let routes = build_routes("Kernel", &requirements(None), &[], &personas, &held);
        let known = KnownVetting {
            routes: routes.clone(),
            ..KnownVetting::default()
        };
        assert_eq!(
            known.routes[opening_row(&known, None)].route,
            JoinRoute::Invitation
        );
        let invitation = option_for(&routes, JoinRoute::Invitation).unwrap();
        assert!(invitation.available());
        assert!(invitation.detail.contains("1 held"));
        assert!(invitation.detail.contains("2026-12-01"));
    }

    fn application_of(persona: PersonaId, satisfied: bool) -> JoinApplication {
        JoinApplication {
            id: "a1".into(),
            persona,
            persona_label: "make-barrel".into(),
            statements: usize::from(satisfied),
            attestations: 0,
            progress: Some(if satisfied { "1 of 1" } else { "0 of 1" }.into()),
            next_step: String::new(),
            satisfied,
        }
    }

    /// The rejoin the page exists for: a persona whose statements are still
    /// ready is listed first and is where the page opens — ahead of an
    /// invitation, and ahead of the persona that sorts first by name — so
    /// Enter on arrival presents them, as that persona.
    #[test]
    fn the_page_opens_on_the_persona_whose_statements_are_ready() {
        let alice = ApplyAs {
            label: "alice".into(),
            ..a_persona()
        };
        let vetted = ApplyAs {
            label: "make-barrel".into(),
            ..a_persona()
        };
        let applications = [application_of(vetted.persona, true)];
        let routes = build_routes(
            "Kernel",
            &requirements(None),
            &applications,
            &[alice.clone(), vetted.clone()],
            &[a_vic()],
        );
        assert_eq!(
            routes[0].applicant,
            Some(Applicant::Persona(vetted.persona)),
            "ready first"
        );
        assert_eq!(
            routes[0].label,
            "Present your vetting statements as make-barrel"
        );
        let known = KnownVetting {
            routes,
            applications: applications.to_vec(),
            ..KnownVetting::default()
        };
        let row = opening_row(&known, None);
        assert_eq!(
            known.routes[row].applicant,
            Some(Applicant::Persona(vetted.persona))
        );
        // A persona just made from this page comes first all the same: making
        // it was the decision about who applies.
        let row = opening_row(&known, Some(alice.persona));
        assert_eq!(
            known.routes[row].applicant,
            Some(Applicant::Persona(alice.persona))
        );
    }

    /// There is a row per persona and one for a new persona, each saying where
    /// that persona stands; the new persona's starts by making it and says
    /// that nothing carries over from another persona.
    #[test]
    fn each_persona_has_its_own_row_and_a_new_one_starts_from_scratch() {
        let alice = ApplyAs {
            label: "alice".into(),
            ..a_persona()
        };
        let bob = ApplyAs {
            label: "bob".into(),
            ..a_persona()
        };
        let vetted = ApplyAs {
            label: "make-barrel".into(),
            ..a_persona()
        };
        let applications = [
            application_of(vetted.persona, true),
            application_of(alice.persona, false),
        ];
        let routes = build_routes(
            "Kernel",
            &requirements(None),
            &applications,
            &[alice.clone(), bob.clone(), vetted.clone()],
            &[],
        );
        let labels: Vec<&str> = routes.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Present your vetting statements as make-barrel",
                "Carry on with your application as alice",
                "Apply for vetting as bob",
                "Apply for vetting as a new persona",
                "Use an invitation",
                "Send an open request",
            ]
        );
        let new = routes
            .iter()
            .find(|r| r.applicant == Some(Applicant::NewPersona))
            .unwrap();
        assert_eq!(new.first_step_kind(), Some(FirstStepKind::CreatePersona));
        assert!(
            new.first_step().unwrap().contains("do not carry over"),
            "{:?}",
            new.first_step()
        );
    }

    /// A 0.3 community whose invitation and vetting criteria go to review is
    /// never described as admitting; one whose criteria admit, or a 0.2 one that
    /// does not say, is left as it was.
    #[test]
    fn a_review_criterion_is_never_worded_as_admitting() {
        use openvtc_core::vetting::book::CommunityCriterion;
        use openvtc_core::vetting::protocol::Admission;
        let criterion = |admission, invitation, vetting| CommunityCriterion {
            id: "c".into(),
            requirements_digest: None,
            admission,
            invitation_required: invitation,
            vetting,
            wallet: false,
            wallet_types: Vec::new(),
            description: None,
        };
        let fresh = || build_routes("Kernel", &requirements(None), &[], &[a_persona()], &[]);

        let mut routes = fresh();
        word_routes_by_admission(
            &mut routes,
            &[
                criterion(Some(Admission::Review), Some(true), false),
                criterion(Some(Admission::Review), None, true),
            ],
        );
        let invitation = option_for(&routes, JoinRoute::Invitation).unwrap();
        assert!(
            !invitation.detail.contains("admits"),
            "{}",
            invitation.detail
        );
        assert!(invitation.detail.contains("administrators"));
        let vetting = option_for(&routes, JoinRoute::Vetting).unwrap();
        assert!(vetting.detail.contains("an administrator decides"));

        for criteria in [
            vec![criterion(Some(Admission::Automatic), Some(true), false)],
            vec![criterion(None, Some(true), true)],
        ] {
            let mut routes = fresh();
            let before: Vec<String> = routes.iter().map(|r| r.detail.clone()).collect();
            word_routes_by_admission(&mut routes, &criteria);
            let after: Vec<String> = routes.iter().map(|r| r.detail.clone()).collect();
            assert_eq!(before, after);
        }
    }

    /// Holding none is two situations, and which one it is follows from the
    /// credential rather than from a guess: a VIC must name a
    /// `credentialSubject.id`, so with no persona no valid invitation can be
    /// *for* you. That row is shut. With a persona, one may exist that this
    /// vault has not seen, and pasting it is a step the join can walk through.
    #[test]
    fn holding_no_invitation_is_shut_without_a_persona_and_a_step_with_one() {
        let no_persona = build_routes("Kernel", &requirements(None), &[], &[], &[]);
        let invitation = option_for(&no_persona, JoinRoute::Invitation).unwrap();
        assert!(
            !invitation.available(),
            "nothing could have been issued yet"
        );
        assert!(
            invitation.blocked().unwrap().contains("you have none yet"),
            "{:?}",
            invitation.blocked()
        );

        let with_persona = build_routes("Kernel", &requirements(None), &[], &[a_persona()], &[]);
        let invitation = option_for(&with_persona, JoinRoute::Invitation).unwrap();
        assert!(invitation.available(), "one could exist outside the vault");
        assert!(
            invitation.first_step().unwrap().contains("paste one"),
            "{:?}",
            invitation.first_step()
        );
    }

    /// An invitation the community *requires* is asked for on top of the
    /// statements, not instead of them. Offering it as its own row would read
    /// as a way around being vetted.
    #[test]
    fn a_required_invitation_is_not_offered_as_a_way_around_vetting() {
        let routes = build_routes(
            "Kernel",
            &requirements(Some("required")),
            &[],
            &[a_persona()],
            &[a_vic()],
        );
        assert!(option_for(&routes, JoinRoute::Invitation).is_none());
        // Said once, beside the vetting heading, rather than on every
        // persona's row.
        let note = vetting_detail_suffix("Kernel", &requirements(Some("required")), 1).unwrap();
        assert!(note.contains("also asks for an invitation"), "{note}");
        assert!(note.contains("1 held"), "{note}");
        assert!(vetting_detail_suffix("Kernel", &requirements(None), 1).is_none());
    }

    /// A community that admits nobody by invitation says so, even to someone
    /// holding one — otherwise the row is an offer that cannot be taken.
    #[test]
    fn a_community_that_takes_no_invitations_says_so() {
        let routes = build_routes(
            "Kernel",
            &requirements(Some("none")),
            &[],
            &[a_persona()],
            &[a_vic()],
        );
        let invitation = option_for(&routes, JoinRoute::Invitation).unwrap();
        assert!(!invitation.available());
        assert!(
            invitation
                .blocked()
                .unwrap()
                .contains("does not admit anyone by invitation")
        );
    }

    /// Applying signs cards with a persona, and the open request mints one on
    /// the way — so with none, both are takeable and only one announces a step.
    ///
    /// The vetting route must read as available: otherwise the route the
    /// community is telling you about looks like the one you cannot use.
    #[test]
    fn with_no_persona_both_routes_are_takeable_and_only_one_says_so() {
        let routes = build_routes("Kernel", &requirements(None), &[], &[], &[]);
        let vetting = option_for(&routes, JoinRoute::Vetting).unwrap();
        let open = option_for(&routes, JoinRoute::OpenRequest).unwrap();
        assert!(vetting.available());
        assert!(open.available());
        assert!(
            vetting.first_step().is_some(),
            "applying starts by making one"
        );
        assert!(
            open.first_step().is_none(),
            "an open request mints one inside the sequence; nothing to announce"
        );
    }

    /// Applying without a persona is a route you can take, not one that is
    /// shut: the join can make a persona, so needing one is the route's first
    /// step. Greyed out, the one route the community was actually telling you
    /// about read as the one you could not use.
    #[test]
    fn applying_without_a_persona_is_takeable_and_starts_by_making_one() {
        let routes = build_routes("Kernel", &requirements(None), &[], &[], &[]);
        let vetting = option_for(&routes, JoinRoute::Vetting).unwrap();
        assert!(vetting.available(), "the route is takeable");
        let step = vetting.first_step().expect("it starts with a step");
        assert!(step.contains("no persona yet"), "{step}");
        assert!(vetting.blocked().is_none());
    }

    /// Not every first step is the same step. Creating a persona is something
    /// the join has to do *before* the route can proceed; being asked to paste
    /// an invitation is a page the route already leads to. Taking the second
    /// must not open the persona overlay.
    #[test]
    fn the_two_first_steps_are_different_steps() {
        let routes = build_routes("Kernel", &requirements(None), &[], &[a_persona()], &[]);
        assert_eq!(
            option_for(&routes, JoinRoute::Invitation)
                .unwrap()
                .first_step_kind(),
            Some(FirstStepKind::OnTheWay),
        );

        let routes = build_routes("Kernel", &requirements(None), &[], &[], &[]);
        assert_eq!(
            option_for(&routes, JoinRoute::Vetting)
                .unwrap()
                .first_step_kind(),
            Some(FirstStepKind::CreatePersona),
        );
    }

    /// The line between the two is who has to supply the missing thing. The
    /// join can make a persona; it cannot make an invitation somebody else has
    /// to have issued — and with no persona there is not even a DID one could
    /// have been issued to.
    #[test]
    fn only_what_the_join_cannot_supply_is_blocked() {
        let routes = build_routes("Kernel", &requirements(None), &[], &[], &[]);
        assert!(
            option_for(&routes, JoinRoute::Invitation)
                .unwrap()
                .blocked()
                .is_some(),
            "no persona means no subject an invitation could name"
        );
        assert!(
            option_for(&routes, JoinRoute::Vetting)
                .unwrap()
                .first_step()
                .is_some(),
            "a persona is something the join can make"
        );
    }

    /// With a persona there is no step to announce — the route is simply ready.
    #[test]
    fn a_route_with_nothing_missing_announces_no_step() {
        let routes = build_routes("Kernel", &requirements(None), &[], &[a_persona()], &[]);
        let vetting = option_for(&routes, JoinRoute::Vetting).unwrap();
        assert!(vetting.available());
        assert!(vetting.first_step().is_none());
    }

    /// Statements ride with an open request whenever the persona chosen for it
    /// has gathered any here — that persona's own, never another's — so the
    /// row must not read as a way to hold them back, nor promise statements to
    /// a persona that has none.
    #[test]
    fn an_open_request_admits_that_statements_go_with_it() {
        let alice = a_persona();
        let application = JoinApplication {
            id: "a1".into(),
            persona: alice.persona,
            persona_label: "alice".into(),
            statements: 2,
            attestations: 0,
            progress: Some("2 counted".into()),
            next_step: "join".into(),
            satisfied: true,
        };
        let routes = build_routes(
            "Kernel",
            &requirements(None),
            std::slice::from_ref(&application),
            std::slice::from_ref(&alice),
            &[],
        );
        let open = option_for(&routes, JoinRoute::OpenRequest).unwrap();
        assert!(
            open.detail
                .contains("a persona with statements here presents them"),
            "{}",
            open.detail
        );
        let vetting = option_for(&routes, JoinRoute::Vetting).unwrap();
        assert_eq!(vetting.label, "Present your vetting statements as alice");
    }

    /// How a community signs is recorded from its resolved DID document, so
    /// the page says PQC-signed or "classical keys only" rather than "not
    /// checked" — whichever route the manifest arrived by.
    #[test]
    fn signing_is_recorded_from_a_resolved_document() {
        use affinidi_tdk::secrets_resolver::secrets::Secret;
        let document = |with_pq: bool| {
            let ed = Secret::generate_ed25519(Some(&format!("{VTC}#key-0")), Some(&[1; 32]));
            let pq = Secret::generate_ml_dsa_44(Some(&format!("{VTC}#key-pq")), Some(&[2; 32]));
            let mut methods = vec![serde_json::json!({
                "id": format!("{VTC}#key-0"),
                "type": "Multikey",
                "controller": VTC,
                "publicKeyMultibase": ed.get_public_keymultibase().unwrap(),
            })];
            let mut assertion = vec![serde_json::json!("#key-0")];
            if with_pq {
                methods.push(serde_json::json!({
                    "id": format!("{VTC}#key-pq"),
                    "type": "Multikey",
                    "controller": VTC,
                    "publicKeyMultibase": pq.get_public_keymultibase().unwrap(),
                }));
                assertion.push(serde_json::json!("#key-pq"));
            }
            serde_json::from_value::<affinidi_tdk::did_common::Document>(serde_json::json!({
                "id": VTC,
                "verificationMethod": methods,
                "assertionMethod": assertion,
            }))
            .expect("a well-formed DID document")
        };
        for (with_pq, said) in [(true, "PQC-SIGNED"), (false, "classical keys only")] {
            let mut config = test_config();
            let now = Utc::now();
            config
                .private
                .vetting
                .learn_manifest(VTC, &manifest(true), now);
            assert_eq!(config.private.vetting.post_quantum_key(VTC), None);
            sequence::note_signing(&mut config, VTC, &document(with_pq));
            assert_eq!(config.private.vetting.post_quantum_key(VTC), Some(with_pq));
            let view = vetting_view(&config, VTC, &[], None, now).unwrap();
            let shown = crate::ui::pages::join_flow::vetting_requirements::body_lines(
                &crate::state_handler::join::JoinState::default(),
                &view,
            )
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
            assert!(shown.contains(said), "{shown}");
            assert!(!shown.contains("not checked"), "{shown}");
        }
    }
}

#[cfg(test)]
mod wallet_tests {
    use super::*;
    use openvtc_core::vetting::queries::wallet_session::{
        start::v0_1 as start, status::v0_1 as status,
    };
    use serde_json::json;

    const COMMUNITY: &str = "did:webvh:example.com:community";
    const SESSION: &str = "s1-0123456789abcdef";

    fn awaiting(asking: &str) -> AwaitingWallet {
        AwaitingWallet {
            vtc_did: COMMUNITY.into(),
            persona: PersonaId::new(),
            applicant_did: "did:webvh:example.com:alice".into(),
            asking: Some(asking.into()),
            asked_at: std::time::Instant::now(),
            session_id: None,
            expires_at: None,
        }
    }

    fn state_offering() -> State {
        let mut state = State::default();
        state.join.wallet = Some(WalletStep {
            community: "Example".into(),
            requirements_digest: "zDigest".into(),
            description: None,
            types: Vec::new(),
            phase: WalletPhase::Opening,
            parked: None,
        });
        state
    }

    fn started(query: &str) -> CommunityAnswer {
        CommunityAnswer::WalletSessionStarted {
            query: query.into(),
            community: COMMUNITY.into(),
            session: serde_json::from_value::<start::Response>(json!({
                "sessionId": SESSION,
                "walletUri": "swiyu-verify://?client_id=x&request_uri=y",
                "clientId": "decentralized_identifier:did:example:verifier",
                "dcqlQuery": { "credentials": [] },
                "expiresAt": "2030-01-01T00:00:00Z"
            }))
            .unwrap(),
        }
    }

    fn status(query: &str, state: &str, reason: Option<&str>) -> CommunityAnswer {
        let mut body = json!({
            "sessionId": SESSION,
            "state": state,
            "expiresAt": "2030-01-01T00:00:00Z"
        });
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        CommunityAnswer::WalletSessionStatus {
            query: query.into(),
            community: COMMUNITY.into(),
            status: serde_json::from_value::<status::Response>(body).unwrap(),
        }
    }

    /// The session opening puts its code on the page; the wallet fetching the
    /// request says so; presenting resumes the launch.
    #[test]
    fn a_wallet_session_runs_from_code_to_presented() {
        let mut state = state_offering();
        let mut waiting = awaiting("q-start");
        assert!(matches!(
            wallet_answer(&mut waiting, &started("q-start"), &mut state),
            Some(None)
        ));
        assert_eq!(waiting.session_id.as_deref(), Some(SESSION));
        assert!(waiting.asking.is_none());
        assert!(matches!(
            state.join.wallet.as_ref().unwrap().phase,
            WalletPhase::Scan {
                retrieved: false,
                ..
            }
        ));

        waiting.asking = Some("q-1".into());
        assert!(matches!(
            wallet_answer(
                &mut waiting,
                &status("q-1", "requestRetrieved", None),
                &mut state
            ),
            Some(None)
        ));
        assert!(matches!(
            state.join.wallet.as_ref().unwrap().phase,
            WalletPhase::Scan {
                retrieved: true,
                ..
            }
        ));

        waiting.asking = Some("q-2".into());
        assert!(matches!(
            wallet_answer(&mut waiting, &status("q-2", "presented", None), &mut state),
            Some(Some(JoinEntry::Wallet {
                end: WalletEnd::Presented
            }))
        ));
    }

    /// A refused or expired session ends the wait and says why; an answer to
    /// another question, or from another community, is not this session's.
    #[test]
    fn a_wallet_session_ends_with_why_and_ignores_other_answers() {
        let mut state = state_offering();
        let mut waiting = awaiting("q-1");
        let Some(Some(JoinEntry::Wallet {
            end: WalletEnd::Unfinished(why),
        })) = wallet_answer(
            &mut waiting,
            &status("q-1", "refused", Some("issuerNotTrusted")),
            &mut state,
        )
        else {
            panic!("a refusal ends the wait");
        };
        assert!(why.contains("issuer"), "{why}");

        let mut waiting = awaiting("q-1");
        assert!(matches!(
            wallet_answer(&mut waiting, &status("q-1", "expired", None), &mut state),
            Some(Some(JoinEntry::Wallet {
                end: WalletEnd::Unfinished(_)
            }))
        ));

        let mut waiting = awaiting("q-1");
        assert!(
            wallet_answer(
                &mut waiting,
                &status("q-other", "presented", None),
                &mut state
            )
            .is_none()
        );
        let elsewhere = CommunityAnswer::WalletSessionStatus {
            query: "q-1".into(),
            community: "did:webvh:example.com:other".into(),
            status: match status("q-1", "presented", None) {
                CommunityAnswer::WalletSessionStatus { status, .. } => status,
                _ => unreachable!(),
            },
        };
        assert!(wallet_answer(&mut waiting, &elsewhere, &mut state).is_none());
    }
}

/// The next presentation the identity-choice page offers for a new persona:
/// the account's preference (`None`), then did:webvh, then did:scid.
pub(crate) fn next_did_method(
    current: Option<vta_sdk::did_scid::DidMethod>,
) -> Option<vta_sdk::did_scid::DidMethod> {
    use vta_sdk::did_scid::DidMethod;
    match current {
        None => Some(DidMethod::Webvh),
        Some(DidMethod::Webvh) => Some(DidMethod::Scid),
        Some(_) => None,
    }
}

#[cfg(test)]
mod did_method_choice_tests {
    use super::next_did_method;
    use vta_sdk::did_scid::DidMethod;

    #[test]
    fn the_choice_cycles_through_the_account_default() {
        assert_eq!(next_did_method(None), Some(DidMethod::Webvh));
        assert_eq!(
            next_did_method(Some(DidMethod::Webvh)),
            Some(DidMethod::Scid)
        );
        assert_eq!(next_did_method(Some(DidMethod::Scid)), None);
    }
}
