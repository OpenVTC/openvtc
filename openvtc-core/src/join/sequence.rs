//! The join sequence's protocol steps, shared by the TUI's join flow and the
//! headless `openvtc community join`.
//!
//! Each step here touches only [`Config`] and the network; what the person is
//! shown about it (the TUI's join page, the headless command's progress lines)
//! stays with the caller, which applies the step's result.
//!
//! Each network step comes in two halves where the TUI needs them apart
//! (#529): an owned I/O half that runs off the runtime loop
//! ([`fetch_over_http`], [`resolve_document`], [`submit_prepared`]) and an
//! apply half that takes `&mut Config` on the loop ([`learn_fetched`],
//! [`note_signing`], [`prepare_submit`]). The one-call forms
//! ([`learn_over_http`], [`learn_signing`], [`submit`]) are those halves in
//! sequence, for callers that own their `Config` outright (`community join`).

use std::time::Duration;

use affinidi_tdk::TDK;
use chrono::Utc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::{
    Config, PeerTransports,
    account::{CommunityRecord, PersonaId},
    community_context,
    context_path::build_sub_context_id,
};
use crate::didcomm::MessagingTransport;
use crate::errors::OpenVTCError;
use crate::health::ProbePolicy;
use crate::vetting::discover;

/// How long resolving a community's DID may take before its endpoint is given
/// up on. Bounded by rule R1.2, like every other outbound step here.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a community could not be asked what it requires.
///
/// The distinction is not cosmetic: it decides whether "join anyway" is an
/// offer at all. A community that resolves but will not answer is one you can
/// still send a request to, and its moderators will see it. A DID that does not
/// resolve names nothing — there is no document, no endpoint and no mediator
/// route, so a join request addressed to it goes nowhere and waits for an
/// answer nobody can send. Offering the same key for both told someone who had
/// mistyped a DID that joining was "the way forward here" (rule R6.4).
pub enum NotLearned {
    /// The identifier did not resolve to a DID document.
    Unresolvable(String),
    /// It resolved; the manifest could not be read from it.
    Unanswered(String),
}

impl NotLearned {
    /// The sentence the page shows.
    pub fn reason(&self) -> &str {
        match self {
            NotLearned::Unresolvable(why) | NotLearned::Unanswered(why) => why,
        }
    }

    /// Whether there is something at this DID to send a join request to.
    pub fn resolvable(&self) -> bool {
        matches!(self, NotLearned::Unanswered(_))
    }
}

/// Read `vtc_did`'s manifest from the REST endpoint it publishes, and learn it.
///
/// The question a community answers about what it requires is a public read
/// (`vetting-process.md` §6.1), and serving it over HTTPS is what makes it
/// answerable on a first join: no mediator socket, no persona to ask as, and no
/// loop that can hear a reply. `Err` is the sentence the page shows, already
/// distinguishing the ways it can fail — rule R6.4.
///
/// Mirrors the DIDComm handler
/// ([`crate::vetting::inbound`]): the book learns the manifest, and any
/// application to this community adopts it, so a change to the requirements
/// mid-application is detectable from either route rather than only from one.
pub async fn learn_over_http(
    config: &mut Config,
    tdk: &TDK,
    vtc_did: &str,
) -> Result<(), NotLearned> {
    let fetched = fetch_over_http(tdk.did_resolver(), vtc_did).await?;
    learn_fetched(config, vtc_did, fetched);
    Ok(())
}

/// A community's manifest, read from its REST endpoint, with the DID document
/// it was found through — what [`learn_fetched`] records.
pub struct OverHttp {
    fetched: discover::FetchedManifest,
    document: affinidi_tdk::did_common::Document,
}

/// The I/O half of [`learn_over_http`]: resolve `vtc_did` and read its
/// manifest. Needs no `Config`, so it can run off the runtime loop.
pub async fn fetch_over_http(
    resolver: &affinidi_tdk::did_resolver::DIDCacheClient,
    vtc_did: &str,
) -> Result<OverHttp, NotLearned> {
    let resolved = tokio::time::timeout(RESOLVE_TIMEOUT, resolver.resolve(vtc_did))
        .await
        .map_err(|_| {
            // A timeout is not "there is nothing there": the resolver may
            // simply be slow or the host briefly down, and the DID is still
            // worth sending to.
            NotLearned::Unanswered(format!(
                "it could not be resolved within {} seconds",
                RESOLVE_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| NotLearned::Unresolvable(format!("it could not be resolved ({e})")))?;
    let doc = serde_json::to_value(&resolved.doc)
        .map_err(|e| NotLearned::Unanswered(format!("its DID document could not be read ({e})")))?;
    let fetched = discover::fetch_manifest(&doc, vtc_did, resolver, ProbePolicy::PublicOnly)
        .await
        .map_err(|e| NotLearned::Unanswered(e.to_string()))?;
    Ok(OverHttp {
        fetched,
        document: resolved.doc,
    })
}

/// The apply half of [`learn_over_http`]: the book learns the manifest, and any
/// application to this community adopts it.
pub fn learn_fetched(config: &mut Config, vtc_did: &str, fetched: OverHttp) {
    let OverHttp {
        fetched:
            discover::FetchedManifest {
                manifest,
                raw,
                protocol,
                meta,
            },
        document,
    } = fetched;
    let now = Utc::now();
    let before = config.private.vetting.vetter_mode(vtc_did).mode();
    config
        .private
        .vetting
        .learn_manifest_in(vtc_did, &manifest, Some(protocol), &meta, now);
    // What its directory would show about the person joining, shown on the
    // review page before anything is sent (`manifest/0.4`).
    config.private.vetting.learn_directory(vtc_did, &raw);
    // Whether it vets by PCS ZKP now, read from the same answer — so the badges, the vetter
    // desk and this join agree on one reading, whichever route brought it.
    config
        .private
        .vetting
        .learn_mode(vtc_did, &raw, before, now);
    // The document is in hand already, so how the community signs is free to
    // learn — and before joining it is the only evidence there is.
    note_signing(config, vtc_did, &document);
    let book = &mut config.private.vetting;
    for application in book
        .applications
        .iter_mut()
        .filter(|a| a.community == vtc_did)
    {
        if let Err(e) = application.adopt_manifest(&manifest, &raw) {
            // Not debug-only: an application that cannot take up its criterion gathers
            // evidence for the wrong one. The vetting page re-reads it (m) and says why.
            warn!(community = %vtc_did, error = %e, "community manifest not adopted");
        }
    }
}

/// Record how `vtc_did` signs, from its resolved DID document: whether it lists
/// a post-quantum signing key. The book keeps it only for a community it
/// already knows, so this follows learning the manifest.
pub fn note_signing(config: &mut Config, vtc_did: &str, doc: &affinidi_tdk::did_common::Document) {
    config
        .private
        .vetting
        .note_post_quantum_key(vtc_did, crate::proof_check::publishes_post_quantum_key(doc));
}

/// Learn how `vtc_did` signs when the book does not know yet, by resolving its
/// DID document — bounded by [`RESOLVE_TIMEOUT`] (rule R1.2).
///
/// Reading the manifest over HTTP resolves the document anyway and records
/// this on the way; a manifest that arrived over DIDComm, or one already in the
/// book from an earlier visit, never did, so the vetting page said "Signing:
/// not checked" about a community whose document resolves perfectly well.
/// Best-effort: a resolve that fails or runs out of time leaves it unknown,
/// and the page says it could not be checked rather than guessing either way.
pub async fn learn_signing(config: &mut Config, tdk: &TDK, vtc_did: &str) {
    if config.private.vetting.post_quantum_key(vtc_did).is_some() {
        return;
    }
    if let Some(doc) = resolve_document(tdk.did_resolver(), vtc_did).await {
        note_signing(config, vtc_did, &doc);
    }
}

/// The I/O half of [`learn_signing`]: resolve `vtc_did`'s DID document,
/// bounded by [`RESOLVE_TIMEOUT`]. `None` when it did not resolve in time.
pub async fn resolve_document(
    resolver: &affinidi_tdk::did_resolver::DIDCacheClient,
    vtc_did: &str,
) -> Option<affinidi_tdk::did_common::Document> {
    match tokio::time::timeout(RESOLVE_TIMEOUT, resolver.resolve(vtc_did)).await {
        Ok(Ok(resolved)) => Some(resolved.doc),
        Ok(Err(e)) => {
            debug!(community = %vtc_did, error = %e, "community DID not resolved; signing not checked");
            None
        }
        Err(_) => {
            debug!(
                community = %vtc_did,
                timeout_secs = RESOLVE_TIMEOUT.as_secs(),
                "community DID resolve timed out; signing not checked"
            );
            None
        }
    }
}

/// Whether `context_id` is already claimed: by a membership, a persona's keys,
/// or a vetting application's face.
pub fn context_taken(config: &Config, context_id: &str) -> bool {
    community_context::context_claimed(
        &config.account,
        &config.private.vetting.applications,
        context_id,
    )
}

/// The new sub-context to suggest for `vtc_did`: named after the community,
/// and not yet claimed.
pub fn suggested_context(config: &Config, vtc_did: &str) -> String {
    let top = &config.account.top_context_id;
    let taken = |id: &str| context_taken(config, id);
    build_sub_context_id(top, config.agent_name_for(vtc_did), vtc_did, taken)
        .or_else(|_| build_sub_context_id(top, Some("community"), vtc_did, taken))
        .unwrap_or_else(|_| top.clone())
}

/// Build the `Pending` [`CommunityRecord`] recorded on a successful submit.
///
/// Pure decision peeled out of the join sequence's submit step; delegates to
/// [`CommunityRecord::new_pending`] so the record shape stays defined in core.
pub fn pending_record(
    vtc_did: String,
    display_name: Option<String>,
    sub_context_id: String,
    persona_id: PersonaId,
    request_id: uuid::Uuid,
    now: chrono::DateTime<Utc>,
    submit_transport: crate::didcomm::MessagingTransport,
) -> CommunityRecord {
    let mut record = CommunityRecord::new_pending(
        vtc_did,
        display_name,
        sub_context_id,
        persona_id,
        request_id,
        now,
    );
    // Which transport carried the submit, so an unacknowledged join can name it
    // rather than leaving every cause looking alike.
    record.submit_transport = Some(submit_transport);
    record
}

/// Remove a persona minted for a join that then failed, from the config only
/// (the caller saves). Shared by the TUI's join and `community join`.
pub fn forget_minted_persona(
    config: &mut Config,
    persona_id: PersonaId,
    keys: Option<&crate::config::PersonaDIDKeys>,
    prior_friendly_name: &str,
) {
    config.account.personas.remove(&persona_id);
    config.identities.remove(&persona_id);
    if let Some(keys) = keys {
        config.key_info.remove(&keys.signing.secret.id);
        config.key_info.remove(&keys.authentication.secret.id);
        config.key_info.remove(&keys.decryption.secret.id);
    }
    // `mint_persona_into` set `public.friendly_name` to the attempted community's
    // persona name; restore the pre-mint value so a failed/cancelled join doesn't
    // leave the self-display name pointing at a community we never joined.
    config.public.friendly_name = prior_friendly_name.to_string();
}

/// Something about the chosen transport the person should be told: the
/// submit is not going the way the community prefers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportNote {
    /// The community prefers TSP, our mediator does not carry it, and the
    /// community also offers DIDComm: the submit goes over DIDComm.
    DidcommFallback,
    /// The community offers TSP only and our mediator does not advertise it:
    /// the submit is attempted over TSP anyway.
    TspAttempted,
}

impl TransportNote {
    /// The sentence the join page shows.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            TransportNote::DidcommFallback => {
                "Your mediator does not carry TSP — submitting over DIDComm instead."
            }
            TransportNote::TspAttempted => {
                "This community offers TSP only, and your mediator does not \
                 advertise it — attempting the submit over TSP anyway."
            }
        }
    }
}

/// How a join request goes out: over TSP (sealed to the community's TSP
/// mediator) or over DIDComm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitRoute {
    /// The community's TSP mediator when the submit goes over TSP.
    pub tsp_mediator: Option<String>,
    /// What to tell the person about the choice, if anything.
    pub note: Option<TransportNote>,
}

impl SubmitRoute {
    /// The transport the submit uses.
    #[must_use]
    pub fn transport(&self) -> MessagingTransport {
        if self.tsp_mediator.is_some() {
            MessagingTransport::Tsp
        } else {
            MessagingTransport::DidComm
        }
    }
}

/// Settle the wire for a submit to `vtc_did` from a persona whose mediator is
/// `our_mediator`.
///
/// TSP needs **both** legs: the protocol is the highest-preference one present
/// in *both* parties' documents. A TSP send posts the raw CESR frame to *our*
/// mediator's `/inbound`; the community's advertised mediator is only the hop
/// the routing layer is sealed to. A mediator without its `tsp` feature rejects
/// the frame as an unparseable DIDComm envelope while the error names the
/// *other* mediator, so the question is answered up front.
///
/// `None` at either end sends over DIDComm, so a community that has not been
/// flipped is unaffected. Where our mediator does not carry TSP (or cannot be
/// asked), DIDComm is preferred when the community offers it; with TSP the
/// community's only transport the submit goes over TSP and the mediator
/// answers — refusing here would only replace one failure with another.
pub async fn choose_submit_route(
    vtc_did: &str,
    our_mediator: &str,
    transports: &PeerTransports,
) -> SubmitRoute {
    let didcomm_offered = transports.didcomm_mediator.is_some();
    let Some(peer_mediator) = crate::config::peer_tsp_mediator(vtc_did).await else {
        return SubmitRoute {
            tsp_mediator: None,
            note: None,
        };
    };
    let (tsp_mediator, note) = match crate::config::our_mediator_carries_tsp(our_mediator).await {
        Some(true) => (Some(peer_mediator), None),
        Some(false) if didcomm_offered => (None, Some(TransportNote::DidcommFallback)),
        Some(false) => (Some(peer_mediator), Some(TransportNote::TspAttempted)),
        // Could not ask. Unknown is not "no": take the community's preference
        // where it has an alternative, since DIDComm is the transport that
        // worked before TSP existed.
        None if didcomm_offered => (None, None),
        None => (Some(peer_mediator), None),
    };
    SubmitRoute { tsp_mediator, note }
}

/// Why a join request could not be sent. Each caller words these for its own
/// surface, and they differ in what is undone: nothing was sent in any of them.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// No messaging (ATM) runtime.
    #[error("messaging (ATM) is unavailable")]
    NoMessaging,
    /// The persona has no runtime messaging identity.
    #[error("the persona has no messaging identity")]
    NoIdentity,
    /// The persona's authentication key, which signs the request, could not be
    /// read.
    #[error("couldn't read the persona's signing key: {0}")]
    Signer(#[source] OpenVTCError),
    /// The request was built but the send failed.
    #[error("{0}")]
    Send(#[source] OpenVTCError),
}

/// Sign and send the join request for `persona_id` to `vtc_did` along
/// `route`. Returns the request id the pending membership is keyed on.
///
/// The submit is signed: `join-requests/submit` declares `proof` REQUIRED, and
/// a persona whose key cannot be read cannot apply — better said here than as
/// a refusal from the community. `Ok` means our mediator accepted the frame,
/// not that the community received it (R1.1).
pub async fn submit(
    config: &Config,
    tdk: &TDK,
    persona_id: PersonaId,
    vtc_did: &str,
    route: &SubmitRoute,
    presentation: crate::join::JoinPresentation,
) -> Result<Uuid, SubmitError> {
    let prepared = prepare_submit(config, tdk, persona_id).await?;
    submit_prepared(&prepared, vtc_did, route, presentation).await
}

/// What sending a join request needs from the config, read out of it so the
/// send can run without it: the messaging runtime, the persona's messaging
/// identity, and the key that signs the request.
pub struct PreparedSubmit {
    atm: affinidi_tdk::messaging::ATM,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    persona_did: String,
    mediator: String,
    signer: affinidi_tdk::secrets_resolver::secrets::Secret,
}

/// The config half of [`submit`]: no network (the key is read from the local
/// secrets the persona was loaded with).
pub async fn prepare_submit(
    config: &Config,
    tdk: &TDK,
    persona_id: PersonaId,
) -> Result<PreparedSubmit, SubmitError> {
    let atm = tdk.atm.clone().ok_or(SubmitError::NoMessaging)?;
    let identity = config
        .identities
        .get(&persona_id)
        .ok_or(SubmitError::NoIdentity)?;
    let persona_did = identity.persona_did().to_string();
    let profile = identity.profile().clone();
    let mediator = identity.mediator_did.clone().unwrap_or_default();
    let signer = config
        .get_persona_keys_for(persona_id, tdk)
        .await
        .map_err(SubmitError::Signer)?
        .authentication
        .secret
        .clone();
    Ok(PreparedSubmit {
        atm,
        profile,
        persona_did,
        mediator,
        signer,
    })
}

/// The send half of [`submit`]: sign and send the request along `route`.
pub async fn submit_prepared(
    prepared: &PreparedSubmit,
    vtc_did: &str,
    route: &SubmitRoute,
    presentation: crate::join::JoinPresentation,
) -> Result<Uuid, SubmitError> {
    let applicant = crate::join::Applicant {
        atm: &prepared.atm,
        profile: &prepared.profile,
        persona_did: &prepared.persona_did,
        signer: &prepared.signer,
        vtc_did,
        mediator_did: &prepared.mediator,
        tsp_mediator_did: route.tsp_mediator.as_deref(),
    };
    crate::join::submit_join_request(&applicant, presentation)
        .await
        .map_err(SubmitError::Send)
}
