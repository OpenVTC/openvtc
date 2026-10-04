//! Hidden-vetter admission: reading what a community publishes, and refusing what this build
//! cannot honour.
//!
//! A community that counts vetting statements from a zero-knowledge proof publishes the
//! parameters an applicant proves against under `vetting.ext`, in a namespace it controls, and
//! marks that namespace in `vetting.extCritical` (Trust Tasks SPEC §4.5.1, manifest 0.2).
//!
//! Criticality is why this module exists at all. Without it, a client that does not implement
//! the namespace ignores it — per the framework's default rule — gathers ordinary named
//! statements and presents them to a criterion whose whole purpose is that it never receives
//! them. The community sees a named submission, the applicant sees a rejection, and neither
//! learns that a downgrade happened. Marked critical, this client stops instead.
//!
//! **Read from the raw criterion, not the parsed one.** `VettingRequirements` is a generated
//! type: it carries the members its schema declares and drops the rest. `ext` is a declared
//! member as of manifest 0.2 + framework 0.4 (`dtgwg-trust-tasks-tf#600`), so it survives the
//! parse once this workspace takes a `trust-tasks-rs` release carrying it — until then the raw
//! criterion is the only place it can be read from, and reading it there works either way.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The namespace this build implements.
pub const HIDDEN_VETTING_NS: &str = "org.openvtc.hidden-vetting";

/// The suite this build implements: Σ-PS with Tag_DDH over BLS12-381.
pub const SUITE: &str = "ps-ddh-bls12381";

/// What a community publishes so an applicant can build a proof, and a vetter can attest.
///
/// Public values only — verification keys and which labels are live. The secrets stay with the
/// community.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenParams {
    /// The proof suite. This build implements [`SUITE`] and refuses the rest.
    pub suite: String,
    /// The community's helper verification key, multibase.
    pub helper_key: String,
    /// The attestation-token verification key, multibase. Never the same key as `helperKey`.
    pub token_key: String,
    /// Live vetter class labels, current first (`["vetter/2026-10", "vetter/2026-09"]`).
    pub vetter_labels: Vec<String>,
    /// Live token labels (`["token/2026-10", "token/event/summit"]`).
    pub token_labels: Vec<String>,
    /// How many attestation tokens a vetter may draw per tick. Published so a vetter knows
    /// what to ask for on its schedule; the community enforces it either way.
    #[serde(default = "default_drip_per_tick")]
    pub drip_per_tick: usize,
    /// Events this community is running, if any (§5.1). The menu a vetter picks from: a vetter
    /// names a tier rather than a number, so that a requested rate is not itself a
    /// distinguishing detail.
    ///
    /// What is published is the offer. Whether *we* are in an event's group is the community's
    /// answer to [`crate::vetting::wire::pcs::EventModeRequest`], never this list.
    #[serde(default)]
    pub events: Vec<HiddenEventOffer>,
}

/// One event a community is running, as it publishes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenEventOffer {
    /// The community's name for the gathering.
    pub event_id: String,
    /// First day, inclusive.
    pub start_date: chrono::NaiveDate,
    /// Last day, inclusive.
    pub end_date: chrono::NaiveDate,
    /// How many vetters the community needs before it will open the event's label at all. Shown
    /// because it is the price of the higher rate: a spend under an event label came from
    /// someone in that group, and the floor is what keeps the group from being a name.
    #[serde(default)]
    pub group_floor: usize,
    /// The rates on offer.
    #[serde(default)]
    pub tiers: Vec<HiddenEventTier>,
}

/// One rate on an event's menu.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenEventTier {
    /// How the menu names it.
    pub name: String,
    /// How many tokens a tick under it yields.
    pub drip_per_tick: usize,
}

/// What a community that publishes no rate is taken to mean — the same default the VTC's own
/// minting half carries.
fn default_drip_per_tick() -> usize {
    openvtc_vetting_pcs::vtc::DEFAULT_DRIP_PER_TICK
}

/// Why a criterion could not be adopted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HiddenError {
    /// The criterion marks a namespace critical that this build does not implement. The
    /// framework's `unsupportedExtension`: the client understood the task and refused over one
    /// namespace, rather than applying in a way the community did not ask for.
    #[error(
        "this community requires `{0}`, which this version of OpenVTC does not implement — \
         applying without it would send the community something it does not accept"
    )]
    UnsupportedExtension(String),
    /// Our own namespace is marked critical but is unreadable, which is the same refusal: we
    /// cannot honour what we cannot parse.
    #[error("this community's `{HIDDEN_VETTING_NS}` parameters could not be read: {0}")]
    Unreadable(String),
    /// A suite this build does not implement, in our own namespace.
    #[error("this community uses the `{0}` proof suite, which this version does not implement")]
    UnsupportedSuite(String),
}

/// What a criterion asks of this client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Statements name their vetters, as they always have.
    Named,
    /// Statements are counted from a proof, under these parameters.
    Hidden(Box<HiddenParams>),
}

/// Read the mode from a criterion **as received**.
///
/// `raw` is the criterion object from the manifest payload, not a re-serialised parse of it.
///
/// Returns [`Mode::Named`] when the criterion publishes no hidden-vetting namespace, which is
/// every criterion today. Returns an error only where the criterion marks something critical
/// that this build cannot honour — the one case where falling back would be worse than failing.
pub fn read_mode(raw: &Value) -> Result<Mode, HiddenError> {
    let vetting = raw.get("vetting");
    let critical: Vec<&str> = vetting
        .and_then(|v| v.get("extCritical"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    // Every critical namespace this build does not implement is a refusal, ours or not.
    if let Some(unknown) = critical.iter().find(|ns| **ns != HIDDEN_VETTING_NS) {
        return Err(HiddenError::UnsupportedExtension((*unknown).to_string()));
    }

    let ours = vetting
        .and_then(|v| v.get("ext"))
        .and_then(|e| e.get(HIDDEN_VETTING_NS));
    let Some(ours) = ours else {
        // Marked critical but absent is the community contradicting itself; refuse rather than
        // guess which half it meant.
        if critical.contains(&HIDDEN_VETTING_NS) {
            return Err(HiddenError::Unreadable(
                "named in extCritical but absent from ext".into(),
            ));
        }
        return Ok(Mode::Named);
    };

    let params: HiddenParams = match serde_json::from_value(ours.clone()) {
        Ok(p) => p,
        Err(e) => {
            // Unreadable parameters are only fatal where the community said they were
            // load-bearing. Unmarked, they are advisory and this client carries on named.
            return if critical.contains(&HIDDEN_VETTING_NS) {
                Err(HiddenError::Unreadable(e.to_string()))
            } else {
                Ok(Mode::Named)
            };
        }
    };
    if params.suite != SUITE {
        return if critical.contains(&HIDDEN_VETTING_NS) {
            Err(HiddenError::UnsupportedSuite(params.suite))
        } else {
            Ok(Mode::Named)
        };
    }
    Ok(Mode::Hidden(Box::new(params)))
}

// ---------------------------------------------------------------------------------------------
// Driving the flow
// ---------------------------------------------------------------------------------------------

pub use openvtc_vetting_pcs::wire::EXTENSIONS_MEMBER;
use openvtc_vetting_pcs::{
    applicant::ApplicantEngine,
    community::CommunityParams,
    meta::StatementMeta,
    snapshot::{ApplicantSnapshot, VetterSnapshot},
    vetter::{HiddenAttestation, VetterEngine},
    wire::SubmissionWire,
};

/// The community's published parameters, in the form the engines take.
///
/// # Errors
/// [`HiddenError::Unreadable`] if a published key or label cannot be decoded.
pub fn community(
    community_did: &str,
    params: &HiddenParams,
) -> Result<CommunityParams, HiddenError> {
    CommunityParams::published(
        community_did,
        &params.helper_key,
        &params.token_key,
        params.vetter_labels.clone(),
        params.token_labels.clone(),
        params.drip_per_tick,
    )
    .map_err(|e| HiddenError::Unreadable(e.to_string()))
}

/// Mint this vetter's key pair for a community, and return the engine to store.
///
/// The counterpart of [`start`] on the other side of the desk, and the step that was missing
/// for the whole of this branch's life: everything after it — enrolment, the drip, attesting —
/// operates on a [`VetterSnapshot`], and nothing created the first one outside a test.
///
/// **`member_did` is load-bearing and is not a label.** It is bound into every opening proof the
/// token drip sends, and the community checks the binding against the DID that signed the
/// request. A snapshot built under any other name draws tokens the community refuses, and the
/// refusal says nothing about why.
///
/// One key pair per (vetter, community), minted once and kept: every tag this vetter ever
/// produces for this community derives from it, so a second one would make the same person count
/// twice in one proof (§13 C2).
///
/// # Errors
///
/// [`HiddenError::Unreadable`] if the community's published parameters cannot be read.
pub fn vetter_start<R: rand::RngCore + rand::CryptoRng>(
    community_did: &str,
    params: &HiddenParams,
    member_did: &str,
    rng: &mut R,
) -> Result<VetterSnapshot, HiddenError> {
    let community = community(community_did, params)?;
    VetterEngine::enrol_new(member_did, &community, rng)
        .and_then(|engine| engine.snapshot())
        .map_err(|e| HiddenError::Unreadable(e.to_string()))
}

/// Start an application under a hidden-vetting criterion: a fresh key, used for this
/// application and no other.
///
/// # Errors
/// [`HiddenError::Unreadable`] if the community's parameters cannot be read.
pub fn start<R: rand::RngCore + rand::CryptoRng>(
    community_did: &str,
    params: &HiddenParams,
    join_did: &str,
    rng: &mut R,
) -> Result<ApplicantSnapshot, HiddenError> {
    let community = community(community_did, params)?;
    let engine = ApplicantEngine::new(&community, join_did, rng)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))
}

/// Take an attestation a vetter sent, after checking it here rather than at submit: an
/// attestation that does not verify, or whose token does not, is refused at the session while
/// the vetter is still there to ask.
///
/// # Errors
/// [`HiddenError::Unreadable`] if the attestation does not verify under the community's
/// published parameters.
pub fn receive(
    community_did: &str,
    params: &HiddenParams,
    state: &mut ApplicantSnapshot,
    attestation: &Value,
) -> Result<(), HiddenError> {
    let community = community(community_did, params)?;
    // The wire form of an attestation is its storable form: same members, same encoding.
    let held: openvtc_vetting_pcs::snapshot::HeldAttestation =
        serde_json::from_value(attestation.clone())
            .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let att: HiddenAttestation = held
        .restore()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let mut engine =
        ApplicantEngine::restore(state).map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    engine
        .receive(&community, att)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    *state = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok(())
}

/// Prove, for `challenge`, that `k` distinct vetters vetted this applicant. The result goes
/// into the submission's `extensions` under [`EXTENSIONS_MEMBER`].
///
/// # Errors
/// [`HiddenError::Unreadable`] if no attestation is usable, or the proof cannot be built.
pub fn prove<R: rand::RngCore + rand::CryptoRng>(
    community_did: &str,
    params: &HiddenParams,
    requirements_digest: &str,
    state: &ApplicantSnapshot,
    challenge: &str,
    rng: &mut R,
) -> Result<Value, HiddenError> {
    let community = community(community_did, params)?;
    let engine =
        ApplicantEngine::restore(state).map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let submission = engine
        .submit(&community, requirements_digest, challenge, rng)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let wire = SubmissionWire::from_submission(&submission)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    serde_json::to_value(&wire).map_err(|e| HiddenError::Unreadable(e.to_string()))
}

/// The vetter's half: attest for `applicant_id` after the human check, spending one token.
///
/// # Errors
/// [`HiddenError::Unreadable`] if the vetter holds no live credential or no free token.
pub fn attest<R: rand::RngCore + rand::CryptoRng>(
    community_did: &str,
    params: &HiddenParams,
    state: &mut VetterSnapshot,
    applicant_id: &str,
    meta: StatementMeta,
    rng: &mut R,
) -> Result<Value, HiddenError> {
    let community = community(community_did, params)?;
    let mut engine = VetterEngine::restore(state, community_did)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let id = openvtc_vetting_pcs::scheme::point_from_text(applicant_id)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let reservation = engine
        .accept(None, 0)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let attestation = engine
        .attest(&community, &reservation, &id, meta, rng)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    *state = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let held = openvtc_vetting_pcs::snapshot::HeldAttestation::of(&attestation)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    serde_json::to_value(&held).map_err(|e| HiddenError::Unreadable(e.to_string()))
}

// ---------------------------------------------------------------------------------------------
// The vetter's half
// ---------------------------------------------------------------------------------------------

/// The member of a `vetting/request` payload's `ext` that carries the applicant's PCS identifier.
///
/// A vetter cannot attest to somebody it cannot name in the scheme's own terms, and the join DID
/// is not that name. The identifier travels in the request's framework extension point rather
/// than in a new member of the payload, because `ext` is what the framework put there for
/// exactly this (SPEC §4.5.1) — and because a community that does not run hidden vetting sees a
/// request it already understands.
pub const REQUEST_EXT_MEMBER: &str = HIDDEN_VETTING_NS;

/// What an applicant puts in its request's `ext` so a vetter can attest to it.
#[must_use]
pub fn request_ext(suite: &str, applicant_id: &str) -> serde_json::Value {
    serde_json::json!({ REQUEST_EXT_MEMBER: { "suite": suite, "id": applicant_id } })
}

/// The applicant's PCS identifier from a request's `ext`, if it carried one.
///
/// Returns `None` for every request from an applicant that is not applying under a hidden
/// criterion — which is most of them, and is not an error.
///
/// # Errors
///
/// [`HiddenError::UnsupportedSuite`] if the applicant names a suite this build does not
/// implement: it is applying under rules we cannot honour, and attesting anyway would hand it
/// something the community refuses.
pub fn read_request_ext(ext: Option<&serde_json::Value>) -> Result<Option<String>, HiddenError> {
    let Some(ours) = ext.and_then(|e| e.get(REQUEST_EXT_MEMBER)) else {
        return Ok(None);
    };
    let suite = ours
        .get("suite")
        .and_then(|s| s.as_str())
        .unwrap_or_default();
    if suite != SUITE {
        return Err(HiddenError::UnsupportedSuite(suite.to_string()));
    }
    match ours.get("id").and_then(|s| s.as_str()) {
        Some(id) if !id.is_empty() => Ok(Some(id.to_string())),
        _ => Err(HiddenError::Unreadable(
            "the request names this namespace but carries no identifier".into(),
        )),
    }
}

/// The statement metadata an attestation binds, from the draft the named path would have signed.
///
/// One function, so the two paths cannot drift about what a statement says. Dates, never
/// timestamps: an exact time would let a community line an attestation up with a vetter's
/// activity, which undoes the proof without touching it (design §6).
///
/// `None` when the draft carries none of the vetter-only members: only a vetter attests on
/// the hidden path, and a vetter's statement always carries all three.
#[must_use]
pub fn statement_meta(
    draft: &vta_sdk::vetting::statement::StatementDraft,
    community: &str,
    requirements_digest: &str,
) -> Option<StatementMeta> {
    let e = &draft.value;
    let members = e.vetter_members()?;
    Some(StatementMeta {
        community: community.to_string(),
        requirements_digest: requirements_digest.to_string(),
        method: e.method,
        claims_verified: e
            .claims_verified
            .iter()
            .map(|c| c.as_str().to_string())
            .collect(),
        liveness_confirmed: e.liveness_confirmed,
        declared_relationship: members.declared_relationship,
        identity_commitment: members.identity_commitment.to_string(),
        card_digest_multibase: members.card_digest_multibase.to_string(),
        valid_from: draft.valid_from.date_naive(),
        valid_until: draft.valid_until.date_naive(),
        token_label: String::new(),
        token_serial: String::new(),
    })
}

// ---------------------------------------------------------------------------------------------
// Enrolment and the drip, from the vetter's side
// ---------------------------------------------------------------------------------------------

/// Build the enrolment request for `period`, and the blinding state that unblinds the answer.
///
/// The state is **not** persisted: it is useless without the answer and dangerous to keep past
/// it, so a client holds it for the round trip and drops it. An enrolment whose answer never
/// arrives is re-asked from scratch, which costs nothing — the community refuses a second
/// credential under the same label, and a request that was never answered issued none.
///
/// # Errors
///
/// [`HiddenError::Unreadable`] if the community's parameters cannot be read, or the request
/// cannot be built.
pub fn enrolment_request<R: rand::RngCore + rand::CryptoRng>(
    community_did: &str,
    params: &HiddenParams,
    snapshot: &VetterSnapshot,
    period: &str,
    rng: &mut R,
) -> Result<(crate::vetting::wire::pcs::RootRequest, Blinding), HiddenError> {
    let params = community(community_did, params)?;
    let engine = VetterEngine::restore(snapshot, community_did)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let (wire, state) = engine
        .enrolment_request(&params, period, rng)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok((
        crate::vetting::wire::pcs::RootRequest {
            label: wire.label,
            id: wire.id,
            request: wire.request,
        },
        state,
    ))
}

/// The blinding state of an enrolment in flight, as this module hands it back.
///
/// Deliberately not serialisable: it belongs to one round trip, and an answer that arrives after
/// a restart is re-asked rather than kept.
pub type Blinding = openvtc_vetting_pcs::vetter::EnrolmentBlinding;

/// Take the community's answer into the engine.
///
/// # Errors
///
/// [`HiddenError::Unreadable`] if the answer cannot be decoded, or does not unblind under the
/// published key — which is what a wrong or swapped answer looks like from here.
pub fn accept_enrolment(
    community_did: &str,
    params: &HiddenParams,
    snapshot: &mut VetterSnapshot,
    answer: &crate::vetting::wire::pcs::RootResponse,
    blinding: &Blinding,
) -> Result<(), HiddenError> {
    let params = community(community_did, params)?;
    let mut engine = VetterEngine::restore(snapshot, community_did)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    engine
        .accept_enrolment(
            &params,
            &openvtc_vetting_pcs::issuer::RootCredentialWire {
                label: answer.label.clone(),
                pre_credential: answer.pre_credential.clone(),
            },
            blinding,
        )
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    *snapshot = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok(())
}

/// Build one tick of the drip: `rate` blinded serials under `label`.
///
/// The wallet's pending state lives in the snapshot, so a client that asks and then restarts can
/// still take the answer.
///
/// # Errors
///
/// [`HiddenError::Unreadable`] if the requests cannot be built.
pub fn drip_request<R: rand::RngCore + rand::CryptoRng>(
    community_did: &str,
    params: &HiddenParams,
    snapshot: &mut VetterSnapshot,
    tick: u32,
    label: &str,
    rate: usize,
    rng: &mut R,
) -> Result<crate::vetting::wire::pcs::TokensRequest, HiddenError> {
    let params_built = community(community_did, params)?;
    let mut engine = VetterEngine::restore(snapshot, community_did)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let batch = engine
        .drip_request(&params_built, tick, label, rate, rng)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    *snapshot = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok(crate::vetting::wire::pcs::TokensRequest {
        label: batch.label,
        tick: batch.tick,
        requests: batch
            .requests
            .into_iter()
            .map(|r| crate::vetting::wire::pcs::TokenRequest {
                commitment: r.commitment,
                opening_proof: r.opening_proof,
            })
            .collect(),
    })
}

/// Take a served batch into the wallet. Returns how many tokens it added.
///
/// # Errors
///
/// [`HiddenError::Unreadable`] if a token cannot be decoded or does not verify under the
/// published token key.
pub fn accept_drip(
    community_did: &str,
    params: &HiddenParams,
    snapshot: &mut VetterSnapshot,
    served: &crate::vetting::wire::pcs::TokensResponse,
) -> Result<usize, HiddenError> {
    let params_built = community(community_did, params)?;
    let mut engine = VetterEngine::restore(snapshot, community_did)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let taken = engine
        .accept_drip(
            &params_built,
            &openvtc_vetting_pcs::issuer::TokenBatchWire {
                label: served.label.clone(),
                tick: served.tick,
                pre_credentials: served.pre_credentials.clone(),
            },
        )
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    *snapshot = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok(taken)
}

// ---------------------------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------------------------

/// How long a drip tick lasts. A day: long enough that a client which is off for an evening
/// loses nothing, short enough that a vetter who runs out is not stuck for a week.
pub const TICK: chrono::Duration = chrono::Duration::days(1);

/// What a vetter's client should do for one community, now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Due {
    /// Nothing: enrolled for the current label and already served this tick.
    Nothing,
    /// Ask to enrol under this class label.
    Enrol {
        /// `vetter/<period>`.
        period: String,
    },
    /// Draw this tick of the drip under this label.
    Draw {
        /// The token label to draw under.
        label: String,
        /// The tick to ask for.
        tick: u32,
        /// How many to ask for — the community's published rate.
        rate: usize,
    },
}

/// An event label this vetter has been approved to draw under, and what it yields.
///
/// It is separate from [`HiddenParams`] because the community publishes the label to everyone
/// and the approval only to the group: a label appearing in `token_labels` says an event exists,
/// never that this vetter is in it. Drawing under a label we were not approved for would be
/// refused, and would announce that we tried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDraw {
    /// `token/event/<eventId>`.
    pub label: String,
    /// The rate of the tier this vetter asked for — not the community's ordinary drip.
    pub rate: usize,
    /// The last day this label is issued or accepted.
    pub closes_after: chrono::NaiveDate,
}

/// Decide what a vetter's client owes this community now.
///
/// Two rules, and the second is the one that matters:
///
/// - Enrol when we hold no credential under the current class label. A rotation is an
///   enrolment, so this covers both the first time and every month after.
/// - **Draw on the schedule, not on demand.** The tick is derived from the clock, never from
///   how many tokens are left: a client that drew when it ran low would turn its token balance
///   into a public signal of how much vetting it had done, which is the one thing this whole
///   exchange exists to hide. A vetter with a full wallet still asks.
///
/// A client that has been offline does **not** get to claim the ticks it missed: `tick` is the
/// current one, and the community serves each at most once. The tokens for a week away are
/// simply not minted — which is the same answer a vetter who was present but idle gets, and
/// that symmetry is the point.
///
/// # One label at a time, and the event's is not the exception
///
/// A vetter in event mode owes this community **two** draws a tick: the event's, and the
/// ordinary monthly one. Skipping the monthly draw for the three days of a conference would say,
/// in the timing of the requests alone, that those three days were a conference — so the
/// ordinary label is drawn throughout, exactly as it would be in an ordinary week.
///
/// `last_ticks` is therefore per label, and this answers the first outstanding one. A caller
/// with more than one owing calls again, recording each label as it goes.
#[must_use]
pub fn due(
    params: &HiddenParams,
    snapshot: Option<&VetterSnapshot>,
    last_ticks: &std::collections::BTreeMap<String, u32>,
    events: &[EventDraw],
    now: chrono::DateTime<chrono::Utc>,
) -> Due {
    let Some(period) = params
        .vetter_labels
        .first()
        .map(|l| l.trim_start_matches("vetter/").to_string())
    else {
        return Due::Nothing;
    };
    let Some(snapshot) = snapshot else {
        return Due::Enrol { period };
    };
    if !snapshot.credentials.contains_key(&period) {
        return Due::Enrol { period };
    }
    let tick = tick_of(now);
    let today = now.date_naive();
    let outstanding = |label: &str| last_ticks.get(label).is_none_or(|&t| tick > t);

    // The ordinary label first: it is the one that must never be skipped.
    if let Some(label) = params.token_labels.first()
        && outstanding(label)
    {
        return Due::Draw {
            label: label.clone(),
            tick,
            rate: params.drip_per_tick,
        };
    }
    // Then each event this vetter was approved for, while its label is still accepted.
    for event in events {
        if today <= event.closes_after && outstanding(&event.label) {
            return Due::Draw {
                label: event.label.clone(),
                tick,
                rate: event.rate,
            };
        }
    }
    Due::Nothing
}

/// The tick `now` falls in: whole days since the epoch.
///
/// Derived from the clock rather than counted locally, so two clients of the same vetter — or
/// one client that lost its state — agree about which tick they are in, and the community's
/// once-per-tick rule stays enforceable rather than becoming a race.
#[must_use]
pub fn tick_of(now: chrono::DateTime<chrono::Utc>) -> u32 {
    u32::try_from(now.timestamp().max(0) / TICK.num_seconds()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use serde_json::json;

    fn params() -> Value {
        json!({
            "suite": SUITE,
            "helperKey": "zHelperKey",
            "tokenKey": "zTokenKey",
            "vetterLabels": ["vetter/2026-10", "vetter/2026-09"],
            "tokenLabels": ["token/2026-10"]
        })
    }

    /// A criterion exactly as `vtc-service` serves one, copied from what
    /// `HiddenVettingConfig::published()` emits.
    ///
    /// The two halves of this feature live in different repositories and neither can compile the
    /// other, so what stands in for an integration test is this: the community's emitted shape,
    /// pinned here, read by the code that will read it live. It has already caught the thing it
    /// exists for — the service stores `hvk`/`tvk`/`livePeriods` and a client reads
    /// `helperKey`/`tokenKey`/`vetterLabels`, so a straight `to_value` of the stored
    /// configuration parses as nothing at all and `read_mode` answers `Named` for a community
    /// that hides every one of its vetters.
    fn as_the_service_serves_it() -> Value {
        // Real keys, from a seeded community, because the shape is only half the contract: the
        // other half is that what a community publishes decodes into the group elements the
        // engines take. Placeholder multibase parses as JSON and fails there.
        let mut rng = rand::rngs::StdRng::from_seed([9u8; 32]);
        let vtc = openvtc_vetting_pcs::vtc::Vtc::new(
            "did:example:kernel-vtc",
            "2026-09",
            json!({
                "version": "0.1",
                "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
                "minStatements": 3,
                "acceptedMethods": ["inPerson", "video"],
                "eligibleVetters": { "role": "vetter" }
            }),
            &mut rng,
        )
        .expect("a community");
        let hvk = openvtc_vetting_pcs::scheme::key_text(vtc.hvk()).expect("hvk");
        let tvk = openvtc_vetting_pcs::scheme::key_text(vtc.tvk()).expect("tvk");
        json!({
            "id": "kernel-developer",
            "vetting": {
                "version": "0.1",
                "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
                "minStatements": 3,
                "acceptedMethods": ["inPerson", "video"],
                "eligibleVetters": { "role": "vetter" },
                "ext": {
                    HIDDEN_VETTING_NS: {
                        "suite": SUITE,
                        "helperKey": hvk,
                        "tokenKey": tvk,
                        "vetterLabels": ["vetter/2026-09"],
                        "tokenLabels": ["token/2026-09", "token/event/kernel-summit-2026"],
                        "dripPerTick": 3,
                        "events": [{
                            "eventId": "kernel-summit-2026",
                            "startDate": "2026-10-12",
                            "endDate": "2026-10-14",
                            "groupFloor": 3,
                            "tiers": [{ "name": "desk", "dripPerTick": 20 }]
                        }]
                    }
                }
            },
            "requirementsDigest": "zQmDigest"
        })
    }

    /// The badge reads the stored criterion the same way the join adopts it:
    /// published parameters are hidden, a plain criterion is named.
    #[test]
    fn a_stored_criterion_knows_whether_its_vetters_are_hidden() {
        let known = |raw: &Value| crate::vetting::book::KnownCriterion {
            community: "did:web:vtc".into(),
            criterion_id: "c".into(),
            requirements_digest: None,
            requirements: serde_json::from_value(raw["vetting"].clone()).expect("requirements"),
            fetched_at: chrono::Utc::now(),
        };
        assert!(known(&as_the_service_serves_it()).hidden_vetting());

        let mut named = as_the_service_serves_it();
        named["vetting"].as_object_mut().unwrap().remove("ext");
        named["vetting"]
            .as_object_mut()
            .unwrap()
            .remove("extCritical");
        assert!(!known(&named).hidden_vetting());
    }

    #[test]
    fn the_shape_the_service_serves_is_the_shape_this_client_reads() {
        let params = match read_mode(&as_the_service_serves_it()).expect("readable") {
            Mode::Hidden(p) => *p,
            Mode::Named => panic!("the criterion publishes parameters; this read them as named"),
        };
        assert_eq!(params.suite, SUITE);
        assert_eq!(params.vetter_labels, ["vetter/2026-09"]);
        assert_eq!(params.drip_per_tick, 3);
        assert_eq!(params.token_labels.len(), 2);

        // The menu a vetter picks an event tier from.
        let event = params.events.first().expect("the event menu is published");
        assert_eq!(event.event_id, "kernel-summit-2026");
        assert_eq!(event.group_floor, 3);
        assert_eq!(event.tiers[0].drip_per_tick, 20);

        // And the keys decode, which is the part a wrong multibase alphabet would fail.
        community("did:example:kernel-vtc", &params)
            .expect("the published keys decode into engine parameters");
    }

    /// The service stores one shape and publishes another, and this is why: the stored one does
    /// not parse. If a future change makes `to_value(config)` the published form, this starts
    /// passing and the assertion below should be read as the warning it is.
    #[test]
    fn the_stored_shape_is_not_the_published_one() {
        let stored = json!({
            "suite": SUITE,
            "hvk": "zHelperKey",
            "tvk": "zTokenKey",
            "livePeriods": ["2026-09"],
            "liveTokenLabels": ["token/2026-09"],
            "dripPerTick": 3,
            "events": []
        });
        assert_eq!(
            read_mode(&criterion(json!({ HIDDEN_VETTING_NS: stored }), None)).unwrap(),
            Mode::Named,
            "the stored configuration must not be mistaken for the published parameters"
        );
    }

    fn criterion(ext: Value, critical: Option<Value>) -> Value {
        let mut vetting = json!({ "version": "0.1", "minStatements": 2, "ext": ext });
        if let Some(c) = critical {
            vetting["extCritical"] = c;
        }
        json!({ "id": "kernel-developer", "vetting": vetting })
    }

    #[test]
    fn a_criterion_without_the_namespace_is_the_named_path() {
        assert_eq!(read_mode(&json!({ "id": "plain" })).unwrap(), Mode::Named);
        assert_eq!(
            read_mode(&json!({ "id": "plain", "vetting": { "minStatements": 2 } })).unwrap(),
            Mode::Named
        );
    }

    #[test]
    fn our_namespace_is_read_whether_or_not_it_is_marked() {
        let ext = json!({ HIDDEN_VETTING_NS: params() });
        for critical in [None, Some(json!([HIDDEN_VETTING_NS]))] {
            match read_mode(&criterion(ext.clone(), critical)).unwrap() {
                Mode::Hidden(p) => {
                    assert_eq!(p.helper_key, "zHelperKey");
                    assert_eq!(p.vetter_labels.len(), 2);
                }
                Mode::Named => panic!("the namespace is present and readable"),
            }
        }
    }

    #[test]
    fn a_critical_namespace_we_do_not_implement_is_refused() {
        // This is the whole point of criticality: no silent fallback to the named path.
        let raw = criterion(
            json!({ "com.example.some-scheme": { "a": 1 } }),
            Some(json!(["com.example.some-scheme"])),
        );
        assert_eq!(
            read_mode(&raw),
            Err(HiddenError::UnsupportedExtension(
                "com.example.some-scheme".into()
            ))
        );
    }

    #[test]
    fn an_unmarked_namespace_we_do_not_implement_is_ignored() {
        // The framework's default rule, and why marking has to be deliberate.
        let raw = criterion(json!({ "com.example.hint": { "a": 1 } }), None);
        assert_eq!(read_mode(&raw).unwrap(), Mode::Named);
    }

    #[test]
    fn marked_but_broken_parameters_refuse_and_unmarked_ones_do_not() {
        let broken = json!({ HIDDEN_VETTING_NS: { "suite": SUITE } }); // no keys, no labels
        assert!(matches!(
            read_mode(&criterion(broken.clone(), Some(json!([HIDDEN_VETTING_NS])))),
            Err(HiddenError::Unreadable(_))
        ));
        assert_eq!(read_mode(&criterion(broken, None)).unwrap(), Mode::Named);

        let mut other_suite = params();
        other_suite["suite"] = json!("bbs-ddh-bls12381");
        let ext = json!({ HIDDEN_VETTING_NS: other_suite });
        assert_eq!(
            read_mode(&criterion(ext.clone(), Some(json!([HIDDEN_VETTING_NS])))),
            Err(HiddenError::UnsupportedSuite("bbs-ddh-bls12381".into()))
        );
        assert_eq!(read_mode(&criterion(ext, None)).unwrap(), Mode::Named);
    }

    #[test]
    fn marked_but_absent_is_a_contradiction_and_refused() {
        let raw = criterion(
            json!({ "com.example.hint": {} }),
            Some(json!([HIDDEN_VETTING_NS])),
        );
        assert!(matches!(read_mode(&raw), Err(HiddenError::Unreadable(_))));
    }
}

#[cfg(test)]
mod schedule_tests {
    use super::*;
    use chrono::{NaiveDate, TimeZone, Utc};
    use std::collections::BTreeMap;

    /// Nothing drawn yet, for any label.
    fn fresh() -> BTreeMap<String, u32> {
        BTreeMap::new()
    }

    /// `label` last drawn at `tick`.
    fn drawn(label: &str, tick: u32) -> BTreeMap<String, u32> {
        BTreeMap::from([(label.to_string(), tick)])
    }

    fn params(drip: usize) -> HiddenParams {
        HiddenParams {
            suite: SUITE.into(),
            helper_key: "zHelper".into(),
            token_key: "zToken".into(),
            vetter_labels: vec!["vetter/2026-09".into()],
            token_labels: vec!["token/2026-09".into()],
            drip_per_tick: drip,
            events: Vec::new(),
        }
    }

    /// A vetter with no engine enrols; a vetter with no credential under the *current* label
    /// enrols again, which is what a rotation is.
    #[test]
    fn enrolment_is_owed_before_the_first_credential_and_after_every_rotation() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 9, 0, 0).unwrap();
        assert_eq!(
            due(&params(3), None, &fresh(), &[], now),
            Due::Enrol {
                period: "2026-09".into()
            }
        );
    }

    /// The tick comes from the clock, not from a local counter: two clients of one vetter, or
    /// one client that lost its state, agree about which tick they are in — so the community's
    /// once-per-tick rule stays a rule rather than a race.
    #[test]
    fn the_tick_is_derived_from_the_clock() {
        let a = Utc.with_ymd_and_hms(2026, 9, 20, 0, 0, 1).unwrap();
        let b = Utc.with_ymd_and_hms(2026, 9, 20, 23, 59, 59).unwrap();
        let c = Utc.with_ymd_and_hms(2026, 9, 21, 0, 0, 1).unwrap();
        assert_eq!(tick_of(a), tick_of(b), "one day is one tick");
        assert_eq!(tick_of(c), tick_of(a) + 1, "the next day is the next tick");
    }

    /// The property the whole drip rests on: a vetter asks on the schedule whether or not it
    /// has anything to spend the tokens on. A client that drew when it ran low would turn its
    /// balance into a public account of how much vetting it had done.
    ///
    /// `due` is given no wallet at all, which is the proof: it cannot consult a balance it
    /// never sees.
    #[test]
    fn the_draw_is_owed_by_the_clock_and_not_by_the_balance() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 9, 0, 0).unwrap();
        let tick = tick_of(now);
        let mut snapshot = VetterSnapshot::without_keys("member-1");
        snapshot
            .credentials
            .insert("2026-09".into(), "zCredential".into());

        // Served this tick already: nothing owed, however empty the wallet is.
        assert_eq!(
            due(
                &params(3),
                Some(&snapshot),
                &drawn("token/2026-09", tick),
                &[],
                now
            ),
            Due::Nothing
        );

        // A new tick: owed, however full it is.
        assert_eq!(
            due(
                &params(3),
                Some(&snapshot),
                &drawn("token/2026-09", tick - 1),
                &[],
                now
            ),
            Due::Draw {
                label: "token/2026-09".into(),
                tick,
                rate: 3,
            }
        );
    }

    /// A vetter that has been away does not get to claim the ticks it missed — it asks for the
    /// current one. The tokens for a week away are simply not minted, which is the same answer
    /// a vetter who was present and idle gets.
    #[test]
    fn a_vetter_who_was_offline_asks_for_this_tick_not_the_missed_ones() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 9, 0, 0).unwrap();
        let mut snapshot = VetterSnapshot::without_keys("member-1");
        snapshot
            .credentials
            .insert("2026-09".into(), "zCredential".into());
        let Due::Draw { tick, .. } = due(
            &params(3),
            Some(&snapshot),
            &drawn("token/2026-09", tick_of(now) - 7),
            &[],
            now,
        ) else {
            panic!("a draw is owed");
        };
        assert_eq!(tick, tick_of(now), "this tick, not the seven behind it");
    }

    /// A vetter in event mode owes two draws a tick, and the **ordinary** one is not the one
    /// that gives. Skipping the monthly draw for the three days of a conference would say, in
    /// the timing of the requests alone, that those three days were a conference.
    #[test]
    fn an_event_draw_is_owed_beside_the_ordinary_one_and_never_instead_of_it() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 9, 0, 0).unwrap();
        let tick = tick_of(now);
        let mut snapshot = VetterSnapshot::without_keys("member-1");
        snapshot
            .credentials
            .insert("2026-09".into(), "zCredential".into());
        let summit = [EventDraw {
            label: "token/event/summit".into(),
            rate: 20,
            closes_after: NaiveDate::from_ymd_opt(2026, 10, 4).unwrap(),
        }];

        // Both outstanding: the ordinary label is answered first.
        assert_eq!(
            due(&params(3), Some(&snapshot), &fresh(), &summit, now),
            Due::Draw {
                label: "token/2026-09".into(),
                tick,
                rate: 3,
            }
        );
        // Once it is recorded, the event's — at the tier's rate, not the community's.
        assert_eq!(
            due(
                &params(3),
                Some(&snapshot),
                &drawn("token/2026-09", tick),
                &summit,
                now
            ),
            Due::Draw {
                label: "token/event/summit".into(),
                tick,
                rate: 20,
            }
        );
    }

    /// An event's label dies shortly after the event, and a client stops asking for it then —
    /// the tokens would be refused, and asking would announce that we tried.
    #[test]
    fn a_closed_event_is_no_longer_drawn_under() {
        let now = Utc.with_ymd_and_hms(2026, 10, 5, 9, 0, 0).unwrap();
        let tick = tick_of(now);
        let mut snapshot = VetterSnapshot::without_keys("member-1");
        snapshot
            .credentials
            .insert("2026-09".into(), "zCredential".into());
        let closed = [EventDraw {
            label: "token/event/summit".into(),
            rate: 20,
            closes_after: NaiveDate::from_ymd_opt(2026, 10, 4).unwrap(),
        }];
        assert_eq!(
            due(
                &params(3),
                Some(&snapshot),
                &drawn("token/2026-09", tick),
                &closed,
                now
            ),
            Due::Nothing
        );
    }
}
