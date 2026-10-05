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
    /// How long one tick of the drip lasts, as the community publishes it: an ISO 8601 duration
    /// of days and hours (`P3D`, `PT12H`, `P1DT6H`), at least an hour. Absent means three days.
    ///
    /// Kept as the text that arrived, and read through [`HiddenParams::tick_length`], so a
    /// malformed value costs this community its own rate rather than costing the client the
    /// whole criterion: a community whose tick length cannot be read is drawn from on the
    /// default, and the log says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_length: Option<String>,
}

impl HiddenParams {
    /// How long one tick of this community's drip lasts. [`DEFAULT_TICK_LENGTH`] when it
    /// publishes none, or one this build cannot read.
    #[must_use]
    pub fn tick_length(&self) -> chrono::Duration {
        match self.tick_length.as_deref() {
            None => DEFAULT_TICK_LENGTH,
            Some(text) => parse_tick_length(text).unwrap_or(DEFAULT_TICK_LENGTH),
        }
    }

    /// Whether `other` was published under the same keys as this. A community whose keys move
    /// has re-keyed: every credential and token held under the old ones is worthless there, and
    /// drawing on would only be refused.
    #[must_use]
    pub fn same_keys(&self, other: &HiddenParams) -> bool {
        self.suite == other.suite
            && self.helper_key == other.helper_key
            && self.token_key == other.token_key
    }
}

/// The tick length a community that publishes none is taken to mean.
pub const DEFAULT_TICK_LENGTH: chrono::Duration = chrono::Duration::days(3);

/// The shortest tick length a community may publish. Shorter is malformed.
pub const MIN_TICK_LENGTH: chrono::Duration = chrono::Duration::hours(1);

/// Read a published tick length: an ISO 8601 duration of days and hours, at least
/// [`MIN_TICK_LENGTH`]. `None` for anything else — weeks, months, minutes, fractions, an empty
/// duration — which the caller treats as the default.
#[must_use]
pub fn parse_tick_length(text: &str) -> Option<chrono::Duration> {
    let rest = text.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((date, time)) => {
            if time.is_empty() {
                return None;
            }
            (date, Some(time))
        }
        None => (rest, None),
    };
    // One `<digits><unit>` component, or nothing.
    fn component(part: &str, unit: char) -> Option<Option<i64>> {
        if part.is_empty() {
            return Some(None);
        }
        let digits = part.strip_suffix(unit)?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse::<i64>().ok().map(Some)
    }
    let days = component(date, 'D')?;
    let hours = match time {
        Some(time) => component(time, 'H')?,
        None => None,
    };
    if days.is_none() && hours.is_none() {
        return None;
    }
    let total = chrono::Duration::try_days(days.unwrap_or(0))?
        .checked_add(&chrono::Duration::try_hours(hours.unwrap_or(0))?)?;
    (total >= MIN_TICK_LENGTH).then_some(total)
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
    /// This vetter holds no class credential under a label the community still accepts: it has
    /// not been enrolled for this community's hidden vetting yet (or the answer was lost). Not a
    /// fault in what the community publishes — the parameters were read.
    #[error(
        "you are not enrolled for this community's PCS ZKP vetting yet, so there is no \
         credential to attest under"
    )]
    NotEnrolled,
    /// This vetter holds no attestation token. The community issues them on its schedule (the
    /// drip); attesting has to wait for the next one. Not a fault in what the community
    /// publishes — the parameters were read.
    #[error("you hold no vetting token for this community yet — it issues them on a schedule")]
    NoToken,
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
    if let Some(text) = params.tick_length.as_deref()
        && parse_tick_length(text).is_none()
    {
        tracing::warn!(
            tick_length = %text,
            default = "P3D",
            "a community publishes a hidden-vetting tick length this build cannot read; \
             drawing on the default"
        );
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
/// [`HiddenError::NotEnrolled`] if the vetter holds no credential under a live class label,
/// [`HiddenError::NoToken`] if it holds no free token, and [`HiddenError::Unreadable`] if the
/// published parameters, the stored engine or the applicant's identifier cannot be read.
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
    // Enrolment first: a vetter that holds no credential holds no token either, and "no token"
    // would send it to wait for a drip it cannot draw.
    let enrolled = params.vetter_labels.iter().any(|l| {
        state
            .credentials
            .contains_key(l.trim_start_matches("vetter/"))
    });
    if !enrolled {
        return Err(HiddenError::NotEnrolled);
    }
    // The tick the engine names in its refusal is not ours to give — the schedule knows when
    // the next drip is due, and the caller says so — so it is not read here.
    let reservation = engine.accept(None, 0).map_err(attest_refusal)?;
    let attestation = engine
        .attest(&community, &reservation, &id, meta, rng)
        .map_err(attest_refusal)?;
    *state = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    let held = openvtc_vetting_pcs::snapshot::HeldAttestation::of(&attestation)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    serde_json::to_value(&held).map_err(|e| HiddenError::Unreadable(e.to_string()))
}

/// What the engine's refusal to attest means for the vetter. Capacity and a missing credential
/// are states the vetter waits out, not unreadable parameters, and are said as such.
fn attest_refusal(e: openvtc_vetting_pcs::ProtoError) -> HiddenError {
    use openvtc_vetting_pcs::ProtoError;
    match e {
        ProtoError::AtCapacity { .. } => HiddenError::NoToken,
        ProtoError::NoLiveCredential => HiddenError::NotEnrolled,
        other => HiddenError::Unreadable(other.to_string()),
    }
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
/// Stored ([`blinding_text`]) before the request goes, in the protected config beside the
/// engine's `usk` and as secret: an answer that arrives after a restart must still open, because
/// asking again under the same label is refused (`alreadyEnrolled`) and the community keeps no
/// copy of its answer to send again.
pub type Blinding = openvtc_vetting_pcs::vetter::EnrolmentBlinding;

/// `blinding` in its storable form: base64url (no padding) over the scheme's own canonical
/// encoding.
///
/// # Errors
/// [`HiddenError::Unreadable`] if it cannot be encoded.
pub fn blinding_text(blinding: &Blinding) -> Result<String, HiddenError> {
    use base64::Engine;
    let bytes = blinding
        .to_bytes()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

/// The blinding [`blinding_text`] stored.
///
/// # Errors
/// [`HiddenError::Unreadable`] if `text` is not one.
pub fn blinding_from_text(text: &str) -> Result<Blinding, HiddenError> {
    use base64::Engine;
    let bytes = zeroize::Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|e| HiddenError::Unreadable(e.to_string()))?,
    );
    Blinding::from_bytes(&bytes).map_err(|e| HiddenError::Unreadable(e.to_string()))
}

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

/// Drop the serials of a draw the community refused, so they do not wait in the snapshot for an
/// answer that is never coming.
///
/// # Errors
///
/// [`HiddenError::Unreadable`] if the snapshot cannot be restored or stored again.
pub fn forget_draw(
    community_did: &str,
    snapshot: &mut VetterSnapshot,
    label: &str,
    tick: u32,
) -> Result<(), HiddenError> {
    let mut engine = VetterEngine::restore(snapshot, community_did)
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    engine.forget_draw(label, tick);
    *snapshot = engine
        .snapshot()
        .map_err(|e| HiddenError::Unreadable(e.to_string()))?;
    Ok(())
}

/// The `pcs-tokens` refusal that means "not yet": the tick asked for has not begun at the
/// community. Retryable, and not a failure — the client's clock ran ahead of the community's, or
/// a pass raced the window opening.
pub const TOKENS_TICK_NOT_YET: &str =
    trust_tasks_rs::specs::vtc::vetting::vetters::pcs_tokens::v0_1::error_codes::TICK_NOT_YET.code;

/// The `pcs-tokens` refusal that means "done": this tick was already served. An answer we lost,
/// or a second client of the same vetter that asked first.
pub const TOKENS_ALREADY_SERVED: &str =
    trust_tasks_rs::specs::vtc::vetting::vetters::pcs_tokens::v0_1::error_codes::ALREADY_SERVED
        .code;

/// A hidden-vetting refusal in words a vetter can act on.
///
/// Each declared code of `pcs-root`, `pcs-tokens`, `event-mode` and `pcs-challenge` gets its own
/// sentence, because each has a different answer — a grant to ask for, a client to update, a
/// community that has stopped. A code this build does not know is said plainly as one, with the
/// code, rather than guessed at (R6.4).
#[must_use]
pub fn refusal_words(code: &str) -> String {
    let local = code.rsplit_once(':').map_or(code, |(_, local)| local);
    let task = code
        .split_once(':')
        .map(|(task, _)| task.rsplit('/').next().unwrap_or(task))
        .unwrap_or("");
    let words = match (task, local) {
        (_, "notAVetter") => {
            "the community holds no live vetter grant for you. Ask its admins to name you a \
             vetter again, or for your vetter credential (g on the desk)."
        }
        ("pcs-root", "wrongLabel") => {
            "it is not enrolling under that month's label any more. The next pass enrols under \
             the current one."
        }
        ("pcs-root", "alreadyEnrolled") => {
            "it already enrolled you under its current label, but this client lost the answer \
             before it could be opened, and it issues one credential per label. You can attest \
             there again once it publishes a new label."
        }
        ("pcs-root", "identifierRebound") => {
            "it has you enrolled under a different hidden-vetting key. This install's key is not \
             the one the community knows — vet from the install that enrolled first."
        }
        ("pcs-root", "badRequest") | ("pcs-tokens", "badOpeningProof") => {
            "it could not verify the request this client built. Update OpenVTC; if that does \
             not help, the community and this client disagree about the scheme."
        }
        ("pcs-tokens", "labelNotLive") => {
            "it is not issuing tokens under that label any more. The next pass draws under the \
             label the community publishes now."
        }
        ("pcs-tokens", "alreadyServed") => "that tick was already served.",
        ("pcs-tokens", "tickNotYet") => {
            "that tick has not begun at the community yet. It is asked for again when its \
             window opens."
        }
        ("pcs-tokens", "overQuota") => {
            "the request asked for more tokens than its published rate. Nothing was signed; the \
             next pass asks for the published rate."
        }
        ("pcs-tokens", "eventRefused") => {
            "you are not in the approved group for that event, so it will not issue its tokens \
             to you. Your ordinary tokens are unaffected."
        }
        ("event-mode", "unknownEvent") => "it is not running that event.",
        ("event-mode", "unknownTier") => "it does not offer that rate for the event.",
        ("event-mode", "badWindow") => "the days asked for are not the event's own.",
        ("event-mode", "alreadyRequested") => {
            "you have already asked to vet at that event; its answer stands."
        }
        ("event-mode", "eventClosed") => "that event has closed.",
        ("pcs-challenge", "notHiddenVetting") => {
            "it no longer counts vetting from a zero-knowledge proof for this criterion."
        }
        _ => return format!("it refused, with a code this client does not know ({code})."),
    };
    words.to_string()
}

// ---------------------------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------------------------

/// The most draws one pass of the schedule sends to one community.
///
/// A vetter back after time away owes every tick of the current label it was not served, and
/// they are asked for oldest first. The bound only keeps one pass from becoming a flood; what is
/// left is asked for on the next pass, and the label itself bounds the whole — a month holds at
/// most a month of ticks.
pub const MAX_DRAWS_PER_PASS: usize = 16;

/// What a vetter's client should do for one community, now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Due {
    /// Nothing: enrolled for the current label, and every tick that has begun is served.
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
        /// The tick to ask for — one that has begun and has not been served.
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
    /// The event's first day. Its label's ticks are counted from midnight UTC on it.
    pub opens_on: chrono::NaiveDate,
    /// The last day this label is issued or accepted.
    pub closes_after: chrono::NaiveDate,
}

/// Midnight UTC on `day`.
fn midnight(day: chrono::NaiveDate) -> chrono::DateTime<chrono::Utc> {
    day.and_time(chrono::NaiveTime::MIN).and_utc()
}

/// The month a `token/YYYY-MM` label covers, as `[start, end)`: midnight UTC on its first day
/// to midnight UTC on the next month's. `None` for any other label.
#[must_use]
pub fn month_of_label(
    label: &str,
) -> Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> {
    let period = label.strip_prefix("token/")?;
    let (year, month) = period.split_once('-')?;
    if year.len() != 4 || month.len() != 2 {
        return None;
    }
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let first = chrono::NaiveDate::from_ymd_opt(year, month, 1)?;
    let next = first.checked_add_months(chrono::Months::new(1))?;
    Some((midnight(first), midnight(next)))
}

/// The tick of a label whose ticks start at `start`, at `now`: tick `t` is the window
/// `[start + t·length, start + (t+1)·length)`. `None` before the label has begun.
///
/// Derived from the clock and the label rather than counted locally, so two clients of the same
/// vetter — or one client that lost its state — agree about which tick they are in, and the
/// community can refuse a tick that has not begun (`tickNotYet`) as well as one it has served.
#[must_use]
pub fn tick_of(
    start: chrono::DateTime<chrono::Utc>,
    length: chrono::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<u32> {
    if now < start || length <= chrono::Duration::zero() {
        return None;
    }
    let elapsed = (now - start).num_seconds();
    u32::try_from(elapsed / length.num_seconds()).ok()
}

/// When tick `tick` of a label starting at `start` opens.
#[must_use]
pub fn tick_start(
    start: chrono::DateTime<chrono::Utc>,
    length: chrono::Duration,
    tick: u32,
) -> chrono::DateTime<chrono::Utc> {
    start + length * i32::try_from(tick).unwrap_or(i32::MAX)
}

/// The community's current monthly label: the published `token/YYYY-MM` label whose month
/// `now` falls in, with that month's bounds.
///
/// `None` when no published label covers `now` — the manifest we hold is from last month. That
/// is not a reason to draw under last month's label: the community stopped issuing under it when
/// its month ended, and a vetter asking anyway would only be refused. The schedule waits for the
/// manifest to catch up instead.
#[must_use]
pub fn current_month_label(
    params: &HiddenParams,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<(
    &str,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
)> {
    params.token_labels.iter().find_map(|label| {
        let (start, end) = month_of_label(label)?;
        (start <= now && now < end).then_some((label.as_str(), start, end))
    })
}

/// The next tick of a label to ask for: the one after the last served, or the first, if it has
/// begun.
///
/// A recorded tick later than the current one is not a tick of this label at all. Before ticks
/// were windows of time, a client counted days since 1970 (≈ 20 000), and a value like that
/// would otherwise stand in front of every real tick of the label for decades. It is read as
/// nothing served.
fn next_tick(
    start: chrono::DateTime<chrono::Utc>,
    length: chrono::Duration,
    last: Option<u32>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<u32> {
    let current = tick_of(start, length, now)?;
    let next = last
        .filter(|t| *t <= current)
        .map_or(0, |t| t.saturating_add(1));
    (next <= current).then_some(next)
}

/// Decide what a vetter's client owes this community now.
///
/// Three rules, and the second is the one that matters:
///
/// - Enrol when we hold no credential under the current class label. A rotation is an
///   enrolment, so this covers both the first time and every month after.
/// - **Draw on the schedule, not on demand.** Which ticks are owed is derived from the clock
///   and the label, never from how many tokens are left: a client that drew when it ran low
///   would turn its token balance into a public signal of how much vetting it had done, which
///   is the one thing this whole exchange exists to hide. A vetter with a full wallet still
///   asks.
/// - **Never ahead of the clock.** A tick is a window of time (`tickLength`, published by the
///   community), and one that has not begun is refused. A tick that has begun and was not served
///   — the client was off — is still owed, and is asked for oldest first. That says when the
///   vetter was offline, never when they vetted.
///
/// # One label at a time, and the event's is not the exception
///
/// A vetter in event mode owes this community draws under **two** labels: the event's, and the
/// ordinary monthly one. Skipping the monthly draw for the three days of a conference would say,
/// in the timing of the requests alone, that those three days were a conference — so the
/// ordinary label is drawn throughout, exactly as it would be in an ordinary week.
///
/// `last_ticks` is therefore per label, and this answers the first outstanding draw. A caller
/// with more than one owing calls again, recording each tick as it goes.
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
    let length = params.tick_length();
    let today = now.date_naive();

    // The ordinary label first: it is the one that must never be skipped.
    if let Some((label, start, _)) = current_month_label(params, now)
        && let Some(tick) = next_tick(start, length, last_ticks.get(label).copied(), now)
    {
        return Due::Draw {
            label: label.to_string(),
            tick,
            rate: params.drip_per_tick,
        };
    }
    // Then each event this vetter was approved for, while its label is still accepted.
    for event in events {
        if today > event.closes_after {
            continue;
        }
        if let Some(tick) = next_tick(
            midnight(event.opens_on),
            length,
            last_ticks.get(&event.label).copied(),
            now,
        ) {
            return Due::Draw {
                label: event.label.clone(),
                tick,
                rate: event.rate,
            };
        }
    }
    Due::Nothing
}

/// When the next tick window this vetter draws under opens, after `now`.
///
/// The earliest of: the ordinary label's next tick, the end of its month (when the next month's
/// label takes over), and each approved event's next tick — or its first, if it has not begun.
/// `None` when nothing is scheduled at all, such as a manifest from last month.
#[must_use]
pub fn next_window(
    params: &HiddenParams,
    events: &[EventDraw],
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let length = params.tick_length();
    let today = now.date_naive();
    let next_of = |start: chrono::DateTime<chrono::Utc>| match tick_of(start, length, now) {
        None => start,
        Some(t) => tick_start(start, length, t.saturating_add(1)),
    };
    let mut candidates = Vec::new();
    if let Some((_, start, end)) = current_month_label(params, now) {
        candidates.push(next_of(start).min(end));
    }
    for event in events.iter().filter(|e| today <= e.closes_after) {
        candidates.push(next_of(midnight(event.opens_on)));
    }
    candidates.into_iter().min()
}

/// The window the current tick of `label` covers, as `(tick, opened, closes)`, if it has begun.
#[must_use]
pub fn current_window(
    params: &HiddenParams,
    label: &str,
    events: &[EventDraw],
    now: chrono::DateTime<chrono::Utc>,
) -> Option<(
    u32,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
)> {
    let start = label_start(label, events)?;
    let length = params.tick_length();
    let tick = tick_of(start, length, now)?;
    Some((
        tick,
        tick_start(start, length, tick),
        tick_start(start, length, tick.saturating_add(1)),
    ))
}

/// Where `label`'s ticks are counted from: the first instant of its month, or of its event's
/// first day. `None` for a label that is neither, or an event we were not approved for.
#[must_use]
pub fn label_start(label: &str, events: &[EventDraw]) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Some((start, _)) = month_of_label(label) {
        return Some(start);
    }
    events
        .iter()
        .find(|e| e.label == label)
        .map(|e| midnight(e.opens_on))
}

/// Make `last_ticks` mean what [`due`] reads it as, and say whether anything changed.
///
/// Drops each entry for a label this vetter no longer draws under, and each one later than its
/// label's current tick — which, for a label that is drawn at all, is only ever a count of days
/// since 1970 left by a client from before ticks were windows of time. Kept, a value like that
/// would read as "served" for every real tick of the label.
pub fn settle_ticks(
    last_ticks: &mut std::collections::BTreeMap<String, u32>,
    params: &HiddenParams,
    events: &[EventDraw],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let length = params.tick_length();
    let before = last_ticks.len();
    last_ticks.retain(|label, tick| {
        let live = params.token_labels.iter().any(|l| l == label)
            || events.iter().any(|e| &e.label == label);
        live && label_start(label, events)
            .and_then(|start| tick_of(start, length, now))
            .is_some_and(|current| *tick <= current)
    });
    last_ticks.len() != before
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
                        "tickLength": "PT12H",
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
        assert_eq!(params.tick_length(), chrono::Duration::hours(12));
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

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
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
            tick_length: None,
        }
    }

    fn with_tick_length(text: &str) -> HiddenParams {
        HiddenParams {
            tick_length: Some(text.into()),
            ..params(3)
        }
    }

    /// Enrolled under 2026-09.
    fn enrolled() -> VetterSnapshot {
        let mut snapshot = VetterSnapshot::without_keys("member-1");
        snapshot
            .credentials
            .insert("2026-09".into(), "zCredential".into());
        snapshot
    }

    fn summit() -> EventDraw {
        EventDraw {
            label: "token/event/summit".into(),
            rate: 20,
            opens_on: NaiveDate::from_ymd_opt(2026, 9, 18).unwrap(),
            closes_after: NaiveDate::from_ymd_opt(2026, 10, 4).unwrap(),
        }
    }

    /// Every draw `due` owes now, recording each as served — what one pass of the schedule asks
    /// for, in order.
    fn plan(
        params: &HiddenParams,
        mut ticks: BTreeMap<String, u32>,
        events: &[EventDraw],
        now: chrono::DateTime<Utc>,
    ) -> Vec<(String, u32)> {
        let snapshot = enrolled();
        let mut out = Vec::new();
        for _ in 0..100 {
            match due(params, Some(&snapshot), &ticks, events, now) {
                Due::Draw { label, tick, .. } => {
                    ticks.insert(label.clone(), tick);
                    out.push((label, tick));
                }
                Due::Nothing => return out,
                Due::Enrol { .. } => panic!("enrolled"),
            }
        }
        panic!("the plan never settles: {out:?}")
    }

    #[test]
    fn tick_lengths_are_days_and_hours_and_at_least_an_hour() {
        assert_eq!(parse_tick_length("P3D"), Some(chrono::Duration::days(3)));
        assert_eq!(
            parse_tick_length("PT12H"),
            Some(chrono::Duration::hours(12))
        );
        assert_eq!(
            parse_tick_length("P1DT6H"),
            Some(chrono::Duration::hours(30))
        );
        assert_eq!(parse_tick_length("PT1H"), Some(chrono::Duration::hours(1)));
        for bad in [
            "", "P", "PT", "P3", "3D", "P1W", "P1M", "PT30M", "PT0H", "P0D", "P-1D", "P1.5D",
            "P1DT", "p3d",
        ] {
            assert_eq!(parse_tick_length(bad), None, "{bad:?} is malformed");
        }
    }

    /// Absent means three days; unreadable is treated the same way rather than refusing the
    /// community — the drip is not where a typo in a manifest should stop a vetter.
    #[test]
    fn a_missing_or_malformed_tick_length_is_three_days() {
        assert_eq!(params(3).tick_length(), chrono::Duration::days(3));
        assert_eq!(with_tick_length("PT30M").tick_length(), DEFAULT_TICK_LENGTH);
        assert_eq!(
            with_tick_length("weekly").tick_length(),
            DEFAULT_TICK_LENGTH
        );
        assert_eq!(
            with_tick_length("PT12H").tick_length(),
            chrono::Duration::hours(12)
        );
    }

    /// A malformed tick length is read, not refused: the criterion still parses, as hidden.
    #[test]
    fn a_malformed_tick_length_does_not_cost_the_criterion() {
        let raw = serde_json::json!({
            "id": "c",
            "vetting": {
                "ext": { HIDDEN_VETTING_NS: {
                    "suite": SUITE,
                    "helperKey": "zH",
                    "tokenKey": "zT",
                    "vetterLabels": ["vetter/2026-09"],
                    "tokenLabels": ["token/2026-09"],
                    "tickLength": "fortnightly"
                }},
                "extCritical": [HIDDEN_VETTING_NS]
            }
        });
        let Mode::Hidden(p) = read_mode(&raw).expect("readable") else {
            panic!("hidden");
        };
        assert_eq!(p.tick_length(), DEFAULT_TICK_LENGTH);
    }

    /// Tick `t` of a month label is the window `t` tick lengths after midnight UTC on the 1st.
    #[test]
    fn a_month_labels_ticks_are_windows_from_the_first_of_the_month() {
        let (start, end) = month_of_label("token/2026-09").unwrap();
        assert_eq!(start, at(2026, 9, 1, 0, 0, 0));
        assert_eq!(end, at(2026, 10, 1, 0, 0, 0));
        let len = chrono::Duration::days(3);
        assert_eq!(tick_of(start, len, at(2026, 8, 31, 23, 59, 59)), None);
        assert_eq!(tick_of(start, len, at(2026, 9, 1, 0, 0, 0)), Some(0));
        assert_eq!(tick_of(start, len, at(2026, 9, 3, 23, 59, 59)), Some(0));
        assert_eq!(tick_of(start, len, at(2026, 9, 4, 0, 0, 0)), Some(1));
        assert_eq!(tick_of(start, len, at(2026, 9, 20, 9, 0, 0)), Some(6));
        assert_eq!(tick_start(start, len, 6), at(2026, 9, 19, 0, 0, 0));

        // December rolls into the next year.
        let (_, end) = month_of_label("token/2026-12").unwrap();
        assert_eq!(end, at(2027, 1, 1, 0, 0, 0));
        // Not month labels.
        for label in [
            "token/event/summit",
            "token/2026-9",
            "token/2026-13",
            "vetter/2026-09",
        ] {
            assert_eq!(month_of_label(label), None, "{label}");
        }
    }

    /// An event label's ticks start at midnight UTC on the event's first day.
    #[test]
    fn an_event_labels_ticks_start_on_its_first_day() {
        let events = [summit()];
        let start = label_start("token/event/summit", &events).unwrap();
        assert_eq!(start, at(2026, 9, 18, 0, 0, 0));
        let p = params(3);
        assert_eq!(
            current_window(&p, "token/event/summit", &events, at(2026, 9, 21, 0, 0, 0)),
            Some((1, at(2026, 9, 21, 0, 0, 0), at(2026, 9, 24, 0, 0, 0)))
        );
        assert_eq!(
            current_window(&p, "token/event/summit", &events, at(2026, 9, 17, 23, 0, 0)),
            None,
            "not begun"
        );
        // An event we were not approved for has no start at all.
        assert_eq!(label_start("token/event/other", &events), None);
    }

    #[test]
    fn a_twelve_hour_tick_length_is_two_ticks_a_day() {
        let p = with_tick_length("PT12H");
        let (start, _) = month_of_label("token/2026-09").unwrap();
        assert_eq!(
            tick_of(start, p.tick_length(), at(2026, 9, 1, 11, 59, 59)),
            Some(0)
        );
        assert_eq!(
            tick_of(start, p.tick_length(), at(2026, 9, 1, 12, 0, 0)),
            Some(1)
        );
        assert_eq!(
            tick_of(start, p.tick_length(), at(2026, 9, 2, 0, 0, 0)),
            Some(2)
        );
        assert_eq!(
            plan(&p, drawn("token/2026-09", 0), &[], at(2026, 9, 2, 1, 0, 0)),
            [
                ("token/2026-09".to_string(), 1),
                ("token/2026-09".to_string(), 2)
            ]
        );
    }

    /// A vetter with no engine enrols; a vetter with no credential under the *current* label
    /// enrols again, which is what a rotation is.
    #[test]
    fn enrolment_is_owed_before_the_first_credential_and_after_every_rotation() {
        let now = at(2026, 9, 20, 9, 0, 0);
        assert_eq!(
            due(&params(3), None, &fresh(), &[], now),
            Due::Enrol {
                period: "2026-09".into()
            }
        );
    }

    /// The property the whole drip rests on: a vetter asks on the schedule whether or not it
    /// has anything to spend the tokens on. A client that drew when it ran low would turn its
    /// balance into a public account of how much vetting it had done.
    ///
    /// `due` is given no wallet at all, which is the proof: it cannot consult a balance it
    /// never sees.
    #[test]
    fn the_draw_is_owed_by_the_clock_and_not_by_the_balance() {
        let now = at(2026, 9, 20, 9, 0, 0); // tick 6 of September at three days
        let snapshot = enrolled();

        // Served this tick already: nothing owed, however empty the wallet is.
        assert_eq!(
            due(
                &params(3),
                Some(&snapshot),
                &drawn("token/2026-09", 6),
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
                &drawn("token/2026-09", 5),
                &[],
                now
            ),
            Due::Draw {
                label: "token/2026-09".into(),
                tick: 6,
                rate: 3,
            }
        );
    }

    /// A vetter that has been away is owed the ticks it missed, and asks for them oldest first
    /// — but never for one that has not begun. The community refuses a tick ahead of the clock,
    /// and asking for one would be the client deciding its own rate.
    #[test]
    fn a_vetter_who_was_offline_catches_up_oldest_first_and_never_ahead() {
        let now = at(2026, 9, 20, 9, 0, 0); // tick 6
        let owed = plan(&params(3), drawn("token/2026-09", 2), &[], now);
        assert_eq!(
            owed,
            (3..=6)
                .map(|t| ("token/2026-09".to_string(), t))
                .collect::<Vec<_>>()
        );

        // One second before tick 7 opens, tick 7 is still not owed.
        let edge = at(2026, 9, 21, 23, 59, 59);
        assert_eq!(plan(&params(3), drawn("token/2026-09", 6), &[], edge), []);
        // And at the second it opens, it is.
        assert_eq!(
            plan(
                &params(3),
                drawn("token/2026-09", 6),
                &[],
                at(2026, 9, 22, 0, 0, 0)
            ),
            [("token/2026-09".to_string(), 7)]
        );

        // The first of the month: tick 0, and only tick 0.
        assert_eq!(
            plan(&params(3), fresh(), &[], at(2026, 9, 1, 9, 0, 0)),
            [("token/2026-09".to_string(), 0)]
        );
    }

    /// Before ticks were windows of time, a client counted days since 1970 and stored that. Such
    /// a value is later than any real tick of the label, so it is read as nothing served — never
    /// as "served until the year 2081".
    #[test]
    fn an_old_epoch_day_tick_does_not_block_the_new_ones() {
        let now = at(2026, 9, 1, 9, 0, 0);
        let old = drawn("token/2026-09", 20_697);
        assert_eq!(
            due(&params(3), Some(&enrolled()), &old, &[], now),
            Due::Draw {
                label: "token/2026-09".into(),
                tick: 0,
                rate: 3,
            }
        );

        // And settling the stored ticks drops it, while keeping a real one.
        let mut stored = BTreeMap::from([
            ("token/2026-09".to_string(), 20_697),
            ("token/event/summit".to_string(), 20_697),
            ("token/2026-08".to_string(), 3),
        ]);
        assert!(settle_ticks(&mut stored, &params(3), &[summit()], now));
        assert!(stored.is_empty(), "{stored:?}");
        let mut real = drawn("token/2026-09", 0);
        assert!(!settle_ticks(&mut real, &params(3), &[], now));
        assert_eq!(real, drawn("token/2026-09", 0));
    }

    /// A vetter in event mode owes draws under two labels, and the **ordinary** one is not the
    /// one that gives. Skipping the monthly draw for the three days of a conference would say,
    /// in the timing of the requests alone, that those three days were a conference.
    #[test]
    fn an_event_draw_is_owed_beside_the_ordinary_one_and_never_instead_of_it() {
        let now = at(2026, 9, 20, 9, 0, 0); // September tick 6; summit tick 0 (opened the 18th)
        let summit = [summit()];

        // Both outstanding: the ordinary label is answered first.
        assert_eq!(
            due(
                &params(3),
                Some(&enrolled()),
                &drawn("token/2026-09", 5),
                &summit,
                now
            ),
            Due::Draw {
                label: "token/2026-09".into(),
                tick: 6,
                rate: 3,
            }
        );
        // Once it is recorded, the event's — at the tier's rate, not the community's — counted
        // from the event's own first day.
        assert_eq!(
            due(
                &params(3),
                Some(&enrolled()),
                &drawn("token/2026-09", 6),
                &summit,
                now
            ),
            Due::Draw {
                label: "token/event/summit".into(),
                tick: 0,
                rate: 20,
            }
        );
    }

    /// An event's label dies shortly after the event, and a client stops asking for it then —
    /// the tokens would be refused, and asking would announce that we tried.
    #[test]
    fn a_closed_event_is_no_longer_drawn_under() {
        let now = at(2026, 9, 25, 9, 0, 0);
        let p = HiddenParams {
            token_labels: vec!["token/2026-09".into()],
            ..params(3)
        };
        let closed = [EventDraw {
            closes_after: NaiveDate::from_ymd_opt(2026, 9, 24).unwrap(),
            ..summit()
        }];
        assert_eq!(plan(&p, drawn("token/2026-09", 8), &closed, now), []);
    }

    /// The rollover. The month's label is last month's once the month is over, and a vetter fed
    /// those labels draws nothing rather than asking under a label the community stopped
    /// issuing. Fed the labels the community publishes now, it enrols under the new class label
    /// and then draws under the new month's token label from tick 0.
    #[test]
    fn a_new_month_is_drawn_under_the_labels_published_now() {
        let october = at(2026, 10, 1, 8, 0, 0);
        let stale = params(3);
        assert_eq!(
            due(
                &stale,
                Some(&enrolled()),
                &drawn("token/2026-09", 9),
                &[],
                october
            ),
            Due::Nothing,
            "never last month's label"
        );
        assert_eq!(next_window(&stale, &[], october), None);

        let live = HiddenParams {
            vetter_labels: vec!["vetter/2026-10".into(), "vetter/2026-09".into()],
            token_labels: vec!["token/2026-10".into(), "token/2026-09".into()],
            ..params(3)
        };
        assert_eq!(
            due(
                &live,
                Some(&enrolled()),
                &drawn("token/2026-09", 9),
                &[],
                october
            ),
            Due::Enrol {
                period: "2026-10".into()
            }
        );
        let mut both = enrolled();
        both.credentials.insert("2026-10".into(), "zOctober".into());
        assert_eq!(
            due(&live, Some(&both), &drawn("token/2026-09", 9), &[], october),
            Due::Draw {
                label: "token/2026-10".into(),
                tick: 0,
                rate: 3,
            }
        );
    }

    /// The next pass is scheduled for the next window that opens: the next tick, or the end of
    /// the month when that comes first, or an approved event's first day.
    #[test]
    fn the_next_window_is_the_next_tick_or_the_months_end() {
        let p = params(3);
        assert_eq!(
            next_window(&p, &[], at(2026, 9, 20, 9, 0, 0)),
            Some(at(2026, 9, 22, 0, 0, 0))
        );
        // Tick 9 runs from the 28th; tick 10 would start on 1 October, which is the month's end.
        assert_eq!(
            next_window(&p, &[], at(2026, 9, 29, 12, 0, 0)),
            Some(at(2026, 10, 1, 0, 0, 0))
        );
        // An event that has not begun opens first.
        let soon = [EventDraw {
            opens_on: NaiveDate::from_ymd_opt(2026, 9, 21).unwrap(),
            ..summit()
        }];
        assert_eq!(
            next_window(&p, &soon, at(2026, 9, 20, 9, 0, 0)),
            Some(at(2026, 9, 21, 0, 0, 0))
        );
    }

    #[test]
    fn the_declared_refusals_are_said_in_words() {
        assert!(refusal_words(TOKENS_TICK_NOT_YET).contains("has not begun"));
        assert!(
            refusal_words("vtc/vetting/vetters/pcs-tokens:labelNotLive")
                .contains("not issuing tokens under that label")
        );
        assert!(refusal_words("vtc/vetting/vetters/pcs-root:notAVetter").contains("vetter grant"));
        assert!(refusal_words("vtc/vetting/vetters/event-mode:eventClosed").contains("has closed"));
        assert!(
            refusal_words("vtc/vetting/vetters/pcs-tokens:somethingNew")
                .contains("(vtc/vetting/vetters/pcs-tokens:somethingNew)")
        );
    }
}
