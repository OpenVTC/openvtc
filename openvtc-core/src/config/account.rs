/*!
 * Multi-community account model (config v2).
 *
 * Replaces the single-persona / single-VTA singleton with an `Account` that
 * owns a collection of [`PersonaRecord`]s and a collection of
 * [`CommunityRecord`]s. See `docs/design/multi-community-support.md` and
 * `docs/design/t1-active-identity-api.md`.
 *
 * Scope note: this module defines the **persisted metadata** model, stored
 * encrypted in the `ProtectedConfig` tier and treated by `Config::load_step2`
 * as the source of truth for the active persona. The account admin credential
 * (a secret) stays in `SecuredConfig`/keyring; persona key material is
 * VTA-managed (`key_refs` are non-secret ids, D12). Runtime resolution lives in
 * [`crate::identity`] (`IdentityContext` / `IdentityRegistry`).
 */

use crate::CredentialKind;
use crate::config::KeyTypes;
use crate::errors::OpenVTCError;
use crate::relationships::Relationships;
use crate::tasks::Tasks;
use crate::vrc::Vrcs;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// A VTC community is keyed by its DID (`did:webvh:...`).
pub type VtcDid = String;

/// Stable, rotation-safe identifier for a persona.
///
/// Decoupled from the persona's `did:webvh` (which can rotate) so that a
/// community's `persona_ref` survives DID rotation (fork resolution: stable
/// UUID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PersonaId(pub Uuid);

impl PersonaId {
    /// Mint a fresh persona id.
    pub fn new() -> Self {
        PersonaId(Uuid::new_v4())
    }
}

impl Default for PersonaId {
    fn default() -> Self {
        PersonaId::new()
    }
}

impl std::fmt::Display for PersonaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A non-secret reference to a VTA-managed key (D12).
///
/// Key material lives at the VTA and is fetched at runtime; only the opaque
/// `key_id`, its purpose, and creation time are persisted locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRef {
    /// Opaque VTA key identifier.
    pub key_id: String,
    /// What the key is used for.
    pub purpose: KeyTypes,
    /// When the key was created.
    pub created_at: DateTime<Utc>,
}

/// An account-level persona — a self-contained `did:webvh` identity that one or
/// more communities may present (D6: context-independent; D1: reusable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonaRecord {
    /// Stable identifier (rotation-safe).
    pub persona_id: PersonaId,
    /// The persona's `did:webvh`.
    pub did: String,
    /// Cached resolved DID document (PERF #3: startup uses this instead of a
    /// fresh network resolve when present — did:webvh documents change rarely
    /// between launches, so a cached doc only goes stale if the persona rotated
    /// keys out-of-band). Persisted with the record; populated at mint/setup and
    /// whenever the persona is resolved. `None` for records minted before this
    /// field existed, in which case load falls back to a network resolve.
    #[serde(default)]
    pub did_document: Option<affinidi_tdk::did_common::Document>,
    /// Non-secret references to this persona's VTA-managed keys.
    pub key_refs: Vec<KeyRef>,
    /// Mediator DID; defaults to the VTA mediator, optional override at mint (D7).
    pub mediator_did: Option<String>,
    /// The VTA context the persona's keys and DID were minted in. A persona can
    /// only be presented from here, so joining a community with it shares this
    /// context ([`crate::config::community_context`]). Empty for a persona
    /// minted before per-community contexts, whose keys are in the account's
    /// top context.
    pub origin_context_id: String,
    /// When the persona was created.
    pub created_at: DateTime<Utc>,
    /// Optional human-friendly label.
    pub label: Option<String>,

    /// Fields written by a build newer than this one, preserved verbatim.
    ///
    /// **D19.** Without this, serde silently drops what it does not know, and a
    /// round trip through an older build is data loss: read a record, discard
    /// the new fields, write it back without them. Harmless while a single
    /// writer owns the config — and exactly why it has never bitten — but the
    /// moment this record is shared with another instance (E2), an older build
    /// would quietly strip a newer one's work.
    ///
    /// Carried, never interpreted. `skip_serializing_if` keeps it off the wire
    /// when empty so existing configs are byte-identical.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Lifecycle state of a community membership (D8). Only [`Active`] is live; all
/// other states are read-only (D14).
///
/// [`Active`]: CommunityStatus::Active
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CommunityStatus {
    /// Join request submitted, awaiting the VTC's decision.
    Pending {
        /// The join request id from the submit receipt.
        request_id: Uuid,
    },
    /// Member in good standing (the only live state).
    Active,
    /// Member voluntarily left (`MEMBER_SELF_REMOVE`).
    Left,
    /// Applicant cancelled a `Pending` join before the VTC decided — the
    /// request is withdrawn. A voluntary, user-chosen outcome (like `Left`), so
    /// it never raises the actions-required badge. The protocol's status
    /// vocabulary calls this `withdrawn`.
    Withdrawn,
    /// Join request denied by the VTC.
    Rejected,
    /// Member removed by the VTC (involuntary).
    Removed,
    /// Pending join unanswered past the 7-day client timeout (D16).
    Expired,
}

impl CommunityStatus {
    /// True only for [`Active`](CommunityStatus::Active) — the single live state.
    pub fn is_active(&self) -> bool {
        matches!(self, CommunityStatus::Active)
    }

    /// True for every non-[`Active`](CommunityStatus::Active) state (read-only, D14).
    pub fn is_read_only(&self) -> bool {
        !self.is_active()
    }

    /// True for terminal/inactive states eligible for archive or delete (R-C-8):
    /// `Left`, `Withdrawn`, `Rejected`, `Removed`, `Expired`. (`Pending` is not —
    /// it is still in flight; cancelling it transitions to `Withdrawn` first.)
    pub fn is_inactive(&self) -> bool {
        matches!(
            self,
            CommunityStatus::Left
                | CommunityStatus::Withdrawn
                | CommunityStatus::Rejected
                | CommunityStatus::Removed
                | CommunityStatus::Expired
        )
    }

    /// The set of *statuses* that can raise the actions-required indicator
    /// (R-C-3 / R-S-2): `Pending` and the terminal `Rejected` / `Removed` /
    /// `Expired`. This is status-only; the acknowledgement-aware,
    /// per-membership predicate is [`CommunityRecord::needs_attention`], which
    /// layers the `acknowledged` flag on top.
    pub fn needs_attention(&self) -> bool {
        matches!(
            self,
            CommunityStatus::Pending { .. }
                | CommunityStatus::Rejected
                | CommunityStatus::Removed
                | CommunityStatus::Expired
        )
    }

    /// True when the membership needs a live DIDComm session: `Active` (to
    /// operate) and `Pending` (so the VTC's join reply is receivable, D16).
    pub fn requires_live_session(&self) -> bool {
        matches!(
            self,
            CommunityStatus::Active | CommunityStatus::Pending { .. }
        )
    }
}

/// A community membership — one per State-B join, referencing an account persona.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "CommunityRecordShadow")]
pub struct CommunityRecord {
    /// The community's VTC DID.
    pub vtc_did: VtcDid,
    /// Display name resolved from the VTC DID document, if available.
    pub display_name: Option<String>,
    /// Sub-context id under the account's top context (`<top>/<slug>`, D9).
    pub sub_context_id: String,
    /// Which account persona is presented to this VTC (must resolve, R-P-1).
    pub persona_ref: PersonaId,
    /// Membership lifecycle state.
    pub status: CommunityStatus,
    /// User-starred favourite (sorts to top; R-C-4).
    #[serde(default)]
    pub favourite: bool,
    /// User-archived (hidden from the default list; R-C-8).
    #[serde(default)]
    pub archived: bool,
    /// Whether the user has acknowledged a terminal outcome
    /// (`Rejected`/`Removed`/`Expired`), clearing the actions-required badge
    /// (R-C-3 / R-S-2). Reset whenever the membership returns to a live state.
    #[serde(default)]
    pub acknowledged: bool,
    /// Set when the membership first becomes `Active` (member-since; R-C-2).
    pub member_since: Option<DateTime<Utc>>,
    /// When the join request was submitted — anchors the 7-day timeout (D16).
    pub requested_at: Option<DateTime<Utc>>,
    /// When the VTC first acknowledged the join (any correlated response: verdict
    /// refer/request_more, status deferred, recoverable trust-task-error, or the
    /// legacy submit-receipt). `Some` means the submit reached the VTC and is
    /// awaiting a decision; `None` while still `Pending` past the grace window
    /// means the submit may have been dropped (size limit / unhandled type) —
    /// surfaced in the UI so it isn't mistaken for a healthy wait (D16).
    #[serde(default)]
    pub receipt_at: Option<DateTime<Utc>>,
    /// Which transport carried the join submit.
    ///
    /// Recorded so an unacknowledged join can say *which* transport went
    /// unanswered. Without it the warning reads identically whether the VTC
    /// ignored us, the mediator dropped the frame, or the peer could not
    /// decode the transport it advertised — which is exactly the ambiguity
    /// that cost a night of log-reading against a VTC advertising `#tsp` that
    /// its binary could not speak.
    ///
    /// `None` on records written before this existed, and on any future path
    /// that submits without going through the join flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_transport: Option<crate::didcomm::MessagingTransport>,
    /// Whether the `Pending` request id is the **community's** id rather than
    /// our submit-time placeholder.
    ///
    /// A join is recorded against the id of the request document we sent,
    /// because that is the only handle we have until the VTC answers; the VTC
    /// mints its own (`Uuid::new_v4()`) and tells us in the first correlated
    /// reply. Which of the two the record currently holds decides whether the
    /// community can be *asked* about this join
    /// ([`crate::join::poll_join_status`]) — a poll quoting our placeholder is
    /// a request the VTC has never heard of, and is answered as such.
    ///
    /// `false` for a record written before this existed: those are never polled,
    /// which is the safe reading (we cannot tell whose id they hold).
    #[serde(default)]
    pub request_id_confirmed: bool,
    /// DIDComm relationships scoped to this community.
    #[serde(default)]
    pub relationships: Relationships,
    /// Reserved per-community inbox (protocol-workflow tasks). The eventual home
    /// for a physically per-community inbox; **not yet populated** — PR-1 scopes
    /// the main page by attribution (relationships/tasks carry an owning-persona
    /// tag and are filtered to the working community) while the collections stay
    /// in the global `ProtectedConfig` tier. Additive + serde(default)-tolerant
    /// so older configs load and a later physical-move migration can fill it.
    #[serde(default)]
    pub tasks: Tasks,
    /// VRCs we have issued within this community.
    #[serde(default)]
    pub vrcs_issued: Vrcs,
    /// VRCs we have received within this community.
    #[serde(default)]
    pub vrcs_received: Vrcs,
    /// Verifiable credentials this VTC has issued to us, keyed by
    /// [`CredentialKind`]. The membership credential (VMC) lands here on
    /// admission and activates the membership; the role endorsement (VEC)
    /// arrives alongside. Stored as the signed W3C VC JSON. Empty until the
    /// join is accepted and credentials arrive (R-B-8).
    ///
    /// Persisted as a JSON object keyed by [`CredentialKind::config_key`].
    /// Configs written before R19 used flat `membership_credential` /
    /// `role_credential` fields; `CommunityRecordShadow` folds those in on
    /// load so older configs keep working.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<CredentialKind, serde_json::Value>,

    /// The membership credential **we** issued to this community — the
    /// member → community half of the membership edge, acknowledging the grant
    /// in [`credentials`](Self::credentials).
    ///
    /// Kept rather than sent and forgotten. Three things need it:
    ///
    /// 1. **Answering "did I consent to this?"** This is the member's own
    ///    consent artifact, and it was the one credential in the exchange that
    ///    nothing on this side could show.
    /// 2. **Re-sending.** Without a copy, "send it again" means minting a
    ///    *different* credential with a different `id` — which the community
    ///    reads as a renewal, not a re-send.
    /// 3. **Knowing whether the edge still stands.** Its `digest` names one
    ///    grant. Once the community re-issues, this no longer matches and the
    ///    member owes a fresh acknowledgement — visible here, and nowhere else.
    ///
    /// Stored as the signed W3C VC JSON, exactly as it went out. `None` until
    /// we have issued one, and on configs written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_vmc: Option<serde_json::Value>,

    /// Fields written by a newer build, preserved verbatim (D19). See
    /// [`Account::extra`] for why.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Deserialize-only shadow of [`CommunityRecord`] that folds pre-R19
/// `membership_credential` / `role_credential` fields into the typed
/// [`credentials`](CommunityRecord::credentials) registry, so older configs
/// keep loading (the project tolerates format evolution via shims, not
/// migrations). New configs deserialize straight through the `credentials`
/// object. Unknown credential keys (e.g. written by a newer version) are
/// dropped rather than failing the whole config load.
#[derive(Deserialize)]
struct CommunityRecordShadow {
    vtc_did: VtcDid,
    display_name: Option<String>,
    sub_context_id: String,
    persona_ref: PersonaId,
    status: CommunityStatus,
    #[serde(default)]
    favourite: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    acknowledged: bool,
    member_since: Option<DateTime<Utc>>,
    requested_at: Option<DateTime<Utc>>,
    #[serde(default)]
    receipt_at: Option<DateTime<Utc>>,
    #[serde(default)]
    submit_transport: Option<crate::didcomm::MessagingTransport>,
    #[serde(default)]
    request_id_confirmed: bool,
    #[serde(default)]
    relationships: Relationships,
    #[serde(default)]
    tasks: Tasks,
    #[serde(default)]
    vrcs_issued: Vrcs,
    #[serde(default)]
    vrcs_received: Vrcs,
    // Keyed by `String`, not `CredentialKind`, on purpose: this is the
    // durability boundary. A strict `CredentialKind` key would make an
    // unrecognised kind (e.g. from a newer build) a fatal whole-config load
    // error; the `From` impl below instead drops unknown keys with a warning.
    #[serde(default)]
    credentials: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    member_vmc: Option<serde_json::Value>,
    // Legacy pre-R19 flat fields, folded into `credentials` below.
    #[serde(default)]
    membership_credential: Option<serde_json::Value>,
    #[serde(default)]
    role_credential: Option<serde_json::Value>,
    // D19: the catch-all has to live HERE, not on `CommunityRecord`. The shadow
    // deserializes first, so anything it does not name is gone before the real
    // type is built.
    #[serde(flatten, default)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl From<CommunityRecordShadow> for CommunityRecord {
    fn from(shadow: CommunityRecordShadow) -> Self {
        // New-format `credentials` keys win; unknown keys are dropped (a newer
        // version may persist kinds this build doesn't know).
        let mut credentials: BTreeMap<CredentialKind, serde_json::Value> = BTreeMap::new();
        for (key, vc) in shadow.credentials {
            match CredentialKind::from_config_key(&key) {
                Some(kind) => {
                    credentials.insert(kind, vc);
                }
                None => tracing::warn!(
                    credential_kind = %key,
                    "dropping unknown stored credential kind",
                ),
            }
        }
        // Fold legacy flat fields in without clobbering a new-format value.
        if let Some(vmc) = shadow.membership_credential {
            credentials.entry(CredentialKind::Membership).or_insert(vmc);
        }
        if let Some(vec) = shadow.role_credential {
            credentials.entry(CredentialKind::Role).or_insert(vec);
        }
        CommunityRecord {
            // D19: carry forward whatever a newer build wrote.
            extra: shadow.extra,
            vtc_did: shadow.vtc_did,
            display_name: shadow.display_name,
            sub_context_id: shadow.sub_context_id,
            persona_ref: shadow.persona_ref,
            status: shadow.status,
            favourite: shadow.favourite,
            archived: shadow.archived,
            acknowledged: shadow.acknowledged,
            member_since: shadow.member_since,
            requested_at: shadow.requested_at,
            receipt_at: shadow.receipt_at,
            submit_transport: shadow.submit_transport,
            request_id_confirmed: shadow.request_id_confirmed,
            relationships: shadow.relationships,
            tasks: shadow.tasks,
            vrcs_issued: shadow.vrcs_issued,
            vrcs_received: shadow.vrcs_received,
            credentials,
            member_vmc: shadow.member_vmc,
        }
    }
}

/// Client-side timeout for an unanswered `Pending` join (D16 / R-B-7): a join
/// request with no decision after this many days transitions to `Expired`.
pub const PENDING_TIMEOUT_DAYS: i64 = 7;

/// Grace period before a `Pending` join with no VTC acknowledgement
/// ([`CommunityRecord::receipt_at`] still `None`) is flagged as possibly-dropped.
/// A verdict/receipt normally returns within seconds; 2 minutes absorbs a slow
/// but healthy round-trip while surfacing a dropped submit (size limit / unhandled
/// type) far earlier than the 7-day [`PENDING_TIMEOUT_DAYS`].
pub const PENDING_ACK_GRACE_SECS: i64 = 120;

impl CommunityRecord {
    /// Build a fresh `Pending` join record (State-B join request, R-B-*).
    ///
    /// `request_id` correlates the VTC's asynchronous accept/reject decision
    /// (R-B-8); `requested_at` is stamped with `now` to anchor the 7-day timeout
    /// (D16). Starts unfavourited, unarchived, unacknowledged, with empty
    /// community-scoped relationship/VRC stores.
    pub fn new_pending(
        vtc_did: VtcDid,
        display_name: Option<String>,
        sub_context_id: String,
        persona_ref: PersonaId,
        request_id: Uuid,
        now: DateTime<Utc>,
    ) -> Self {
        CommunityRecord {
            extra: serde_json::Map::new(),
            vtc_did,
            display_name,
            sub_context_id,
            persona_ref,
            status: CommunityStatus::Pending { request_id },
            favourite: false,
            archived: false,
            acknowledged: false,
            member_since: None,
            requested_at: Some(now),
            receipt_at: None,
            // Set by the join flow once it knows which transport carried the
            // submit; `new_pending` itself is transport-agnostic.
            submit_transport: None,
            // `request_id` here is the id of the document we just sent. It only
            // becomes the community's once a reply says so — see
            // `confirm_request_id`.
            request_id_confirmed: false,
            relationships: Relationships::default(),
            tasks: Tasks::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
            credentials: BTreeMap::new(),
            member_vmc: None,
        }
    }

    /// True for a membership that needs a live DIDComm session (Active or
    /// Pending) — so the VTC's asynchronous join reply is receivable (D16).
    pub fn is_live(&self) -> bool {
        self.status.requires_live_session()
    }

    /// Transition to `Active` on acceptance (R-B-8). Stamps `member_since` with
    /// `now` the first time the membership becomes active (R-C-2); leaves an
    /// existing timestamp untouched so a re-activation keeps the original date.
    /// Returning to a live state clears any prior acknowledgement (R-S-2).
    pub fn activate(&mut self, now: DateTime<Utc>) {
        if self.member_since.is_none() {
            self.member_since = Some(now);
        }
        self.status = CommunityStatus::Active;
        self.acknowledged = false;
    }

    /// Transition to `Rejected` — the VTC denied the join request (R-B-8). A
    /// fresh terminal outcome starts unacknowledged so it raises the
    /// actions-required badge until the user clears it (R-S-2).
    pub fn reject(&mut self) {
        self.status = CommunityStatus::Rejected;
        self.acknowledged = false;
    }

    /// Transition to `Removed` — the VTC removed an active member (R-B-8). Starts
    /// unacknowledged (R-S-2).
    pub fn remove(&mut self) {
        self.status = CommunityStatus::Removed;
        self.acknowledged = false;
    }

    /// Transition to `Left` — the member voluntarily left (R-L-1). `Left` never
    /// raises the actions-required badge (the user chose to leave).
    pub fn leave(&mut self) {
        self.status = CommunityStatus::Left;
        self.acknowledged = false;
    }

    /// Transition to `Withdrawn` — the applicant cancelled a `Pending` join
    /// before the VTC decided. Like `Left`, a voluntary outcome that never
    /// raises the actions-required badge. The record becomes inactive, so it can
    /// then be deleted or re-joined. No-op (returns `false`) unless currently
    /// `Pending`; callers gate the action to pending rows, and this re-checks so
    /// a stray call can't withdraw an active/terminal membership.
    pub fn withdraw(&mut self) -> bool {
        if !matches!(self.status, CommunityStatus::Pending { .. }) {
            return false;
        }
        self.status = CommunityStatus::Withdrawn;
        self.acknowledged = false;
        true
    }

    /// Acknowledge a terminal outcome (`Rejected`/`Removed`/`Expired`), clearing
    /// the actions-required badge for this community (R-S-2). No effect on the
    /// `Pending` badge, which only clears when the request resolves.
    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }

    /// Whether this community raises the actions-required indicator (R-C-3):
    /// `Pending` always (a decision is awaited), or an **unacknowledged**
    /// terminal outcome `Rejected`/`Removed`/`Expired` (R-S-2). `Active` and
    /// `Left` never do.
    pub fn needs_attention(&self) -> bool {
        match self.status {
            CommunityStatus::Pending { .. } => true,
            CommunityStatus::Rejected | CommunityStatus::Removed | CommunityStatus::Expired => {
                !self.acknowledged
            }
            CommunityStatus::Active | CommunityStatus::Left | CommunityStatus::Withdrawn => false,
        }
    }

    /// Toggle the favourite/star flag (R-C-4). Returns the new value.
    pub fn toggle_favourite(&mut self) -> bool {
        self.favourite = !self.favourite;
        self.favourite
    }

    /// Whether this membership may be archived or deleted (R-C-8): only an
    /// **inactive** one (`Left`/`Rejected`/`Removed`/`Expired`). An active or
    /// pending membership must be left first.
    pub fn can_archive_or_delete(&self) -> bool {
        self.status.is_inactive()
    }

    /// Expire a stale `Pending` join past the [`PENDING_TIMEOUT_DAYS`] client
    /// timeout (R-B-7 / D16). No-op unless the membership is currently `Pending`
    /// with a `requested_at` at least the timeout old. Returns `true` if it
    /// transitioned to `Expired`.
    pub fn expire_if_stale(&mut self, now: DateTime<Utc>) -> bool {
        self.expire_if_stale_after(now, TimeDelta::days(PENDING_TIMEOUT_DAYS))
    }

    /// [`Self::expire_if_stale`] with the timeout given — a community's
    /// published `decisionSla` for a vetted join, which may be longer or shorter
    /// than the client default.
    pub fn expire_if_stale_after(&mut self, now: DateTime<Utc>, timeout: TimeDelta) -> bool {
        if matches!(self.status, CommunityStatus::Pending { .. })
            && let Some(requested) = self.requested_at
            && now - requested >= timeout
        {
            self.status = CommunityStatus::Expired;
            self.acknowledged = false;
            return true;
        }
        false
    }

    /// Record that the VTC has acknowledged this join — i.e. *some* correlated
    /// response arrived (verdict refer/request_more, status deferred, a
    /// recoverable trust-task-error, or the legacy submit-receipt). Stamps
    /// [`receipt_at`](Self::receipt_at) once with `now`; subsequent calls are
    /// no-ops (the first contact is what matters). Returns `true` if it set the
    /// timestamp (the caller should persist). Only meaningful while `Pending`.
    pub fn mark_acknowledged(&mut self, now: DateTime<Utc>) -> bool {
        if self.receipt_at.is_none() {
            self.receipt_at = Some(now);
            return true;
        }
        false
    }

    /// Adopt the community's own request id for a still-`Pending` join, replacing
    /// the submit-time placeholder.
    ///
    /// Every correlated VTC reply carries it — the submit-receipt, and the
    /// verdict envelope (`VerdictResponse.requestId`) that a `refer` /
    /// `request_more` arrives in. Adopting it from *whichever* lands first is
    /// what makes a join that is parked for human review askable-about later:
    /// the id is the only thing `join-requests/status` can name.
    ///
    /// Returns `true` if the record changed (the caller should persist). A no-op
    /// once the id is confirmed and unchanged, and on a non-`Pending` record —
    /// a terminal state has nothing left to poll for.
    pub fn confirm_request_id(&mut self, request_id: Uuid) -> bool {
        let CommunityStatus::Pending { request_id: held } = &self.status else {
            return false;
        };
        if *held == request_id && self.request_id_confirmed {
            return false;
        }
        self.status = CommunityStatus::Pending { request_id };
        self.request_id_confirmed = true;
        true
    }

    /// Whether the community can be asked about this join. Any `Pending` record
    /// qualifies.
    ///
    /// This used to also require [`Self::request_id_confirmed`], because the
    /// poll had to quote the community's own id and our placeholder would be
    /// answered `not found`. That made the mechanism unusable in the one case it
    /// exists for: a join whose first correlated reply was lost is exactly the
    /// join whose id we never learned, so it could never be asked about and sat
    /// `Pending` for good. The other recovery — collecting stored mail — is
    /// empty once that mail has been acked and deleted, so both failed together
    /// (#221).
    ///
    /// The community now answers an id-less poll from the authenticated
    /// applicant (`join-requests/status/0.1` with no `requestId`), and its reply
    /// carries the id, so an unconfirmed record repairs itself on the first
    /// answer. `request_id_confirmed` still decides *what we send* — see
    /// [`Account::pollable_pending`] — it just no longer decides whether we may
    /// ask at all.
    ///
    /// [`Account::pollable_pending`]: crate::config::account::Account::pollable_pending
    pub fn is_pollable_pending(&self) -> bool {
        matches!(self.status, CommunityStatus::Pending { .. })
    }

    /// Whether this is a `Pending` join the VTC has not acknowledged within
    /// [`PENDING_ACK_GRACE_SECS`] of submission — the signal that the submit may
    /// have been dropped (size limit / unhandled type) rather than healthily
    /// awaiting a decision. False once any response has set `receipt_at`, for
    /// non-`Pending` states, or while still inside the grace window.
    pub fn pending_unacknowledged(&self, now: DateTime<Utc>) -> bool {
        matches!(self.status, CommunityStatus::Pending { .. })
            && self.receipt_at.is_none()
            && self
                .requested_at
                .is_some_and(|r| now - r >= TimeDelta::seconds(PENDING_ACK_GRACE_SECS))
    }
}

/// One `Pending` join that can be reconciled with its community, flattened out
/// of the record so the poll can be driven without holding a `Config` borrow
/// across the network I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPoll {
    pub vtc_did: VtcDid,
    pub persona_ref: PersonaId,
    /// The **community's** request id when we hold it, `None` when we still
    /// hold our own submit-time placeholder (see
    /// [`CommunityRecord::request_id_confirmed`]).
    ///
    /// `None` is not a degraded poll — it asks the community "what is my open
    /// request?", which it answers from the authenticated applicant, and the
    /// answer carries the id. So the record repairs itself on the first reply
    /// and every later poll quotes the real id.
    pub request_id: Option<Uuid>,
    /// The transport the submit used, so the poll takes the same route. A
    /// community reachable only over TSP would never see a DIDComm poll.
    pub submit_transport: Option<crate::didcomm::MessagingTransport>,
}

/// The account — the OpenVTC ↔ VTA relationship (State-A bootstrap) plus its
/// personas and community memberships.
///
/// The account **admin credential** is a secret and is NOT stored here — it
/// lives in `SecuredConfig`/keyring (D12). This struct is the `ProtectedConfig`
/// (encrypted) metadata tier.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    /// DID of the VTA this account is provisioned against.
    pub vta_did: String,
    /// Base URL of the VTA (empty for DIDComm-only VTAs).
    pub vta_url: String,
    /// The top-level context this account administers.
    pub top_context_id: String,
    /// Organisation DID this account is affiliated with (the former
    /// `public.lk_did` singleton). Account-level, not persona-scoped.
    #[serde(default)]
    pub org_did: String,
    /// Account personas, keyed by stable id.
    #[serde(default)]
    pub personas: HashMap<PersonaId, PersonaRecord>,
    /// Community memberships, grouped by VTC DID. A community may hold more than
    /// one membership, each presenting a **different** persona — the
    /// `(vtc_did, persona_ref)` pair is unique. Backward compatible:
    /// `de_communities` folds the legacy one-record-per-VTC shape (and a bare
    /// record) into the grouped form on load.
    #[serde(default, deserialize_with = "de_communities")]
    pub communities: HashMap<VtcDid, Vec<CommunityRecord>>,

    /// Fields written by a build newer than this one, preserved verbatim.
    ///
    /// **D19.** Without this, serde silently drops what it does not know, and a
    /// round trip through an older build is data loss: read a record, discard
    /// the new fields, write it back without them. Harmless while a single
    /// writer owns the config — and exactly why it has never bitten — but the
    /// moment this record is shared with another instance (E2), an older build
    /// would quietly strip a newer one's work.
    ///
    /// Carried, never interpreted. `skip_serializing_if` keeps it off the wire
    /// when empty so existing configs are byte-identical.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Deserialize [`Account::communities`] tolerantly: each VTC's value may be a
/// list of memberships (the current shape) or a single record (legacy configs
/// written before multi-membership). Both fold into `Vec<CommunityRecord>`.
fn de_communities<'de, D>(d: D) -> Result<HashMap<VtcDid, Vec<CommunityRecord>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        // Try the list shape first; a legacy object value fails the seq parse
        // and falls through to the single-record variant.
        Many(Vec<CommunityRecord>),
        One(Box<CommunityRecord>),
    }
    let raw: HashMap<VtcDid, OneOrMany> = HashMap::deserialize(d)?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| {
            let list = match v {
                OneOrMany::Many(list) => list,
                OneOrMany::One(rec) => vec![*rec],
            };
            (k, list)
        })
        .collect())
}

impl Account {
    /// Every membership across all communities (flattened). A community may
    /// contribute more than one — one per presented persona.
    pub fn memberships(&self) -> impl Iterator<Item = &CommunityRecord> {
        self.communities.values().flatten()
    }

    /// Mutable iterator over every membership.
    pub fn memberships_mut(&mut self) -> impl Iterator<Item = &mut CommunityRecord> {
        self.communities.values_mut().flatten()
    }

    /// The memberships held with one community (empty if none).
    pub fn memberships_for(&self, vtc: &str) -> &[CommunityRecord] {
        self.communities.get(vtc).map(Vec::as_slice).unwrap_or(&[])
    }

    /// A specific membership: community `vtc` presented as `persona`. The
    /// `(vtc, persona)` pair is unique, so this resolves at most one.
    pub fn membership(&self, vtc: &str, persona: PersonaId) -> Option<&CommunityRecord> {
        self.memberships_for(vtc)
            .iter()
            .find(|c| c.persona_ref == persona)
    }

    /// Mutable [`Self::membership`] — for applying a lifecycle transition.
    pub fn membership_mut(
        &mut self,
        vtc: &str,
        persona: PersonaId,
    ) -> Option<&mut CommunityRecord> {
        self.communities
            .get_mut(vtc)?
            .iter_mut()
            .find(|c| c.persona_ref == persona)
    }

    /// The pending membership of community `vtc` awaiting the join reply with
    /// `request_id` — the disambiguator when several personas have joined the
    /// same community (each Pending submit carries a unique id). Resolves at most
    /// one membership.
    pub fn membership_by_pending_request(
        &mut self,
        vtc: &str,
        request_id: Uuid,
    ) -> Option<&mut CommunityRecord> {
        self.communities.get_mut(vtc)?.iter_mut().find(
            |c| matches!(&c.status, CommunityStatus::Pending { request_id: r } if *r == request_id),
        )
    }

    /// Every `Pending` join the community can be asked about, as the tuple a
    /// status poll needs: which community, which persona speaks to it, the
    /// community's request id **if we know it**, and the transport the submit
    /// went out on.
    ///
    /// Read-only and cheap — the caller (a periodic reconcile) runs this on
    /// every tick and expects an empty vector to be the normal answer.
    pub fn pollable_pending(&self) -> Vec<PendingPoll> {
        self.memberships()
            .filter(|c| c.is_pollable_pending())
            .filter_map(|c| {
                let CommunityStatus::Pending { request_id } = c.status else {
                    return None;
                };
                Some(PendingPoll {
                    vtc_did: c.vtc_did.clone(),
                    persona_ref: c.persona_ref,
                    // Only the community's own id is worth quoting. Our
                    // placeholder names a document the VTC has never heard of
                    // and is answered `not found`; omitting it asks the
                    // question that can actually be answered.
                    request_id: c.request_id_confirmed.then_some(request_id),
                    submit_transport: c.submit_transport,
                })
            })
            .collect()
    }

    /// Add a new membership. Callers gate on [`Self::has_live_membership`] first
    /// (R-B-9): a community may hold many memberships, but not two for the same
    /// persona.
    pub fn add_membership(&mut self, record: CommunityRecord) {
        self.communities
            .entry(record.vtc_did.clone())
            .or_default()
            .push(record);
    }

    /// Whether a *live* (Active/Pending) membership already exists for
    /// `(vtc, persona)`. Join idempotency is per-persona: a live membership as
    /// *this* persona blocks a duplicate, but the same community may still be
    /// joined as a different persona.
    pub fn has_live_membership(&self, vtc: &str, persona: PersonaId) -> bool {
        self.membership(vtc, persona).is_some_and(|c| c.is_live())
    }

    /// The id of the account persona whose `did` equals `did`, if any. Maps an
    /// addressed persona DID (e.g. an inbound message's recipient) back to its
    /// [`PersonaId`] for D10 attribution tagging.
    pub fn persona_id_for_did(&self, did: &str) -> Option<PersonaId> {
        self.personas
            .iter()
            .find(|(_, p)| p.did == did)
            .map(|(id, _)| *id)
    }

    /// Resolve the persona presented for a specific membership.
    pub fn membership_persona(&self, vtc: &str, persona: PersonaId) -> Option<&PersonaRecord> {
        self.membership(vtc, persona)
            .and_then(|c| self.personas.get(&c.persona_ref))
    }

    /// True if any membership references this persona.
    pub fn persona_referenced(&self, id: &PersonaId) -> bool {
        self.memberships().any(|c| &c.persona_ref == id)
    }

    /// Whether a persona may be deleted (R-P-1): it must exist and not be
    /// referenced by any membership.
    pub fn can_delete_persona(&self, id: &PersonaId) -> bool {
        self.personas.contains_key(id) && !self.persona_referenced(id)
    }

    /// Any `persona_ref`s that do not resolve to an existing persona — should
    /// always be empty (referential integrity, R-P-1).
    pub fn dangling_refs(&self) -> Vec<(&VtcDid, &PersonaId)> {
        self.communities
            .iter()
            .flat_map(|(vtc, list)| list.iter().map(move |c| (vtc, c)))
            .filter(|(_, c)| !self.personas.contains_key(&c.persona_ref))
            .map(|(vtc, c)| (vtc, &c.persona_ref))
            .collect()
    }

    /// Iterator over memberships in the `Active` (live) state.
    pub fn active_communities(&self) -> impl Iterator<Item = &CommunityRecord> {
        self.memberships().filter(|c| c.status.is_active())
    }

    /// Sweep all `Pending` memberships, expiring any past the client timeout
    /// (R-B-7 / D16). Returns the `(vtc, persona)` of each membership that
    /// transitioned to `Expired` so the caller can persist and raise the
    /// actions-required indicator (R-S-2).
    pub fn expire_stale_pending(&mut self, now: DateTime<Utc>) -> Vec<(VtcDid, PersonaId)> {
        self.expire_stale_pending_with(now, |_| TimeDelta::days(PENDING_TIMEOUT_DAYS))
    }

    /// [`Self::expire_stale_pending`] with a timeout chosen per membership, so a
    /// community that publishes a `decisionSla` is waited on for that long
    /// rather than the fixed client default (vetting-process.md §14.1).
    pub fn expire_stale_pending_with(
        &mut self,
        now: DateTime<Utc>,
        timeout_for: impl Fn(&CommunityRecord) -> TimeDelta,
    ) -> Vec<(VtcDid, PersonaId)> {
        let mut expired = Vec::new();
        for community in self.memberships_mut() {
            let timeout = timeout_for(community);
            if community.expire_if_stale_after(now, timeout) {
                expired.push((community.vtc_did.clone(), community.persona_ref));
            }
        }
        expired
    }

    /// Number of memberships currently raising the actions-required indicator
    /// (R-C-3): see [`CommunityRecord::needs_attention`]. Archived memberships
    /// are excluded — archiving hides one from the default list, so it no longer
    /// nags.
    pub fn actions_required_count(&self) -> usize {
        self.memberships()
            .filter(|c| !c.archived && c.needs_attention())
            .count()
    }

    /// Memberships for the overview page in display order (R-C-4): grouped by
    /// community (display name, case-insensitive, unnamed last; then VTC DID),
    /// favourites first within the list, then by presented persona for a stable
    /// order. Archived memberships are excluded unless `include_archived` (R-C-8).
    pub fn communities_for_display(&self, include_archived: bool) -> Vec<&CommunityRecord> {
        let mut list: Vec<&CommunityRecord> = self
            .memberships()
            .filter(|c| include_archived || !c.archived)
            .collect();
        list.sort_by(|a, b| {
            // Favourites first.
            b.favourite
                .cmp(&a.favourite)
                // Then group by display name, case-insensitive; unnamed last.
                .then_with(|| match (&a.display_name, &b.display_name) {
                    (Some(an), Some(bn)) => an.to_lowercase().cmp(&bn.to_lowercase()),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
                // Then the VTC DID, then the persona, for a stable order that
                // keeps a community's memberships adjacent (for grouped display).
                .then_with(|| a.vtc_did.cmp(&b.vtc_did))
                .then_with(|| a.persona_ref.cmp(&b.persona_ref))
        });
        list
    }

    /// The membership to use as the default working context (D10 / R-C-6/7) when
    /// the user hasn't explicitly selected one: the first **Active** membership
    /// in display order. Returns `None` when there is none. Deterministic so the
    /// working context is stable across launches.
    pub fn default_working_membership(&self) -> Option<(VtcDid, PersonaId)> {
        self.communities_for_display(false)
            .into_iter()
            .find(|c| c.status.is_active())
            .map(|c| (c.vtc_did.clone(), c.persona_ref))
    }

    /// Archive an inactive membership (R-C-8): retain its data but hide it from
    /// the default list. Errors if the membership is unknown or still
    /// active/pending (it must be left first).
    pub fn archive_membership(
        &mut self,
        vtc: &str,
        persona: PersonaId,
    ) -> Result<(), OpenVTCError> {
        let community = self
            .membership_mut(vtc, persona)
            .ok_or_else(|| OpenVTCError::Config(format!("Unknown membership: {vtc}")))?;
        if !community.can_archive_or_delete() {
            return Err(OpenVTCError::Config(format!(
                "Cannot archive an active/pending community ({vtc}); leave it first"
            )));
        }
        community.archived = true;
        Ok(())
    }

    /// Delete an inactive membership's local record (R-C-8), returning the removed
    /// record. Errors if it is unknown or still active/pending. The presented
    /// persona is retained even if now unreferenced (R-P-2).
    pub fn delete_membership(
        &mut self,
        vtc: &str,
        persona: PersonaId,
    ) -> Result<CommunityRecord, OpenVTCError> {
        let list = self
            .communities
            .get_mut(vtc)
            .ok_or_else(|| OpenVTCError::Config(format!("Unknown membership: {vtc}")))?;
        let idx = list
            .iter()
            .position(|c| c.persona_ref == persona)
            .ok_or_else(|| OpenVTCError::Config(format!("Unknown membership: {vtc}")))?;
        if !list[idx].can_archive_or_delete() {
            return Err(OpenVTCError::Config(format!(
                "Cannot delete an active/pending community ({vtc}); leave it first"
            )));
        }
        let removed = list.remove(idx);
        // Drop the community's bucket once its last membership is gone.
        if list.is_empty() {
            self.communities.remove(vtc);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona(label: &str) -> PersonaRecord {
        PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id: PersonaId::new(),
            did: format!("did:webvh:example.com:{label}"),
            did_document: None,
            key_refs: vec![KeyRef {
                key_id: format!("key-{label}"),
                purpose: KeyTypes::PersonaSigning,
                created_at: Utc::now(),
            }],
            mediator_did: None,
            origin_context_id: format!("openvtc/{label}"),
            created_at: Utc::now(),
            label: Some(label.to_string()),
        }
    }

    /// `PersonaRecord.did_document` persists a whole DID Document into the
    /// encrypted config. `affinidi-did-common` 0.4 added `alsoKnownAs` to that
    /// struct (it is the field agent-name verification reads), so a config
    /// written by a pre-0.4 build has no such key. It must still load — the
    /// project tolerates format evolution via serde defaults, not migrations.
    #[test]
    fn persona_did_document_without_also_known_as_still_loads() {
        let legacy = serde_json::json!({
            "persona_id": PersonaId::new().0,
            "did": "did:webvh:example.com:dave",
            // A did-common 0.3-shaped document: no `alsoKnownAs` key at all.
            "did_document": { "id": "did:webvh:example.com:dave" },
            "key_refs": [],
            "mediator_did": null,
            "origin_context_id": "openvtc/dave",
            "created_at": Utc::now(),
            "label": "Dave",
        });

        let rec: PersonaRecord =
            serde_json::from_value(legacy).expect("pre-0.4 persona config must still deserialize");
        let doc = rec.did_document.expect("document should be present");
        assert!(
            doc.also_known_as.is_empty(),
            "a document that claimed no names must load as claiming none, not fail"
        );
    }

    fn community(vtc: &str, persona_ref: PersonaId, status: CommunityStatus) -> CommunityRecord {
        CommunityRecord {
            extra: serde_json::Map::new(),
            vtc_did: vtc.to_string(),
            display_name: Some(vtc.to_string()),
            sub_context_id: format!("openvtc/{vtc}"),
            submit_transport: None,
            request_id_confirmed: false,
            persona_ref,
            status,
            favourite: false,
            archived: false,
            acknowledged: false,
            member_since: None,
            requested_at: None,
            receipt_at: None,
            relationships: Relationships::default(),
            tasks: Tasks::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
            credentials: BTreeMap::new(),
            member_vmc: None,
        }
    }

    #[test]
    fn persona_id_for_did_maps_addressed_did_to_persona() {
        let pa = persona("alice");
        let pb = persona("bob");
        let (pid_a, did_a) = (pa.persona_id, pa.did.clone());
        let mut acct = Account::default();
        acct.personas.insert(pa.persona_id, pa);
        acct.personas.insert(pb.persona_id, pb);
        assert_eq!(acct.persona_id_for_did(&did_a), Some(pid_a));
        assert_eq!(acct.persona_id_for_did("did:web:nobody"), None);
    }

    #[test]
    fn default_working_community_prefers_favourite_active_and_skips_inactive() {
        let p = persona("p");
        let mut acct = Account::default();
        let vtc = |a: &Account| a.default_working_membership().map(|(v, _)| v);
        // No communities → no working context.
        assert_eq!(vtc(&acct), None);

        // An inactive (Left) community is never the working context.
        let left = community("did:web:left", p.persona_id, CommunityStatus::Left);
        acct.add_membership(left);
        assert_eq!(vtc(&acct), None);

        // A plain active community becomes the default.
        let act = community("did:web:active", p.persona_id, CommunityStatus::Active);
        acct.add_membership(act);
        assert_eq!(vtc(&acct).as_deref(), Some("did:web:active"));

        // A favourited active community wins (sorts first in display order).
        let mut fav = community("did:web:fav", p.persona_id, CommunityStatus::Active);
        fav.favourite = true;
        acct.add_membership(fav);
        acct.personas.insert(p.persona_id, p);
        assert_eq!(vtc(&acct).as_deref(), Some("did:web:fav"));
    }

    #[test]
    fn community_record_tasks_survive_json_round_trip() {
        use crate::tasks::TaskType;
        use std::sync::Arc;

        let pid = PersonaId::new();
        let mut comm = community("did:web:vtc-rt", pid, CommunityStatus::Active);
        comm.tasks.new_task(
            &Arc::new("task-rt".to_string()),
            TaskType::RelationshipRequestRejected,
        );
        let json = serde_json::to_string(&comm).expect("serialize");
        let back: CommunityRecord = serde_json::from_str(&json).expect("deserialize");
        assert!(
            back.tasks
                .get_by_id(&Arc::new("task-rt".to_string()))
                .is_some(),
            "per-community task should survive the round trip"
        );
    }

    /// Pre-R19 configs stored credentials as flat `membership_credential` /
    /// `role_credential` fields. They must still load, folded into the typed
    /// `credentials` registry (config round-trip — no migration).
    #[test]
    fn legacy_flat_credential_fields_load_into_registry() {
        let legacy = serde_json::json!({
            "vtc_did": "did:webvh:vtc.example",
            "display_name": "Example VTC",
            "sub_context_id": "openvtc/example",
            "persona_ref": PersonaId::new().0,
            "status": { "state": "active" },
            "member_since": null,
            "requested_at": null,
            "membership_credential": { "type": ["MembershipCredential"], "id": "vmc-1" },
            "role_credential": { "type": ["EndorsementCredential"], "id": "vec-1" },
        });
        let rec: CommunityRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(
            rec.credentials
                .get(&CredentialKind::Membership)
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str()),
            Some("vmc-1"),
        );
        assert_eq!(
            rec.credentials
                .get(&CredentialKind::Role)
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str()),
            Some("vec-1"),
        );
    }

    /// The new `credentials` object round-trips, serializes under stable
    /// `config_key` names, and tolerates an unknown key (dropped, not fatal).
    #[test]
    fn typed_credentials_round_trip_and_tolerate_unknown() {
        let mut rec = community(
            "did:webvh:vtc.example",
            PersonaId::new(),
            CommunityStatus::Active,
        );
        rec.credentials.insert(
            CredentialKind::Membership,
            serde_json::json!({ "id": "vmc-1" }),
        );

        let json = serde_json::to_value(&rec).unwrap();
        assert!(
            json["credentials"]["Membership"]["id"] == "vmc-1",
            "credentials must persist under the config_key name: {json}",
        );

        let back: CommunityRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.credentials, rec.credentials);

        // An unrecognised kind (e.g. from a newer build) is dropped, not fatal.
        let with_unknown = serde_json::json!({
            "vtc_did": "did:webvh:vtc.example",
            "display_name": null,
            "sub_context_id": "openvtc/x",
            "persona_ref": PersonaId::new().0,
            "status": { "state": "active" },
            "member_since": null,
            "requested_at": null,
            "credentials": { "FutureKind": { "id": "x" } },
        });
        let rec: CommunityRecord = serde_json::from_value(with_unknown).unwrap();
        assert!(rec.credentials.is_empty());
    }

    #[test]
    fn new_pending_builds_a_live_pending_record() {
        let now = Utc::now();
        let pid = PersonaId::new();
        let req = Uuid::new_v4();
        let rec = CommunityRecord::new_pending(
            "did:webvh:vtc.example".to_string(),
            Some("Example VTC".to_string()),
            "openvtc/example".to_string(),
            pid,
            req,
            now,
        );
        assert!(matches!(rec.status, CommunityStatus::Pending { request_id } if request_id == req));
        assert_eq!(rec.persona_ref, pid);
        assert_eq!(rec.requested_at, Some(now));
        assert_eq!(rec.member_since, None);
        assert!(rec.is_live());
        assert!(rec.needs_attention());
        assert!(!rec.favourite && !rec.archived && !rec.acknowledged);

        // Idempotency (R-B-9): a pending join is a live membership, so a re-join
        // attempt as the same persona finds it.
        let mut acct = Account::default();
        let pref = rec.persona_ref;
        let vtc = rec.vtc_did.clone();
        acct.add_membership(rec.clone());
        assert!(acct.has_live_membership(&vtc, pref));
    }

    #[test]
    fn status_classification() {
        assert!(CommunityStatus::Active.is_active());
        assert!(!CommunityStatus::Active.is_read_only());
        assert!(!CommunityStatus::Active.needs_attention());

        for s in [
            CommunityStatus::Left,
            CommunityStatus::Withdrawn,
            CommunityStatus::Rejected,
            CommunityStatus::Removed,
            CommunityStatus::Expired,
        ] {
            assert!(s.is_read_only(), "{s:?} should be read-only");
            assert!(s.is_inactive(), "{s:?} should be inactive (archive/delete)");
        }

        let pending = CommunityStatus::Pending {
            request_id: Uuid::new_v4(),
        };
        assert!(pending.is_read_only());
        assert!(!pending.is_inactive(), "pending is in-flight, not inactive");
        assert!(pending.needs_attention());
        assert!(CommunityStatus::Rejected.needs_attention());
        assert!(!CommunityStatus::Left.needs_attention());
        // Withdrawn is a voluntary outcome (like Left) — it never nags.
        assert!(!CommunityStatus::Withdrawn.needs_attention());
    }

    #[test]
    fn persona_for_resolves_ref() {
        let mut acct = Account::default();
        let p = persona("alice");
        let pid = p.persona_id;
        acct.personas.insert(pid, p);
        acct.add_membership(community("vtc:a", pid, CommunityStatus::Active));

        let resolved = acct.membership_persona("vtc:a", pid).expect("resolves");
        assert_eq!(resolved.persona_id, pid);
        assert!(acct.membership_persona("vtc:missing", pid).is_none());
        assert!(acct.dangling_refs().is_empty());
    }

    #[test]
    fn referential_integrity_blocks_persona_delete() {
        let mut acct = Account::default();
        let p = persona("bob");
        let pid = p.persona_id;
        acct.personas.insert(pid, p);

        // Unreferenced: deletable.
        assert!(acct.can_delete_persona(&pid));

        // Now referenced by an active community: not deletable (R-P-1).
        acct.add_membership(community("vtc:b", pid, CommunityStatus::Active));
        assert!(acct.persona_referenced(&pid));
        assert!(!acct.can_delete_persona(&pid));

        // Unknown persona is never deletable.
        assert!(!acct.can_delete_persona(&PersonaId::new()));
    }

    #[test]
    fn active_communities_filters() {
        let mut acct = Account::default();
        let p = persona("carol");
        let pid = p.persona_id;
        acct.personas.insert(pid, p);
        acct.add_membership(community("a", pid, CommunityStatus::Active));
        acct.add_membership(community("b", pid, CommunityStatus::Left));
        acct.add_membership(community(
            "c",
            pid,
            CommunityStatus::Pending {
                request_id: Uuid::new_v4(),
            },
        ));
        assert_eq!(acct.active_communities().count(), 1);
    }

    #[test]
    fn account_json_round_trip_preserves_shape() {
        let mut acct = Account {
            vta_did: "did:webvh:vta.example".into(),
            vta_url: "https://vta.example".into(),
            top_context_id: "openvtc".into(),
            ..Account::default()
        };
        let p = persona("dave");
        let pid = p.persona_id;
        let req = Uuid::new_v4();
        acct.personas.insert(pid, p);
        acct.add_membership(community(
            "vtc:x",
            pid,
            CommunityStatus::Pending { request_id: req },
        ));

        let json = serde_json::to_string(&acct).expect("serialize");
        let back: Account = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.vta_did, acct.vta_did);
        assert_eq!(back.top_context_id, "openvtc");
        assert_eq!(back.personas.len(), 1);
        let bp = back.personas.get(&pid).expect("persona survives");
        assert_eq!(bp.did, "did:webvh:example.com:dave");
        let bc = back.membership("vtc:x", pid).expect("community survives");
        assert_eq!(bc.persona_ref, pid);
        assert_eq!(bc.status, CommunityStatus::Pending { request_id: req });
    }

    #[test]
    fn community_status_tag_is_stable() {
        // The serde tag is part of the on-disk format; pin it.
        let j = serde_json::to_string(&CommunityStatus::Active).unwrap();
        assert_eq!(j, r#"{"state":"active"}"#);
        let j = serde_json::to_string(&CommunityStatus::Expired).unwrap();
        assert_eq!(j, r#"{"state":"expired"}"#);
        let j = serde_json::to_string(&CommunityStatus::Withdrawn).unwrap();
        assert_eq!(j, r#"{"state":"withdrawn"}"#);
    }

    fn pending() -> CommunityStatus {
        CommunityStatus::Pending {
            request_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn activate_stamps_member_since_once() {
        let pid = PersonaId::new();
        let mut c = community("v", pid, pending());
        let t0 = Utc::now();
        c.activate(t0);
        assert_eq!(c.status, CommunityStatus::Active);
        assert_eq!(c.member_since, Some(t0));

        // Re-activating keeps the original member-since date.
        c.activate(t0 + TimeDelta::days(5));
        assert_eq!(c.member_since, Some(t0), "member_since must not be reset");
    }

    #[test]
    fn terminal_transitions_set_status() {
        let pid = PersonaId::new();

        let mut r = community("v", pid, pending());
        r.reject();
        assert_eq!(r.status, CommunityStatus::Rejected);

        let mut rm = community("v", pid, CommunityStatus::Active);
        rm.remove();
        assert_eq!(rm.status, CommunityStatus::Removed);

        let mut l = community("v", pid, CommunityStatus::Active);
        l.leave();
        assert_eq!(l.status, CommunityStatus::Left);
    }

    #[test]
    fn withdraw_cancels_a_pending_join() {
        let pid = PersonaId::new();

        // Pending → Withdrawn: succeeds, becomes inactive, and never nags.
        let mut p = community("v", pid, pending());
        p.acknowledged = false;
        assert!(p.withdraw(), "withdraw applies to a pending join");
        assert_eq!(p.status, CommunityStatus::Withdrawn);
        assert!(
            p.can_archive_or_delete(),
            "withdrawn is deletable/archivable"
        );
        assert!(!p.needs_attention(), "a withdrawn join must not nag");
        assert!(!p.is_live(), "withdrawn needs no live session");

        // Idempotent / guarded: a second call (now Withdrawn) is a no-op, and an
        // Active membership can't be withdrawn (only left).
        assert!(!p.withdraw(), "withdraw is a no-op once not pending");
        let mut active = community("v", pid, CommunityStatus::Active);
        assert!(
            !active.withdraw(),
            "withdraw must not touch an active membership"
        );
        assert_eq!(active.status, CommunityStatus::Active);
    }

    #[test]
    fn expire_if_stale_only_fires_for_old_pending() {
        let pid = PersonaId::new();
        let now = Utc::now();

        // Fresh pending (just under the timeout): not expired.
        let mut fresh = community("v", pid, pending());
        fresh.requested_at = Some(now - TimeDelta::days(PENDING_TIMEOUT_DAYS - 1));
        assert!(!fresh.expire_if_stale(now));
        assert!(matches!(fresh.status, CommunityStatus::Pending { .. }));

        // Stale pending (at the timeout): expires.
        let mut stale = community("v", pid, pending());
        stale.requested_at = Some(now - TimeDelta::days(PENDING_TIMEOUT_DAYS));
        assert!(stale.expire_if_stale(now));
        assert_eq!(stale.status, CommunityStatus::Expired);

        // Active is never expired, however old.
        let mut active = community("v", pid, CommunityStatus::Active);
        active.requested_at = Some(now - TimeDelta::days(365));
        assert!(!active.expire_if_stale(now));
        assert_eq!(active.status, CommunityStatus::Active);

        // Pending with no requested_at can't be judged stale.
        let mut no_ts = community("v", pid, pending());
        no_ts.requested_at = None;
        assert!(!no_ts.expire_if_stale(now));
    }

    #[test]
    fn mark_acknowledged_stamps_once() {
        let pid = PersonaId::new();
        let now = Utc::now();
        let mut c = community("v", pid, pending());
        assert!(c.receipt_at.is_none());
        // First contact stamps; returns true (caller persists).
        assert!(c.mark_acknowledged(now));
        assert_eq!(c.receipt_at, Some(now));
        // A later contact is a no-op — first contact is what matters.
        assert!(!c.mark_acknowledged(now + TimeDelta::seconds(10)));
        assert_eq!(c.receipt_at, Some(now));
    }

    #[test]
    fn pending_unacknowledged_flags_only_unacked_pending_past_grace() {
        let pid = PersonaId::new();
        let now = Utc::now();
        let grace = TimeDelta::seconds(PENDING_ACK_GRACE_SECS);

        // Pending, no receipt, within grace: not yet flagged.
        let mut fresh = community("v", pid, pending());
        fresh.requested_at = Some(now - grace + TimeDelta::seconds(1));
        assert!(!fresh.pending_unacknowledged(now));

        // Pending, no receipt, past grace: flagged (possibly dropped).
        let mut stuck = community("v", pid, pending());
        stuck.requested_at = Some(now - grace);
        assert!(stuck.pending_unacknowledged(now));

        // Pending but acknowledged: never flagged, however old.
        let mut acked = community("v", pid, pending());
        acked.requested_at = Some(now - TimeDelta::days(1));
        acked.mark_acknowledged(now - TimeDelta::days(1));
        assert!(!acked.pending_unacknowledged(now));

        // Non-Pending is never flagged.
        let mut active = community("v", pid, CommunityStatus::Active);
        active.requested_at = Some(now - TimeDelta::days(1));
        assert!(!active.pending_unacknowledged(now));
    }

    #[test]
    fn confirm_request_id_adopts_the_communitys_id_only_while_pending() {
        let pid = PersonaId::new();
        let real = Uuid::new_v4();

        let mut c = community("v", pid, pending());
        assert!(
            c.is_pollable_pending(),
            "a record still holding our submit id is exactly the one worth asking \
             about — it asks id-less, and the answer carries the id"
        );
        assert!(
            c.confirm_request_id(real),
            "adopting is a change to persist"
        );
        assert!(matches!(c.status, CommunityStatus::Pending { request_id } if request_id == real));
        assert!(c.is_pollable_pending());
        assert!(
            !c.confirm_request_id(real),
            "re-confirming the same id changes nothing, so it must not force a save"
        );

        // A terminal record has nothing left to poll for, so a late reply
        // carrying an id must not resurrect it as pollable.
        let mut rejected = community("v", pid, CommunityStatus::Rejected);
        assert!(!rejected.confirm_request_id(real));
        assert!(!rejected.is_pollable_pending());
    }

    /// Every `Pending` join is askable; only what we *quote* differs.
    ///
    /// This used to list confirmed records only, which meant the joins most in
    /// need of reconciling — the ones whose reply was lost, so whose id we never
    /// learned — were the exact ones never polled (#221).
    #[test]
    fn pollable_pending_covers_unconfirmed_joins_and_omits_their_id() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        let real = Uuid::new_v4();

        acct.add_membership(community("unconfirmed", pid, pending()));
        // Active — nothing to ask.
        acct.add_membership(community("active", pid, CommunityStatus::Active));
        let mut confirmed = community("confirmed", pid, pending());
        confirmed.confirm_request_id(real);
        confirmed.submit_transport = Some(crate::didcomm::MessagingTransport::Tsp);
        acct.add_membership(confirmed);

        let pollable = acct.pollable_pending();
        assert_eq!(
            pollable.len(),
            2,
            "both pending joins are askable: {pollable:?}"
        );

        let unconfirmed = pollable
            .iter()
            .find(|p| p.vtc_did == "unconfirmed")
            .expect("the unconfirmed join must be polled");
        assert_eq!(
            unconfirmed.request_id, None,
            "our placeholder names a document the VTC has never heard of; omitting \
             it is what makes the poll answerable"
        );

        let confirmed = pollable
            .iter()
            .find(|p| p.vtc_did == "confirmed")
            .expect("the confirmed join is still polled");
        assert_eq!(
            confirmed.request_id,
            Some(real),
            "quote the community's own id"
        );
        assert_eq!(
            confirmed.submit_transport,
            Some(crate::didcomm::MessagingTransport::Tsp),
            "the poll must take the transport the submit took"
        );
    }

    #[test]
    fn live_community_filters_inactive() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.add_membership(community("active", pid, CommunityStatus::Active));
        acct.add_membership(community("left", pid, CommunityStatus::Left));
        acct.add_membership(community("pend", pid, pending()));

        assert!(acct.has_live_membership("active", pid));
        assert!(acct.has_live_membership("pend", pid));
        assert!(
            !acct.has_live_membership("left", pid),
            "Left is not a live membership"
        );
        assert!(!acct.has_live_membership("missing", pid));
    }

    #[test]
    fn favourite_toggle_and_archive_delete_guard() {
        let pid = PersonaId::new();
        let mut c = community("v", pid, CommunityStatus::Active);
        assert!(!c.favourite);
        assert!(c.toggle_favourite());
        assert!(c.favourite);
        assert!(!c.toggle_favourite());

        // Active/pending cannot be archived/deleted; inactive can.
        assert!(!community("v", pid, CommunityStatus::Active).can_archive_or_delete());
        assert!(!community("v", pid, pending()).can_archive_or_delete());
        for s in [
            CommunityStatus::Left,
            CommunityStatus::Rejected,
            CommunityStatus::Removed,
            CommunityStatus::Expired,
        ] {
            assert!(community("v", pid, s).can_archive_or_delete());
        }
    }

    #[test]
    fn communities_for_display_orders_and_filters() {
        let mut acct = Account::default();
        let pid = PersonaId::new();

        let mut zebra = community("did:z", pid, CommunityStatus::Active);
        zebra.display_name = Some("Zebra".into());
        let mut acme = community("did:a", pid, CommunityStatus::Active);
        acme.display_name = Some("acme".into()); // lowercase: case-insensitive sort
        let mut fav = community("did:f", pid, CommunityStatus::Active);
        fav.display_name = Some("Middle".into());
        fav.favourite = true;
        let mut archived = community("did:x", pid, CommunityStatus::Left);
        archived.display_name = Some("Aardvark".into());
        archived.archived = true;

        for c in [zebra, acme, fav, archived] {
            acct.add_membership(c);
        }

        // Default: archived excluded; favourite first, then name (ci).
        let names: Vec<&str> = acct
            .communities_for_display(false)
            .iter()
            .map(|c| c.display_name.as_deref().unwrap())
            .collect();
        assert_eq!(names, vec!["Middle", "acme", "Zebra"]);

        // With archived included, "Aardvark" appears (still after the favourite).
        let with_archived: Vec<&str> = acct
            .communities_for_display(true)
            .iter()
            .map(|c| c.display_name.as_deref().unwrap())
            .collect();
        assert_eq!(with_archived, vec!["Middle", "Aardvark", "acme", "Zebra"]);
    }

    #[test]
    fn archive_and_delete_respect_guards() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.add_membership(community("active", pid, CommunityStatus::Active));
        acct.add_membership(community("left", pid, CommunityStatus::Left));

        // Active cannot be archived or deleted.
        assert!(acct.archive_membership("active", pid).is_err());
        assert!(acct.delete_membership("active", pid).is_err());
        // Unknown errors too.
        assert!(acct.archive_membership("missing", pid).is_err());

        // Inactive archives, then deletes.
        acct.archive_membership("left", pid).unwrap();
        assert!(acct.membership("left", pid).unwrap().archived);
        let removed = acct.delete_membership("left", pid).unwrap();
        assert_eq!(removed.vtc_did, "left");
        assert!(acct.membership("left", pid).is_none());
    }

    #[test]
    fn a_published_decision_sla_replaces_the_client_timeout() {
        let now = Utc::now();
        let mut acct = Account::default();
        let mut record = CommunityRecord::new_pending(
            "did:webvh:vetted".into(),
            None,
            "top/vetted".into(),
            PersonaId::new(),
            Uuid::new_v4(),
            now,
        );
        // Older than the 7-day default, younger than a 30-day SLA.
        record.requested_at = Some(now - TimeDelta::days(PENDING_TIMEOUT_DAYS + 3));
        acct.add_membership(record);

        let expired = acct.expire_stale_pending_with(now, |c| {
            if c.vtc_did == "did:webvh:vetted" {
                TimeDelta::days(30)
            } else {
                TimeDelta::days(PENDING_TIMEOUT_DAYS)
            }
        });
        assert!(expired.is_empty(), "the community said it may take 30 days");
        assert!(
            !acct.expire_stale_pending(now).is_empty(),
            "the default would have expired it"
        );
    }

    #[test]
    fn expire_stale_pending_sweeps_and_reports() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        let now = Utc::now();

        let mut stale = community("stale", pid, pending());
        stale.requested_at = Some(now - TimeDelta::days(10));
        acct.add_membership(stale);

        let mut fresh = community("fresh", pid, pending());
        fresh.requested_at = Some(now - TimeDelta::days(1));
        acct.add_membership(fresh);

        acct.add_membership(community("active", pid, CommunityStatus::Active));

        let expired = acct.expire_stale_pending(now);
        assert_eq!(expired, vec![("stale".to_string(), pid)]);
        assert_eq!(
            acct.membership("stale", pid).unwrap().status,
            CommunityStatus::Expired
        );
        assert!(matches!(
            acct.membership("fresh", pid).unwrap().status,
            CommunityStatus::Pending { .. }
        ));
        assert_eq!(
            acct.membership("active", pid).unwrap().status,
            CommunityStatus::Active
        );
    }

    #[test]
    fn needs_attention_covers_pending_and_unacked_terminals() {
        let pid = PersonaId::new();
        assert!(community("v", pid, pending()).needs_attention());
        assert!(!community("v", pid, CommunityStatus::Active).needs_attention());
        assert!(
            !community("v", pid, CommunityStatus::Left).needs_attention(),
            "Left is voluntary — never an action"
        );
        for s in [
            CommunityStatus::Rejected,
            CommunityStatus::Removed,
            CommunityStatus::Expired,
        ] {
            let mut c = community("v", pid, s.clone());
            assert!(c.needs_attention(), "{s:?} should nag until acknowledged");
            c.acknowledge();
            assert!(!c.needs_attention(), "{s:?} clears once acknowledged");
        }
    }

    #[test]
    fn fresh_terminal_outcome_resets_acknowledgement() {
        let pid = PersonaId::new();
        // Acknowledge a Rejected, re-activate, then get Removed: the new terminal
        // outcome must nag again — acknowledgement does not carry across
        // transitions.
        let mut c = community("v", pid, CommunityStatus::Rejected);
        c.acknowledge();
        assert!(!c.needs_attention());
        c.activate(Utc::now());
        assert!(!c.acknowledged, "returning to a live state clears the ack");
        assert!(!c.needs_attention(), "Active never nags");
        c.remove();
        assert!(
            c.needs_attention(),
            "a fresh Removed must nag despite the earlier ack"
        );
    }

    #[test]
    fn actions_required_count_excludes_acknowledged_and_archived() {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.add_membership(community("pending", pid, pending()));
        acct.add_membership(community("active", pid, CommunityStatus::Active));

        // Acknowledged Removed → does not count.
        let mut acked = community("acked", pid, CommunityStatus::Removed);
        acked.acknowledge();
        acct.add_membership(acked);

        // Archived (unacknowledged) Expired → hidden, so does not count.
        let mut archived = community("archived", pid, CommunityStatus::Expired);
        archived.archived = true;
        acct.add_membership(archived);

        // Unacknowledged Rejected → counts.
        acct.add_membership(community("rejected", pid, CommunityStatus::Rejected));
        // pending + rejected.
        assert_eq!(acct.actions_required_count(), 2);

        // Acknowledging the rejection drops the count to just the pending.
        acct.membership_mut("rejected", pid).unwrap().acknowledge();
        assert_eq!(acct.actions_required_count(), 1);
    }

    #[test]
    fn multiple_memberships_per_community_keyed_by_persona() {
        let mut acct = Account::default();
        let alice = PersonaId::new();
        let bob = PersonaId::new();
        let vtc = "did:web:acme";
        // The same community joined as two different personas — both coexist.
        acct.add_membership(community(vtc, alice, CommunityStatus::Active));
        acct.add_membership(community(vtc, bob, pending()));
        assert_eq!(acct.memberships_for(vtc).len(), 2);
        assert_eq!(acct.memberships().count(), 2);

        // Per-persona resolution + idempotency: a live membership blocks only the
        // same persona, never another.
        assert!(acct.membership(vtc, alice).is_some());
        assert!(acct.membership(vtc, bob).is_some());
        assert!(acct.has_live_membership(vtc, alice));
        assert!(acct.has_live_membership(vtc, bob));
        assert!(!acct.has_live_membership(vtc, PersonaId::new()));

        // Deleting one membership leaves the other (and the community bucket).
        acct.membership_mut(vtc, alice).unwrap().leave();
        acct.delete_membership(vtc, alice).unwrap();
        assert!(acct.membership(vtc, alice).is_none());
        assert!(acct.membership(vtc, bob).is_some());
    }

    #[test]
    fn legacy_single_record_config_loads_into_grouped_form() {
        // Pre-multi-membership configs stored ONE CommunityRecord per VTC DID —
        // the value was the record object, not a list. It must still load.
        let pid = PersonaId::new();
        let rec = community("did:web:acme", pid, CommunityStatus::Active);
        let legacy = serde_json::json!({
            "vta_did": "",
            "vta_url": "",
            "top_context_id": "",
            "communities": { "did:web:acme": rec },
        });
        let acct: Account = serde_json::from_value(legacy).expect("legacy config loads");
        assert_eq!(acct.memberships().count(), 1);
        assert!(acct.membership("did:web:acme", pid).is_some());

        // And a new-format config (value is a list) round-trips through the same path.
        let modern = serde_json::json!({
            "vta_did": "",
            "vta_url": "",
            "top_context_id": "",
            "communities": { "did:web:acme": [community("did:web:acme", pid, CommunityStatus::Active)] },
        });
        let acct: Account = serde_json::from_value(modern).expect("modern config loads");
        assert_eq!(acct.memberships().count(), 1);
    }
}

#[cfg(test)]
mod forward_compat_tests {
    //! D19 — a record written by a newer build must survive a round trip
    //! through this one. Harmless while a single writer owns the config; data
    //! loss the moment the record is shared (E2).
    use super::*;

    /// The failure this exists to stop: read, write back, and the newer build's
    /// fields are gone.
    #[test]
    fn unknown_persona_fields_survive_a_round_trip() {
        let json = serde_json::json!({
            "persona_id": Uuid::nil(),
            "did": "did:webvh:Qm:example.com:alice",
            "key_refs": [],
            "origin_context_id": "top",
            "created_at": "2026-08-20T00:00:00Z",
            "label": "Alice",
            // Written by a build that knows about something this one does not.
            "recovery_approver": "did:key:zApprover",
            "future_nested": { "a": 1, "b": [true, null] }
        });

        let record: PersonaRecord = serde_json::from_value(json).expect("deserialize");
        assert_eq!(record.label.as_deref(), Some("Alice"));

        let back = serde_json::to_value(&record).expect("serialize");
        assert_eq!(
            back.get("recovery_approver").and_then(|v| v.as_str()),
            Some("did:key:zApprover"),
            "an unknown field was dropped: {back}"
        );
        assert_eq!(
            back.get("future_nested"),
            Some(&serde_json::json!({ "a": 1, "b": [true, null] })),
            "nested structure was not preserved verbatim: {back}"
        );
    }

    /// `CommunityRecord` deserializes through a shadow, so the catch-all has to
    /// live there. This is the test that catches putting it on the wrong type —
    /// the record would compile, and silently drop everything.
    #[test]
    fn unknown_membership_fields_survive_the_shadow() {
        let json = serde_json::json!({
            "vtc_did": "did:webvh:Qm:vtc.example.com:acme",
            "display_name": "Acme",
            "sub_context_id": "top/acme",
            "persona_ref": Uuid::nil(),
            "status": { "state": "active" },
            "invented_by_a_newer_build": "keep me"
        });

        let record: CommunityRecord = serde_json::from_value(json).expect("deserialize");
        let back = serde_json::to_value(&record).expect("serialize");
        assert_eq!(
            back.get("invented_by_a_newer_build")
                .and_then(|v| v.as_str()),
            Some("keep me"),
            "the shadow dropped an unknown field: {back}"
        );
    }

    /// A record with nothing unknown must serialize byte-identically to before
    /// D19 — no empty `extra`, no new keys. Existing configs must not churn.
    #[test]
    fn a_known_record_gains_nothing_on_the_wire() {
        let (id, record) = {
            let id = PersonaId(Uuid::nil());
            (
                id,
                PersonaRecord {
                    persona_id: id,
                    did: "did:webvh:Qm:example.com:alice".to_string(),
                    did_document: None,
                    key_refs: Vec::new(),
                    mediator_did: None,
                    origin_context_id: "top".to_string(),
                    created_at: Utc::now(),
                    label: None,
                    extra: serde_json::Map::new(),
                },
            )
        };
        let _ = id;
        let json = serde_json::to_value(&record).expect("serialize");
        assert!(json.get("extra").is_none(), "{json}");
        let obj = json.as_object().expect("object");
        assert!(
            !obj.keys().any(|k| k.starts_with('_')),
            "unexpected synthetic key: {json}"
        );
    }

    /// The account itself carries unknowns too — it is the outermost shared
    /// record, so losing a field here loses whatever it described.
    #[test]
    fn unknown_account_fields_survive_a_round_trip() {
        let json = serde_json::json!({
            "vta_did": "did:webvh:Qm:vta.example.com:agent",
            "vta_url": "",
            "top_context_id": "top",
            "recovery_approver_set": ["did:key:zA", "did:key:zB"]
        });
        let account: Account = serde_json::from_value(json).expect("deserialize");
        let back = serde_json::to_value(&account).expect("serialize");
        assert_eq!(
            back.get("recovery_approver_set"),
            Some(&serde_json::json!(["did:key:zA", "did:key:zB"])),
            "{back}"
        );
    }
}
