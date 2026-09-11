use std::collections::HashMap;
use std::sync::Arc;

use dtg_credentials::DTGCredential;

/// Lazily-rendered raw credential JSON for credential detail views.
///
/// Holds the credential *source* (an `Arc`, so cloning a panel state is a
/// pointer bump) and pretty-prints it only when a detail view is actually
/// rendered — avoiding a `serde_json::to_string_pretty` per credential on
/// every `sync_from_config` (i.e. every config mutation / inbound message).
///
/// Two source shapes exist because the displayed JSON must be **byte-identical**
/// to the previous eager output:
///   - [`RawCredential::Vrc`] serializes the `DTGCommon` returned by
///     `vrc.credential()` directly, preserving struct field order.
///   - [`RawCredential::Value`] serializes a `serde_json::Value` (membership /
///     role credentials are stored as `Value` on the community record).
///
/// Routing everything through `serde_json::Value` is *not* equivalent: without
/// the `preserve_order` feature, `Value::Object` sorts keys alphabetically,
/// which would reorder the `DTGCommon` fields versus the original
/// struct-field-order output. Keeping the typed source preserves the bytes.
#[derive(Clone, Debug)]
pub enum RawCredential {
    /// A VRC — serialize its `DTGCommon` credential body directly.
    Vrc(Arc<DTGCredential>),
    /// A membership/role credential already held as a JSON value.
    Value(Arc<serde_json::Value>),
}

impl RawCredential {
    /// Pretty-print the credential to JSON, matching the previous eager
    /// `serde_json::to_string_pretty` output byte-for-byte. Called only at
    /// detail-render / clipboard-copy time.
    #[must_use]
    pub fn to_pretty_json(&self) -> String {
        match self {
            RawCredential::Vrc(vrc) => serde_json::to_string_pretty(vrc.credential())
                .unwrap_or_else(|_| "Failed to serialize credential".to_string()),
            RawCredential::Value(value) => serde_json::to_string_pretty(value.as_ref())
                .unwrap_or_else(|_| "Failed to serialize credential".to_string()),
        }
    }
}

// ****************************************************************************
// Content Panel State
// ****************************************************************************

/// Top-level state for the content panel (right side of main page).
#[derive(Clone, Debug, Default)]
pub struct ContentPanelState {
    /// Is this content panel currently focused?
    pub selected: bool,
    /// Inbox/tasks panel state
    pub inbox: InboxState,
    /// Relationships panel state
    pub relationships: RelationshipsState,
    /// Credentials (VRCs) panel state
    pub credentials: CredentialsState,
    /// Settings panel state
    pub settings: SettingsState,
    /// VTA service panel state
    pub vta: VtaState,
    /// Logs panel state
    pub logs: LogsState,
    /// Communities overview panel state
    pub communities: CommunitiesState,
    /// Per-community capabilities view (opened from Communities with `c`).
    pub capabilities: CapabilitiesState,
    /// The holder's own identity: personas, pool, profiles, and what each persona
    /// presents where.
    pub identity: IdentityState,
}

// ****************************************************************************
// Capabilities State
// ****************************************************************************

/// Load phase of the capabilities view. The reply arrives asynchronously
/// over DIDComm; `Loading` carries the send instant so the loop's sweep can
/// fail the query closed after the reply window.
#[derive(Clone, Debug, PartialEq)]
pub enum CapabilitiesPhase {
    Loading,
    Loaded,
    Failed(String),
}

/// The capabilities view for one selected community. `None` in
/// [`CapabilitiesState::view`] means the Communities panel renders normally.
#[derive(Clone, Debug)]
pub struct CapabilitiesView {
    /// Community (VTC) whose capabilities are shown.
    pub vtc_did: String,
    /// Persona the queries are sent as.
    pub persona: openvtc_core::config::account::PersonaId,
    /// Display name for the header.
    pub community_name: String,
    pub phase: CapabilitiesPhase,
    pub items: Vec<openvtc_core::capabilities::CapabilitySummary>,
    pub selected: usize,
    /// Detail view open for the selected capability.
    pub detail: bool,
    /// When `Some(index)`, an enable/disable of that capability awaits
    /// `y`/`⏎` confirmation.
    pub confirm_toggle: Option<usize>,
    /// threadId of the in-flight request (list or toggle).
    pub pending_thid: Option<String>,
    /// When the in-flight request was sent (reply-timeout sweep).
    pub sent_at: Option<std::time::Instant>,
    /// Transient status message.
    pub status_message: Option<String>,
}

impl CapabilitiesView {
    pub fn new(
        vtc_did: String,
        persona: openvtc_core::config::account::PersonaId,
        community_name: String,
    ) -> Self {
        Self {
            vtc_did,
            persona,
            community_name,
            phase: CapabilitiesPhase::Loading,
            items: Vec::new(),
            selected: 0,
            detail: false,
            confirm_toggle: None,
            pending_thid: None,
            sent_at: None,
            status_message: None,
        }
    }
}

/// Wrapper so `ContentPanelState` stays `Default`-derivable.
#[derive(Clone, Debug, Default)]
pub struct CapabilitiesState {
    pub view: Option<CapabilitiesView>,
}

// ****************************************************************************
// Communities State (R-C-*)
// ****************************************************************************

/// State for the Communities overview panel — the account's community
/// memberships, in display order (favourites first).
#[derive(Clone, Debug, Default)]
pub struct CommunitiesState {
    /// Display summaries of the (non-archived) communities, in display order.
    /// `Arc<[…]>` so cloning the panel state (per frame / per event) is a
    /// pointer bump rather than a deep copy; rebuilt wholesale in
    /// `sync_from_config`.
    pub items: Arc<[CommunitySummary]>,
    /// Currently selected index in the list.
    pub selected_index: usize,
    /// Number of communities raising the actions-required indicator (R-C-3).
    pub actions_required: usize,
    /// Transient status message.
    pub status_message: Option<String>,
    /// When `Some(index)`, a removal of that community is awaiting `y`/`n`
    /// confirmation (the panel shows a prompt and other keys are suppressed).
    pub confirm_delete: Option<usize>,
    /// When `Some(index)`, leaving that community is awaiting `y`/`n`
    /// confirmation (R-L-1).
    pub confirm_leave: Option<usize>,
    /// When `Some(index)`, cancelling that community's pending join is awaiting
    /// `y`/`n` confirmation. Transitions the record to `Withdrawn` so it can then
    /// be deleted or re-joined.
    pub confirm_withdraw: Option<usize>,
    /// Whether archived communities are included in the list (R-C-8). Off by
    /// default; toggled so archived records stay discoverable.
    pub show_archived: bool,
    /// The personhood challenge this member is part-way through answering, if
    /// any. `Some` between the community's challenge reply arriving and the
    /// assertion being sent or the challenge lapsing.
    ///
    /// Deliberately **not** persisted to the account. The challenge is
    /// single-use with a ten-minute life, so a copy surviving a restart could
    /// only ever be a stale one — and showing a member a match code the
    /// community has already forgotten is worse than showing none.
    pub personhood_challenge: Option<PersonhoodChallengeView>,
}

/// A live personhood challenge, as the panel shows it.
#[derive(Clone, Debug)]
pub struct PersonhoodChallengeView {
    /// Which membership it belongs to. A member may hold several, and a
    /// challenge minted for one community means nothing to another.
    pub vtc_did: String,
    pub persona: openvtc_core::config::account::PersonaId,
    /// The nonce the presentation must carry.
    pub challenge_id: uuid::Uuid,
    /// The eight characters to read aloud, derived from `challenge_id`.
    pub match_code: String,
    /// When the community stops accepting a presentation for it.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl PersonhoodChallengeView {
    /// Whether the community would still accept a presentation for this.
    ///
    /// The panel checks at render time rather than on a timer: a lapsed
    /// challenge should stop offering to be answered the moment a person looks
    /// at it, and the alternative — a countdown task per challenge — is state
    /// to keep in sync for no gain.
    pub fn is_live(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        now < self.expires_at
    }
}

/// Quick community-switcher overlay state (R-C-7). `Some` while the Ctrl+K popup
/// is open; it lists the **Active** communities (the only switchable ones) and
/// owns all key input until dismissed.
#[derive(Clone, Debug, Default)]
pub struct CommunitySwitcherState {
    /// Active communities, in display order (favourites first).
    pub items: Vec<SwitcherItem>,
    /// Highlighted entry.
    pub selected: usize,
}

/// "Create a new persona DID" overlay. `Some` while open; floats over the main
/// page like the switcher. Walks `Label` (enter a label) → `Working` (the VTA
/// mint runs) → `Done` (show + copy the DID) or `Failed`. The minted persona is
/// standalone (orphan) — handing its DID to a VTC lets the VTC issue a VIC bound
/// to it, which a later join then redeems on the clean join-as-subject path.
#[derive(Clone, Debug, Default)]
pub struct CreatePersonaState {
    /// Which step of the overlay is showing.
    pub phase: CreatePersonaPhase,
    /// Label/username input, used while in the `Label` phase.
    pub label: tui_input::Input,
    /// Progress / error lines shown in the `Working` and `Failed` phases.
    pub messages: Vec<String>,
    /// The minted persona `did:webvh`, set in the `Done` phase.
    pub did: Option<String>,
    /// Whether [`did`](Self::did) was copied to the clipboard.
    pub copied: bool,
}

/// "Manage agent names" overlay for a persona. `Some` while open; floats over
/// the main page. Lists the persona's names (parked ones included), and claims /
/// parks / resumes / removes them via the VTA's agent-name Trust Tasks. The
/// registry is authoritative — it is (re)fetched after every mutation, so what
/// the overlay shows is what the host actually holds.
#[derive(Clone, Debug, Default)]
pub struct AgentNameManagerState {
    /// The persona whose names are being managed.
    pub persona_did: String,
    /// The persona's label, for the overlay title.
    pub persona_label: String,
    /// The persona's domain-derived host (`example.com`), so the overlay can
    /// show the full name a local part will bind to. Empty if underivable.
    pub host: String,
    /// Current registry entries (name, enabled/parked, created-at). Empty until
    /// the first list completes.
    pub names: Vec<AgentNameRow>,
    /// Selected row in [`names`](Self::names), for park/resume/remove.
    pub selected: usize,
    /// New-name input (local part), used to claim a name.
    pub input: tui_input::Input,
    /// What the overlay is doing right now (input locked while `Working`).
    pub phase: AgentNameManagerPhase,
    /// Transient status / error line.
    pub message: Option<String>,
    /// The registry could not be read, so [`names`](Self::names) is not known to
    /// be the host's current answer.
    ///
    /// Only the empty case is actually dangerous, and it is why this flag
    /// exists: a claim that succeeded and a reload that then failed left the
    /// overlay rendering "No agent names yet." directly above "Applied, but
    /// could not reload the list" — the two lines contradict each other, and the
    /// prominent one says the opposite of what happened. The name was claimed,
    /// and the DID document proved it.
    pub list_stale: bool,
    /// Armed remove confirmation: `Some(row)` while awaiting `y`/Enter to
    /// release that name (a destructive op — the name becomes free for anyone to
    /// reclaim). Any other key cancels. `None` when nothing is armed.
    pub confirm_remove: Option<usize>,
}

/// One agent-name registry row shown in the manager overlay.
#[derive(Clone, Debug)]
pub struct AgentNameRow {
    /// Local part, without the `@`.
    pub name: String,
    /// Whether it currently resolves (`false` = parked, still reserved).
    pub enabled: bool,
}

/// What the [`AgentNameManagerState`] overlay is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AgentNameManagerPhase {
    /// Fetching the registry (initial open or post-mutation refresh).
    #[default]
    Loading,
    /// Idle — showing the list, accepting input and row actions.
    Ready,
    /// A mutation or check is running; input and actions are locked.
    Working,
}

/// Step of the [`CreatePersonaState`] overlay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CreatePersonaPhase {
    /// Awaiting the persona label (text input).
    #[default]
    Label,
    /// The VTA mint sequence is running (input locked).
    Working,
    /// The persona was minted; show the DID + copy affordance.
    Done,
    /// The mint failed; show the error.
    Failed,
}

/// One entry in the community switcher overlay.
#[derive(Clone, Debug)]
pub struct SwitcherItem {
    /// The community's VTC DID — half of the switch target.
    pub vtc_did: openvtc_core::config::account::VtcDid,
    /// The presented persona — the other half of the target, since a community
    /// may hold more than one membership.
    pub persona_ref: openvtc_core::config::account::PersonaId,
    /// Display name (resolved name, or the shortened VTC DID when unnamed).
    pub display_name: String,
    /// The presented persona's label, shown to disambiguate multiple memberships
    /// of the same community.
    pub persona_label: String,
    /// Whether this is the current working membership.
    pub is_current: bool,
}

/// Lightweight display summary of a community membership (no Arc/Mutex).
#[derive(Clone, Debug)]
pub struct CommunitySummary {
    /// Display name (resolved name, or the VTC DID when unnamed).
    pub display_name: String,
    /// Human-readable membership status (e.g. "Active", "Pending", "Left").
    pub status_label: String,
    /// Label of the persona presented to this community.
    pub persona_label: String,
    /// Member-since date (when Active), formatted; empty otherwise.
    pub member_since: String,
    /// Whether the user has starred this community (R-C-4).
    pub favourite: bool,
    /// Whether the membership is Active — the only state you can leave (R-L-1)
    /// or set as the working context (R-C-6).
    pub is_active: bool,
    /// Whether the membership is inactive (Left/Withdrawn/Rejected/Removed/
    /// Expired) — the only states that can be archived or deleted, and rendered
    /// read-only (D14).
    pub is_inactive: bool,
    /// Whether the membership is `Pending` — the only state whose join can be
    /// cancelled (withdrawn).
    pub is_pending: bool,
    /// Whether this is a `Pending` join the VTC hasn't acknowledged within the
    /// grace window — the submit may have been dropped rather than healthily
    /// awaiting a decision. Drives a warning hint on the row (D16).
    pub pending_unacknowledged: bool,
    /// Which transport carried the join submit, when the record knows.
    ///
    /// Only used to qualify the unacknowledged warning. Without it the warning
    /// reads the same whether the community ignored us or could not decode the
    /// transport it advertised, which is the ambiguity that made a real failure
    /// take a night to find. `None` for records written before it was recorded.
    pub submit_transport: Option<String>,
    /// Whether this community is archived (R-C-8); only shown when "show archived"
    /// is on, with a marker.
    pub archived: bool,
    /// Whether this community raises the actions-required indicator (R-C-3).
    pub needs_attention: bool,
    /// Full persona `did:webvh` presented to this community (troubleshooting
    /// detail). Empty if the `persona_ref` dangles.
    pub persona_did: String,
    /// Verified agent name for [`Self::persona_did`], if it has one.
    ///
    /// Shown on its own row *above* the DID rather than replacing it: the
    /// troubleshooting block's DID rows are what you read and copy when
    /// diagnosing, so the DID stays put and the name is added alongside.
    pub persona_agent_name: Option<String>,
    /// The community's VTC `did:webvh` (troubleshooting detail).
    pub vtc_did: String,
    /// Verified agent name for [`Self::vtc_did`], if it has one.
    pub vtc_agent_name: Option<String>,
    /// The per-community sub-context id (troubleshooting detail).
    pub sub_context_id: String,
    /// The join request id while `Pending`; empty otherwise.
    pub request_id: String,
    /// Whether the membership credential (VMC) has been received + stored.
    pub has_membership_credential: bool,
    /// Whether the role endorsement credential (VEC) has been received.
    pub has_role_credential: bool,
}

// ****************************************************************************
// Personas State — the holder's own identity
// ****************************************************************************

/// Which part of the identity story the pane is showing.
///
/// The order is the story: who I am, what I know about myself, what I choose to
/// show, and who sees which of it. Every tab after the first depends on the one
/// before it, so a holder who reads them in order never meets a term that has
/// not been introduced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PersonaTab {
    /// The persona DIDs themselves — a persona as an *identity*.
    #[default]
    Personas,
    /// The attribute pool: the attributes, held once.
    Attributes,
    /// Named projections over the pool.
    Profiles,
    /// The facets: parts of a life, and the projections that belong to them.
    Facets,
    /// Which persona each community sees, and what it presents there.
    Communities,
    /// What has actually left, and to whom.
    Disclosures,
}

impl PersonaTab {
    /// Every tab, in display order.
    #[must_use]
    pub fn all() -> [PersonaTab; 6] {
        [
            PersonaTab::Personas,
            PersonaTab::Attributes,
            PersonaTab::Profiles,
            PersonaTab::Facets,
            PersonaTab::Communities,
            PersonaTab::Disclosures,
        ]
    }

    /// The tab's name in the header strip — the words a person reads, which are
    /// not the words the code and the wire use
    /// (`design-docs/persona-vocabulary.md`).
    ///
    /// The variants keep the spec's nouns because that is what they address:
    /// `Profiles` is `persona/profile/*`. The screen says *Faces*, because
    /// "profile" already means three things in this product and "my LinkedIn
    /// page" to everyone else; `Facets` is `persona/facet/*` and the screen
    /// says *Worlds*, because nobody says "my work facet" to a friend.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PersonaTab::Personas => "Personas",
            PersonaTab::Attributes => "Your attributes",
            PersonaTab::Profiles => "Faces",
            PersonaTab::Facets => "Worlds",
            PersonaTab::Communities => "Communities",
            PersonaTab::Disclosures => "What has left",
        }
    }

    /// Whether this tab's contents come from the agent rather than `Config`.
    ///
    /// Drives which tabs a refresh has anything to do, and which can draw
    /// before the agent has ever answered. Personas are local: an account with no
    /// VTA session still has personas, and a pane that showed nothing until the
    /// network answered would be lying about the ones on disk.
    #[must_use]
    pub fn needs_agent(self) -> bool {
        matches!(
            self,
            PersonaTab::Attributes
                | PersonaTab::Profiles
                | PersonaTab::Facets
                | PersonaTab::Communities
                | PersonaTab::Disclosures
        )
    }

    #[must_use]
    pub fn next(self) -> PersonaTab {
        match self {
            PersonaTab::Personas => PersonaTab::Attributes,
            PersonaTab::Attributes => PersonaTab::Profiles,
            PersonaTab::Profiles => PersonaTab::Facets,
            PersonaTab::Facets => PersonaTab::Communities,
            PersonaTab::Communities => PersonaTab::Disclosures,
            PersonaTab::Disclosures => PersonaTab::Personas,
        }
    }

    #[must_use]
    pub fn prev(self) -> PersonaTab {
        match self {
            PersonaTab::Personas => PersonaTab::Disclosures,
            PersonaTab::Attributes => PersonaTab::Personas,
            PersonaTab::Profiles => PersonaTab::Attributes,
            PersonaTab::Facets => PersonaTab::Profiles,
            PersonaTab::Communities => PersonaTab::Facets,
            PersonaTab::Disclosures => PersonaTab::Communities,
        }
    }
}

/// One community membership, as the Communities tab needs it: which persona this
/// community sees, and enough to look up what that persona presents.
#[derive(Clone, Debug, Default)]
pub struct PersonaMembership {
    /// Display name of the community.
    pub community_name: String,
    /// The VTA context the binding lives in.
    pub sub_context_id: String,
    /// The persona DID this community sees.
    pub persona_did: String,
    /// The holder's label for that persona (or its agent name / DID).
    pub persona_label: String,
    /// Membership lifecycle, already worded for display.
    pub status_label: String,
    /// How many *other* communities are shown this same persona.
    ///
    /// The linkage number. Two communities shown one persona can compare notes and
    /// discover they are talking to the same person, which is the single most
    /// consequential fact about a persona arrangement and the one a holder
    /// cannot recompute by looking at one row.
    pub shared_with: usize,
}

/// A confirmation the pane is waiting on. One at a time, because the panel has
/// one prompt line and a holder answering `y` must never be able to wonder
/// which question they answered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PersonaConfirm {
    #[default]
    None,
    /// Remove an orphan persona DID (index into `personas`).
    ///
    /// The one variant still addressed by index, because it hands off to the
    /// existing identity-deletion path, which takes one and re-resolves the DID
    /// under its own guards before anything is removed.
    DeletePersona(usize),
    /// Delete a pool attribute, named by what it is rather than by where it sat.
    ///
    /// **Not an index.** An armed question survives across a listing that
    /// arrives while it is on screen, and an index into the old listing points
    /// at a different attribute in the new one — which would delete something
    /// the operator never selected while showing them the name of something
    /// else. The name is carried for the same reason: the prompt has to name
    /// what was armed, not whatever now occupies that row.
    ///
    /// `cascade` is decided when the question is put, from the profile listing
    /// the pane already holds: the VTA refuses a plain delete while a profile
    /// references the attribute, so cascading is what will actually happen and
    /// the prompt says so the first time.
    DeleteAttribute {
        attribute_id: String,
        name: String,
        cascade: bool,
    },
    /// Delete a profile. Named, not indexed, for the reason above.
    ///
    /// `unbind` is the same decision one layer up: it makes every persona
    /// presenting under this profile present nothing, and it is decided from
    /// the binding map rather than discovered from a refusal.
    DeleteProfile {
        profile_id: String,
        name: String,
        unbind: bool,
    },
    /// Delete a world. Named, not indexed, for the reason above.
    ///
    /// `faces` is how many faces belong to it now, so the prompt can say what
    /// will *not* happen: a world arranges, it does not contain, and "delete
    /// Work" reads to almost everyone as though the faces in it go too. The
    /// count is resolved against the face list rather than taken from the
    /// record, so it is the number the holder can see on screen.
    DeleteFacet {
        facet_id: String,
        name: String,
        expected_version: Option<u64>,
        faces: usize,
    },
    /// Clear what one persona presents in one context — the pair the binding is
    /// addressed by, carried whole for the same reason as above.
    Unbind {
        context_id: String,
        persona_did: String,
        community: String,
    },
}

/// Which field of the attribute editor has the keyboard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttributeField {
    /// The vocabulary token (`email.work`).
    #[default]
    ClaimType,
    /// The holder's own label.
    Label,
    /// String / number / boolean / date / object.
    ValueType,
    /// The value itself.
    Value,
}

impl AttributeField {
    #[must_use]
    pub fn next(self) -> AttributeField {
        match self {
            AttributeField::ClaimType => AttributeField::Label,
            AttributeField::Label => AttributeField::ValueType,
            AttributeField::ValueType => AttributeField::Value,
            AttributeField::Value => AttributeField::ClaimType,
        }
    }

    #[must_use]
    pub fn prev(self) -> AttributeField {
        match self {
            AttributeField::ClaimType => AttributeField::Value,
            AttributeField::Label => AttributeField::ClaimType,
            AttributeField::ValueType => AttributeField::Label,
            AttributeField::Value => AttributeField::ValueType,
        }
    }
}

/// The attribute editor — create when `attribute_id` is `None`, else edit.
#[derive(Clone, Debug, Default)]
pub struct AttributeForm {
    /// The attribute being edited; `None` creates a new one.
    pub attribute_id: Option<String>,
    /// The version the form was opened against, sent back as the write's
    /// precondition so an edit made elsewhere in the meantime is refused rather
    /// than silently overwritten.
    pub expected_version: Option<u64>,
    pub claim_type: tui_input::Input,
    pub label: tui_input::Input,
    /// Index into [`VALUE_TYPES`].
    pub value_type: usize,
    pub value: tui_input::Input,
    pub field: AttributeField,
    /// Why the last submit did not go through — a parse failure on the value,
    /// or the VTA's own refusal. Shown against the form, not the list, so the
    /// holder keeps what they typed.
    pub error: Option<String>,
    /// A write is in flight; the form is read-only until it lands.
    pub working: bool,
}

/// The value types the editor offers, in the order it cycles them. Mirrors the
/// SDK's `ValueType`; kept as strings because the form is a UI object and the
/// conversion belongs at the write, in `persona::pool::value_type_from_str`.
pub const VALUE_TYPES: [&str; 5] = ["string", "number", "boolean", "date", "object"];

/// Which half of the profile editor has the keyboard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProfileFormFocus {
    #[default]
    Name,
    Entries,
}

/// The profile editor: a name, and a tick-list over the pool.
#[derive(Clone, Debug, Default)]
pub struct ProfileForm {
    /// The profile being edited; `None` creates a new one.
    pub profile_id: Option<String>,
    pub expected_version: Option<u64>,
    pub name: tui_input::Input,
    /// Attribute ids the holder has ticked, in the order they were ticked —
    /// which is the order the profile will present them in.
    pub ticked: Vec<String>,
    /// Cursor into the pool list.
    pub cursor: usize,
    pub focus: ProfileFormFocus,
    /// Pinned / overridden / inline entries read from the profile, carried here
    /// so the save writes them back untouched.
    ///
    /// This build's editor owns live references and nothing else. Rebuilding
    /// the profile from only the ticked boxes would delete the other forms the
    /// first time a holder renamed it, and the deletion would be invisible —
    /// the profile would still resolve, just to less than it did.
    pub preserved: Vec<vta_sdk::protocols::persona::ProfileEntry>,
    pub error: Option<String>,
    pub working: bool,
}

/// The profile picker for one membership: what should this persona present here?
#[derive(Clone, Debug, Default)]
pub struct BindPicker {
    /// The binding this picker will write, named rather than indexed. The
    /// membership list is rebuilt from `Config` on every sync — an inbound
    /// message is enough — and an index into the old list would point at a
    /// different membership in the new one, sending the holder's identity to a
    /// community they were not looking at.
    pub context_id: String,
    pub persona_did: String,
    /// Display only: who is being shown something, and as whom.
    pub community: String,
    pub persona_label: String,
    /// Cursor over the options, where 0 is always "present nothing" — a
    /// first-class choice rather than the absence of one, because a persona that
    /// deliberately shows nothing is a common and legitimate arrangement.
    pub cursor: usize,
    pub working: bool,
    pub error: Option<String>,
}

/// The editor for one world: its name, its colour, its mark.
///
/// Membership is **not** edited here, and the omission is deliberate. A world's
/// faces are changed from the Faces tab, where the holder can see the face they
/// are moving; a second membership editor would be a second place to get the
/// replace semantics of `persona/facet/put` wrong. What the form does carry is
/// the whole membership as read, so that saving a rename puts it back untouched
/// — the field below is that copy, and it is why this form cannot be built from
/// nothing.
#[derive(Clone, Debug, Default)]
pub struct FacetForm {
    /// The world being edited; `None` creates a new one.
    pub facet_id: Option<String>,
    pub expected_version: Option<u64>,
    pub name: tui_input::Input,
    /// Cursor into [`Colour::all`](openvtc_core::persona::facet::Colour::all).
    pub colour: usize,
    /// One or two emoji, or nothing. Optional, and a terminal that cannot draw
    /// it loses nothing that carries meaning.
    pub icon: tui_input::Input,
    pub focus: FacetFormFocus,
    /// The membership as it was read, written back unchanged.
    ///
    /// `put` is a replace: omitting these means *empty them*, not "leave them
    /// alone". A form that rebuilt the record from its own fields would empty
    /// the world every time somebody renamed it, and the loss would be silent —
    /// the world would still be there, just with nothing in it.
    pub face_ids: Vec<String>,
    pub attribute_ids: Vec<String>,
    pub error: Option<String>,
    pub working: bool,
}

/// Which field of [`FacetForm`] has the keyboard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FacetFormFocus {
    #[default]
    Name,
    Colour,
    Icon,
}

impl FacetFormFocus {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Colour,
            Self::Colour => Self::Icon,
            Self::Icon => Self::Name,
        }
    }

    #[must_use]
    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Icon,
            Self::Colour => Self::Name,
            Self::Icon => Self::Colour,
        }
    }
}

/// The world picker for one face: which part of your life does this belong to?
#[derive(Clone, Debug, Default)]
pub struct FacePlacer {
    /// The face being moved, named rather than indexed — the face list is
    /// re-sorted by world on every read, so an index taken before a refresh
    /// would name a different face afterwards, and this picker's whole job is
    /// to move a specific one.
    pub profile_id: String,
    /// Display only: which face the holder is looking at.
    pub face_name: String,
    /// Cursor over the options, where 0 is always "belongs to no world" — a
    /// first-class choice rather than the absence of one. Every face belonging
    /// somewhere is fine too, and a picker with no way back out would make a
    /// world a trap rather than an arrangement.
    pub cursor: usize,
    pub working: bool,
    pub error: Option<String>,
}

/// What owns the keyboard inside the pane.
#[derive(Clone, Debug, Default)]
pub enum PersonaMode {
    #[default]
    View,
    Attribute(AttributeForm),
    Profile(ProfileForm),
    Facet(FacetForm),
    PlaceFace(FacePlacer),
    Bind(BindPicker),
}

/// The persona pane: every surface for the holder's own identity, in one place.
///
/// Five of the six tabs are served by the agent and one by `Config`, and the
/// difference is load-bearing rather than incidental. Personas are on disk, so
/// they draw at launch with no session; the pool, the profiles, the facets and
/// the bindings are the agent's, so each of them has to be able to say "I could
/// not ask" distinctly from "you hold nothing" — see
/// [`load_error`](Self::load_error).
#[derive(Clone, Debug, Default)]
pub struct IdentityState {
    pub tab: PersonaTab,

    // ── Personas (from `Config`) ────────────────────────────────────────────
    /// Every persona DID in the account, with how many communities present it.
    pub personas: Arc<[ManagedDid]>,
    pub persona_selected: usize,

    // ── Communities (from `Config`, annotated from the agent) ────────────
    pub memberships: Arc<[PersonaMembership]>,
    pub membership_selected: usize,
    /// What each persona presents in each community's context, keyed by
    /// `(sub_context_id, persona_did)` — the pair `persona/binding/get` is
    /// addressed by, and the pair every membership row already carries.
    ///
    /// **Session state, deliberately not persisted.** The agent-name cache is
    /// persisted, and the difference is the point: a verified name is a
    /// property of a DID document that rarely changes and costs a network
    /// round-trip to establish, so showing it instantly at launch is worth
    /// keeping on disk. A binding is the holder's own current decision, cheap
    /// to fetch, and editable from `pnm` at any moment — a persisted copy would
    /// show what they used to present, on the one surface whose job is to tell
    /// them what they present now. `prune_agent_name_negatives` already draws
    /// this line for negatives; this is the same argument applied to the whole
    /// record.
    ///
    /// An absent entry is not "presents nothing" — see
    /// [`BindingSummary::unknown`](openvtc_core::persona::binding::BindingSummary::unknown).
    /// Read by the communities panel too, which renders the same fact on its
    /// own rows; it lives here because this is the pane that changes it.
    pub bindings: HashMap<(String, String), openvtc_core::persona::binding::BindingSummary>,

    // ── The pool (from the agent) ────────────────────────────────────────
    pub attributes: Arc<[openvtc_core::persona::pool::PoolAttribute]>,
    pub attribute_selected: usize,
    /// Whether the listing asked for values.
    ///
    /// Off by default, and it re-reads rather than filtering what it already
    /// holds: a list fetched without values does not *have* them, which is the
    /// difference between an opt-in and a blindfold. Toggling it is the
    /// holder asking to see their own identity, so it is a keypress they make
    /// on purpose and a network round-trip, not a display flag.
    pub show_values: bool,
    /// The one attribute whose value is being shown unmasked, by `attribute_id`.
    ///
    /// One, and only while it is also the selected row — the render checks
    /// both. Sensitivity is a property of the claim type, so a card number and
    /// a date of birth are masked even in a listing the holder asked to see
    /// (`openvtc_core::persona::claim_types`), and lifting that is a per-attribute
    /// act rather than a mode the pane can be left in.
    ///
    /// Cleared by moving the selection, changing tab, or a re-read. A reveal
    /// that outlived the row it was granted for would be a global unmask
    /// arrived at one keypress at a time.
    pub revealed_attribute: Option<String>,

    // ── Links (from the agent) ───────────────────────────────────────────
    /// Where the holder's identities join up, and which joins cross a world.
    ///
    /// Read alongside the pool rather than on demand: the answer is computed
    /// across every attribute at once, so a per-row question would be one
    /// round-trip each for a page the agent builds in one.
    ///
    /// Empty means the agent found nothing *or* does not serve
    /// `persona/correlation/analyze`. Neither is a failure; a read that failed
    /// lands in [`load_error`](Self::load_error), because a clean bill of
    /// health nobody computed is the answer that misleads.
    pub links: Arc<[openvtc_core::persona::correlation::Finding]>,

    // ── Worlds (from the agent) ──────────────────────────────────────────
    /// The parts of the holder's life, and which faces belong to them.
    ///
    /// Empty is a real answer and means the holder has arranged nothing yet —
    /// or that the agent predates `persona/facet/*`, which amounts to the same
    /// thing from here, because such a holder cannot have a world to show. A
    /// read that *failed* lands in [`load_error`](Self::load_error) instead.
    pub facets: Arc<[openvtc_core::persona::facet::Facet]>,
    pub facet_selected: usize,

    // ── Profiles (from the agent) ────────────────────────────────────────
    pub profiles: Arc<[openvtc_core::persona::profile::ProfileSummary]>,
    pub profile_selected: usize,
    /// The profile opened with Enter, resolved to what it would present.
    pub open_profile: Option<openvtc_core::persona::profile::ProfileDetail>,
    /// The claim under the cursor inside that opened face.
    ///
    /// Separate from [`profile_selected`](Self::profile_selected), which keeps
    /// pointing at the face in the list behind the detail — closing the detail
    /// has to land back on the face that was opened, so the two cursors cannot
    /// share a field.
    pub face_claim_selected: usize,
    /// The one claim of the opened face being shown unmasked, by index.
    ///
    /// The same grant the attributes tab makes, on the same terms: one claim,
    /// and only while it is also the selected one — the render checks both.
    /// Indices rather than identifiers because a resolved claim has no id of
    /// its own to key on (an inline value has no pool attribute behind it), and
    /// the order is fixed for as long as a detail is open: every path that
    /// replaces `open_profile` clears this too.
    pub revealed_face_claim: Option<usize>,

    // ── Disclosures (from the agent) ─────────────────────────────────────
    /// What has actually left, newest first, across every context.
    ///
    /// Read-only, and capped: the record is append-only and unbounded, so the
    /// pane asks for a page of it rather than all of it. See
    /// [`crate::state_handler::persona_actions::DISCLOSURE_PAGE`].
    pub disclosures: Arc<[openvtc_core::persona::disclosure::DisclosureRow]>,
    pub disclosure_selected: usize,

    // ── Shared ───────────────────────────────────────────────────────────
    /// The claim-type registry this agent resolves against — how each value is
    /// shown, and what it takes to let it leave.
    ///
    /// Read once per load and held for the session, because it is a constant
    /// for a given agent. It starts as the compiled copy so the very first
    /// frame has a table to draw with; the read replaces it, and
    /// [`Registry::is_fallback`](openvtc_core::persona::claim_types::Registry::is_fallback)
    /// is what lets the pane say when a masking decision came from a table the
    /// holder's own agent did not supply.
    pub claim_types: openvtc_core::persona::claim_types::Registry,
    /// Whether [`claim_types`](Self::claim_types) is still the compiled copy
    /// this pane started with.
    ///
    /// Separate from `Registry::is_fallback`, which answers a different
    /// question: that one says *the agent told us it cannot serve the table*,
    /// this one says *we have not asked yet*. Collapsing them would make a
    /// refresh re-read a constant, or make a never-asked pane claim its agent
    /// is old.
    pub claim_types_loaded: bool,
    /// The `did:key` this install authenticates to the agent as, when the
    /// account is agent-managed.
    ///
    /// Display-only, and here for one line: the grant hint shown when the agent
    /// refuses a read names a `pnm acl update` command, and that command needs
    /// this DID. A placeholder there is a command the reader cannot run — they
    /// would have to go and find the DID on another pane first, which is the
    /// step the hint exists to remove.
    pub agent_credential_did: Option<String>,
    /// A read is in flight.
    pub loading: bool,
    /// Why the last read failed, kept until one succeeds.
    ///
    /// An empty pool and an unreachable agent look identical on screen unless
    /// something says otherwise, and of the two, "you have no attributes" is
    /// the confident wrong answer about the holder's own data (VTI R6.4).
    pub load_error: Option<String>,
    /// Whether the agent-served tabs have ever been read in this session.
    pub loaded: bool,
    /// A refresh was asked for while one was in flight. Re-issued when the
    /// domain frees, rather than dropped: the request that prompted it (a write
    /// that just landed) is exactly when a stale list misleads most.
    pub refresh_queued: bool,
    pub confirm: PersonaConfirm,
    pub mode: PersonaMode,
    /// Transient status line.
    pub status_message: Option<String>,
}

impl IdentityState {
    /// What one membership's persona presents, as far as we know.
    ///
    /// Falls back to `unknown` rather than a default summary: the two render
    /// differently on purpose, and a caller reaching for `unwrap_or_default()`
    /// would turn "we have not asked" into "you are sharing nothing".
    #[must_use]
    pub fn binding_for(
        &self,
        membership: &PersonaMembership,
    ) -> openvtc_core::persona::binding::BindingSummary {
        self.bindings
            .get(&(
                membership.sub_context_id.clone(),
                membership.persona_did.clone(),
            ))
            .cloned()
            .unwrap_or_else(openvtc_core::persona::binding::BindingSummary::unknown)
    }
}

// ****************************************************************************
// VTA State
// ****************************************************************************

/// State for the VTA service information panel.
#[derive(Clone, Debug, Default)]
pub struct VtaState {
    /// Active configuration profile name
    pub profile: String,
    /// VTA context name (fetched from VTA service)
    pub context_name: Option<String>,
    /// Persona DID
    pub persona_did: String,
    /// Verified agent name for the persona DID (`example.com/@me`), if cached —
    /// shown above the DID in the panel.
    pub persona_agent_name: Option<String>,
    /// Mediator DID
    pub mediator_did: String,
    /// Verified agent name for [`mediator_did`](Self::mediator_did), if cached.
    pub mediator_agent_name: Option<String>,
    /// VTA service URL
    pub vta_url: String,
    /// VTA service DID
    pub vta_did: String,
    /// Verified agent name for [`vta_did`](Self::vta_did), if cached.
    pub vta_agent_name: Option<String>,
    /// Credential DID used for VTA authentication
    pub credential_did: String,
    /// Which transports the VTA advertises and which one this process is on.
    pub transports: VtaTransports,
    /// Total number of keys managed
    pub key_count: usize,
    /// Number of persona keys
    pub persona_key_count: usize,
    /// Number of relationship keys
    pub relationship_key_count: usize,
    /// Whether the VTA key backend is in use
    pub is_vta_managed: bool,
    /// DIDs in use (persona + relationship R-DIDs). `Arc<[…]>` for cheap
    /// per-frame clones; rebuilt wholesale in `sync_from_config`.
    pub active_dids: Arc<[ActiveDid]>,

    /// Invitation credentials (VICs) the holder holds in the VTA credential
    /// vault, for the VIC manager. Populated by an async query (not derived from
    /// `Config`), refreshed after each mutation. `Arc<[…]>` for cheap per-frame
    /// clones.
    pub vics: Arc<[VicSummary]>,
    /// Selected index into [`Self::vics`] (VIC manager navigation).
    pub vic_selected_index: usize,
    /// When `Some(index)`, a soft-delete of that VIC is awaiting `y`/`n`.
    pub confirm_delete_vic: Option<usize>,
    /// When `Some(index)`, a *purge* (irreversible) of that VIC is awaiting
    /// `y`/`n` — kept distinct from the soft-delete arm so the prompt is explicit.
    pub confirm_purge_vic: Option<usize>,
    /// Whether the VIC list includes archived + soft-deleted entries (the
    /// `include_archived` / `include_deleted` query modifiers). Toggled with `i`.
    pub vic_show_inactive: bool,
    /// A vault query is in flight. The list load is a network round-trip that no
    /// longer blocks the loop, so the panel says so rather than showing a stale
    /// (or empty) list with no sign that an answer is coming.
    pub vic_loading: bool,
    /// A refresh was asked for while one was already in flight, and must be
    /// re-run once it lands. Set by the spawn helper when the busy-guard rejects
    /// it: the in-flight query was issued *before* the mutation (or filter flip)
    /// that prompted this request, so its result is already stale — dropping the
    /// request instead would leave an archived VIC rendered as active until the
    /// next manual refresh.
    pub vic_refresh_queued: bool,
}

/// How this process reaches the VTA, and what the VTA says it offers.
///
/// Two independently-sourced halves, deliberately kept apart:
///
/// - [`in_use`](Self::in_use) is what *this* process connects over, derived
///   synchronously from the stored key backend — `build_runtime_vta_client`
///   picks DIDComm when a mediator DID is recorded and REST otherwise, so the
///   same condition decides the label. No network, always accurate.
/// - [`advertised`](Self::advertised) is what the VTA's own DID document
///   publishes (`#tsp`, `#vta-rest` and `DIDCommMessaging` services), which needs a
///   resolve. `None` until the background probe lands, so the panel can say
///   "checking…" rather than claim a transport is unavailable merely because
///   nothing has been asked yet.
///
/// Keeping them separate is what makes the panel able to distinguish "the VTA
/// offers REST too" from "we could not ask" (VTI R6.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VtaTransports {
    /// Transport this process is configured to use.
    pub in_use: VtaTransport,
    /// REST base URL from the stored config, if any. This is the URL that was
    /// `VTA URL` before — kept as *detail under* the transport rather than as
    /// the headline fact.
    pub rest_url: String,
    /// What the VTA's DID document advertises. `None` until probed.
    pub advertised: Option<AdvertisedTransports>,
}

/// One VTA transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VtaTransport {
    /// DIDComm via a mediator (the VTA session is the authenticator).
    #[default]
    DidComm,
    /// REST challenge-response against the VTA URL.
    Rest,
}

impl VtaTransport {
    /// Label for the panel.
    pub fn label(self) -> &'static str {
        match self {
            VtaTransport::DidComm => "DIDComm",
            VtaTransport::Rest => "REST",
        }
    }
}

/// The transports a VTA's DID document advertises, as resolved by
/// `vta_sdk::provision_client::resolve_vta`.
///
/// This is *offered*, not *usable*: a transport appears here because the VTA
/// publishes it, regardless of whether this CLI can speak it. TSP is currently
/// the case in point — advertised by the VTA, not yet spoken by us — and the
/// panel has to keep those apart, because "not offered" and "offered but we
/// cannot use it" call for different operator action (VTI R6.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdvertisedTransports {
    /// Mediator DID from the document's `#tsp` (`TSPTransport`) service, if any.
    ///
    /// Read from that entry specifically — *not* assumed to equal
    /// [`mediator_did`](Self::mediator_did), even though a dual-transport VTA
    /// usually points both at the same mediator.
    pub tsp_mediator_did: Option<String>,
    /// Mediator DID from the document's `DIDCommMessaging` service, if any.
    pub mediator_did: Option<String>,
    /// REST base URL from the document's `#vta-rest` service, if any.
    pub rest_url: Option<String>,
    /// Set when the probe itself failed — the transports are unknown, not
    /// absent. Rendered as an explicit "could not check" so an unreachable
    /// publication endpoint never reads as "the VTA offers nothing".
    pub error: Option<String>,
}

/// Display summary of one held VIC, mapped from the VTA credential-vault
/// `CredentialDescriptor` (descriptor only — the credential body is never
/// fetched for the list). Wire fields are camelCase.
#[derive(Clone, Debug, Default)]
pub struct VicSummary {
    /// Vault id — the handle for archive / delete / restore / purge.
    pub id: String,
    /// Issuer DID (the community that issued the invitation), if recorded.
    pub issuer: String,
    /// Verified agent name for [`issuer`](Self::issuer), if cached.
    ///
    /// The issuer is a community VTC DID, which the agent-name background sweep
    /// already targets, so a name is usually available. Not set by
    /// [`VicSummary::from_descriptor`] — that maps a vault descriptor and has no
    /// `Config` — but stitched on in `MainPageState::sync_vic_agent_names`,
    /// which runs at every `sync_from_config` and after every vault reload.
    pub issuer_agent_name: Option<String>,
    /// Validity status: "valid" / "expired" / "revoked" / "unknown".
    pub status: String,
    /// Archival lifecycle (active / archived / deleted), orthogonal to status.
    pub lifecycle: VicLifecycle,
    /// RFC 3339 validity-window end, if declared (shown as detail).
    pub valid_until: String,
}

impl VicSummary {
    /// Map one `credentials[]` descriptor (camelCase JSON) to a summary.
    pub fn from_descriptor(d: &serde_json::Value) -> Self {
        let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        VicSummary {
            id: s("id"),
            issuer: s("issuerDid"),
            // No `Config` here; filled in by `sync_vic_agent_names`.
            issuer_agent_name: None,
            status: {
                let st = s("status");
                if st.is_empty() {
                    "unknown".to_string()
                } else {
                    st
                }
            },
            lifecycle: VicLifecycle::from_wire(d.get("lifecycle").and_then(|v| v.as_str())),
            valid_until: s("validUntil"),
        }
    }
}

/// The archival lifecycle state of a held VIC (vault `lifecycle` dimension).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VicLifecycle {
    /// Live and presentable. Omitted from the descriptor → defaults here.
    #[default]
    Active,
    /// Hidden from presentation but retained; restorable via unarchive.
    Archived,
    /// Soft-deleted tombstone; restorable within the grace window, else purged.
    Deleted,
}

impl VicLifecycle {
    fn from_wire(s: Option<&str>) -> Self {
        match s {
            Some("archived") => VicLifecycle::Archived,
            Some("deleted") => VicLifecycle::Deleted,
            _ => VicLifecycle::Active,
        }
    }

    /// Short tag for the panel row.
    pub fn tag(self) -> &'static str {
        match self {
            VicLifecycle::Active => "active",
            VicLifecycle::Archived => "archived",
            VicLifecycle::Deleted => "deleted",
        }
    }
}

/// "Import an invitation credential" overlay (paste a VIC → store it in the
/// vault). `Some` while open; floats over the main page like the create-persona
/// overlay. Walks `Input` (paste the VIC JSON) → `Working` (the vault receive
/// runs) → `Done` or `Failed`.
#[derive(Clone, Debug, Default)]
pub struct AddVicState {
    /// Which step of the overlay is showing.
    pub phase: AddVicPhase,
    /// The pasted VIC JSON, used while in the `Input` phase.
    pub input: tui_input::Input,
    /// Progress / validation / error lines.
    pub messages: Vec<String>,
}

/// Step of the [`AddVicState`] overlay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AddVicPhase {
    /// Awaiting the pasted VIC JSON (validated on submit).
    #[default]
    Input,
    /// The vault receive is running (input locked).
    Working,
    /// Stored successfully.
    Done,
    /// Validation or storage failed; show the error.
    Failed,
}

/// A persona DID in the account's context, for the DID manager view.
#[derive(Clone, Debug, Default)]
pub struct ManagedDid {
    /// The persona `did:webvh`.
    pub did: String,
    /// Verified agent name for [`did`](Self::did) (`example.com/@me`), if one is
    /// cached. Shown in place of the DID; the DID is the fallback. Populated in
    /// `sync_from_config` from the persisted cache, which only ever holds
    /// round-tripped (verified) lookups.
    pub agent_name: Option<String>,
    /// Optional human label.
    pub label: String,
    /// How many communities present this persona (0 ⇒ orphan).
    pub bound_communities: usize,
    /// Whether this is the account's current active persona.
    pub is_active: bool,
}

/// A DID in active use within this context.
#[derive(Clone, Debug, Default)]
pub struct ActiveDid {
    /// The DID string
    pub did: String,
    /// Verified agent name for [`did`](Self::did), if one is cached. Shown in
    /// place of the DID; the DID is the fallback. A relationship R-DID is a
    /// per-relationship pseudonym and never carries one, so this stays `None`
    /// for those rows.
    pub agent_name: Option<String>,
    /// Human-readable label
    pub label: String,
}

// ****************************************************************************
// Inbox State
// ****************************************************************************

/// State for the inbox/tasks panel.
#[derive(Clone, Debug, Default)]
pub struct InboxState {
    /// Display summaries of all pending tasks. `Arc<[…]>` for cheap per-frame
    /// clones; rebuilt wholesale in `sync_from_config`.
    pub tasks: Arc<[TaskSummary]>,
    /// Currently selected task index in the list
    pub selected_index: usize,
    /// When viewing a specific task's details
    pub active_task: Option<ActiveTaskView>,
    /// Transient status message (e.g., "Task accepted", "Error: ...")
    pub status_message: Option<String>,
    /// When `Some`, a destructive inbox action (dismiss one task, or clear all)
    /// is awaiting `y`/`n` confirmation; the panel shows a prompt and other keys
    /// are suppressed. Mirrors the Communities/VTA-DID confirm pattern (R25).
    pub confirm: Option<InboxConfirm>,
}

/// A pending destructive inbox action awaiting `y`/`n` confirmation (R25).
#[derive(Clone, Debug)]
pub enum InboxConfirm {
    /// Dismiss a single task (by id) — armed from the list or a task detail.
    Dismiss { task_id: String },
    /// Clear every pending task.
    ClearAll,
}

/// Lightweight display summary of a task (no Arc/Mutex).
#[derive(Clone, Debug)]
pub struct TaskSummary {
    /// Task ID
    pub id: String,
    /// Human-friendly type description (e.g., "Relationship Request (Inbound)")
    pub type_display: String,
    /// Categorization for UI rendering and action dispatch
    pub kind: TaskKind,
    /// Shortened DID of the remote party (if applicable)
    pub remote_did: String,
    /// Verified agent name for exactly the DID held in
    /// [`remote_did`](Self::remote_did), if one is cached — shown in its place.
    /// Only ever sourced from `Config::agent_name_for` (verified, round-tripped
    /// lookups); it outranks the requester-supplied `name` on an inbound
    /// relationship request, which is self-asserted and therefore spoofable.
    pub remote_agent_name: Option<String>,
    /// Formatted creation timestamp
    pub created: String,
}

/// Categorizes tasks for UI rendering and determining available actions.
#[derive(Clone, Debug)]
// Some variant fields (e.g. `Informational(String)`) are populated but not yet
// read by the UI — kept for future detail-view rendering.
#[allow(dead_code)]
pub enum TaskKind {
    /// Inbound relationship request awaiting accept/reject
    RelationshipRequestInbound {
        from_did: String,
        their_did: String,
        reason: Option<String>,
        /// Friendly name of the requester (if provided)
        name: Option<String>,
    },
    /// Outbound relationship request awaiting response
    RelationshipRequestOutbound {
        our_did: String,
        /// Verified agent name for `our_did`, if cached. `None` when we sent the
        /// request from a generated R-DID (a pseudonym, which carries no name).
        our_agent_name: Option<String>,
    },
    /// Inbound VRC request awaiting accept/reject
    VRCRequestInbound { reason: Option<String> },
    /// Outbound VRC request awaiting response
    VRCRequestOutbound,
    /// A VRC was issued to us, awaiting acceptance
    VRCIssued,
    /// Trust ping awaiting pong
    TrustPing,
    /// Informational task (accepted, rejected, finalized, etc.)
    Informational(String),
}

/// Detailed view of a specific task for the interaction screen.
///
/// Every `*_agent_name` is the **verified** name for exactly the DID in the
/// field it sits beside (from `Config::agent_name_for`), so rendering the name
/// in place of that DID never relabels a different identity. `their_did` — the
/// requester's relationship DID — has no name field on purpose: an R-DID is a
/// per-relationship pseudonym, deliberately not a stable named identity.
#[derive(Clone, Debug)]
pub enum ActiveTaskView {
    RelationshipRequestInbound {
        task_id: String,
        from_did: String,
        from_agent_name: Option<String>,
        their_did: String,
        reason: Option<String>,
        name: Option<String>,
    },
    /// Outbound relationship request — waiting for response
    RelationshipRequestOutbound {
        task_id: String,
        to_did: String,
        to_agent_name: Option<String>,
        our_did: String,
        our_agent_name: Option<String>,
        state: String,
    },
    VRCRequestInbound {
        task_id: String,
        from_did: String,
        from_agent_name: Option<String>,
        reason: Option<String>,
    },
    /// Outbound VRC request — waiting for response
    VRCRequestOutbound {
        task_id: String,
        remote_did: String,
        remote_agent_name: Option<String>,
    },
    VRCIssued {
        task_id: String,
        issuer: String,
        issuer_agent_name: Option<String>,
    },
    /// Generic info task (ping, pong, informational)
    Info {
        task_id: String,
        type_display: String,
        remote_did: String,
        remote_agent_name: Option<String>,
    },
}

// ****************************************************************************
// Relationships State
// ****************************************************************************

/// State for the relationships panel.
#[derive(Clone, Debug, Default)]
pub struct RelationshipsState {
    /// Display summaries of all relationships. `Arc<[…]>` for cheap per-frame
    /// clones; rebuilt wholesale in `sync_from_config`.
    pub relationships: Arc<[RelationshipSummary]>,
    /// Currently selected index in the list
    pub selected_index: usize,
    /// Current panel mode (list, detail, new request form)
    pub mode: RelationshipsMode,
    /// Transient status message
    pub status_message: Option<String>,
    /// When `Some(remote_p_did)`, removal of that relationship is awaiting
    /// `y`/`n` confirmation (armed from the detail view). Mirrors the
    /// Communities/VTA-DID confirm pattern (R25).
    pub confirm_delete: Option<String>,
}

/// Display modes for the relationships panel.
#[derive(Clone, Debug, Default)]
pub enum RelationshipsMode {
    /// Browsing the list of relationships
    #[default]
    List,
    /// Viewing details of a specific relationship.
    /// `selected_vrc`: None = relationship info shown, Some(n) = VRC at index n expanded.
    Detail {
        index: usize,
        selected_vrc: Option<usize>,
    },
    /// Editing the alias for an existing relationship
    EditAlias { index: usize, alias_input: String },
    /// Filling out a new relationship request form
    NewRequest {
        did_input: String,
        alias_input: String,
        reason_input: String,
        /// Whether to generate a random relationship DID (privacy)
        generate_r_did: bool,
        /// Which form field is currently focused (0=DID, 1=Alias, 2=Reason, 3=R-DID toggle)
        active_field: usize,
    },
}

/// Lightweight display summary of a relationship.
#[derive(Clone, Debug)]
pub struct RelationshipSummary {
    /// Remote party's persona DID
    pub remote_p_did: String,
    /// Contact alias (if set)
    pub alias: Option<String>,
    /// Verified agent name for the remote persona DID (`example.com/@bob`), if
    /// one is cached. Shown when there is no user alias; the DID is the last
    /// resort. Populated in `sync_from_config` from the persisted cache.
    pub agent_name: Option<String>,
    /// Human-readable state (e.g., "Established", "Request Sent")
    pub state: String,
    /// Our DID used in this relationship
    pub our_did: String,
    /// Remote party's DID for this relationship
    pub remote_did: String,
    /// Formatted creation timestamp
    pub created: String,
    /// VRCs we issued to this party
    pub vrcs_issued: Vec<RelationshipVrc>,
    /// VRCs we received from this party
    pub vrcs_received: Vec<RelationshipVrc>,
    /// Whether this relationship's R-DID keys were lost and could not be
    /// recovered at load (see `Relationship::needs_reestablishment`). When set,
    /// the list shows a "needs re-establishment" badge: the relationship can no
    /// longer send or receive and must be re-created.
    pub needs_reestablishment: bool,
}

/// VRC info for display in the relationship detail view.
///
/// Carries the same issuer/subject name pair as [`VrcSummary`] — the credentials
/// panel and this list show the same credentials from two different screens, so
/// they resolve names identically (verified-only, via `Config::agent_name_for`).
#[derive(Clone, Debug)]
pub struct RelationshipVrc {
    /// Issuer DID (shortened for display)
    pub issuer: String,
    /// Verified agent name for the issuer DID, if cached. Shown in place of
    /// [`issuer`](Self::issuer) on the list row; the expanded detail keeps
    /// [`issuer_full`](Self::issuer_full) so the DID is still readable/copyable.
    pub issuer_agent_name: Option<String>,
    /// Full issuer DID
    pub issuer_full: String,
    /// Subject DID (shortened for display)
    pub subject: String,
    /// Verified agent name for the subject DID, if cached. Same treatment as
    /// [`issuer_agent_name`](Self::issuer_agent_name).
    pub subject_agent_name: Option<String>,
    /// Full subject DID
    pub subject_full: String,
    /// Formatted valid_from date
    pub valid_from: String,
    /// Formatted valid_until date (if set)
    pub valid_until: Option<String>,
    /// Raw credential source, pretty-printed lazily at detail-view time.
    pub raw_json: RawCredential,
}

// ****************************************************************************
// Credentials State
// ****************************************************************************

/// State for the credentials (VRCs) panel.
#[derive(Clone, Debug, Default)]
pub struct CredentialsState {
    /// VRCs we received. `Arc<[…]>` for cheap per-frame clones.
    pub received: Arc<[VrcSummary]>,
    /// VRCs we issued. `Arc<[…]>` for cheap per-frame clones.
    pub issued: Arc<[VrcSummary]>,
    /// Membership (VMC) + role (VEC) credentials issued to us by the VTCs we've
    /// joined, one or two entries per community (reuses [`VrcSummary`]).
    /// `Arc<[…]>` for cheap per-frame clones.
    pub membership: Arc<[VrcSummary]>,
    /// Which tab is active
    pub selected_tab: CredentialTab,
    /// Currently selected index in the active tab's list
    pub selected_index: usize,
    /// Current panel mode
    pub mode: CredentialsMode,
    /// Transient status message
    pub status_message: Option<String>,
    /// When `Some(vrc_id)`, removal of that credential is awaiting `y`/`n`
    /// confirmation (armed from the detail view). Mirrors the Communities/
    /// VTA-DID confirm pattern (R25).
    pub confirm_delete: Option<String>,
}

/// Which credential tab is active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CredentialTab {
    #[default]
    Received,
    Issued,
    /// Membership (VMC) + role (VEC) credentials issued to us by joined VTCs.
    Membership,
}

/// Display modes for the credentials panel.
#[derive(Clone, Debug, Default)]
pub enum CredentialsMode {
    /// Browsing the list of credentials
    #[default]
    List,
    /// Viewing details of a specific credential
    Detail { index: usize },
    /// Requesting a new VRC: selecting a relationship
    NewRequest {
        /// Index into the established relationships list
        relationship_index: usize,
        reason_input: String,
    },
}

/// Lightweight display summary of a VRC.
#[derive(Clone, Debug)]
pub struct VrcSummary {
    /// VRC identifier (proof value hash)
    pub vrc_id: String,
    /// Remote party's persona DID
    pub remote_p_did: String,
    /// Verified agent name for [`remote_p_did`](Self::remote_p_did), if cached.
    /// Shown when there is no user alias; the DID is the last resort. Populated
    /// in `sync_from_config` from the persisted (verified-only) cache.
    pub remote_agent_name: Option<String>,
    /// Raw credential source, pretty-printed lazily at detail-view time.
    pub raw_json: RawCredential,
    /// Contact alias (if set)
    pub alias: Option<String>,
    /// Issuer DID
    pub issuer: String,
    /// Verified agent name for [`issuer`](Self::issuer), if cached.
    pub issuer_agent_name: Option<String>,
    /// Subject DID
    pub subject: String,
    /// Verified agent name for [`subject`](Self::subject), if cached.
    pub subject_agent_name: Option<String>,
    /// Formatted valid_from date
    pub valid_from: String,
    /// Formatted valid_until date (if set)
    pub valid_until: Option<String>,
    /// What this credential asserts — "Membership", "Role" — when known.
    ///
    /// Previously only reachable by parsing it back out of [`alias`](Self::alias),
    /// which packed `"<community> — <kind>"` into one string.
    pub kind: Option<String>,
    /// Whether the subject is one of this account's own personas, so the detail
    /// view can say which side is you rather than leaving two names to compare.
    pub subject_is_self: bool,
    /// The validity window in human form, with a relative note — e.g.
    /// `"22 Jul 2026 → 21 Aug 2026 · 29 days left"`.
    ///
    /// Composed where `chrono` and the current time are already at hand, so the
    /// renderer stays free of date arithmetic.
    pub validity: String,
    /// One-word validity state for the header line: `valid`, `expired`, or
    /// `not yet valid`. Derived from the window only — this is **not** a
    /// revocation check, which needs the issuer's status list.
    pub status: String,
}

// ****************************************************************************
// Logs State
// ****************************************************************************

/// State for the logs panel.
#[derive(Clone, Debug, Default)]
pub struct LogsState {
    /// Currently selected log entry index (0 = newest).
    /// Managed locally by the UI component, not stored in State.
    pub selected_index: usize,
    /// When true, show the full text of the selected log entry.
    pub detail_view: bool,
}

// ****************************************************************************
// Settings State
// ****************************************************************************

/// State for the settings panel.
#[derive(Clone, Debug, Default)]
pub struct SettingsState {
    /// Current friendly name
    pub friendly_name: String,
    /// Current mediator DID
    pub mediator_did: String,
    /// Current organization DID
    pub org_did: String,
    /// Persona DID (read-only display)
    pub persona_did: String,
    /// Verified agent name for the persona DID, if cached.
    pub persona_agent_name: Option<String>,
    /// How the config is protected (Token/Encrypted/Plaintext)
    pub protection_type: String,
    /// This account's top trust context at the agent (`top_context_id`).
    ///
    /// Display-only, and here for the wipe screen: that screen sends the
    /// operator to `pnm contexts delete`, which takes the id positionally, and
    /// once the profile is gone this pane was the last place the id appeared.
    /// Empty when no account is loaded.
    pub context_id: String,

    /// Warning shown when this profile's secret is in a store that will not
    /// keep it — the Linux kernel keyring, which is RAM-only. `None` when the
    /// store is durable.
    ///
    /// Refreshed deliberately (at startup, and after a protection change) rather
    /// than on every config sync: answering it means reading the credential back
    /// out of the OS store, which is not something to do on every keystroke.
    pub storage_warning: Option<String>,
    /// Currently selected setting index
    pub selected_index: usize,
    /// Current panel mode
    pub mode: SettingsMode,
    /// Transient status message
    pub status_message: Option<String>,
    /// Hardware token management state
    #[cfg(feature = "openpgp-card")]
    pub token: TokenManagementState,
    /// did-git-sign install info, when this persona has been configured for
    /// git commit signing. Surfaced on the Help/Status panel so the operator
    /// can copy the SSH public key into their git host's signing-key
    /// settings.
    pub did_git_sign: Option<DidGitSignInfo>,
}

/// Snapshot of the local did-git-sign install for this persona.
#[derive(Clone, Debug)]
pub struct DidGitSignInfo {
    /// Verification method id from the SigningConfig file.
    pub did_key_id: String,
    /// Persona signing public key formatted as `ssh-ed25519 AAAA…`.
    pub ssh_public_key: String,
    /// Filesystem path to the SigningConfig the install wrote.
    pub config_path: String,
}

/// Hardware token management state.
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Debug, Default)]
pub struct TokenManagementState {
    /// Number of detected tokens
    pub detected_count: usize,
    /// Status messages from token operations
    pub messages: Vec<String>,
    /// Whether a factory reset was completed
    pub reset_completed: bool,
}

/// Display modes for the settings panel.
#[derive(Clone, Debug, Default)]
pub enum SettingsMode {
    /// Viewing settings list
    #[default]
    View,
    /// Editing the friendly name
    EditFriendlyName { input: String },
    /// Editing the org DID
    EditOrgDid { input: String },
    /// Export config form (path + passphrase length for masked display)
    ExportConfig {
        path_input: String,
        /// Length of the passphrase (actual value held only in UI component)
        passphrase_len: usize,
        active_field: usize,
    },
    /// Import config form (path + passphrase length for masked display)
    ImportConfig {
        path_input: String,
        /// Length of the passphrase (actual value held only in UI component)
        passphrase_len: usize,
        active_field: usize,
    },
    /// Changing protection level (set/remove passphrase)
    ChangeProtection {
        /// 0 = Set passphrase, 1 = Remove passphrase (keyring only)
        selected_option: usize,
        /// Length of the passphrase (actual value held only in UI component)
        passphrase_len: usize,
        /// Length of the confirm passphrase (actual value held only in UI component)
        confirm_len: usize,
        /// Which field is active (0 = option list, 1 = passphrase, 2 = confirm)
        active_field: usize,
    },
    /// Token management sub-screen
    #[cfg(feature = "openpgp-card")]
    TokenManagement { selected_index: usize },
    /// Wipe-profile confirmation. Operator must type the literal token
    /// `WIPE` (case-insensitive) into `confirm_input` before the wipe is
    /// permitted to proceed. Anything else just closes the dialog.
    WipeConfirm {
        /// Live text the operator is typing into the confirm field.
        confirm_input: String,
    },
    /// Choosing a theme. The highlighted theme is previewed on the whole
    /// screen; `original` is put back if the choice is cancelled.
    ThemePicker {
        rows: Vec<ThemeRow>,
        selected: usize,
        original: String,
    },
}

/// A theme on the picker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThemeRow {
    pub id: String,
    pub name: String,
    /// Where it comes from, in a word or two.
    pub source: String,
}
