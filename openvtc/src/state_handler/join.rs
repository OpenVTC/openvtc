//! State-B "join a community" flow state (R-A-5 Stage 4).
//!
//! Holds the transient UI/progress state for the two-page join flow:
//! `VtcEnterDid` (the operator pastes the community VTC DID) and `JoinProgress`
//! (a live log of the automated persona-mint → sub-context → join-submit
//! sequence). Persona-mint working fields are reused from
//! [`SetupState`](crate::state_handler::setup_sequence::SetupState) on
//! `State.setup`; this struct only tracks the join-specific surface.

use openvtc_core::config::account::{CommunityRecord, PersonaId};
use openvtc_core::config::community_context::{ContextKind, ContextOption};
use serde_json::Value;

use crate::state_handler::setup_sequence::{Completion, MessageType};

/// Which page of the join flow is currently active.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JoinPage {
    /// Operator enters the community (VTC) DID.
    #[default]
    EnterDid,
    /// Choose whether to present an invitation (VIC) for this community, or join
    /// as an open request. Always shown on the reuse path, even with no VIC
    /// found: the step carries a paste row, so "I have an invitation, it just
    /// isn't in the vault yet" is answerable. Skipping it when the vault happened
    /// to be empty meant an operator holding an invitation was never asked and
    /// silently sent an open request instead.
    InvitationChoice,
    /// Choose the identity to present (R-B-3 / D1): reuse an existing persona or
    /// mint a fresh one. Skipped when the account has no personas yet.
    IdentityChoice,
    /// Choose the VTA context the community lives in: a new sub-context of its
    /// own, one already in use, or the top context. Skipped when the identity
    /// allows only one.
    ContextChoice,
    /// Automated mint + join sequence progress / result.
    Progress,
    /// A community that vets its members: what it requires, in plain words,
    /// before anything about the applicant is sent — with the persona's
    /// application if there is one, and the ways on (apply, join anyway,
    /// cancel). Also the page shown while the community is being asked.
    Vetting,
}

/// A community that vets, as the join flow's vetting page shows it.
#[derive(Clone, Debug)]
pub struct JoinVettingView {
    /// The community's VTC DID.
    pub community: String,
    /// Its name, already sanitised.
    pub name: String,
    /// The accent colour it publishes.
    pub accent: Option<(u8, u8, u8)>,
    pub phase: VettingPhase,
}

/// How much is known of what a community requires.
#[derive(Clone, Debug)]
pub enum VettingPhase {
    /// The community is being asked. The runtime loop, which hears the
    /// answer, draws the page while it waits.
    Asking,
    /// Its requirements could not be learned; why.
    Unknown { reason: String },
    /// It vets, and this is what it asks.
    Known(Box<KnownVetting>),
}

/// A vetting community's requirements and where this persona stands.
#[derive(Clone, Debug, Default)]
pub struct KnownVetting {
    /// What it requires, one sentence each.
    pub requirements: Vec<String>,
    /// Where it says how it decides.
    pub governance_url: Option<String>,
    /// Our application to it, when there is one.
    pub application: Option<JoinApplication>,
    /// Personas a new application can be made as.
    pub personas: Vec<ApplyAs>,
    pub persona_index: usize,
    /// Where a new application's face is worn.
    pub context_options: Vec<ContextOption>,
    pub context_index: usize,
    /// 0 = persona, 1 = context.
    pub field: usize,
}

/// A persona an application can be made as.
#[derive(Clone, Debug)]
pub struct ApplyAs {
    pub persona: PersonaId,
    pub label: String,
    pub did: String,
}

/// An application already under way, as the join page shows it.
#[derive(Clone, Debug)]
pub struct JoinApplication {
    pub id: String,
    pub persona: PersonaId,
    pub persona_label: String,
    /// Statements that would be presented now.
    pub statements: usize,
    /// Progress against the published requirements.
    pub progress: Option<String>,
    /// What to do next, with its key on the Vetting page.
    pub next_step: String,
    /// It meets the published requirements.
    pub satisfied: bool,
}

/// The identity a join presents, once chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityPick {
    /// A new persona, minted into the chosen context.
    Mint,
    /// An existing persona.
    Reuse(PersonaId),
}

/// Summary of the invitation credential (VIC) actually presented with a join,
/// shown on the success page so the operator can tell *whether* and *which*
/// invitation was used (vs. an open request awaiting manual approval). `None` on
/// the join state means no VIC was presented.
#[derive(Clone, Debug)]
pub struct PresentedInvitation {
    /// The VIC's top-level `id` (its consumption / linkage handle).
    pub id: String,
    /// The persona DID the VIC is bound to (`credentialSubject.id`), if present.
    pub subject: Option<String>,
    /// Verified agent name for [`subject`](Self::subject), if cached. The subject
    /// is one of this account's own persona DIDs, which the agent-name sweep
    /// already targets, so a name is often available. Sourced only from
    /// `Config::agent_name_for`; `None` keeps the DID on screen.
    pub subject_agent_name: Option<String>,
}

/// One selectable existing persona on the identity-choice page (R-B-3).
#[derive(Clone, Debug)]
pub struct PersonaOption {
    /// Stable persona id, the reuse target.
    pub id: PersonaId,
    /// Human label (the persona's label, or a shortened DID).
    pub label: String,
    /// The persona's `did:webvh` (shown as detail).
    pub did: String,
    /// Display names of communities this persona is *already* presented to —
    /// drives the cross-community linkage warning (D1).
    pub linked_communities: Vec<String>,
    /// Count of valid invitations (VICs) for the community being joined that are
    /// bound to this persona — shown as a badge so the operator can pick the
    /// identity that holds a usable invitation.
    pub valid_vic_count: usize,
}

/// A valid invitation (VIC) available to present for the community being joined,
/// with the fields shown on the invitation-choice step and the body to present.
#[derive(Clone, Debug)]
pub struct AvailableVic {
    /// The VIC's top-level `id`.
    pub id: String,
    /// The persona DID it is bound to (`credentialSubject.id`), if present —
    /// used to group invitations under each persona.
    pub subject: Option<String>,
    /// Validity-window start (`validFrom`, RFC 3339), shown as "Issued".
    pub valid_from: String,
    /// Validity-window end (`validUntil`, RFC 3339), shown as "Expires".
    pub valid_until: String,
    /// The signed VIC body, presented verbatim when this one is chosen.
    pub body: Value,
}

/// Transient state for the join flow.
#[derive(Clone, Debug, Default)]
pub struct JoinState {
    /// Active page within the join flow.
    pub page: JoinPage,
    /// Display name resolved from the VTC DID document (best-effort).
    pub display_name: Option<String>,
    /// The VTC DID awaiting an identity choice (set on `EnterDid` submit, read
    /// when the chosen identity launches the sequence).
    pub pending_vtc: Option<String>,
    /// Existing personas offered for reuse on the identity-choice page (R-B-3).
    pub persona_options: Vec<PersonaOption>,
    /// Highlighted row on the identity-choice page. `0..persona_options.len()`
    /// indexes a reuse option; `persona_options.len()` is the "mint new" row.
    pub identity_selected: usize,
    /// When `Some(id)`, the cross-community linkage warning for reusing that
    /// persona is shown and awaiting `y`/`n` confirmation (D1).
    pub reuse_confirm: Option<PersonaId>,
    /// True while the background mint+join sequence is running. Locks input.
    pub processing: bool,
    /// Progress / error log shown on the `JoinProgress` page.
    pub messages: Vec<MessageType>,
    /// Overall outcome of the sequence.
    pub completed: Completion,
    /// The pending community record created on success (for the success page).
    pub created_community: Option<CommunityRecord>,
    /// The DID of the persona presented for this community, shown on the success
    /// page alongside the community DID.
    pub created_persona_did: Option<String>,
    /// Whether an invitation credential (VIC) was supplied at launch and will be
    /// presented with this join. Mirrored from the top-level
    /// [`State`](crate::state_handler::state::State) when the flow opens (it
    /// survives `reset`, which is called once at open) so the entry page can show
    /// the operator that their invitation will be used.
    pub has_invitation: bool,
    /// The invitation actually presented to the community, resolved at submit
    /// time (community-matched + unexpired). `Some` drives the success page's
    /// "Invitation: Presented" detail; `None` reads as an open request. Distinct
    /// from [`has_invitation`](Self::has_invitation), which reflects what was
    /// *loaded* on the entry page before community matching.
    pub presented_invitation: Option<PresentedInvitation>,
    /// The community (VTC) DID that issued the invitation loaded on the entry
    /// page. For an `InvitationCredential` the issuer *is* the community, so a
    /// pasted VIC already names the community it is for: the entry page shows it
    /// alongside the "invitation loaded" line and prefills the DID input with it,
    /// rather than making the operator find and retype a DID the credential in
    /// hand already carries. Prefilled, not auto-submitted — a VIC arrives from
    /// someone else, so the community it points at stays visible and editable
    /// before Enter commits to joining it.
    pub invitation_issuer: Option<String>,
    /// True when the operator explicitly cleared a loaded VIC on the entry page,
    /// so the status text reads "joining without an invitation" rather than the
    /// generic "no VIC" tip. Distinguishes a deliberate clear from never having
    /// had one; re-pasting a VIC (`JoinPasteVic`) flips it back to `false`.
    pub vic_cleared: bool,
    /// All valid invitations (VICs) for the community being joined, across
    /// personas — collected once after the VTC DID is entered and used to badge
    /// each persona with its count on the identity step.
    pub available_vics: Vec<AvailableVic>,
    /// The chosen persona's invitations, listed on the
    /// [`InvitationChoice`](JoinPage::InvitationChoice) page (a subset of
    /// [`available_vics`](Self::available_vics) bound to that persona).
    pub invitation_options: Vec<AvailableVic>,
    /// Which persona the invitation step is choosing for — the reuse target the
    /// join launches with once the invitation choice is made.
    pub invitation_for_persona: Option<PersonaId>,
    /// The chosen persona's DID, kept alongside
    /// [`invitation_for_persona`](Self::invitation_for_persona) so the invitation
    /// step can tell a pasted VIC bound to *this* identity from one bound to
    /// another (which needs a subject-linkage proof) and say so on the row.
    pub invitation_persona_did: Option<String>,
    /// Highlighted row on the invitation-choice page. See
    /// [`invitation_paste_row`](Self::invitation_paste_row) and
    /// [`invitation_without_row`](Self::invitation_without_row) for the layout.
    pub invitation_use_selected: usize,
    /// The committed invitation decision, read by the join sequence. `true`
    /// presents the chosen VIC (set into `State.invitation_credential`); `false`
    /// submits an open request. Set when the invitation choice is made, or
    /// directly (false) on paths with no available invitation.
    pub present_invitation: bool,
    /// The identity the context step is choosing for.
    pub picked_identity: Option<IdentityPick>,
    /// Contexts offered on the context-choice page, the default first.
    pub context_options: Vec<ContextOption>,
    /// Highlighted row on the context-choice page.
    pub context_selected: usize,
    /// The name typed for a new sub-context: its last path segment.
    pub context_slug: String,
    /// Display names for the communities listed under each context, by VTC DID.
    pub context_community_names: Vec<(String, String)>,
    /// The vetting page, while the community being joined vets its members.
    pub vetting: Option<JoinVettingView>,
}

impl JoinState {
    /// Reset to a fresh `EnterDid` page (called when the flow opens).
    pub fn reset(&mut self) {
        *self = JoinState::default();
    }

    /// The index of the "mint a new identity" row (one past the reuse options).
    pub fn mint_row(&self) -> usize {
        self.persona_options.len()
    }

    /// Whether the highlighted identity-choice row is the "mint new" row.
    pub fn mint_row_selected(&self) -> bool {
        self.identity_selected >= self.persona_options.len()
    }

    /// The index of the "paste an invitation" row on the invitation-choice page —
    /// one past the listed invitations. Choosing it loads a VIC rather than
    /// launching the join, so the step can be answered with an invitation the
    /// vault has never seen.
    pub fn invitation_paste_row(&self) -> usize {
        self.invitation_options.len()
    }

    /// The index of the trailing "join without it" row — one past the paste row.
    /// It is also the clamp ceiling for `invitation_use_selected`.
    pub fn invitation_without_row(&self) -> usize {
        self.invitation_options.len() + 1
    }

    /// Whether the highlighted context row is the new sub-context.
    pub fn new_context_selected(&self) -> bool {
        self.context_options
            .get(self.context_selected)
            .is_some_and(|o| o.kind == ContextKind::New)
    }

    /// The display name for a community listed under a context.
    pub fn community_name<'a>(&'a self, vtc_did: &'a str) -> &'a str {
        self.context_community_names
            .iter()
            .find(|(did, _)| did == vtc_did)
            .map_or(vtc_did, |(_, name)| name.as_str())
    }

    /// Append an info message to the progress log.
    pub fn info(&mut self, msg: impl Into<String>) {
        self.messages.push(MessageType::Info(msg.into()));
    }

    /// Append an error message and mark the sequence failed.
    pub fn fail(&mut self, msg: impl Into<String>) {
        self.messages.push(MessageType::Error(msg.into()));
        self.completed = Completion::CompletedFail;
        self.processing = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt() -> PersonaOption {
        PersonaOption {
            id: PersonaId::new(),
            label: "p".to_string(),
            did: "did:webvh:x".to_string(),
            linked_communities: Vec::new(),
            valid_vic_count: 0,
        }
    }

    #[test]
    fn vic_cleared_defaults_false_and_resets() {
        let mut js = JoinState::default();
        assert!(!js.vic_cleared);
        js.vic_cleared = true;
        js.has_invitation = true;
        js.reset();
        assert!(!js.vic_cleared);
        assert!(!js.has_invitation);
    }

    #[test]
    fn mint_row_sits_past_the_reuse_options() {
        let mut js = JoinState::default();
        // No personas: the only row is "mint", at index 0.
        assert_eq!(js.mint_row(), 0);
        assert!(js.mint_row_selected());

        js.persona_options = vec![opt(), opt()];
        assert_eq!(js.mint_row(), 2);
        js.identity_selected = 0;
        assert!(!js.mint_row_selected());
        js.identity_selected = 1;
        assert!(!js.mint_row_selected());
        js.identity_selected = 2;
        assert!(js.mint_row_selected());
    }

    #[test]
    fn only_the_new_row_takes_a_typed_name() {
        let option = |context_id: &str, kind| ContextOption {
            context_id: context_id.to_string(),
            kind,
            communities: Vec::new(),
            holds_persona_keys: false,
        };
        let mut js = JoinState {
            context_options: vec![
                option("openvtc/kernel", ContextKind::New),
                option("openvtc/work", ContextKind::Existing),
                option("openvtc", ContextKind::Top),
            ],
            ..JoinState::default()
        };
        assert!(js.new_context_selected());
        js.context_selected = 1;
        assert!(!js.new_context_selected());
        js.context_selected = 2;
        assert!(!js.new_context_selected());
    }

    #[test]
    fn the_paste_row_precedes_join_without_it() {
        let mut js = JoinState::default();
        // The empty case is the one the flow used to skip entirely: there is
        // still a paste row to answer with, and it must not be the "without" row.
        assert_eq!(js.invitation_paste_row(), 0);
        assert_eq!(js.invitation_without_row(), 1);

        js.invitation_options = vec![
            AvailableVic {
                id: "urn:uuid:a".to_string(),
                subject: None,
                valid_from: String::new(),
                valid_until: String::new(),
                body: Value::Null,
            },
            AvailableVic {
                id: "urn:uuid:b".to_string(),
                subject: None,
                valid_from: String::new(),
                valid_until: String::new(),
                body: Value::Null,
            },
        ];
        assert_eq!(js.invitation_paste_row(), 2);
        assert_eq!(js.invitation_without_row(), 3);
    }
}
