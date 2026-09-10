//! Identity-pane business logic: what each key does to the pane's state, and
//! which of them need the agent.
//!
//! Split the way the architecture asks for it. [`apply`] is pure — it takes
//! `&mut State` and an action, mutates the pane, and *names* any network work
//! as a [`PersonaEffect`] rather than doing it. The loop spawns that off-thread
//! and folds the result back in through [`PersonaOutcome::apply`], on the loop
//! thread, so the single-mutator invariant holds and every decision this module
//! makes is testable without a `VtaClient`.
//!
//! # One domain for the whole pane
//!
//! Reads and writes share one dispatch domain
//! ([`DispatchDomain::PersonaManage`](crate::state_handler::background_dispatch::DispatchDomain::PersonaManage)),
//! so a listing cannot overtake the write that invalidated it. A write asks for a re-read by
//! setting `refresh_queued` rather than starting one, because its own outcome
//! is still holding the domain — the same shape the VIC manager uses.
//!
//! # The words, and where they change
//!
//! This module is engineering-side: it keeps the spec's nouns
//! (`attribute`, `profile`, `binding`), because those are what it addresses on
//! the wire. The strings it *hands to the panel* — status lines, refusals — use
//! the vocabulary a person reads (`design-docs/persona-vocabulary.md`): an attribute,
//! a face, wearing one.
//!
//! # Questions are asked once, and correctly
//!
//! Deleting an attribute a profile references is refused by the VTA unless the
//! caller cascades; deleting a profile a persona presents is refused unless the
//! caller unbinds. Neither refusal is *discovered* here. The profile listing
//! already says which attributes are referenced and the binding map already
//! says which profiles are presented, so the prompt names the real consequence
//! the first time it is put. Asking "delete this?", being refused, and then
//! asking "delete it and edit three profiles?" trains a holder to answer the
//! second question with the first one's reasoning.

use std::collections::HashMap;

use openvtc_core::persona::{
    binding, claim_types, disclosure,
    pool::{self, AttributeDraft, PoolAttribute},
    profile::{self, ProfileDetail, ProfileSummary},
};
use vta_sdk::client::VtaClient;

use crate::state_handler::actions::PersonaAction;
use crate::state_handler::main_page::content::{
    AttributeField, AttributeForm, BindPicker, PersonaConfirm, PersonaMode, PersonaTab,
    ProfileForm, ProfileFormFocus, VALUE_TYPES,
};
use crate::state_handler::persona_binding_refresh::{self, BindingTarget};
use crate::state_handler::state::State;

/// What an action needs beyond the state change [`apply`] already made.
pub(crate) enum PersonaEffect {
    /// Nothing — a pure view change.
    None,
    /// Re-read the agent-served tabs.
    Read,
    /// One round-trip, already resolved to its arguments on the loop thread.
    Job(PersonaJob),
}

/// A single persona round-trip.
pub(crate) enum PersonaJob {
    AttributePut(AttributeDraft),
    AttributeDelete {
        attribute_id: String,
        cascade: bool,
    },
    ProfilePut {
        profile_id: Option<String>,
        name: String,
        live_refs: Vec<String>,
        other_entries: Vec<vta_sdk::protocols::persona::ProfileEntry>,
        expected_version: Option<u64>,
    },
    ProfileDelete {
        profile_id: String,
        unbind: bool,
    },
    /// Read one profile — to show what it presents, or to fill the editor.
    ProfileGet {
        profile_id: String,
        /// `true` fills the editor: it needs the entries, not the values, so it
        /// does not ask the VTA to resolve them. A read that decrypts the pool
        /// to populate a form the holder may cancel is a read that did not need
        /// to happen.
        edit: bool,
    },
    /// Decide what one persona presents in one context.
    Bind {
        context_id: String,
        persona_did: String,
        profile_id: Option<String>,
        community: String,
    },
}

// ---------------------------------------------------------------------------
// The reducer
// ---------------------------------------------------------------------------

/// Apply one identity-pane action. Pure: mutates the pane and returns the
/// network work the loop still owes.
pub(crate) fn apply(state: &mut State, action: &PersonaAction) -> PersonaEffect {
    match action {
        PersonaAction::TabNext | PersonaAction::TabPrev => {
            let p = &mut state.main_page.content_panel.identity;
            p.tab = match action {
                PersonaAction::TabNext => p.tab.next(),
                _ => p.tab.prev(),
            };
            // Leaving a tab drops what was armed or opened on it. A `y` is
            // answered on the screen that asked, never two tabs later.
            p.confirm = PersonaConfirm::None;
            p.open_profile = None;
            p.status_message = None;
            // A reveal is granted to one row on one tab. Coming back to the
            // attributes — or to a face — should find them masked again, not
            // still open.
            p.revealed_attribute = None;
            p.revealed_face_claim = None;
            // Read on arrival, once. The agent-served tabs are not polled: a
            // pane nobody has opened should not be asking the agent about the
            // holder's identity every few seconds.
            if p.tab.needs_agent() && !p.loaded && !p.loading {
                return PersonaEffect::Read;
            }
            PersonaEffect::None
        }
        PersonaAction::Select(index) => {
            let p = &mut state.main_page.content_panel.identity;
            // The selection moved, so the reveal it was granted for is over.
            // Carrying it to the next row is how "one value" becomes "all of
            // them", one press of ↓ at a time.
            p.revealed_attribute = None;
            match p.tab {
                PersonaTab::Personas => p.persona_selected = *index,
                PersonaTab::Attributes => p.attribute_selected = *index,
                PersonaTab::Profiles => p.profile_selected = *index,
                PersonaTab::Communities => p.membership_selected = *index,
                PersonaTab::Disclosures => p.disclosure_selected = *index,
            }
            PersonaEffect::None
        }
        PersonaAction::Refresh => PersonaEffect::Read,
        PersonaAction::ToggleValues => {
            let p = &mut state.main_page.content_panel.identity;
            p.show_values = !p.show_values;
            p.revealed_attribute = None;
            // A re-read, not a redraw: a listing fetched without values does
            // not hold them. Flipping a display flag over data already in
            // memory would mean the values had been read all along.
            PersonaEffect::Read
        }
        PersonaAction::RevealValue(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(attr) = p.attributes.get(*index) else {
                return PersonaEffect::None;
            };
            // A second press puts it back, so the key the holder used to show
            // the value is also the one that hides it again.
            p.revealed_attribute = match &p.revealed_attribute {
                Some(id) if id == &attr.attribute_id => None,
                _ => Some(attr.attribute_id.clone()),
            };
            // No read: this lifts a mask over a value already in memory, which
            // is exactly why the mask is not a security control. The read-path
            // control — a listing that is never *sent* sensitive values —
            // would belong here and does not exist; see
            // `openvtc_core::persona::claim_types`.
            PersonaEffect::None
        }

        // ── Attributes ───────────────────────────────────────────────────
        PersonaAction::AttributeNew => {
            let p = &mut state.main_page.content_panel.identity;
            p.mode = PersonaMode::Attribute(AttributeForm::default());
            PersonaEffect::None
        }
        PersonaAction::AttributeEdit(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(attr) = p.attributes.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            if !attr.provenance.is_editable_here() {
                // Refused with the reason, not with a form that would fail on
                // save. See `pool`'s module header.
                if let pool::AttributeEdit::Refused(why) =
                    pool::AttributeEdit::refusal(attr.provenance)
                {
                    p.status_message = Some(why);
                }
                return PersonaEffect::None;
            }
            p.mode = PersonaMode::Attribute(form_for(&attr));
            // The editor was opened without a value in hand if the listing was
            // fetched without one, and saving would then blank it. Fetch the
            // values so the form starts from what is actually stored.
            if !p.show_values {
                p.show_values = true;
                return PersonaEffect::Read;
            }
            PersonaEffect::None
        }
        PersonaAction::AttributeDeleteArm(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(attr) = p.attributes.get(*index) else {
                return PersonaEffect::None;
            };
            // Referenced by a profile? Then the only delete that will succeed
            // is the cascading one, and that is the question to put.
            let cascade = p
                .profiles
                .iter()
                .any(|profile| profile.referenced.contains(&attr.attribute_id));
            p.confirm = PersonaConfirm::DeleteAttribute {
                attribute_id: attr.attribute_id.clone(),
                name: attr.display_name().to_string(),
                cascade,
            };
            PersonaEffect::None
        }

        // ── Profiles ─────────────────────────────────────────────────────
        PersonaAction::ProfileOpen(index) | PersonaAction::ProfileEdit(index) => {
            let edit = matches!(action, PersonaAction::ProfileEdit(_));
            let p = &mut state.main_page.content_panel.identity;
            let Some(profile) = p.profiles.get(*index) else {
                return PersonaEffect::None;
            };
            PersonaEffect::Job(PersonaJob::ProfileGet {
                profile_id: profile.profile_id.clone(),
                edit,
            })
        }
        PersonaAction::ProfileClose => {
            let p = &mut state.main_page.content_panel.identity;
            p.open_profile = None;
            p.revealed_face_claim = None;
            PersonaEffect::None
        }
        PersonaAction::FaceClaimSelect(index) => {
            let p = &mut state.main_page.content_panel.identity;
            // Same rule as the attributes tab: the selection moved, so the
            // reveal it was granted for is over. Carrying it down the list is
            // how "one value" becomes "all of them", one press of ↓ at a time.
            p.revealed_face_claim = None;
            p.face_claim_selected = *index;
            PersonaEffect::None
        }
        PersonaAction::RevealFaceClaim(index) => {
            let p = &mut state.main_page.content_panel.identity;
            // Bounds-checked against the open face rather than assumed: the
            // detail can be replaced by a re-read between the keypress and here.
            let claims = p.open_profile.as_ref().map_or(0, |d| d.resolved.len());
            if *index >= claims {
                return PersonaEffect::None;
            }
            // A second press puts it back, so the key that showed the value is
            // also the one that hides it again.
            p.revealed_face_claim = match p.revealed_face_claim {
                Some(i) if i == *index => None,
                _ => Some(*index),
            };
            // No read: a face detail is resolved in full when it is opened, so
            // this lifts a mask over a value already in memory. Which is
            // exactly why the mask is not a security control — see
            // `openvtc_core::persona::claim_types`.
            PersonaEffect::None
        }
        PersonaAction::ProfileNew => {
            state.main_page.content_panel.identity.mode =
                PersonaMode::Profile(ProfileForm::default());
            PersonaEffect::None
        }
        PersonaAction::ProfileDeleteArm(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(profile) = p.profiles.get(*index) else {
                return PersonaEffect::None;
            };
            // Presented by a persona somewhere? Deleting then leaves that persona
            // presenting nothing, which the prompt has to say.
            let unbind = p
                .bindings
                .values()
                .any(|b| b.profile_id.as_deref() == Some(profile.profile_id.as_str()));
            p.confirm = PersonaConfirm::DeleteProfile {
                profile_id: profile.profile_id.clone(),
                name: profile.display_name().to_string(),
                unbind,
            };
            PersonaEffect::None
        }

        // ── Communities ──────────────────────────────────────────────────
        PersonaAction::BindOpen(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(membership) = p.memberships.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            // Start on what is bound now, so ⏎ on an unchanged picker is a
            // no-op rather than a silent unbind.
            let current = p.binding_for(&membership).profile_id;
            let cursor = current
                .and_then(|id| p.profiles.iter().position(|x| x.profile_id == id))
                .map_or(0, |i| i + 1);
            p.mode = PersonaMode::Bind(BindPicker {
                context_id: membership.sub_context_id.clone(),
                persona_did: membership.persona_did.clone(),
                community: membership.community_name.clone(),
                persona_label: membership.persona_label.clone(),
                cursor,
                working: false,
                error: None,
            });
            PersonaEffect::None
        }
        PersonaAction::UnbindArm(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(m) = p.memberships.get(*index) else {
                return PersonaEffect::None;
            };
            p.confirm = PersonaConfirm::Unbind {
                context_id: m.sub_context_id.clone(),
                persona_did: m.persona_did.clone(),
                community: m.community_name.clone(),
            };
            PersonaEffect::None
        }

        // ── The confirmation slot ────────────────────────────────────────
        PersonaAction::ConfirmNo => {
            state.main_page.content_panel.identity.confirm = PersonaConfirm::None;
            PersonaEffect::None
        }
        PersonaAction::ConfirmYes => confirm_yes(state),

        // ── Forms ────────────────────────────────────────────────────────
        PersonaAction::FormKey(key) => {
            use tui_input::backend::crossterm::EventHandler;
            let p = &mut state.main_page.content_panel.identity;
            let event = crossterm::event::Event::Key(*key);
            match &mut p.mode {
                PersonaMode::Attribute(form) => {
                    match form.field {
                        AttributeField::ClaimType => form.claim_type.handle_event(&event),
                        AttributeField::Label => form.label.handle_event(&event),
                        AttributeField::Value => form.value.handle_event(&event),
                        // The type is a choice, not a text field: ←/→ move it
                        // and a keystroke here is not an edit.
                        AttributeField::ValueType => None,
                    };
                }
                PersonaMode::Profile(form) => {
                    if form.focus == ProfileFormFocus::Name {
                        form.name.handle_event(&event);
                    }
                }
                PersonaMode::Bind(_) | PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormField(forwards) => {
            let p = &mut state.main_page.content_panel.identity;
            match &mut p.mode {
                PersonaMode::Attribute(form) => {
                    form.field = if *forwards {
                        form.field.next()
                    } else {
                        form.field.prev()
                    };
                }
                PersonaMode::Profile(form) => {
                    form.focus = match form.focus {
                        ProfileFormFocus::Name => ProfileFormFocus::Entries,
                        ProfileFormFocus::Entries => ProfileFormFocus::Name,
                    };
                }
                PersonaMode::Bind(_) | PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormCycle(forwards) => {
            let attribute_count = state.main_page.content_panel.identity.attributes.len();
            let option_count = state.main_page.content_panel.identity.profiles.len() + 1;
            let p = &mut state.main_page.content_panel.identity;
            match &mut p.mode {
                PersonaMode::Attribute(form) => {
                    if form.field == AttributeField::ValueType {
                        let n = VALUE_TYPES.len();
                        form.value_type = if *forwards {
                            (form.value_type + 1) % n
                        } else {
                            (form.value_type + n - 1) % n
                        };
                    }
                }
                PersonaMode::Profile(form) => {
                    form.cursor = step(form.cursor, attribute_count, *forwards);
                }
                PersonaMode::Bind(picker) => {
                    picker.cursor = step(picker.cursor, option_count, *forwards);
                }
                PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormToggleEntry => {
            let attribute_id = {
                let p = &state.main_page.content_panel.identity;
                match &p.mode {
                    PersonaMode::Profile(form) => p
                        .attributes
                        .get(form.cursor)
                        .map(|a| a.attribute_id.clone()),
                    _ => None,
                }
            };
            let p = &mut state.main_page.content_panel.identity;
            if let (PersonaMode::Profile(form), Some(id)) = (&mut p.mode, attribute_id) {
                match form.ticked.iter().position(|x| *x == id) {
                    Some(i) => {
                        form.ticked.remove(i);
                    }
                    // Appended, so tick order is presentation order — the
                    // profile shows its claims in the order they were chosen.
                    None => form.ticked.push(id),
                }
            }
            PersonaEffect::None
        }
        PersonaAction::FormCancel => {
            state.main_page.content_panel.identity.mode = PersonaMode::View;
            PersonaEffect::None
        }
        PersonaAction::FormSubmit => form_submit(state),
    }
}

/// Answer the armed question.
///
/// Every arm acts on what the question named, not on where it sat: a listing
/// that arrived while the prompt was on screen cannot redirect the answer onto
/// a row the operator never selected.
fn confirm_yes(state: &mut State) -> PersonaEffect {
    let p = &mut state.main_page.content_panel.identity;
    let confirm = std::mem::replace(&mut p.confirm, PersonaConfirm::None);
    match confirm {
        // A persona deletion is not answered here — the pane arms the question and
        // the existing identity-deletion path answers it. See the key handler.
        PersonaConfirm::None | PersonaConfirm::DeletePersona(_) => PersonaEffect::None,
        PersonaConfirm::DeleteAttribute {
            attribute_id,
            cascade,
            ..
        } => PersonaEffect::Job(PersonaJob::AttributeDelete {
            attribute_id,
            cascade,
        }),
        PersonaConfirm::DeleteProfile {
            profile_id, unbind, ..
        } => PersonaEffect::Job(PersonaJob::ProfileDelete { profile_id, unbind }),
        PersonaConfirm::Unbind {
            context_id,
            persona_did,
            community,
        } => PersonaEffect::Job(PersonaJob::Bind {
            context_id,
            persona_did,
            profile_id: None,
            community,
        }),
    }
}

/// Validate and submit whichever form is open.
fn form_submit(state: &mut State) -> PersonaEffect {
    let profiles: Vec<ProfileSummary> = state
        .main_page
        .content_panel
        .identity
        .profiles
        .iter()
        .cloned()
        .collect();
    let p = &mut state.main_page.content_panel.identity;

    match &mut p.mode {
        PersonaMode::View => PersonaEffect::None,
        PersonaMode::Attribute(form) => {
            let claim_type = form.claim_type.value().trim().to_string();
            if claim_type.is_empty() {
                // Named rather than generic: the type is the one field with no
                // sensible default, because it is what a verifier matches on.
                form.error = Some("A type is required — e.g. email.work.".to_string());
                return PersonaEffect::None;
            }
            let value_type = pool::value_type_from_str(VALUE_TYPES[form.value_type]);
            let value = match pool::parse_typed_value(form.value.value(), value_type) {
                Ok(value) => value,
                Err(why) => {
                    form.error = Some(why);
                    return PersonaEffect::None;
                }
            };
            let label = form.label.value().trim();
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::AttributePut(AttributeDraft {
                attribute_id: form.attribute_id.clone(),
                expected_version: form.expected_version,
                claim_type,
                label: (!label.is_empty()).then(|| label.to_string()),
                value,
                value_type,
            }))
        }
        PersonaMode::Profile(form) => {
            let name = form.name.value().trim().to_string();
            if name.is_empty() {
                form.error = Some("A face needs a name — \"Work\", \"Gaming\".".to_string());
                return PersonaEffect::None;
            }
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::ProfilePut {
                profile_id: form.profile_id.clone(),
                name,
                live_refs: form.ticked.clone(),
                other_entries: form.preserved.clone(),
                expected_version: form.expected_version,
            })
        }
        PersonaMode::Bind(picker) => {
            // Row 0 is "nothing"; the rest index the profile list.
            let profile_id = picker
                .cursor
                .checked_sub(1)
                .and_then(|i| profiles.get(i))
                .map(|profile| profile.profile_id.clone());
            picker.error = None;
            picker.working = true;
            PersonaEffect::Job(PersonaJob::Bind {
                context_id: picker.context_id.clone(),
                persona_did: picker.persona_did.clone(),
                profile_id,
                community: picker.community.clone(),
            })
        }
    }
}

/// Give an open form back to the operator after a request that never left.
///
/// A form marked `working` is waiting on an answer, and if the request was
/// never sent there is no answer coming: the form would stay locked, showing
/// "Saving…" over an edit nobody is saving, until the pane was closed. Both
/// callers are the paths where the loop declines to spawn — no admin session,
/// and the domain already busy.
pub(crate) fn release_form(state: &mut State, reason: String) {
    let p = &mut state.main_page.content_panel.identity;
    match &mut p.mode {
        PersonaMode::Attribute(form) => {
            form.working = false;
            form.error = Some(reason);
        }
        PersonaMode::Profile(form) => {
            form.working = false;
            form.error = Some(reason);
        }
        PersonaMode::Bind(picker) => {
            picker.working = false;
            picker.error = Some(reason);
        }
        PersonaMode::View => p.status_message = Some(reason),
    }
}

/// Prefill the editor from an existing attribute.
fn form_for(attr: &PoolAttribute) -> AttributeForm {
    AttributeForm {
        attribute_id: Some(attr.attribute_id.clone()),
        expected_version: Some(attr.version),
        claim_type: tui_input::Input::new(attr.claim_type.clone()),
        label: tui_input::Input::new(attr.label.clone().unwrap_or_default()),
        value_type: VALUE_TYPES
            .iter()
            .position(|t| *t == attr.value_type)
            .unwrap_or(0),
        value: tui_input::Input::new(match &attr.value {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        }),
        field: AttributeField::default(),
        error: None,
        working: false,
    }
}

/// Move a cursor one step, stopping at the ends rather than wrapping: a list
/// that jumps from bottom to top under a held arrow key loses the operator's
/// place.
fn step(cursor: usize, len: usize, forwards: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forwards {
        (cursor + 1).min(len - 1)
    } else {
        cursor.saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// The jobs
// ---------------------------------------------------------------------------

/// How much of the disclosure history one read asks for.
///
/// The record is append-only and never trimmed, so "all of it" is a query that
/// gets slower for the life of the account. A page of the newest releases is
/// what the pane can show and what the holder opens it to see; the whole
/// history is a `pnm persona disclosure history` question.
pub(crate) const DISCLOSURE_PAGE: u64 = 100;

/// One backgrounded read of everything the agent-served tabs show.
pub(crate) struct PersonaReadJob {
    pub(crate) admin_vta: VtaClient,
    pub(crate) include_values: bool,
    pub(crate) targets: Vec<BindingTarget>,
    /// Whether this read should also fetch the claim-type registry.
    ///
    /// Once per session, not once per refresh: the table is a constant for a
    /// given agent, and a round-trip on every `r` would buy nothing but
    /// latency on the one action whose whole point is to feel immediate.
    pub(crate) needs_claim_types: bool,
}

impl PersonaReadJob {
    /// The targets a read should ask about: one per membership.
    pub(crate) fn targets(state: &State) -> Vec<BindingTarget> {
        state
            .main_page
            .content_panel
            .identity
            .memberships
            .iter()
            .filter(|m| !m.sub_context_id.is_empty() && !m.persona_did.is_empty())
            .map(|m| (m.sub_context_id.clone(), m.persona_did.clone()))
            .collect()
    }

    /// I/O only.
    pub(crate) async fn run(self) -> PersonaOutcome {
        let attributes = pool::list(&self.admin_vta, self.include_values)
            .await
            .map_err(|e| format!("{e}"));
        let profiles = profile::list(&self.admin_vta)
            .await
            .map_err(|e| format!("{e}"));
        let disclosures = match std::num::NonZeroU64::new(DISCLOSURE_PAGE) {
            Some(limit) => disclosure::history(&self.admin_vta, limit)
                .await
                .map_err(|e| format!("{e}")),
            None => Ok(Vec::new()),
        };
        let claim_types = match self.needs_claim_types {
            true => Some(
                claim_types::Registry::fetch(&self.admin_vta)
                    .await
                    .map(Box::new)
                    .map_err(|e| format!("{e}")),
            ),
            false => None,
        };
        let bindings = persona_binding_refresh::resolve_batch(self.admin_vta, self.targets).await;
        PersonaOutcome::Read {
            attributes,
            profiles,
            disclosures,
            bindings,
            claim_types,
            include_values: self.include_values,
        }
    }
}

/// One backgrounded write (or single-profile read).
pub(crate) struct PersonaJobRun {
    pub(crate) admin_vta: VtaClient,
    pub(crate) job: PersonaJob,
}

impl PersonaJobRun {
    /// I/O only.
    pub(crate) async fn run(self) -> PersonaOutcome {
        let client = self.admin_vta;
        match self.job {
            PersonaJob::AttributePut(draft) => PersonaOutcome::Written {
                verb: "Saved the attribute",
                error: pool::put(&client, draft)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::AttributeDelete {
                attribute_id,
                cascade,
            } => PersonaOutcome::Written {
                verb: "Forgot the attribute",
                error: pool::delete(&client, &attribute_id, cascade)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::ProfilePut {
                profile_id,
                name,
                live_refs,
                other_entries,
                expected_version,
            } => PersonaOutcome::Written {
                verb: "Saved the face",
                error: profile::put(
                    &client,
                    profile_id.as_deref(),
                    &name,
                    &live_refs,
                    &other_entries,
                    expected_version,
                )
                .await
                .err()
                .map(|e| format!("{e}")),
            },
            PersonaJob::ProfileDelete { profile_id, unbind } => PersonaOutcome::Written {
                verb: "Deleted the face",
                error: profile::delete(&client, &profile_id, unbind)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::ProfileGet { profile_id, edit } => PersonaOutcome::ProfileRead {
                edit,
                result: profile::get(&client, &profile_id, !edit)
                    .await
                    .map_err(|e| format!("{e}")),
            },
            PersonaJob::Bind {
                context_id,
                persona_did,
                profile_id,
                community,
            } => PersonaOutcome::Bound {
                community,
                cleared: profile_id.is_none(),
                error: binding::set(&client, &context_id, &persona_did, profile_id.as_deref())
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// The outcomes
// ---------------------------------------------------------------------------

/// What a persona job produced. Data only; applied on the loop thread.
pub(crate) enum PersonaOutcome {
    Read {
        attributes: Result<Vec<PoolAttribute>, String>,
        profiles: Result<Vec<ProfileSummary>, String>,
        disclosures: Result<Vec<disclosure::DisclosureRow>, String>,
        bindings: HashMap<BindingTarget, openvtc_core::persona::binding::BindingSummary>,
        /// The claim-type registry, when this read asked for it. `None` means
        /// it was not asked for — a refresh over a table already held — which
        /// is a different thing from a read that failed.
        ///
        /// Boxed because this variant is already the widest of the four and a
        /// whole registry inline pushes `DispatchOutcome` past what
        /// `clippy::large_enum_variant` will accept: every outcome, including
        /// the three one-word ones, would then be moved at the width of the
        /// table.
        claim_types: Option<Result<Box<claim_types::Registry>, String>>,
        include_values: bool,
    },
    Written {
        verb: &'static str,
        error: Option<String>,
    },
    ProfileRead {
        edit: bool,
        result: Result<ProfileDetail, String>,
    },
    Bound {
        community: String,
        cleared: bool,
        error: Option<String>,
    },
}

impl PersonaOutcome {
    /// Fold the result into the pane, on the loop thread.
    pub(crate) fn apply(self, state: &mut State) {
        let p = &mut state.main_page.content_panel.identity;
        p.loading = false;

        match self {
            PersonaOutcome::Read {
                attributes,
                profiles,
                disclosures,
                bindings,
                claim_types,
                include_values,
            } => {
                // A listing for a filter the operator has since flipped is
                // dropped: they pressed `v` while it was in flight, so it
                // answers the old question and a fresh job is already queued.
                if include_values != p.show_values {
                    return;
                }
                // The first failure is the one shown, and it is shown *instead*
                // of an empty list — the whole reason `load_error` exists. The
                // registry is in that chain rather than silently below it: a
                // failed read leaves the pane drawing from the compiled copy,
                // and a masking decision this binary made where the agent's own
                // table was supposed to speak is exactly the kind of thing R6.4
                // says must not pass for a normal screen.
                p.load_error = attributes
                    .as_ref()
                    .err()
                    .or(profiles.as_ref().err())
                    .or(disclosures.as_ref().err())
                    .or_else(|| claim_types.as_ref().and_then(|r| r.as_ref().err()))
                    .cloned();
                // A successful read is kept whatever else failed, and marks the
                // table read for the session; a failed one leaves the previous
                // table in place and stays unmarked, so the next refresh asks
                // again rather than settling for spec 0.1 forever.
                if let Some(Ok(registry)) = claim_types {
                    p.claim_types = *registry;
                    p.claim_types_loaded = true;
                }
                if let Ok(list) = attributes {
                    p.attribute_selected = p.attribute_selected.min(list.len().saturating_sub(1));
                    p.attributes = list.into();
                    // The list under the reveal has been rebuilt and may be
                    // ordered differently, so the grant no longer names a row
                    // the holder chose.
                    p.revealed_attribute = None;
                }
                if let Ok(list) = profiles {
                    p.profile_selected = p.profile_selected.min(list.len().saturating_sub(1));
                    p.profiles = list.into();
                }
                if let Ok(list) = disclosures {
                    p.disclosure_selected = p.disclosure_selected.min(list.len().saturating_sub(1));
                    p.disclosures = list.into();
                }
                // Merged, not replaced: a read only carries the targets it was
                // given, and replacing would blank every row it did not cover —
                // which reads on screen as those personas having stopped
                // presenting anything.
                p.bindings.extend(bindings);
                if p.load_error.is_none() {
                    p.loaded = true;
                }
            }

            PersonaOutcome::Written { verb, error } => {
                // The store is authoritative and has just been invalidated, so
                // ask for a re-read either way. A failed write is exactly when
                // a stale list misleads most: its state is now unknown.
                p.refresh_queued = true;
                match error {
                    None => {
                        p.mode = PersonaMode::View;
                        p.status_message = Some(format!("{verb}."));
                        state.main_page.log(format!("{verb}."));
                    }
                    Some(e) => {
                        // Into the form when one is open, so the holder keeps
                        // what they typed and can fix it.
                        match &mut p.mode {
                            PersonaMode::Attribute(form) => {
                                form.working = false;
                                form.error = Some(e.clone());
                            }
                            PersonaMode::Profile(form) => {
                                form.working = false;
                                form.error = Some(e.clone());
                            }
                            _ => p.status_message = Some(e.clone()),
                        }
                        state
                            .main_page
                            .log_error(format!("{verb} failed"), e.as_str());
                    }
                }
            }

            PersonaOutcome::ProfileRead { edit, result } => match result {
                Ok(detail) => {
                    if edit {
                        if detail.is_editable_here() {
                            p.mode = PersonaMode::Profile(ProfileForm {
                                profile_id: Some(detail.summary.profile_id.clone()),
                                expected_version: Some(detail.summary.version),
                                name: tui_input::Input::new(detail.summary.name.clone()),
                                ticked: detail.live_refs.clone(),
                                cursor: 0,
                                focus: ProfileFormFocus::Name,
                                preserved: detail.other_entries.clone(),
                                error: None,
                                working: false,
                            });
                        } else {
                            // Refused rather than opened: saving could not
                            // round-trip an entry this build cannot read, and a
                            // save that silently drops one is invisible.
                            p.status_message = Some(detail.refusal());
                        }
                    } else {
                        p.open_profile = Some(detail);
                        // A fresh detail is a fresh set of rows: the cursor
                        // starts at the top and nothing is revealed. Carrying
                        // an index over would grant a reveal on whatever
                        // happens to sit at that position now.
                        p.face_claim_selected = 0;
                        p.revealed_face_claim = None;
                    }
                }
                Err(e) => {
                    p.status_message = Some(e.clone());
                    state
                        .main_page
                        .log_error("Reading the profile failed", e.as_str());
                }
            },

            PersonaOutcome::Bound {
                community,
                cleared,
                error,
            } => {
                p.refresh_queued = true;
                match error {
                    None => {
                        p.mode = PersonaMode::View;
                        let msg = if cleared {
                            format!("Taken off. {community} is now shown nothing.")
                        } else {
                            format!("Changed the face {community} sees.")
                        };
                        p.status_message = Some(msg.clone());
                        state.main_page.log(msg);
                    }
                    Some(e) => {
                        if let PersonaMode::Bind(picker) = &mut p.mode {
                            picker.working = false;
                            picker.error = Some(e.clone());
                        } else {
                            p.status_message = Some(e.clone());
                        }
                        state
                            .main_page
                            .log_error("Changing the face failed", e.as_str());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{IdentityState, PersonaMembership};
    use openvtc_core::persona::binding::BindingSummary;
    use openvtc_core::persona::pool::ProvenanceKind;

    fn attribute(id: &str) -> PoolAttribute {
        PoolAttribute {
            attribute_id: id.to_string(),
            claim_type: "email.work".to_string(),
            value_type: "string".to_string(),
            version: 4,
            ..PoolAttribute::default()
        }
    }

    fn state_with(personas: IdentityState) -> State {
        let mut state = State::default();
        state.main_page.content_panel.identity = personas;
        state
    }

    fn personas(state: &State) -> &IdentityState {
        &state.main_page.content_panel.identity
    }

    /// Deleting an attribute a profile uses asks the cascading question *first*.
    ///
    /// The listing already says which attributes are referenced, so there is no
    /// reason to put a question the VTA is going to refuse and then put a
    /// different one — a holder who has already answered "yes, delete it"
    /// answers the follow-up with the first question's reasoning.
    #[test]
    fn a_referenced_attribute_arms_the_cascading_question_directly() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A"), attribute("01B")].into(),
            profiles: vec![ProfileSummary {
                profile_id: "01P".into(),
                name: "Work".into(),
                referenced: vec!["01A".into()],
                ..ProfileSummary::default()
            }]
            .into(),
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::AttributeDeleteArm(0));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteAttribute {
                attribute_id: "01A".into(),
                name: "email.work".into(),
                cascade: true
            }
        );

        apply(&mut state, &PersonaAction::AttributeDeleteArm(1));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteAttribute {
                attribute_id: "01B".into(),
                name: "email.work".into(),
                cascade: false
            },
            "an unreferenced attribute needs no cascade"
        );
    }

    /// Same rule one layer up: deleting a profile a persona presents asks the
    /// unbinding question, because that is what will actually happen.
    #[test]
    fn a_presented_profile_arms_the_unbinding_question() {
        let mut bindings = HashMap::new();
        bindings.insert(
            ("ctx".to_string(), "did:webvh:example.com:alice".to_string()),
            BindingSummary {
                bound: true,
                profile_id: Some("01P".into()),
                ..BindingSummary::default()
            },
        );
        let mut state = state_with(IdentityState {
            profiles: vec![
                ProfileSummary {
                    profile_id: "01P".into(),
                    ..ProfileSummary::default()
                },
                ProfileSummary {
                    profile_id: "01Q".into(),
                    ..ProfileSummary::default()
                },
            ]
            .into(),
            bindings,
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::ProfileDeleteArm(0));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteProfile {
                profile_id: "01P".into(),
                name: "unnamed face".into(),
                unbind: true
            }
        );
        apply(&mut state, &PersonaAction::ProfileDeleteArm(1));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteProfile {
                profile_id: "01Q".into(),
                name: "unnamed face".into(),
                unbind: false
            }
        );
    }

    /// A listing that lands while a question is on screen cannot redirect the
    /// answer.
    ///
    /// The prompt is armed against the attribute the operator selected, and a
    /// refresh (or another surface's write) can reorder the pool underneath it
    /// before they press `y`. An index into the old listing would then name a
    /// different attribute in the new one — deleting something they never
    /// selected while showing them the name of something else.
    #[test]
    fn an_armed_delete_survives_the_list_moving_underneath_it() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A"), attribute("01B")].into(),
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::AttributeDeleteArm(0));

        // A read lands, and the pool comes back in a different order.
        PersonaOutcome::Read {
            attributes: Ok(vec![attribute("01B"), attribute("01A")]),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            claim_types: None,
            include_values: false,
        }
        .apply(&mut state);

        match apply(&mut state, &PersonaAction::ConfirmYes) {
            PersonaEffect::Job(PersonaJob::AttributeDelete { attribute_id, .. }) => {
                assert_eq!(
                    attribute_id, "01A",
                    "the armed attribute is the one deleted"
                )
            }
            _ => panic!("expected a delete"),
        }
    }

    /// A credential-backed attribute does not open an editor. The refusal is
    /// the point: retyping its value would manufacture an attested claim out of
    /// a typed string.
    #[test]
    fn a_credential_backed_attribute_refuses_the_editor() {
        let mut attr = attribute("01A");
        attr.provenance = ProvenanceKind::CredentialBacked;
        let mut state = state_with(IdentityState {
            attributes: vec![attr].into(),
            show_values: true,
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::AttributeEdit(0));

        assert!(matches!(personas(&state).mode, PersonaMode::View));
        assert!(
            personas(&state)
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("comes from a credential")),
            "the refusal has to say why"
        );
    }

    /// Opening the editor when the listing was fetched without values re-reads
    /// with them. Without this the form would open empty and save a blank over
    /// a value the holder never saw.
    #[test]
    fn editing_without_values_in_hand_asks_for_them() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A")].into(),
            show_values: false,
            ..IdentityState::default()
        });

        let effect = apply(&mut state, &PersonaAction::AttributeEdit(0));

        assert!(matches!(effect, PersonaEffect::Read));
        assert!(personas(&state).show_values);
        assert!(matches!(personas(&state).mode, PersonaMode::Attribute(_)));
    }

    /// A reveal names one attribute, is put back by the same key, and never becomes
    /// a read.
    ///
    /// Lifting the mask touches nothing but this pane: the value is already in
    /// memory, which is the whole of why the mask is not a control. The control
    /// that would be one is a listing that is never sent sensitive values, and
    /// it does not exist yet.
    #[test]
    fn a_reveal_names_one_fact_and_toggles_off() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A"), attribute("01B")].into(),
            show_values: true,
            ..IdentityState::default()
        });

        let effect = apply(&mut state, &PersonaAction::RevealValue(1));
        assert!(matches!(effect, PersonaEffect::None), "no round-trip");
        assert_eq!(personas(&state).revealed_attribute.as_deref(), Some("01B"));

        apply(&mut state, &PersonaAction::RevealValue(1));
        assert!(personas(&state).revealed_attribute.is_none());
    }

    /// The editor opens on the value, never on the mask.
    ///
    /// A mask is a rendering and must never reach what is stored or sent —
    /// which it would, silently and permanently, if a form filled from
    /// `display_value` were saved: the holder's card number would become eight
    /// bullets and the version check would raise nothing, because the write is
    /// perfectly well-formed.
    #[test]
    fn the_editor_opens_on_the_value_not_on_the_mask() {
        let mut attr = attribute("01A");
        attr.claim_type = "payment.card".into();
        attr.value = Some(serde_json::json!("4242424242424242"));
        assert!(
            attr.is_masked(&claim_types::Registry::vendored()),
            "the fixture has to be a masked one"
        );

        let mut state = state_with(IdentityState {
            attributes: vec![attr].into(),
            show_values: true,
            ..IdentityState::default()
        });
        apply(&mut state, &PersonaAction::AttributeEdit(0));

        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert_eq!(form.value.value(), "4242424242424242");
            }
            _ => panic!("expected the editor"),
        }
    }

    /// A reveal on a row that is not there changes nothing — an index into a
    /// list that has since shrunk must not open whatever now sits at it.
    #[test]
    fn a_reveal_of_a_missing_row_reveals_nothing() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A")].into(),
            show_values: true,
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::RevealValue(7));
        assert!(personas(&state).revealed_attribute.is_none());
    }

    /// A face detail with three claims, two of which carry a mask style.
    fn open_face() -> openvtc_core::persona::profile::ProfileDetail {
        use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};
        ProfileDetail {
            summary: ProfileSummary {
                profile_id: "01P".into(),
                name: "OSS Developer".into(),
                ..ProfileSummary::default()
            },
            resolved: vec![
                ResolvedClaim {
                    claim_type: "name.legal".into(),
                    value: Some(serde_json::json!("Glenn Gore")),
                    ..ResolvedClaim::default()
                },
                ResolvedClaim {
                    claim_type: "email.work".into(),
                    value: Some(serde_json::json!("glenn@example.com")),
                    ..ResolvedClaim::default()
                },
            ],
            ..ProfileDetail::default()
        }
    }

    /// `s` on a face opens one claim, and pressing it again closes it — the key
    /// that showed the value is the one that hides it.
    #[test]
    fn a_face_reveal_toggles_on_the_same_key() {
        let mut state = state_with(IdentityState {
            tab: PersonaTab::Profiles,
            open_profile: Some(open_face()),
            face_claim_selected: 1,
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::RevealFaceClaim(1));
        assert_eq!(personas(&state).revealed_face_claim, Some(1));

        apply(&mut state, &PersonaAction::RevealFaceClaim(1));
        assert!(
            personas(&state).revealed_face_claim.is_none(),
            "toggled off"
        );
    }

    /// A reveal aimed past the end of the face opens nothing.
    ///
    /// The index comes from a keypress against what was on screen, and the
    /// detail can be replaced between the two — so it is checked against the
    /// open face rather than trusted.
    #[test]
    fn a_face_reveal_past_the_end_reveals_nothing() {
        let mut state = state_with(IdentityState {
            tab: PersonaTab::Profiles,
            open_profile: Some(open_face()),
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::RevealFaceClaim(7));
        assert!(personas(&state).revealed_face_claim.is_none());
    }

    /// A reveal with no face open at all opens nothing, rather than arming a
    /// grant that the next face to be opened would inherit.
    #[test]
    fn a_face_reveal_with_nothing_open_reveals_nothing() {
        let mut state = state_with(IdentityState {
            tab: PersonaTab::Profiles,
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::RevealFaceClaim(0));
        assert!(personas(&state).revealed_face_claim.is_none());
    }

    /// Everything that changes what is on screen puts a face's mask back too.
    ///
    /// Same rule as the attributes tab, and the same reason: a reveal is
    /// granted to one claim on one open face, and moving the cursor, closing
    /// the face or leaving the tab each ends it.
    #[test]
    fn moving_anywhere_puts_a_face_mask_back() {
        let revealed = || {
            state_with(IdentityState {
                tab: PersonaTab::Profiles,
                open_profile: Some(open_face()),
                face_claim_selected: 1,
                revealed_face_claim: Some(1),
                loaded: true,
                ..IdentityState::default()
            })
        };

        let mut moved = revealed();
        apply(&mut moved, &PersonaAction::FaceClaimSelect(0));
        assert!(personas(&moved).revealed_face_claim.is_none(), "cursor");
        assert_eq!(personas(&moved).face_claim_selected, 0);

        let mut closed = revealed();
        apply(&mut closed, &PersonaAction::ProfileClose);
        assert!(personas(&closed).revealed_face_claim.is_none(), "closed");

        let mut tabbed = revealed();
        apply(&mut tabbed, &PersonaAction::TabNext);
        assert!(personas(&tabbed).revealed_face_claim.is_none(), "tab");
    }

    /// Opening a face starts at the top with nothing revealed.
    ///
    /// A carried-over index would grant a reveal on whatever now sits at that
    /// position, which is a different claim in a different face.
    #[test]
    fn opening_a_face_starts_closed_and_at_the_top() {
        let mut state = state_with(IdentityState {
            tab: PersonaTab::Profiles,
            face_claim_selected: 1,
            revealed_face_claim: Some(1),
            ..IdentityState::default()
        });

        PersonaOutcome::ProfileRead {
            edit: false,
            result: Ok(open_face()),
        }
        .apply(&mut state);
        assert_eq!(personas(&state).face_claim_selected, 0);
        assert!(personas(&state).revealed_face_claim.is_none());
    }

    /// Everything that changes what is on screen puts the mask back.
    ///
    /// This is what keeps the reveal from becoming a global unmask reached one
    /// keypress at a time: it is granted to a row on a tab in a listing, and
    /// each of those three moving ends it.
    #[test]
    fn moving_anywhere_puts_the_mask_back() {
        let revealed = || {
            state_with(IdentityState {
                tab: PersonaTab::Attributes,
                attributes: vec![attribute("01A"), attribute("01B")].into(),
                show_values: true,
                loaded: true,
                revealed_attribute: Some("01A".to_string()),
                ..IdentityState::default()
            })
        };

        let mut moved = revealed();
        apply(&mut moved, &PersonaAction::Select(1));
        assert!(personas(&moved).revealed_attribute.is_none(), "selection");

        let mut tabbed = revealed();
        apply(&mut tabbed, &PersonaAction::TabNext);
        assert!(personas(&tabbed).revealed_attribute.is_none(), "tab");

        let mut toggled = revealed();
        apply(&mut toggled, &PersonaAction::ToggleValues);
        assert!(personas(&toggled).revealed_attribute.is_none(), "values");

        let mut re_read = revealed();
        PersonaOutcome::Read {
            attributes: Ok(vec![attribute("01B"), attribute("01A")]),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            claim_types: None,
            include_values: true,
        }
        .apply(&mut re_read);
        assert!(personas(&re_read).revealed_attribute.is_none(), "re-read");
    }

    /// Toggling values is a re-read, not a redraw — a listing fetched without
    /// values does not hold them.
    #[test]
    fn toggling_values_re_reads() {
        let mut state = State::default();
        let effect = apply(&mut state, &PersonaAction::ToggleValues);
        assert!(matches!(effect, PersonaEffect::Read));
        assert!(personas(&state).show_values);
    }

    /// A read that answers a question the operator has already changed is
    /// dropped rather than flashed — the same rule the VIC listing follows.
    #[test]
    fn a_superseded_read_is_discarded() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A")].into(),
            show_values: true,
            ..IdentityState::default()
        });

        PersonaOutcome::Read {
            attributes: Ok(vec![attribute("01B"), attribute("01C")]),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            claim_types: None,
            include_values: false,
        }
        .apply(&mut state);

        assert_eq!(
            personas(&state).attributes.len(),
            1,
            "the superseded listing must not apply"
        );
    }

    /// A failed read keeps the previous list and records why — it must never
    /// leave the pane claiming the holder has no attributes.
    #[test]
    fn a_failed_read_keeps_the_list_and_says_why() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A")].into(),
            loaded: true,
            ..IdentityState::default()
        });

        PersonaOutcome::Read {
            attributes: Err("connection refused".to_string()),
            profiles: Ok(Vec::new()),
            disclosures: Ok(Vec::new()),
            bindings: HashMap::new(),
            claim_types: None,
            include_values: false,
        }
        .apply(&mut state);

        assert_eq!(personas(&state).attributes.len(), 1);
        assert_eq!(
            personas(&state).load_error.as_deref(),
            Some("connection refused")
        );
    }

    /// A write asks for a re-read whether it succeeded or failed. After a
    /// failure the store's state is unknown, which is when a stale list is most
    /// misleading.
    #[test]
    fn every_write_asks_for_a_re_read() {
        for error in [None, Some("refused".to_string())] {
            let mut state = State::default();
            PersonaOutcome::Written {
                verb: "Saved the attribute",
                error,
            }
            .apply(&mut state);
            assert!(personas(&state).refresh_queued);
        }
    }

    /// A request the loop declines to send hands the form back.
    ///
    /// The form is marked `working` the moment it is submitted, and that flag
    /// is what locks the keyboard. If the loop then declines to spawn — no
    /// admin session, or the domain already busy — nothing is coming back to
    /// clear it, and the form sits on "Saving…" over an edit nobody is saving.
    #[test]
    fn a_request_that_never_left_unlocks_the_form() {
        let mut state = state_with(IdentityState {
            mode: PersonaMode::Attribute(AttributeForm {
                working: true,
                ..AttributeForm::default()
            }),
            ..IdentityState::default()
        });

        release_form(&mut state, "no session".to_string());

        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert!(!form.working);
                assert_eq!(form.error.as_deref(), Some("no session"));
            }
            _ => panic!("the form must stay open"),
        }
    }

    /// The picker is the same: it locks itself on submit and has to be given
    /// back if the write never went.
    #[test]
    fn a_request_that_never_left_unlocks_the_picker() {
        let mut state = state_with(IdentityState {
            mode: PersonaMode::Bind(BindPicker {
                working: true,
                ..BindPicker::default()
            }),
            ..IdentityState::default()
        });

        release_form(&mut state, "busy".to_string());

        match &personas(&state).mode {
            PersonaMode::Bind(picker) => {
                assert!(!picker.working);
                assert_eq!(picker.error.as_deref(), Some("busy"));
            }
            _ => panic!("the picker must stay open"),
        }
    }

    /// A failed save keeps the form open with the reason on it, so the holder
    /// does not lose what they typed.
    #[test]
    fn a_failed_save_keeps_the_form_and_its_contents() {
        let mut state = state_with(IdentityState {
            mode: PersonaMode::Attribute(AttributeForm {
                claim_type: tui_input::Input::new("email.work".into()),
                working: true,
                ..AttributeForm::default()
            }),
            ..IdentityState::default()
        });

        PersonaOutcome::Written {
            verb: "Saved the attribute",
            error: Some("version conflict".to_string()),
        }
        .apply(&mut state);

        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert_eq!(form.claim_type.value(), "email.work");
                assert!(!form.working, "the form has to become editable again");
                assert_eq!(form.error.as_deref(), Some("version conflict"));
            }
            _ => panic!("the form must stay open"),
        }
    }

    /// An empty type is refused before the round-trip, because it is the one
    /// field with no sensible default: it is what a verifier matches on.
    #[test]
    fn a_typeless_attribute_is_refused_locally() {
        let mut state = state_with(IdentityState {
            mode: PersonaMode::Attribute(AttributeForm::default()),
            ..IdentityState::default()
        });

        let effect = apply(&mut state, &PersonaAction::FormSubmit);

        assert!(matches!(effect, PersonaEffect::None));
        match &personas(&state).mode {
            PersonaMode::Attribute(form) => {
                assert!(form.error.as_deref().is_some_and(|e| e.contains("type")));
                assert!(!form.working, "nothing was sent, so nothing is in flight");
            }
            _ => panic!("the form must stay open"),
        }
    }

    /// The picker opens on what is bound now, so pressing ⏎ without moving
    /// leaves the binding alone instead of silently clearing it.
    #[test]
    fn the_picker_opens_on_the_current_binding() {
        let membership = PersonaMembership {
            community_name: "Acme".into(),
            sub_context_id: "ctx".into(),
            persona_did: "did:webvh:example.com:alice".into(),
            ..PersonaMembership::default()
        };
        let mut bindings = HashMap::new();
        bindings.insert(
            ("ctx".to_string(), membership.persona_did.clone()),
            BindingSummary {
                bound: true,
                profile_id: Some("01Q".into()),
                ..BindingSummary::default()
            },
        );
        let mut state = state_with(IdentityState {
            memberships: vec![membership].into(),
            profiles: vec![
                ProfileSummary {
                    profile_id: "01P".into(),
                    ..ProfileSummary::default()
                },
                ProfileSummary {
                    profile_id: "01Q".into(),
                    ..ProfileSummary::default()
                },
            ]
            .into(),
            bindings,
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::BindOpen(0));

        match &personas(&state).mode {
            // Row 0 is "nothing", so the second profile is row 2.
            PersonaMode::Bind(picker) => {
                assert_eq!(picker.cursor, 2);
                // Named, not indexed: the membership list is rebuilt from
                // `Config` on every sync, and an inbound message is enough to
                // reorder it while the picker is open. An index would then send
                // the holder's identity to a community they were not looking at.
                assert_eq!(picker.context_id, "ctx");
                assert_eq!(picker.persona_did, "did:webvh:example.com:alice");
            }
            _ => panic!("the picker must be open"),
        }
    }

    /// An unbound persona opens the picker on "nothing", which is where it
    /// already is.
    #[test]
    fn an_unbound_persona_opens_the_picker_on_nothing() {
        let mut state = state_with(IdentityState {
            memberships: vec![PersonaMembership::default()].into(),
            ..IdentityState::default()
        });
        apply(&mut state, &PersonaAction::BindOpen(0));
        match &personas(&state).mode {
            PersonaMode::Bind(picker) => assert_eq!(picker.cursor, 0),
            _ => panic!("the picker must be open"),
        }
    }

    /// Ticking appends, so the order the holder chose is the order the profile
    /// presents.
    #[test]
    fn ticking_preserves_the_order_entries_were_chosen_in() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A"), attribute("01B"), attribute("01C")].into(),
            mode: PersonaMode::Profile(ProfileForm {
                focus: ProfileFormFocus::Entries,
                ..ProfileForm::default()
            }),
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::FormCycle(true)); // → 01B
        apply(&mut state, &PersonaAction::FormToggleEntry);
        apply(&mut state, &PersonaAction::FormCycle(false)); // → 01A
        apply(&mut state, &PersonaAction::FormToggleEntry);

        match &personas(&state).mode {
            PersonaMode::Profile(form) => {
                assert_eq!(form.ticked, vec!["01B".to_string(), "01A".to_string()])
            }
            _ => panic!("the form must be open"),
        }

        // And ticking again removes it.
        apply(&mut state, &PersonaAction::FormToggleEntry);
        match &personas(&state).mode {
            PersonaMode::Profile(form) => assert_eq!(form.ticked, vec!["01B".to_string()]),
            _ => panic!("the form must be open"),
        }
    }

    /// Editing a profile this build cannot fully read is refused rather than
    /// opened. A save from that form could not round-trip the entry it could
    /// not parse, and dropping it would be invisible.
    #[test]
    fn a_profile_with_unreadable_entries_refuses_the_editor() {
        let mut state = State::default();
        PersonaOutcome::ProfileRead {
            edit: true,
            result: Ok(ProfileDetail {
                unreadable_entries: 1,
                ..ProfileDetail::default()
            }),
        }
        .apply(&mut state);

        assert!(matches!(personas(&state).mode, PersonaMode::View));
        assert!(
            personas(&state)
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("cannot read"))
        );
    }

    /// Moving tabs drops what was armed or opened on the one being left: a `y`
    /// belongs to the screen that asked the question.
    #[test]
    fn changing_tab_disarms_the_confirmation() {
        let mut state = state_with(IdentityState {
            tab: PersonaTab::Attributes,
            confirm: PersonaConfirm::DeleteAttribute {
                attribute_id: "01A".into(),
                name: "email.work".into(),
                cascade: false,
            },
            ..IdentityState::default()
        });

        apply(&mut state, &PersonaAction::TabNext);

        assert_eq!(personas(&state).tab, PersonaTab::Profiles);
        assert_eq!(personas(&state).confirm, PersonaConfirm::None);
    }

    /// The agent-served tabs read on first arrival and not again — the pane is
    /// not a poller.
    #[test]
    fn an_agent_tab_reads_once_on_arrival() {
        let mut state = State::default();
        // Personas → Attributes: needs the agent, nothing loaded yet.
        assert!(matches!(
            apply(&mut state, &PersonaAction::TabNext),
            PersonaEffect::Read
        ));

        state.main_page.content_panel.identity.loaded = true;
        assert!(matches!(
            apply(&mut state, &PersonaAction::TabNext),
            PersonaEffect::None
        ));
    }
}
