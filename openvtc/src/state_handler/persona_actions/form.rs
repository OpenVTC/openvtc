//! The pane's forms: validating and submitting whichever is open, releasing one
//! whose request never left, and filling editors from existing records.

use crate::state_handler::main_page::status::Status;
use openvtc_core::persona::{
    contacts, lifecycle,
    pool::{self, AttributeDraft, PoolAttribute},
    profile::ProfileSummary,
    world,
};

use super::jobs::PersonaJob;
use super::reducer::PersonaEffect;
use crate::state_handler::main_page::content::{
    AttributeField, AttributeForm, ComposeRow, PersonaMode, VALUE_TYPES, WorldForm,
};
use crate::state_handler::state::State;

/// Validate and submit whichever form is open.
pub(super) fn form_submit(state: &mut State) -> PersonaEffect {
    let profiles: Vec<ProfileSummary> = state
        .main_page
        .content_panel
        .identity
        .profiles
        .iter()
        .cloned()
        .collect();
    // Taken here, before the mode is borrowed mutably, and handed to the job
    // whole: placing a face is two conditional writes, and both need the
    // versions that were on screen when the holder chose.
    let worlds: Vec<world::World> = state
        .main_page
        .content_panel
        .identity
        .worlds
        .iter()
        .cloned()
        .collect();
    let p = &mut state.main_page.content_panel.identity;

    match &mut p.mode {
        // Read-only overlays: ⏎ has nothing to submit, and Esc closes them.
        PersonaMode::View | PersonaMode::Renderers(_) | PersonaMode::KnownHere(_) => {
            PersonaEffect::None
        }
        PersonaMode::Attribute(form) => {
            // The same check the vetting page's make-a-face form makes when it
            // saves a value in place, so the two cannot drift apart.
            let value_type = pool::value_type_from_str(VALUE_TYPES[form.value_type]);
            let draft = match pool::draft_from_text(
                form.claim_type.value(),
                form.value.value(),
                value_type,
                Some(form.label.value()),
            ) {
                Ok(draft) => draft,
                Err(why) => {
                    form.error = Some(why);
                    return PersonaEffect::None;
                }
            };
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::AttributePut(AttributeDraft {
                attribute_id: form.attribute_id.clone(),
                expected_version: form.expected_version,
                endorsements: form.endorsements.clone(),
                ..draft
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
        PersonaMode::World(form) => {
            let name = form.name.value().trim().to_string();
            if name.is_empty() {
                form.error = Some("A world needs a name — \"Work\", \"Home\".".to_string());
                return PersonaEffect::None;
            }
            let icon = form.icon.value().trim();
            // Bounded at 8 bytes by the schema, because it is a mark and not a
            // field: anything longer is text, and text belongs in the name
            // where it will be laid out. Refused here rather than at the agent
            // so the holder is told which field, while they are still in it.
            if icon.len() > 8 {
                form.error = Some(
                    "A mark is one or two emoji. Longer text belongs in the name.".to_string(),
                );
                return PersonaEffect::None;
            }
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::WorldPut(world::WorldDraft {
                world_id: form.world_id.clone(),
                name,
                colour: world::Colour::all()[form.colour.min(world::Colour::all().len() - 1)],
                icon: (!icon.is_empty()).then(|| icon.to_string()),
                // Straight back out as they came in. See `WorldForm`.
                face_ids: form.face_ids.clone(),
                attribute_ids: form.attribute_ids.clone(),
                // `Some(0)` on a create, so a retry after a lost response
                // cannot replace what the first attempt made.
                expected_version: form.expected_version.or(Some(0)),
            }))
        }
        PersonaMode::PlaceFace(picker) => {
            // Row 0 is "belongs to no world"; the rest index the world list.
            let into = picker
                .cursor
                .checked_sub(1)
                .and_then(|i| worlds.get(i))
                .map(|f| f.world_id.clone());
            picker.error = None;
            picker.working = true;
            PersonaEffect::Job(PersonaJob::FacePlace {
                worlds,
                profile_id: picker.profile_id.clone(),
                into,
            })
        }
        PersonaMode::People(view) => {
            // An armed delete is what ⏎ answers first: it is on screen, and
            // anything else would act past a question the holder can see.
            if let Some((contact_id, _)) = view.deleting.clone() {
                view.working = true;
                return PersonaEffect::Job(PersonaJob::ContactDelete {
                    context_id: view.context_id.clone(),
                    contact_id,
                });
            }
            let Some(form) = &mut view.form else {
                // No form up: ⏎ reads the row under the cursor instead, which
                // is what the list's own hint offers.
                return PersonaEffect::None;
            };
            let subject_did = form.subject_did.value().trim().to_string();
            if subject_did.is_empty() {
                view.error = Some("Whose card is this? Give the DID they gave you.".into());
                return PersonaEffect::None;
            }
            let mut facts = Vec::new();
            for row in &form.rows {
                let claim_type = row.claim_type.value().trim().to_string();
                let value = row.value.value().trim().to_string();
                match (claim_type.is_empty(), value.is_empty()) {
                    (true, true) => continue,
                    (false, false) => facts.push(contacts::ContactFact { claim_type, value }),
                    // Half a row is a typo, not a fact: refused here rather
                    // than filed as something they did not say.
                    _ => {
                        view.error =
                            Some("Each fact needs both what it is and what they said.".into());
                        return PersonaEffect::None;
                    }
                }
            }
            if facts.is_empty() {
                view.error = Some("Nothing to record — add at least one fact.".into());
                return PersonaEffect::None;
            }
            let notes = form.notes.value().trim().to_string();
            view.working = true;
            view.error = None;
            PersonaEffect::Job(PersonaJob::ContactPut {
                context_id: view.context_id.clone(),
                subject_did,
                known_by_persona: view.persona_did.clone(),
                facts,
                notes: (!notes.is_empty()).then_some(notes),
            })
        }
        PersonaMode::LocalFaces(view) => {
            if let Some(form) = &view.form {
                let name = form.name.value().trim().to_string();
                if name.is_empty() {
                    view.error = Some("Give the face a name — only you see it.".into());
                    return PersonaEffect::None;
                }
                let mut values = Vec::new();
                for row in &form.rows {
                    let claim_type = row.claim_type.value().trim().to_string();
                    let value = row.value.value().trim().to_string();
                    match (claim_type.is_empty(), value.is_empty()) {
                        (true, true) => continue,
                        (false, false) => values.push(lifecycle::ComposeValue {
                            claim_type,
                            value,
                            // Never shared from here: making a value reusable
                            // is the promote step, asked separately because it
                            // cannot be undone.
                            share: false,
                        }),
                        _ => {
                            view.error =
                                Some("Each value needs both what it is and what it says.".into());
                            return PersonaEffect::None;
                        }
                    }
                }
                if values.is_empty() {
                    view.error = Some("A face with nothing on it shows nothing.".into());
                    return PersonaEffect::None;
                }
                view.working = true;
                view.error = None;
                return PersonaEffect::Job(PersonaJob::LocalFacePut {
                    context_id: view.context_id.clone(),
                    name,
                    values,
                });
            }
            if let Some((profile_id, _)) = view.deleting.clone() {
                view.working = true;
                return PersonaEffect::Job(PersonaJob::LocalFaceDelete {
                    context_id: view.context_id.clone(),
                    profile_id,
                });
            }
            let Some((profile_id, positions)) = view.chosen.clone() else {
                view.error = Some("Choose a value with space first.".to_string());
                return PersonaEffect::None;
            };
            // Asked once, on screen, before anything moves: it cannot be undone.
            if !view.confirming {
                view.confirming = true;
                view.error = None;
                return PersonaEffect::None;
            }
            let version = match &view.faces {
                Some(Ok(faces)) => faces
                    .iter()
                    .find(|f| f.profile_id == profile_id)
                    .map(|f| f.version),
                _ => None,
            };
            let Some(version) = version else {
                return PersonaEffect::None;
            };
            view.working = true;
            view.confirming = false;
            PersonaEffect::Job(PersonaJob::Promote {
                context_id: view.context_id.clone(),
                profile_id,
                positions,
                expected_version: version,
            })
        }
        PersonaMode::Compose(form) => {
            let name = form.name.value().trim().to_string();
            if name.is_empty() {
                form.error = Some("A face needs a name — only you ever see it.".to_string());
                return PersonaEffect::None;
            }
            let values = match compose_values(&form.rows) {
                Ok(v) => v,
                Err(why) => {
                    form.error = Some(why);
                    return PersonaEffect::None;
                }
            };
            form.error = None;
            form.working = true;
            PersonaEffect::Job(PersonaJob::Compose {
                context_id: form.context_id.clone(),
                persona_did: form.persona_did.clone(),
                community: form.community.clone(),
                name,
                values,
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
        PersonaMode::World(form) => {
            form.working = false;
            form.error = Some(reason);
        }
        PersonaMode::PlaceFace(picker) => {
            picker.working = false;
            picker.error = Some(reason);
        }
        PersonaMode::Bind(picker) => {
            picker.working = false;
            picker.error = Some(reason);
        }
        PersonaMode::Compose(form) => {
            form.working = false;
            form.error = Some(reason);
        }
        PersonaMode::LocalFaces(view) => {
            view.working = false;
            view.error = Some(reason);
        }
        PersonaMode::People(view) => {
            view.working = false;
            view.error = Some(reason);
        }
        // A read-only overlay has no in-flight write to release; the pane's own
        // status line is where the reason belongs.
        PersonaMode::View | PersonaMode::Renderers(_) | PersonaMode::KnownHere(_) => {
            p.status_message = Some(Status::error(reason));
        }
    }
}

/// The compose form's rows as the values a face is made from, or why they
/// cannot be sent. Blank rows are dropped; a half-filled one is refused; the
/// claim type is checked here so the holder is told on the row rather than by
/// the agent refusing the whole face.
pub(crate) fn compose_values(rows: &[ComposeRow]) -> Result<Vec<lifecycle::ComposeValue>, String> {
    let mut out = Vec::new();
    for row in rows {
        let claim_type = row.claim_type.value().trim();
        let value = row.value.value().trim();
        if claim_type.is_empty() && value.is_empty() {
            continue;
        }
        if claim_type.is_empty() || value.is_empty() {
            return Err("A row needs both what it is and its value.".to_string());
        }
        let well_formed = claim_type
            .strip_prefix("x:")
            .unwrap_or(claim_type)
            .split('.')
            .all(|seg| {
                seg.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && seg.chars().all(|c| c.is_ascii_alphanumeric())
            });
        if !well_formed {
            return Err(format!(
                "\"{claim_type}\" is not a claim type — dotted and lower-case, like name.display."
            ));
        }
        out.push(lifecycle::ComposeValue {
            claim_type: claim_type.to_string(),
            value: value.to_string(),
            share: row.share,
        });
    }
    if out.is_empty() {
        return Err("A face needs at least one thing to show.".to_string());
    }
    Ok(out)
}

/// Prefill the editor from an existing attribute.
pub(super) fn form_for(attr: &PoolAttribute) -> AttributeForm {
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
        endorsements: attr.endorsements.clone(),
        field: AttributeField::default(),
        error: None,
        working: false,
    }
}

/// Move a cursor one step, stopping at the ends rather than wrapping: a list
/// that jumps from bottom to top under a held arrow key loses the operator's
/// place.
pub(super) fn step(cursor: usize, len: usize, forwards: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if forwards {
        (cursor + 1).min(len - 1)
    } else {
        cursor.saturating_sub(1)
    }
}

/// The editor, filled from a world that already exists.
///
/// Membership comes across whole and untouched. `persona/world/put` is a
/// replace, so a form that carried only the fields it can edit would empty the
/// world's faces and attributes the first time somebody renamed it — and the
/// world would still be there afterwards, just with nothing in it.
pub(super) fn form_for_world(world: &world::World) -> WorldForm {
    WorldForm {
        world_id: Some(world.world_id.clone()),
        expected_version: Some(world.version),
        name: tui_input::Input::new(world.name.clone()),
        colour: world::Colour::all()
            .iter()
            .position(|c| *c == world.colour)
            .unwrap_or_default(),
        icon: tui_input::Input::new(world.icon.clone().unwrap_or_default()),
        face_ids: world.face_ids.clone(),
        attribute_ids: world.attribute_ids.clone(),
        ..WorldForm::default()
    }
}

/// Where a face sorts: by the world that holds it, in the order the worlds are
/// listed, and after every placed face when no world holds it.
///
/// `usize::MAX` for a homeless face rather than a sentinel at the front,
/// because "belongs to no world" is the group the console draws last and it is
/// the honest end of the list: every face belonging somewhere is fine too, and
/// leading with the ones that do not would read as a fault.
pub(super) fn world_rank(worlds: &[world::World], profile_id: &str) -> usize {
    worlds
        .iter()
        .position(|f| f.holds_face(profile_id))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::IdentityState;
    use crate::state_handler::main_page::content::{
        AttributeForm, BindPicker, ComposeRow, PersonaMode,
    };
    use crate::state_handler::persona_actions::test_support::{personas, state_with};

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

    #[test]
    fn a_claim_type_is_checked_on_the_row() {
        let row = |t: &str, v: &str| ComposeRow {
            claim_type: tui_input::Input::new(t.into()),
            value: tui_input::Input::new(v.into()),
            share: false,
        };
        assert!(compose_values(&[row("Name Display", "x")]).is_err());
        assert!(compose_values(&[row("", "")]).is_err(), "nothing to show");
        assert!(compose_values(&[row("x:nickname", "Ada"), row("", "")]).is_ok());
    }
}
