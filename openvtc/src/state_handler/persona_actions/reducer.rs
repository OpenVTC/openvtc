//! The identity-pane reducer: [`apply`] maps each `PersonaAction` onto the pane
//! and names the network work it needs as a [`PersonaEffect`]; plus answering
//! an armed confirmation.

use crate::state_handler::main_page::status::Status;
use openvtc_core::persona::{lifecycle, pool, world};

use super::form::{form_for, form_for_world, form_submit, step};
use super::jobs::PersonaJob;
use crate::state_handler::actions::PersonaAction;
use crate::state_handler::main_page::content::{
    AttributeField, AttributeForm, BindPicker, ComposeForm, ComposeRow, ContactForm, FacePlacer,
    KnownHereView, LocalFaceForm, LocalFacesView, PeopleView, PersonaConfirm, PersonaMode,
    PersonaTab, ProfileForm, ProfileFormFocus, RenderersView, VALUE_TYPES, WorldForm,
    WorldFormFocus,
};
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
                PersonaTab::Worlds => p.world_selected = *index,
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
            // A second press puts it back, so the key the holder used to show the
            // value is also the one that hides it again.
            if p.revealed_attribute.as_deref() == Some(attr.attribute_id.as_str()) {
                p.revealed_attribute = None;
                return PersonaEffect::None;
            }
            // A value not in memory is fetched on its own (`pool::reveal`): a
            // sensitive one the bulk listing withheld, or any value at all while
            // values are hidden — that listing carries none. The value is
            // spliced in and the mask lifted when it returns
            // (`AttributeRevealed`); nothing is revealed until then.
            //
            // Keyed on the value being absent, not on sensitivity: keyed on
            // sensitivity, `s` with values hidden lifted the mask over nothing
            // and the row went on reading "(hidden)" — a key that did nothing.
            if attr.value.is_none() && !attr.stale {
                return PersonaEffect::Job(PersonaJob::AttributeReveal {
                    attribute_id: attr.attribute_id.clone(),
                });
            }
            // Otherwise just lift the mask over a value already in memory — no
            // read, which is exactly why the mask is not a security control.
            p.revealed_attribute = Some(attr.attribute_id.clone());
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
                    p.status_message = Some(Status::error(why));
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

        PersonaAction::AttributePurgeArm(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(attr) = p.attributes.get(*index) else {
                return PersonaEffect::None;
            };
            // Faces that use it at all. Which of them pin an *old* version is
            // not in the listing, so the question names what is at risk and the
            // purge reports what it actually broke.
            let used_by = p
                .profiles
                .iter()
                .filter(|profile| profile.referenced.contains(&attr.attribute_id))
                .count();
            p.confirm = PersonaConfirm::PurgeAttribute {
                attribute_id: attr.attribute_id.clone(),
                name: attr.display_name().to_string(),
                used_by,
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
            p.face_history = None;
            PersonaEffect::None
        }
        PersonaAction::FaceHistory => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(detail) = p.open_profile.as_ref() else {
                return PersonaEffect::None;
            };
            if p.face_history.take().is_some() {
                return PersonaEffect::None;
            }
            PersonaEffect::Job(PersonaJob::FaceHistoryRead {
                profile_id: detail.summary.profile_id.clone(),
            })
        }
        PersonaAction::ToggleRetired => {
            let p = &mut state.main_page.content_panel.identity;
            p.show_retired = !p.show_retired;
            p.profile_selected = 0;
            p.open_profile = None;
            p.face_history = None;
            PersonaEffect::None
        }
        PersonaAction::ProfileRetireArm(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(profile) = p.profiles.get(*index) else {
                return PersonaEffect::None;
            };
            let worn = p
                .bindings
                .values()
                .filter(|b| b.profile_id.as_deref() == Some(profile.profile_id.as_str()))
                .count();
            p.confirm = PersonaConfirm::RetireFace {
                profile_id: profile.profile_id.clone(),
                name: profile.display_name().to_string(),
                worn,
            };
            PersonaEffect::None
        }
        PersonaAction::ProfileReinstate(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(face) = p.retired_faces.get(*index) else {
                return PersonaEffect::None;
            };
            // No question: reinstating binds nothing and removes nothing, so
            // there is nothing to confirm.
            PersonaEffect::Job(PersonaJob::ProfileReinstate {
                profile_id: face.profile_id.clone(),
            })
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
            // How far this face has spoken, said before it is deleted: a delete
            // does not un-tell anyone. Known already when the face is open;
            // otherwise asked for, and the prompt fills in when it answers.
            let known = p
                .open_profile
                .as_ref()
                .filter(|d| d.summary.profile_id == profile.profile_id)
                .map(|d| lifecycle::untell_words(d.disclosed_to));
            let profile_id = profile.profile_id.clone();
            p.confirm = PersonaConfirm::DeleteProfile {
                profile_id: profile_id.clone(),
                name: profile.display_name().to_string(),
                unbind,
                untell: known.clone().flatten(),
            };
            match known {
                Some(_) => PersonaEffect::None,
                None => PersonaEffect::Job(PersonaJob::ProfileSpoken { profile_id }),
            }
        }

        PersonaAction::FacePlaceOpen(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(face) = p.profiles.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            // Start on the world that holds it now, so ⏎ on an unchanged
            // picker is a no-op rather than a silent removal.
            let cursor = p
                .worlds
                .iter()
                .position(|f| f.holds_face(&face.profile_id))
                .map_or(0, |i| i + 1);
            p.mode = PersonaMode::PlaceFace(FacePlacer {
                profile_id: face.profile_id.clone(),
                face_name: face.display_name().to_string(),
                cursor,
                ..FacePlacer::default()
            });
            PersonaEffect::None
        }

        // ── Worlds ───────────────────────────────────────────────────────
        PersonaAction::WorldNew => {
            state.main_page.content_panel.identity.mode = PersonaMode::World(WorldForm::default());
            PersonaEffect::None
        }
        PersonaAction::WorldEdit(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(world) = p.worlds.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            p.mode = PersonaMode::World(form_for_world(&world));
            PersonaEffect::None
        }
        PersonaAction::WorldDeleteArm(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(world) = p.worlds.get(*index) else {
                return PersonaEffect::None;
            };
            // Counted against the face list rather than off the record: a world
            // may name faces that have since been deleted, and the prompt has
            // to say the number the holder can see.
            let faces = world
                .face_ids
                .iter()
                .filter(|id| p.profiles.iter().any(|x| &&x.profile_id == id))
                .count();
            p.confirm = PersonaConfirm::DeleteWorld {
                world_id: world.world_id.clone(),
                name: world.display_name().to_string(),
                expected_version: Some(world.version),
                faces,
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
        PersonaAction::ComposeOpen(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(membership) = p.memberships.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            p.mode = PersonaMode::Compose(ComposeForm {
                context_id: membership.sub_context_id.clone(),
                persona_did: membership.persona_did.clone(),
                name: tui_input::Input::new(membership.community_name.clone()),
                community: membership.community_name,
                rows: vec![ComposeRow {
                    claim_type: tui_input::Input::new("name.display".to_string()),
                    ..ComposeRow::default()
                }],
                // Straight to the first value: the name and the type are
                // prefilled, and what the holder came to type is the value.
                field: 2,
                ..ComposeForm::default()
            });
            PersonaEffect::None
        }
        PersonaAction::RenderersOpen => {
            let p = &mut state.main_page.content_panel.identity;
            p.mode = PersonaMode::Renderers(RenderersView::default());
            PersonaEffect::Job(PersonaJob::RenderersRead)
        }
        PersonaAction::KnownHereOpen(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(membership) = p.memberships.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            p.mode = PersonaMode::KnownHere(KnownHereView {
                context_id: membership.sub_context_id.clone(),
                community: membership.community_name,
                personas: None,
            });
            PersonaEffect::Job(PersonaJob::KnownHereRead {
                context_id: membership.sub_context_id,
            })
        }
        PersonaAction::PeopleOpen(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(membership) = p.memberships.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            p.mode = PersonaMode::People(PeopleView {
                context_id: membership.sub_context_id.clone(),
                community: membership.community_name,
                persona_did: membership.persona_did,
                ..PeopleView::default()
            });
            PersonaEffect::Job(PersonaJob::PeopleRead {
                context_id: membership.sub_context_id,
            })
        }
        PersonaAction::ContactOpen => {
            let p = &mut state.main_page.content_panel.identity;
            let PersonaMode::People(view) = &mut p.mode else {
                return PersonaEffect::None;
            };
            let Some(Ok(contacts)) = &view.contacts else {
                return PersonaEffect::None;
            };
            let Some(contact) = contacts.get(view.selected) else {
                return PersonaEffect::None;
            };
            let contact_id = contact.contact_id.clone();
            let context_id = view.context_id.clone();
            // A placeholder rather than an empty pane: the read is a round-trip
            // and the holder pressed ⏎ on a row that is already on screen.
            view.open = None;
            view.working = true;
            PersonaEffect::Job(PersonaJob::ContactRead {
                context_id,
                contact_id,
            })
        }
        PersonaAction::ContactNew => {
            let p = &mut state.main_page.content_panel.identity;
            if let PersonaMode::People(view) = &mut p.mode {
                view.form = Some(ContactForm::new());
                view.error = None;
            }
            PersonaEffect::None
        }
        PersonaAction::ContactDeleteArm => {
            let p = &mut state.main_page.content_panel.identity;
            let PersonaMode::People(view) = &mut p.mode else {
                return PersonaEffect::None;
            };
            let Some(Ok(contacts)) = &view.contacts else {
                return PersonaEffect::None;
            };
            if let Some(contact) = contacts.get(view.selected) {
                // Named, not indexed: a listing that arrives while the question
                // is up must not move the answer onto another row.
                view.deleting = Some((contact.contact_id.clone(), contact.label()));
            }
            PersonaEffect::None
        }
        PersonaAction::LocalFaceNew => {
            if let PersonaMode::LocalFaces(view) = &mut state.main_page.content_panel.identity.mode
            {
                view.form = Some(LocalFaceForm::new());
                view.error = None;
                view.confirming = false;
            }
            PersonaEffect::None
        }
        PersonaAction::LocalFaceDeleteArm => {
            let p = &mut state.main_page.content_panel.identity;
            let PersonaMode::LocalFaces(view) = &mut p.mode else {
                return PersonaEffect::None;
            };
            let Some(face) = view.face_under_cursor() else {
                return PersonaEffect::None;
            };
            view.deleting = Some((face.profile_id, face.name));
            view.confirming = false;
            PersonaEffect::None
        }
        PersonaAction::LocalFaceWear => {
            let p = &mut state.main_page.content_panel.identity;
            let PersonaMode::LocalFaces(view) = &mut p.mode else {
                return PersonaEffect::None;
            };
            let Some(face) = view.face_under_cursor() else {
                return PersonaEffect::None;
            };
            view.working = true;
            PersonaEffect::Job(PersonaJob::LocalFaceWear {
                context_id: view.context_id.clone(),
                persona_did: view.persona_did.clone(),
                profile_id: face.profile_id,
            })
        }
        PersonaAction::LocalFacesOpen(index) => {
            let p = &mut state.main_page.content_panel.identity;
            let Some(membership) = p.memberships.get(*index).cloned() else {
                return PersonaEffect::None;
            };
            p.mode = PersonaMode::LocalFaces(LocalFacesView {
                context_id: membership.sub_context_id.clone(),
                community: membership.community_name,
                persona_did: membership.persona_did,
                ..LocalFacesView::default()
            });
            PersonaEffect::Job(PersonaJob::LocalFacesRead {
                context_id: membership.sub_context_id,
            })
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
                PersonaMode::World(form) => match form.focus {
                    WorldFormFocus::Name => {
                        form.name.handle_event(&event);
                    }
                    WorldFormFocus::Icon => {
                        form.icon.handle_event(&event);
                    }
                    // The colour is a choice, not a text field: ←/→ move it and
                    // a keystroke here is not an edit.
                    WorldFormFocus::Colour => {}
                },
                PersonaMode::Compose(form) => {
                    let field = form.field;
                    match form.focused_row() {
                        None => {
                            form.name.handle_event(&event);
                        }
                        Some(row) => {
                            if let Some(r) = form.rows.get_mut(row) {
                                if (field - 1) % 2 == 0 {
                                    r.claim_type.handle_event(&event);
                                } else {
                                    r.value.handle_event(&event);
                                }
                            }
                        }
                    }
                }
                PersonaMode::LocalFaces(view) => {
                    if let Some(form) = &mut view.form {
                        match form.field {
                            0 => {
                                form.name.handle_event(&event);
                            }
                            f => {
                                if let Some(r) = form.rows.get_mut((f - 1) / 2) {
                                    if (f - 1) % 2 == 0 {
                                        r.claim_type.handle_event(&event);
                                    } else {
                                        r.value.handle_event(&event);
                                    }
                                }
                            }
                        }
                    }
                }
                PersonaMode::People(view) => {
                    // Only the form takes typing; the listing behind it does
                    // not, and a keystroke that reached it would be silently
                    // editing something the holder cannot see.
                    if let Some(form) = &mut view.form {
                        let notes = form.notes_field();
                        match form.field {
                            0 => {
                                form.subject_did.handle_event(&event);
                            }
                            f if f == notes => {
                                form.notes.handle_event(&event);
                            }
                            f => {
                                if let Some(r) = form.rows.get_mut((f - 1) / 2) {
                                    if (f - 1) % 2 == 0 {
                                        r.claim_type.handle_event(&event);
                                    } else {
                                        r.value.handle_event(&event);
                                    }
                                }
                            }
                        }
                    }
                }
                PersonaMode::PlaceFace(_)
                | PersonaMode::Bind(_)
                | PersonaMode::Renderers(_)
                | PersonaMode::KnownHere(_)
                | PersonaMode::View => {}
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
                PersonaMode::World(form) => {
                    form.focus = if *forwards {
                        form.focus.next()
                    } else {
                        form.focus.prev()
                    };
                }
                PersonaMode::Compose(form) => {
                    let n = form.field_count();
                    form.field = if *forwards {
                        (form.field + 1) % n
                    } else {
                        (form.field + n - 1) % n
                    };
                }
                PersonaMode::LocalFaces(view) => {
                    if let Some(form) = &mut view.form {
                        let n = form.field_count();
                        form.field = if *forwards {
                            (form.field + 1) % n
                        } else {
                            (form.field + n - 1) % n
                        };
                    }
                }
                PersonaMode::People(view) => {
                    if let Some(form) = &mut view.form {
                        let n = form.notes_field() + 1;
                        form.field = if *forwards {
                            (form.field + 1) % n
                        } else {
                            (form.field + n - 1) % n
                        };
                    }
                }
                PersonaMode::PlaceFace(_)
                | PersonaMode::Bind(_)
                | PersonaMode::Renderers(_)
                | PersonaMode::KnownHere(_)
                | PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormCycle(forwards) => {
            let attribute_count = state.main_page.content_panel.identity.attributes.len();
            let option_count = state.main_page.content_panel.identity.profiles.len() + 1;
            // …and one more than the worlds, because row 0 is always "belongs
            // to no world".
            let world_count = state.main_page.content_panel.identity.worlds.len() + 1;
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
                PersonaMode::World(form) => {
                    if form.focus == WorldFormFocus::Colour {
                        form.colour = step(form.colour, world::Colour::all().len(), *forwards);
                    }
                }
                PersonaMode::PlaceFace(picker) => {
                    picker.cursor = step(picker.cursor, world_count, *forwards);
                }
                PersonaMode::Bind(picker) => {
                    picker.cursor = step(picker.cursor, option_count, *forwards);
                }
                // Read-only overlays: nothing to move between.
                PersonaMode::Renderers(_) | PersonaMode::KnownHere(_) => {}
                PersonaMode::People(view) => match &mut view.form {
                    // In the form, ↓ on the last field adds a fact and ↑ on an
                    // empty last row takes it away — the same shape as compose,
                    // so one gesture means one thing across the pane.
                    Some(form) => {
                        let last = form.notes_field();
                        if *forwards && form.field == last {
                            form.rows.push(ComposeRow::default());
                            form.field = form.notes_field() - 2;
                        } else if !*forwards
                            && form.rows.len() > 1
                            && form.rows.last().is_some_and(|r| {
                                r.claim_type.value().is_empty() && r.value.value().is_empty()
                            })
                            && form.field >= form.notes_field() - 2
                        {
                            form.rows.pop();
                            form.field = form.notes_field();
                        } else {
                            let n = last + 1;
                            form.field = if *forwards {
                                (form.field + 1) % n
                            } else {
                                (form.field + n - 1) % n
                            };
                        }
                    }
                    None => {
                        let len = match &view.contacts {
                            Some(Ok(rows)) => rows.len(),
                            _ => 0,
                        };
                        view.selected = step(view.selected, len, *forwards);
                        // Moving on withdraws an armed question: it named the
                        // row it was armed against, not wherever the cursor is.
                        view.deleting = None;
                        view.open = None;
                    }
                },
                PersonaMode::LocalFaces(view) => match &mut view.form {
                    Some(form) => {
                        let last = form.field_count() - 1;
                        if *forwards && form.field == last {
                            form.rows.push(ComposeRow::default());
                            form.field = form.field_count() - 2;
                        } else if !*forwards
                            && form.rows.len() > 1
                            && form.rows.last().is_some_and(|r| {
                                r.claim_type.value().is_empty() && r.value.value().is_empty()
                            })
                            && form.field >= form.field_count() - 2
                        {
                            form.rows.pop();
                            form.field = form.field_count() - 1;
                        } else {
                            let n = form.field_count();
                            form.field = if *forwards {
                                (form.field + 1) % n
                            } else {
                                (form.field + n - 1) % n
                            };
                        }
                    }
                    None => {
                        let n = view.rows().len();
                        view.cursor = step(view.cursor, n, *forwards);
                        // Moving on is not agreeing: the question is put again.
                        view.confirming = false;
                        view.deleting = None;
                    }
                },
                // ↓ on the last field adds a value; ↑ on an empty last row
                // takes it away again. Elsewhere they move between fields.
                PersonaMode::Compose(form) => {
                    let last = form.field_count() - 1;
                    if *forwards && form.field == last {
                        form.rows.push(ComposeRow::default());
                        form.field = form.field_count() - 2;
                    } else if !*forwards
                        && form.rows.len() > 1
                        && form.focused_row() == Some(form.rows.len() - 1)
                        && form.rows.last().is_some_and(|r| {
                            r.claim_type.value().is_empty() && r.value.value().is_empty()
                        })
                    {
                        form.rows.pop();
                        form.field = form.field_count() - 1;
                    } else if *forwards {
                        form.field += 1;
                    } else {
                        form.field = form.field.saturating_sub(1);
                    }
                }
                PersonaMode::View => {}
            }
            PersonaEffect::None
        }
        PersonaAction::FormToggleEntry => {
            // Among the faces made here, choose (or unchoose) the value under
            // the cursor. One face at a time: a promotion moves one face.
            if let PersonaMode::LocalFaces(view) = &mut state.main_page.content_panel.identity.mode
            {
                let rows = view.rows();
                if let (Some(&(f, e)), Some(Ok(faces))) = (rows.get(view.cursor), &view.faces) {
                    let face = &faces[f];
                    let position = face.entries[e].position;
                    match &mut view.chosen {
                        Some((id, positions)) if *id == face.profile_id => {
                            match positions.iter().position(|p| *p == position) {
                                Some(i) => {
                                    positions.remove(i);
                                }
                                None => positions.push(position),
                            }
                            if positions.is_empty() {
                                view.chosen = None;
                            }
                        }
                        _ => view.chosen = Some((face.profile_id.clone(), vec![position])),
                    }
                    view.confirming = false;
                }
                return PersonaEffect::None;
            }
            // In the compose form this is "use in my other faces too" for the
            // row the focus is in.
            if let PersonaMode::Compose(form) = &mut state.main_page.content_panel.identity.mode {
                if let Some(row) = form.focused_row().and_then(|r| form.rows.get_mut(r)) {
                    row.share = !row.share;
                }
                return PersonaEffect::None;
            }
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
            let p = &mut state.main_page.content_panel.identity;
            // Esc withdraws one thing at a time. A view that holds a form, an
            // armed question or an open record closes that first: dropping the
            // whole view instead would throw away a half-typed card to answer
            // "not that one", and the holder would have to find their way back.
            match &mut p.mode {
                PersonaMode::People(view) if view.form.is_some() => view.form = None,
                PersonaMode::People(view) if view.deleting.is_some() => view.deleting = None,
                PersonaMode::People(view) if view.open.is_some() => view.open = None,
                PersonaMode::LocalFaces(view) if view.form.is_some() => view.form = None,
                PersonaMode::LocalFaces(view) if view.deleting.is_some() => view.deleting = None,
                PersonaMode::LocalFaces(view) if view.confirming => view.confirming = false,
                _ => p.mode = PersonaMode::View,
            }
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
            profile_id,
            name,
            unbind,
            ..
        } => PersonaEffect::Job(PersonaJob::ProfileDelete {
            profile_id,
            name,
            unbind,
        }),
        PersonaConfirm::RetireFace { profile_id, .. } => {
            PersonaEffect::Job(PersonaJob::ProfileRetire { profile_id })
        }
        PersonaConfirm::DeleteWorld {
            world_id,
            expected_version,
            ..
        } => PersonaEffect::Job(PersonaJob::WorldDelete {
            world_id,
            expected_version,
        }),
        PersonaConfirm::PurgeAttribute { attribute_id, .. } => {
            PersonaEffect::Job(PersonaJob::AttributePurge { attribute_id })
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::actions::PersonaAction;
    use crate::state_handler::main_page::content::{
        AttributeForm, PersonaConfirm, PersonaMode, PersonaTab, ProfileForm, ProfileFormFocus,
    };
    use crate::state_handler::main_page::content::{IdentityState, PersonaMembership};
    use crate::state_handler::persona_actions::outcome::PersonaOutcome;
    use crate::state_handler::persona_actions::test_support::{
        attribute, open_face, personas, state_with,
    };
    use crate::state_handler::state::State;
    use openvtc_core::persona::binding::BindingSummary;
    use openvtc_core::persona::pool::ProvenanceKind;
    use openvtc_core::persona::{
        claim_types, contacts, lifecycle, pool::PoolAttribute, profile::ProfileSummary,
    };
    use std::collections::HashMap;

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
                unbind: true,
                // Not yet known: the face is not open, so the agent is asked.
                untell: None,
            }
        );
        apply(&mut state, &PersonaAction::ProfileDeleteArm(1));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::DeleteProfile {
                profile_id: "01Q".into(),
                name: "unnamed face".into(),
                unbind: false,
                // Not yet known: the face is not open, so the agent is asked.
                untell: None,
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
            retired: Ok(vec![]),
            disclosures: Ok(Vec::new()),
            worlds: Ok(Vec::new()),
            links: Ok(Vec::new()),
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
                .as_ref()
                .map(|s| s.text.as_str())
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
        let held = |id: &str| PoolAttribute {
            value: Some(serde_json::json!("a@example.com")),
            ..attribute(id)
        };
        let mut state = state_with(IdentityState {
            attributes: vec![held("01A"), held("01B")].into(),
            show_values: true,
            ..IdentityState::default()
        });

        let effect = apply(&mut state, &PersonaAction::RevealValue(1));
        assert!(matches!(effect, PersonaEffect::None), "no round-trip");
        assert_eq!(personas(&state).revealed_attribute.as_deref(), Some("01B"));

        apply(&mut state, &PersonaAction::RevealValue(1));
        assert!(personas(&state).revealed_attribute.is_none());
    }

    /// A reveal of a *sensitive* value the bulk listing withheld becomes a
    /// targeted fetch — the value was never carried into memory — not an
    /// in-memory mask-lift. Nothing is revealed until the fetch returns.
    #[test]
    fn a_reveal_of_a_withheld_sensitive_value_fetches_it() {
        let mut attr = attribute("01C");
        attr.claim_type = "medical.condition".into();
        attr.value = None;
        assert!(
            attr.is_withheld_sensitive(&claim_types::Registry::vendored(), true),
            "the fixture has to be a withheld sensitive attribute"
        );

        let mut state = state_with(IdentityState {
            attributes: vec![attr].into(),
            show_values: true,
            ..IdentityState::default()
        });

        let effect = apply(&mut state, &PersonaAction::RevealValue(0));
        assert!(
            matches!(
                effect,
                PersonaEffect::Job(PersonaJob::AttributeReveal { .. })
            ),
            "a withheld sensitive value is fetched, not mask-lifted"
        );
        assert!(
            personas(&state).revealed_attribute.is_none(),
            "nothing is revealed until the fetched value is spliced in"
        );
    }

    /// With values hidden the listing carries none, so `s` on any attribute is
    /// a fetch of that one value — not a mask lifted over nothing, which left
    /// the row reading "(hidden)" and the key looking dead.
    #[test]
    fn a_reveal_while_values_are_hidden_fetches_the_one_value() {
        let mut attr = attribute("01A");
        attr.value = None;
        let mut state = state_with(IdentityState {
            attributes: vec![attr].into(),
            show_values: false,
            ..IdentityState::default()
        });

        let effect = apply(&mut state, &PersonaAction::RevealValue(0));
        assert!(
            matches!(
                effect,
                PersonaEffect::Job(PersonaJob::AttributeReveal { ref attribute_id })
                    if attribute_id == "01A"
            ),
            "a value not in memory is fetched"
        );
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
            retired: Ok(vec![]),
            disclosures: Ok(Vec::new()),
            worlds: Ok(Vec::new()),
            links: Ok(Vec::new()),
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

    /// A face worn by a persona outside this account's memberships — invisible
    /// to the binding map, so first asked about as unworn — is asked about
    /// again once the VTA refuses, with the consequence named and `unbind` set.
    /// Never retried with `unbind` on the holder's behalf.
    #[test]
    fn a_face_worn_elsewhere_is_asked_about_again_not_failed() {
        let mut state = State::default();
        PersonaOutcome::ProfileWorn {
            profile_id: "01F".into(),
            name: "OSS Developer".into(),
            worn: 1,
        }
        .apply(&mut state);

        assert!(matches!(
            &personas(&state).confirm,
            PersonaConfirm::DeleteProfile { profile_id, unbind: true, .. } if profile_id == "01F"
        ));
        assert!(
            personas(&state)
                .status_message
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("worn by 1 persona outside"))
        );
        match apply(&mut state, &PersonaAction::ConfirmYes) {
            PersonaEffect::Job(PersonaJob::ProfileDelete { unbind, .. }) => assert!(unbind),
            _ => panic!("y must send the delete with unbind"),
        }
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

    fn two_faces_one_worn() -> State {
        let mut bindings = HashMap::new();
        bindings.insert(
            ("ctx".to_string(), "did:key:zP".to_string()),
            BindingSummary {
                bound: true,
                profile_id: Some("01P".into()),
                ..BindingSummary::default()
            },
        );
        state_with(IdentityState {
            profiles: vec![
                ProfileSummary {
                    profile_id: "01P".into(),
                    name: "Conference".into(),
                    ..ProfileSummary::default()
                },
                ProfileSummary {
                    profile_id: "01Q".into(),
                    name: "Club".into(),
                    ..ProfileSummary::default()
                },
            ]
            .into(),
            retired_faces: vec![ProfileSummary {
                profile_id: "01R".into(),
                name: "Old job".into(),
                retired: true,
                ..ProfileSummary::default()
            }]
            .into(),
            bindings,
            ..IdentityState::default()
        })
    }

    /// Retiring asks first, says where the face comes off, and retires the
    /// face that was armed.
    #[test]
    fn retiring_a_worn_face_asks_and_says_where_it_comes_off() {
        let mut state = two_faces_one_worn();
        apply(&mut state, &PersonaAction::ProfileRetireArm(0));
        assert_eq!(
            personas(&state).confirm,
            PersonaConfirm::RetireFace {
                profile_id: "01P".into(),
                name: "Conference".into(),
                worn: 1,
            }
        );
        match apply(&mut state, &PersonaAction::ConfirmYes) {
            PersonaEffect::Job(PersonaJob::ProfileRetire { profile_id }) => {
                assert_eq!(profile_id, "01P")
            }
            _ => panic!("expected a retire"),
        }
    }

    /// Reinstating is addressed in the retired list, binds nothing, and so asks
    /// nothing.
    #[test]
    fn reinstating_works_from_the_retired_list_without_a_question() {
        let mut state = two_faces_one_worn();
        apply(&mut state, &PersonaAction::ToggleRetired);
        assert!(personas(&state).show_retired);
        match apply(&mut state, &PersonaAction::ProfileReinstate(0)) {
            PersonaEffect::Job(PersonaJob::ProfileReinstate { profile_id }) => {
                assert_eq!(
                    profile_id, "01R",
                    "the retired face, not the worn one at index 0"
                )
            }
            _ => panic!("expected a reinstate"),
        }
        assert_eq!(personas(&state).confirm, PersonaConfirm::None);
    }

    /// A delete prompt learns how far the face has spoken, and only its own
    /// prompt does.
    #[test]
    fn a_delete_prompt_learns_that_deleting_does_not_un_tell() {
        let mut state = two_faces_one_worn();
        match apply(&mut state, &PersonaAction::ProfileDeleteArm(1)) {
            PersonaEffect::Job(PersonaJob::ProfileSpoken { profile_id }) => {
                assert_eq!(profile_id, "01Q")
            }
            _ => panic!("the agent is asked how far the face has spoken"),
        }
        PersonaOutcome::Spoken {
            profile_id: "01P".into(),
            untell: Some("wrong face".into()),
        }
        .apply(&mut state);
        assert!(matches!(
            &personas(&state).confirm,
            PersonaConfirm::DeleteProfile { untell: None, .. }
        ));
        PersonaOutcome::Spoken {
            profile_id: "01Q".into(),
            untell: Some("It has disclosed to 2 parties".into()),
        }
        .apply(&mut state);
        assert!(matches!(
            &personas(&state).confirm,
            PersonaConfirm::DeleteProfile { untell: Some(w), .. } if w.contains("2 parties")
        ));
    }

    /// Making a face for a community: typed values stay local unless shared,
    /// the persona the community sees is the one that wears it, and a half row
    /// is refused before anything is sent.
    #[test]
    fn a_face_made_for_a_community_is_local_unless_a_value_is_shared() {
        let mut state = state_with(IdentityState {
            memberships: vec![PersonaMembership {
                community_name: "Co-op".into(),
                sub_context_id: "ctx-coop".into(),
                persona_did: "did:key:zCoop".into(),
                ..PersonaMembership::default()
            }]
            .into(),
            ..IdentityState::default()
        });
        apply(&mut state, &PersonaAction::ComposeOpen(0));
        let type_into = |state: &mut State, text: &str| {
            for c in text.chars() {
                apply(
                    state,
                    &PersonaAction::FormKey(crossterm::event::KeyEvent::from(
                        crossterm::event::KeyCode::Char(c),
                    )),
                );
            }
        };
        // The focus opens on the first value; name and type are prefilled.
        type_into(&mut state, "Ada");
        // ↓ on the last field adds a row, focused on its type.
        apply(&mut state, &PersonaAction::FormCycle(true));
        type_into(&mut state, "email.personal");
        apply(&mut state, &PersonaAction::FormField(true));
        // Half a row is refused, naming why.
        assert!(matches!(
            apply(&mut state, &PersonaAction::FormSubmit),
            PersonaEffect::None
        ));
        match &personas(&state).mode {
            PersonaMode::Compose(form) => assert!(form.error.as_deref().unwrap().contains("both")),
            _ => panic!("the form stays open"),
        }
        type_into(&mut state, "ada@example.org");
        apply(&mut state, &PersonaAction::FormToggleEntry);
        match apply(&mut state, &PersonaAction::FormSubmit) {
            PersonaEffect::Job(PersonaJob::Compose {
                context_id,
                persona_did,
                name,
                values,
                ..
            }) => {
                assert_eq!(context_id, "ctx-coop");
                assert_eq!(persona_did, "did:key:zCoop");
                assert_eq!(name, "Co-op");
                assert_eq!(
                    values,
                    vec![
                        lifecycle::ComposeValue {
                            claim_type: "name.display".into(),
                            value: "Ada".into(),
                            share: false,
                        },
                        lifecycle::ComposeValue {
                            claim_type: "email.personal".into(),
                            value: "ada@example.org".into(),
                            share: true,
                        },
                    ]
                );
            }
            _ => panic!("expected a compose"),
        }
    }

    fn local_face(id: &str, name: &str, version: u64, types: &[&str]) -> lifecycle::LocalFace {
        lifecycle::LocalFace {
            profile_id: id.into(),
            name: name.into(),
            version,
            entries: types
                .iter()
                .enumerate()
                .map(|(i, t)| lifecycle::LocalEntry {
                    position: i as u64,
                    claim_type: (*t).into(),
                })
                .collect(),
        }
    }

    /// Promoting from a community's own faces: values are chosen within one
    /// face, the one-way question is put before anything is sent, and a
    /// listing for another community is not taken for this one.
    #[test]
    fn values_made_here_are_promoted_only_after_the_one_way_question() {
        let mut state = state_with(IdentityState {
            memberships: vec![PersonaMembership {
                community_name: "Co-op".into(),
                sub_context_id: "ctx-coop".into(),
                persona_did: "did:key:zCoop".into(),
                ..PersonaMembership::default()
            }]
            .into(),
            ..IdentityState::default()
        });
        match apply(&mut state, &PersonaAction::LocalFacesOpen(0)) {
            PersonaEffect::Job(PersonaJob::LocalFacesRead { context_id }) => {
                assert_eq!(context_id, "ctx-coop")
            }
            _ => panic!("expected a read"),
        }
        // A late listing for somewhere else changes nothing.
        PersonaOutcome::LocalFacesRead {
            context_id: "ctx-other".into(),
            result: Ok(vec![local_face("p-x", "X", 1, &["name.display"])]),
        }
        .apply(&mut state);
        match &personas(&state).mode {
            PersonaMode::LocalFaces(view) => assert!(view.faces.is_none()),
            _ => panic!("the view stays open"),
        }
        PersonaOutcome::LocalFacesRead {
            context_id: "ctx-coop".into(),
            result: Ok(vec![
                local_face("p-a", "Market", 3, &["name.display", "email.personal"]),
                local_face("p-b", "Stall", 7, &["phone.mobile"]),
            ]),
        }
        .apply(&mut state);

        // Nothing chosen: Enter says so and sends nothing.
        assert!(matches!(
            apply(&mut state, &PersonaAction::FormSubmit),
            PersonaEffect::None
        ));
        // Choose the first face's second value, then the second face's only
        // one: a choice in another face replaces, it does not mix.
        apply(&mut state, &PersonaAction::FormCycle(true));
        apply(&mut state, &PersonaAction::FormToggleEntry);
        apply(&mut state, &PersonaAction::FormCycle(true));
        apply(&mut state, &PersonaAction::FormToggleEntry);
        match &personas(&state).mode {
            PersonaMode::LocalFaces(view) => {
                assert_eq!(view.chosen, Some(("p-b".to_string(), vec![0])));
                assert!(view.error.is_some(), "the empty Enter was answered");
            }
            _ => panic!("the view stays open"),
        }
        // The first Enter asks; moving away withdraws the question.
        assert!(matches!(
            apply(&mut state, &PersonaAction::FormSubmit),
            PersonaEffect::None
        ));
        apply(&mut state, &PersonaAction::FormCycle(true));
        match &personas(&state).mode {
            PersonaMode::LocalFaces(view) => assert!(!view.confirming),
            _ => panic!("the view stays open"),
        }
        apply(&mut state, &PersonaAction::FormSubmit);
        match apply(&mut state, &PersonaAction::FormSubmit) {
            PersonaEffect::Job(PersonaJob::Promote {
                context_id,
                profile_id,
                positions,
                expected_version,
            }) => {
                assert_eq!(context_id, "ctx-coop");
                assert_eq!(profile_id, "p-b");
                assert_eq!(positions, vec![0]);
                assert_eq!(expected_version, 7);
            }
            _ => panic!("expected a promotion"),
        }
        // A refusal lands on the view, which stays open.
        PersonaOutcome::Written {
            verb: "Made the values reusable",
            error: Some("version conflict".into()),
        }
        .apply(&mut state);
        match &personas(&state).mode {
            PersonaMode::LocalFaces(view) => {
                assert!(!view.working);
                assert!(view.error.as_deref().unwrap().contains("version conflict"));
            }
            _ => panic!("the view stays open on a refusal"),
        }
    }

    /// Contacts: a community's people are read when the view opens, a half
    /// row is refused before anything is sent, and a delete is armed against
    /// the contact it named rather than whatever row the cursor later sits on.
    #[test]
    fn what_a_community_told_you_is_recorded_against_the_persona_it_reached() {
        let mut state = state_with(IdentityState {
            memberships: vec![PersonaMembership {
                community_name: "Co-op".into(),
                sub_context_id: "ctx-coop".into(),
                persona_did: "did:key:zCoop".into(),
                ..PersonaMembership::default()
            }]
            .into(),
            ..IdentityState::default()
        });
        match apply(&mut state, &PersonaAction::PeopleOpen(0)) {
            PersonaEffect::Job(PersonaJob::PeopleRead { context_id }) => {
                assert_eq!(context_id, "ctx-coop")
            }
            _ => panic!("expected a read"),
        }
        PersonaOutcome::PeopleRead {
            context_id: "ctx-coop".into(),
            result: Ok(vec![contacts::ContactSummary {
                contact_id: "01C".into(),
                subject_did: "did:key:zPeer".into(),
                known_by_persona: "did:key:zCoop".into(),
                display_name: Some("Ada".into()),
                claim_count: 2,
                rev: 1,
                received_at: "2026-09-07T10:00:00Z".into(),
                unseen_change: false,
            }]),
        }
        .apply(&mut state);

        apply(&mut state, &PersonaAction::ContactNew);
        let type_into = |state: &mut State, text: &str| {
            for c in text.chars() {
                apply(
                    state,
                    &PersonaAction::FormKey(crossterm::event::KeyEvent::from(
                        crossterm::event::KeyCode::Char(c),
                    )),
                );
            }
        };
        // No DID: refused, and said so.
        assert!(matches!(
            apply(&mut state, &PersonaAction::FormSubmit),
            PersonaEffect::None
        ));
        type_into(&mut state, "did:key:zPeer");
        apply(&mut state, &PersonaAction::FormField(true));
        type_into(&mut state, "name.display");
        // Half a row is refused too.
        assert!(matches!(
            apply(&mut state, &PersonaAction::FormSubmit),
            PersonaEffect::None
        ));
        apply(&mut state, &PersonaAction::FormField(true));
        type_into(&mut state, "Ada");
        match apply(&mut state, &PersonaAction::FormSubmit) {
            PersonaEffect::Job(PersonaJob::ContactPut {
                context_id,
                subject_did,
                known_by_persona,
                facts,
                notes,
            }) => {
                assert_eq!(context_id, "ctx-coop");
                assert_eq!(subject_did, "did:key:zPeer");
                // Filed against the persona this community knows, not the
                // holder's account or their first persona.
                assert_eq!(known_by_persona, "did:key:zCoop");
                assert_eq!(facts.len(), 1);
                assert_eq!(facts[0].claim_type, "name.display");
                assert_eq!(notes, None);
            }
            _ => panic!("expected a contact write"),
        }

        // Esc withdraws the form, not the view.
        apply(&mut state, &PersonaAction::FormCancel);
        match &personas(&state).mode {
            PersonaMode::People(view) => assert!(view.form.is_none()),
            _ => panic!("the view stays open"),
        }
        // An armed delete names the contact, and survives a listing that
        // arrives while the question is on screen.
        apply(&mut state, &PersonaAction::ContactDeleteArm);
        PersonaOutcome::PeopleRead {
            context_id: "ctx-other".into(),
            result: Ok(Vec::new()),
        }
        .apply(&mut state);
        match apply(&mut state, &PersonaAction::FormSubmit) {
            PersonaEffect::Job(PersonaJob::ContactDelete { contact_id, .. }) => {
                assert_eq!(contact_id, "01C")
            }
            _ => panic!("expected a delete"),
        }
    }

    /// Forgetting earlier versions asks first, names the attribute it armed,
    /// and says how many faces use it.
    #[test]
    fn forgetting_earlier_versions_is_asked_before_it_is_done() {
        let mut state = state_with(IdentityState {
            attributes: vec![attribute("01A")].into(),
            ..IdentityState::default()
        });
        apply(&mut state, &PersonaAction::AttributePurgeArm(0));
        match &personas(&state).confirm {
            PersonaConfirm::PurgeAttribute {
                attribute_id, name, ..
            } => {
                assert_eq!(attribute_id, "01A");
                assert_eq!(name, "email.work");
            }
            _ => panic!("expected the question to be armed"),
        }
        match apply(&mut state, &PersonaAction::ConfirmYes) {
            PersonaEffect::Job(PersonaJob::AttributePurge { attribute_id }) => {
                assert_eq!(attribute_id, "01A")
            }
            _ => panic!("expected a purge"),
        }
    }

    /// A face made inside a community carries no shared values: making one
    /// reusable is the separate, one-way promote step.
    #[test]
    fn a_face_made_here_is_made_with_nothing_shared() {
        let mut state = state_with(IdentityState {
            memberships: vec![PersonaMembership {
                community_name: "Co-op".into(),
                sub_context_id: "ctx-coop".into(),
                persona_did: "did:key:zCoop".into(),
                ..PersonaMembership::default()
            }]
            .into(),
            ..IdentityState::default()
        });
        apply(&mut state, &PersonaAction::LocalFacesOpen(0));
        PersonaOutcome::LocalFacesRead {
            context_id: "ctx-coop".into(),
            result: Ok(Vec::new()),
        }
        .apply(&mut state);
        apply(&mut state, &PersonaAction::LocalFaceNew);
        let type_into = |state: &mut State, text: &str| {
            for c in text.chars() {
                apply(
                    state,
                    &PersonaAction::FormKey(crossterm::event::KeyEvent::from(
                        crossterm::event::KeyCode::Char(c),
                    )),
                );
            }
        };
        type_into(&mut state, "Market");
        apply(&mut state, &PersonaAction::FormField(true));
        type_into(&mut state, "name.display");
        apply(&mut state, &PersonaAction::FormField(true));
        type_into(&mut state, "Ada");
        match apply(&mut state, &PersonaAction::FormSubmit) {
            PersonaEffect::Job(PersonaJob::LocalFacePut {
                context_id,
                name,
                values,
            }) => {
                assert_eq!(context_id, "ctx-coop");
                assert_eq!(name, "Market");
                assert_eq!(values.len(), 1);
                assert!(!values[0].share, "nothing made here is shared by making it");
            }
            _ => panic!("expected a local face write"),
        }
    }
}
