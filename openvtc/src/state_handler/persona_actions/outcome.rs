//! [`PersonaOutcome`]: what a persona job produced, folded back into the pane on
//! the loop thread.

use crate::state_handler::main_page::content::AgentError;
use crate::state_handler::main_page::status::Status;
use std::collections::HashMap;

use openvtc_core::persona::{
    claim_types, correlation, disclosure, family, lifecycle,
    pool::PoolAttribute,
    profile::{ProfileDetail, ProfileSummary},
    world,
};

use super::form::world_rank;
use crate::state_handler::main_page::content::{
    PersonaConfirm, PersonaMode, ProfileForm, ProfileFormFocus,
};
use crate::state_handler::persona_binding_refresh::BindingTarget;
use crate::state_handler::state::State;

// ---------------------------------------------------------------------------
// The outcomes
// ---------------------------------------------------------------------------

/// What a persona job produced. Data only; applied on the loop thread.
pub(crate) enum PersonaOutcome {
    Read {
        attributes: Result<Vec<PoolAttribute>, AgentError>,
        profiles: Result<Vec<ProfileSummary>, AgentError>,
        /// The retired faces. Its own result: it feeds an optional view, and a
        /// failure there must not blank the faces the holder wears.
        retired: Result<Vec<ProfileSummary>, AgentError>,
        worlds: Result<Vec<world::World>, AgentError>,
        links: Result<Vec<correlation::Finding>, AgentError>,
        disclosures: Result<Vec<disclosure::DisclosureRow>, AgentError>,
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
        claim_types: Option<Result<Box<claim_types::Registry>, AgentError>>,
        include_values: bool,
    },
    Written {
        verb: &'static str,
        error: Option<String>,
    },
    /// A deletion that succeeded and has something to say about what it left
    /// behind. Distinct from a [`Written`](Self::Written) success, whose whole
    /// message is its verb.
    Deleted { message: String },
    /// A face delete the VTA refused because personas this account cannot see
    /// still wear it. Asked again, with that named, rather than shown as an
    /// error the holder has no way to act on.
    ProfileWorn {
        profile_id: String,
        name: String,
        worn: usize,
    },
    ProfileRead {
        edit: bool,
        result: Result<ProfileDetail, String>,
    },
    /// One attribute's value, fetched on its own for the `s` reveal. Spliced into
    /// the in-memory row and the mask lifted, without a full re-read.
    AttributeRevealed {
        attribute_id: String,
        result: Result<Option<PoolAttribute>, String>,
    },
    Bound {
        community: String,
        cleared: bool,
        error: Option<String>,
    },
    /// The formats the agent can produce.
    RenderersRead {
        result: Result<Vec<openvtc_core::persona::disclosure::Renderer>, String>,
    },
    /// The contacts filed in one community, for the view that asked.
    PeopleRead {
        context_id: String,
        result: Result<Vec<openvtc_core::persona::contacts::ContactSummary>, String>,
    },
    /// One contact in full.
    ContactRead {
        context_id: String,
        result: Result<openvtc_core::persona::contacts::ContactDetail, String>,
    },
    /// A contact write finished — the listing is re-read either way.
    ContactWritten {
        context_id: String,
        error: Option<String>,
    },
    /// Who one community knows the holder as, for the view that asked.
    KnownHereRead {
        context_id: String,
        result: Result<Vec<openvtc_core::persona::binding::KnownHere>, String>,
    },
    /// The faces made inside a community, for the view that asked.
    LocalFacesRead {
        context_id: String,
        result: Result<Vec<lifecycle::LocalFace>, String>,
    },
    /// How far a face has spoken, for a delete prompt that may still be up.
    Spoken {
        profile_id: String,
        untell: Option<String>,
    },
    /// Where a face is worn and what it has done.
    FaceHistoryRead {
        profile_id: String,
        result: Result<lifecycle::FaceHistory, String>,
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
                retired,
                worlds,
                links,
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
                    .or(worlds.as_ref().err())
                    .or(links.as_ref().err())
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
                if let Ok(mut list) = attributes {
                    // Grouped order, decided here rather than in the renderer.
                    // The pane draws the pool under family headings, and the
                    // cursor walks `attributes` by index — so if the list order
                    // were not the *drawn* order, `j` would move the highlight
                    // between groups at random. `pool::list` cannot do this
                    // sort: a family is a question about the claim-type table,
                    // and the table is only known here.
                    list.sort_by(|a, b| {
                        family::Family::of(&a.claim_type, &p.claim_types)
                            .cmp(&family::Family::of(&b.claim_type, &p.claim_types))
                            .then_with(|| a.claim_type.cmp(&b.claim_type))
                            .then_with(|| a.display_name().cmp(b.display_name()))
                    });
                    p.attribute_selected = p.attribute_selected.min(list.len().saturating_sub(1));
                    p.attributes = list.into();
                    // The list under the reveal has been rebuilt and may be
                    // ordered differently, so the grant no longer names a row
                    // the holder chose.
                    p.revealed_attribute = None;
                }
                // Worlds before faces: the face list is sorted by which world
                // holds each face, so the sort needs the answer that is about
                // to land rather than the one from the previous read.
                if let Ok(list) = links {
                    p.links = list.into();
                }
                if let Ok(list) = worlds {
                    p.world_selected = p.world_selected.min(list.len().saturating_sub(1));
                    p.worlds = list.into();
                }
                if let Ok(mut list) = profiles {
                    // Grouped order, for the reason the pool is grouped here
                    // too: the cursor walks this slice by index, so the drawn
                    // order has to *be* the list order or `j` moves the
                    // highlight between worlds at random.
                    list.sort_by(|a, b| {
                        world_rank(&p.worlds, &a.profile_id)
                            .cmp(&world_rank(&p.worlds, &b.profile_id))
                            .then_with(|| a.display_name().cmp(b.display_name()))
                    });
                    if !p.show_retired {
                        p.profile_selected = p.profile_selected.min(list.len().saturating_sub(1));
                    }
                    p.profiles = list.into();
                }
                match retired {
                    Ok(list) => {
                        // The cursor walks whichever list the tab shows.
                        if p.show_retired {
                            p.profile_selected =
                                p.profile_selected.min(list.len().saturating_sub(1));
                        }
                        p.retired_faces = list.into();
                        p.retired_error = None;
                    }
                    Err(e) => p.retired_error = Some(e.text),
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
                        p.status_message = Some(Status::success(format!("{verb}.")));
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
                            PersonaMode::World(form) => {
                                form.working = false;
                                form.error = Some(e.clone());
                            }
                            PersonaMode::PlaceFace(picker) => {
                                picker.working = false;
                                picker.error = Some(e.clone());
                            }
                            PersonaMode::Compose(form) => {
                                form.working = false;
                                form.error = Some(e.clone());
                            }
                            PersonaMode::LocalFaces(view) => {
                                view.working = false;
                                view.error = Some(e.clone());
                            }
                            PersonaMode::People(view) => {
                                view.working = false;
                                view.error = Some(e.clone());
                            }
                            _ => p.status_message = Some(Status::error(e.clone())),
                        }
                        state
                            .main_page
                            .log_error(format!("{verb} failed"), e.as_str());
                    }
                }
            }

            PersonaOutcome::RenderersRead { result } => {
                if let PersonaMode::Renderers(view) = &mut p.mode {
                    view.formats = Some(result);
                }
            }

            PersonaOutcome::PeopleRead { context_id, result } => {
                if let PersonaMode::People(view) = &mut p.mode
                    && view.context_id == context_id
                {
                    // A write that succeeded closes what it was answering: the
                    // form is done with, and the armed delete has happened.
                    if result.is_ok() {
                        view.form = None;
                        view.deleting = None;
                        view.open = None;
                        view.error = None;
                    }
                    let len = result.as_ref().map(Vec::len).unwrap_or(0);
                    view.contacts = Some(result);
                    view.selected = view.selected.min(len.saturating_sub(1));
                    view.working = false;
                }
            }

            PersonaOutcome::ContactRead { context_id, result } => {
                if let PersonaMode::People(view) = &mut p.mode
                    && view.context_id == context_id
                {
                    view.open = Some(result);
                    view.working = false;
                }
            }

            PersonaOutcome::ContactWritten { context_id, error } => {
                if let PersonaMode::People(view) = &mut p.mode
                    && view.context_id == context_id
                {
                    view.working = false;
                    view.error = error.clone();
                }
            }

            PersonaOutcome::KnownHereRead { context_id, result } => {
                if let PersonaMode::KnownHere(view) = &mut p.mode
                    && view.context_id == context_id
                {
                    view.personas = Some(result);
                }
            }

            PersonaOutcome::LocalFacesRead { context_id, result } => {
                if let PersonaMode::LocalFaces(view) = &mut p.mode
                    && view.context_id == context_id
                {
                    if result.is_ok() {
                        // A write that succeeded closes what it was answering.
                        view.form = None;
                        view.deleting = None;
                        view.chosen = None;
                        view.error = None;
                    }
                    view.faces = Some(result);
                    view.cursor = 0;
                    view.working = false;
                }
            }

            PersonaOutcome::ProfileWorn {
                profile_id,
                name,
                worn,
            } => {
                // The binding map only covers this account's memberships, so
                // the first question went out without the consequence. It is
                // the same question with the consequence named now — never a
                // silent retry with `unbind`, which would take the face off
                // personas the holder was never told about.
                p.refresh_queued = true;
                let message = format!(
                    "\"{name}\" is worn by {worn} persona{} outside your communities here — \
                     another client sharing this VTA, or a binding made with pnm. y deletes it \
                     and takes it off {}.",
                    if worn == 1 { "" } else { "s" },
                    if worn == 1 { "that persona" } else { "them" },
                );
                p.status_message = Some(Status::warning(message.clone()));
                p.confirm = PersonaConfirm::DeleteProfile {
                    profile_id,
                    name,
                    unbind: true,
                    untell: None,
                };
                state.main_page.log(message);
            }

            PersonaOutcome::Spoken { profile_id, untell } => {
                // Only into the prompt it was asked for: a different face's
                // question may be up by now, and it must not borrow this one's.
                if let PersonaConfirm::DeleteProfile {
                    profile_id: armed,
                    untell: slot,
                    ..
                } = &mut p.confirm
                    && *armed == profile_id
                {
                    *slot = untell;
                }
            }

            PersonaOutcome::FaceHistoryRead { profile_id, result } => {
                if p.open_profile
                    .as_ref()
                    .is_some_and(|d| d.summary.profile_id == profile_id)
                {
                    p.face_history = Some(result);
                }
            }

            PersonaOutcome::Deleted { message } => {
                p.refresh_queued = true;
                p.mode = PersonaMode::View;
                p.status_message = Some(Status::success(message.clone()));
                state.main_page.log(message);
            }

            PersonaOutcome::ProfileRead { edit, result } => match result {
                Ok(detail) => {
                    if edit {
                        if detail.is_editable_here() {
                            // A reference to an attribute that has left the pool
                            // — deleted from another client sharing this VTA —
                            // fails every save and has no row to untick. Judged
                            // only against a pool that read cleanly: a failed
                            // read must not read as "everything is gone".
                            let (ticked, missing): (Vec<_>, Vec<_>) =
                                if p.loaded && p.load_error.is_none() {
                                    detail.live_refs.iter().cloned().partition(|id| {
                                        p.attributes.iter().any(|a| &a.attribute_id == id)
                                    })
                                } else {
                                    (detail.live_refs.clone(), Vec::new())
                                };
                            p.mode = PersonaMode::Profile(ProfileForm {
                                profile_id: Some(detail.summary.profile_id.clone()),
                                expected_version: Some(detail.summary.version),
                                name: tui_input::Input::new(detail.summary.name.clone()),
                                ticked,
                                cursor: 0,
                                focus: ProfileFormFocus::Name,
                                preserved: detail.other_entries.clone(),
                                dropped: missing.len(),
                                error: None,
                                working: false,
                            });
                        } else {
                            // Refused rather than opened: saving could not
                            // round-trip an entry this build cannot read, and a
                            // save that silently drops one is invisible.
                            p.status_message = Some(Status::warning(detail.refusal()));
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
                    p.status_message = Some(Status::error(e.clone()));
                    state
                        .main_page
                        .log_error("Reading the profile failed", e.as_str());
                }
            },

            PersonaOutcome::AttributeRevealed {
                attribute_id,
                result,
            } => match result {
                // Splice the fetched value into the in-memory row (rebuilding the
                // shared slice) and lift the mask. Only when a value actually came
                // back — a fetch that returns nothing must not reveal a blank.
                Ok(Some(fetched)) if fetched.value.is_some() => {
                    let updated: Vec<PoolAttribute> = p
                        .attributes
                        .iter()
                        .map(|a| {
                            if a.attribute_id == attribute_id {
                                PoolAttribute {
                                    value: fetched.value.clone(),
                                    stale: fetched.stale,
                                    stale_reason: fetched.stale_reason.clone(),
                                    version: fetched.version,
                                    ..a.clone()
                                }
                            } else {
                                a.clone()
                            }
                        })
                        .collect();
                    p.attributes = updated.into();
                    p.revealed_attribute = Some(attribute_id);
                }
                Ok(_) => {
                    p.status_message = Some(Status::error(
                        "That value can't be shown — it has no single stored value.".to_string(),
                    ));
                }
                Err(e) => {
                    p.status_message = Some(Status::error(e.clone()));
                    state
                        .main_page
                        .log_error("Revealing the value failed", e.as_str());
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
                        p.status_message = Some(Status::success(msg.clone()));
                        state.main_page.log(msg);
                    }
                    Some(e) => {
                        if let PersonaMode::Bind(picker) = &mut p.mode {
                            picker.working = false;
                            picker.error = Some(e.clone());
                        } else {
                            p.status_message = Some(Status::error(e.clone()));
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
    use crate::state_handler::main_page::content::IdentityState;
    use crate::state_handler::main_page::content::{AttributeForm, PersonaMode, PersonaTab};
    use crate::state_handler::persona_actions::test_support::{
        attribute, open_face, personas, state_with,
    };
    use crate::state_handler::state::State;
    use openvtc_core::persona::profile::ProfileDetail;
    use std::collections::HashMap;

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
            retired: Ok(vec![]),
            disclosures: Ok(Vec::new()),
            worlds: Ok(Vec::new()),
            links: Ok(Vec::new()),
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
            attributes: Err(AgentError::new(
                "connection refused",
                openvtc_core::errors::ErrorClass::Unreachable,
            )),
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

        assert_eq!(personas(&state).attributes.len(), 1);
        assert_eq!(
            personas(&state)
                .load_error
                .as_ref()
                .map(|e| e.text.as_str()),
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
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("cannot read"))
        );
    }

    /// A face that still references an attribute the pool no longer holds —
    /// deleted from another client on the same VTA — opens with that reference
    /// left out and counted. Carried, it failed every save with "profile
    /// references 1 attribute(s) the pool does not hold", and with no row to
    /// untick the holder could not fix it from here.
    #[test]
    fn the_editor_drops_references_to_attributes_the_pool_no_longer_holds() {
        let open = |loaded: bool, load_error: Option<AgentError>| {
            let mut state = state_with(IdentityState {
                attributes: vec![attribute("01A")].into(),
                loaded,
                load_error,
                ..IdentityState::default()
            });
            PersonaOutcome::ProfileRead {
                edit: true,
                result: Ok(ProfileDetail {
                    live_refs: vec!["01A".into(), "01GONE".into()],
                    ..ProfileDetail::default()
                }),
            }
            .apply(&mut state);
            match &personas(&state).mode {
                PersonaMode::Profile(form) => (form.ticked.clone(), form.dropped),
                _ => panic!("the form must be open"),
            }
        };

        assert_eq!(open(true, None), (vec!["01A".to_string()], 1));
        // A pool that did not read cleanly is no evidence anything is gone.
        assert_eq!(
            open(
                true,
                Some(AgentError::new(
                    "unreachable",
                    openvtc_core::errors::ErrorClass::Unreachable,
                )),
            ),
            (vec!["01A".to_string(), "01GONE".to_string()], 0)
        );
        assert_eq!(
            open(false, None),
            (vec!["01A".to_string(), "01GONE".to_string()], 0)
        );
    }
}
