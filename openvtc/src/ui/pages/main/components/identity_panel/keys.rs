//! Identity-pane key handling, beside the pane's rendering in
//! `identity_panel.rs`.

use crate::state_handler::actions::Action;
use crate::state_handler::main_page::MainPanel;
use crate::ui::pages::main::MainPage;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl MainPage {
    /// Identity-pane keys.
    ///
    /// Three layers, in this order, and the order is what keeps them legible:
    /// an open form or picker owns every key; then an armed confirmation owns
    /// `y`/`n`; then the active tab's own verbs apply. Anything reaching layer
    /// three has already been shown to be unambiguous.
    pub(in crate::ui::pages::main) fn handle_personas_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::actions::PersonaAction as PA;
        use crate::state_handler::main_page::content::{
            PersonaConfirm, PersonaMode, PersonaTab, ProfileFormFocus, WorldFormFocus,
        };

        let personas = &self.props.main_page.content_panel.identity;
        let send = |action: PA| {
            let _ = self.action_tx.send(Action::Persona(action));
            true
        };

        // ── An open form or picker owns the keyboard ──────────────────────
        match &personas.mode {
            PersonaMode::Attribute(form) => {
                // A write is in flight: swallow input rather than editing a
                // form whose result is already on the wire.
                if form.working {
                    return true;
                }
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Tab | KeyCode::Down => send(PA::FormField(true)),
                    KeyCode::BackTab | KeyCode::Up => send(PA::FormField(false)),
                    KeyCode::Right => send(PA::FormCycle(true)),
                    KeyCode::Left => send(PA::FormCycle(false)),
                    _ => send(PA::FormKey(key)),
                };
            }
            PersonaMode::Profile(form) => {
                if form.working {
                    return true;
                }
                let on_entries = form.focus == ProfileFormFocus::Entries;
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Tab => send(PA::FormField(true)),
                    KeyCode::BackTab => send(PA::FormField(false)),
                    KeyCode::Down if on_entries => send(PA::FormCycle(true)),
                    KeyCode::Up if on_entries => send(PA::FormCycle(false)),
                    // Only a keystroke *on the list* ticks an entry. On the
                    // name field a space is a space — a form that swallowed it
                    // would refuse to let a profile be called "Work laptop".
                    KeyCode::Char(' ') if on_entries => send(PA::FormToggleEntry),
                    _ => send(PA::FormKey(key)),
                };
            }
            PersonaMode::World(form) => {
                if form.working {
                    return true;
                }
                let on_colour = form.focus == WorldFormFocus::Colour;
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Tab => send(PA::FormField(true)),
                    KeyCode::BackTab => send(PA::FormField(false)),
                    // ←/→ move the colour wherever the focus is, so a holder
                    // who has not worked out that the swatch row is a field can
                    // still change it. On the colour field ↑/↓ do it too.
                    KeyCode::Right => send(PA::FormCycle(true)),
                    KeyCode::Left => send(PA::FormCycle(false)),
                    KeyCode::Down if on_colour => send(PA::FormCycle(true)),
                    KeyCode::Up if on_colour => send(PA::FormCycle(false)),
                    _ => send(PA::FormKey(key)),
                };
            }
            PersonaMode::PlaceFace(picker) => {
                if picker.working {
                    return true;
                }
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Down => send(PA::FormCycle(true)),
                    KeyCode::Up => send(PA::FormCycle(false)),
                    _ => false,
                };
            }
            PersonaMode::Bind(picker) => {
                if picker.working {
                    return true;
                }
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Down => send(PA::FormCycle(true)),
                    KeyCode::Up => send(PA::FormCycle(false)),
                    _ => false,
                };
            }
            PersonaMode::Compose(form) => {
                if form.working {
                    return true;
                }
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Tab => send(PA::FormField(true)),
                    KeyCode::BackTab => send(PA::FormField(false)),
                    KeyCode::Down => send(PA::FormCycle(true)),
                    KeyCode::Up => send(PA::FormCycle(false)),
                    // Not space: a value is text, and "Ada King" has one.
                    KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        send(PA::FormToggleEntry)
                    }
                    _ => send(PA::FormKey(key)),
                };
            }
            PersonaMode::LocalFaces(view) => {
                if view.working {
                    return true;
                }
                // The form owns the keyboard while it is up, so a name can
                // contain the letters the list uses as verbs.
                if view.form.is_some() {
                    return match key.code {
                        KeyCode::Esc => send(PA::FormCancel),
                        KeyCode::Enter => send(PA::FormSubmit),
                        KeyCode::Tab => send(PA::FormField(true)),
                        KeyCode::BackTab => send(PA::FormField(false)),
                        KeyCode::Down => send(PA::FormCycle(true)),
                        KeyCode::Up => send(PA::FormCycle(false)),
                        _ => send(PA::FormKey(key)),
                    };
                }
                // A deletion, or making a value reusable — both one-way — is
                // committed by `y` alone (#579).
                if view.deleting.is_some() || view.confirming {
                    return if crate::ui::pages::main::confirm::is_yes(&key) {
                        send(PA::FormSubmit)
                    } else {
                        send(PA::FormCancel)
                    };
                }
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::FormSubmit),
                    KeyCode::Down => send(PA::FormCycle(true)),
                    KeyCode::Up => send(PA::FormCycle(false)),
                    KeyCode::Char(' ') => send(PA::FormToggleEntry),
                    KeyCode::Char('n') => send(PA::LocalFaceNew),
                    KeyCode::Char('w') => send(PA::LocalFaceWear),
                    KeyCode::Char('d') | KeyCode::Delete => send(PA::LocalFaceDeleteArm),
                    _ => false,
                };
            }
            // Read-only overlays: any key but Esc is ignored rather than
            // falling through to the tab behind, which is not on screen.
            PersonaMode::Renderers(_) | PersonaMode::KnownHere(_) => {
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    _ => false,
                };
            }
            PersonaMode::People(view) => {
                if view.working {
                    return true;
                }
                // The form owns the keyboard while it is up; the list's own
                // verbs would otherwise eat letters being typed into a field.
                if view.form.is_some() {
                    return match key.code {
                        KeyCode::Esc => send(PA::FormCancel),
                        KeyCode::Enter => send(PA::FormSubmit),
                        KeyCode::Tab => send(PA::FormField(true)),
                        KeyCode::BackTab => send(PA::FormField(false)),
                        KeyCode::Down => send(PA::FormCycle(true)),
                        KeyCode::Up => send(PA::FormCycle(false)),
                        _ => send(PA::FormKey(key)),
                    };
                }
                // Forgetting someone is committed by `y` alone (#579).
                if view.deleting.is_some() {
                    return if crate::ui::pages::main::confirm::is_yes(&key) {
                        send(PA::FormSubmit)
                    } else {
                        send(PA::FormCancel)
                    };
                }
                return match key.code {
                    KeyCode::Esc => send(PA::FormCancel),
                    KeyCode::Enter => send(PA::ContactOpen),
                    KeyCode::Down => send(PA::FormCycle(true)),
                    KeyCode::Up => send(PA::FormCycle(false)),
                    KeyCode::Char('n') => send(PA::ContactNew),
                    KeyCode::Char('d') | KeyCode::Delete => send(PA::ContactDeleteArm),
                    _ => false,
                };
            }
            PersonaMode::View => {}
        }

        // ── An armed confirmation owns y/n ────────────────────────────────
        //
        // Removing a persona goes through the existing identity-deletion path
        // (`DeleteDid`), which does the VTA delete, the listener teardown and
        // the local cleanup. The pane owns the *question*; it does not own a
        // second implementation of the answer.
        match personas.confirm {
            PersonaConfirm::None => {}
            PersonaConfirm::DeletePersona(i) => {
                let act = match key.code {
                    KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                        Action::DeleteDid(i)
                    }
                    _ => Action::DidCancelDelete,
                };
                let _ = self.action_tx.send(act);
                return true;
            }
            _ => {
                return match key.code {
                    KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                        send(PA::ConfirmYes)
                    }
                    _ => send(PA::ConfirmNo),
                };
            }
        }

        // ── Tab navigation and the pane-wide verbs ────────────────────────
        match key.code {
            KeyCode::Tab | KeyCode::Right => return send(PA::TabNext),
            KeyCode::BackTab | KeyCode::Left => return send(PA::TabPrev),
            KeyCode::Esc => {
                // Esc backs out of the opened profile first, so it is not also
                // the key that leaves the panel while a detail view is up.
                if personas.open_profile.is_some() {
                    return send(PA::ProfileClose);
                }
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                return true;
            }
            KeyCode::Char('r') if personas.tab.needs_agent() => return send(PA::Refresh),
            _ => {}
        }

        match personas.tab {
            PersonaTab::Personas => {
                let count = personas.personas.len();
                let selected = personas.persona_selected;
                match key.code {
                    KeyCode::Up if count > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::DidSelect(selected.saturating_sub(1)));
                        true
                    }
                    KeyCode::Down if count > 0 => {
                        let _ = self
                            .action_tx
                            .send(Action::DidSelect((selected + 1).min(count - 1)));
                        true
                    }
                    KeyCode::Char('n') => {
                        let _ = self.action_tx.send(Action::StartCreatePersona);
                        true
                    }
                    KeyCode::Char('g') => {
                        let _ = self.action_tx.send(Action::StartAgentNameManager(selected));
                        true
                    }
                    // Only an orphan is removable: a persona a community still
                    // presents cannot be deleted without leaving that community
                    // first, and the deletion path refuses it anyway. Refusing
                    // to *arm* it keeps the prompt from appearing over a
                    // question that has already been answered no.
                    KeyCode::Char('d') | KeyCode::Delete
                        if personas
                            .personas
                            .get(selected)
                            .is_some_and(|f| f.bound_communities == 0) =>
                    {
                        let _ = self.action_tx.send(Action::DidConfirmDelete(selected));
                        true
                    }
                    _ => false,
                }
            }
            PersonaTab::Attributes => {
                let count = personas.attributes.len();
                let selected = personas.attribute_selected;
                match key.code {
                    KeyCode::Up if count > 0 => send(PA::Select(selected.saturating_sub(1))),
                    KeyCode::Down if count > 0 => send(PA::Select((selected + 1).min(count - 1))),
                    KeyCode::Char('v') => send(PA::ToggleValues),
                    // `s` shows one value; `v` asks the agent for all of them.
                    // Two different questions, and the narrower one is not a
                    // shortcut to the wider: `s` on a listing fetched without
                    // values has nothing to unmask.
                    KeyCode::Char('s') if selected < count => send(PA::RevealValue(selected)),
                    KeyCode::Char('n') => send(PA::AttributeNew),
                    KeyCode::Char('e') if selected < count => send(PA::AttributeEdit(selected)),
                    // `p` forgets the versions behind the current one. Not on
                    // `d`'s neighbour keys by accident: it is one-way, and the
                    // question names what stops being shown.
                    KeyCode::Char('p') if selected < count => send(PA::AttributePurgeArm(selected)),
                    KeyCode::Char('d') | KeyCode::Delete if selected < count => {
                        send(PA::AttributeDeleteArm(selected))
                    }
                    _ => false,
                }
            }
            PersonaTab::Profiles => {
                let count = personas.profiles.len();
                let selected = personas.profile_selected;
                // The opened detail view is a mode of this tab, not of the
                // pane, so its keys live here.
                if let Some(detail) = personas.open_profile.as_ref() {
                    let claims = detail.resolved.len();
                    let claim = personas.face_claim_selected;
                    return match key.code {
                        KeyCode::Enter => send(PA::ProfileClose),
                        KeyCode::Up if claims > 0 => {
                            send(PA::FaceClaimSelect(claim.saturating_sub(1)))
                        }
                        KeyCode::Down if claims > 0 => {
                            send(PA::FaceClaimSelect((claim + 1).min(claims - 1)))
                        }
                        // The same `s` the attributes tab uses, on the same
                        // terms: one claim, the selected one, and pressing it
                        // again puts the mask back. There is no `v` here
                        // because there is nothing for it to ask — a face
                        // detail is resolved in full when it is opened, so
                        // every value is already in hand and the mask is the
                        // only thing between it and the screen.
                        KeyCode::Char('s') if claim < claims => send(PA::RevealFaceClaim(claim)),
                        KeyCode::Char('e') => send(PA::ProfileEdit(selected)),
                        KeyCode::Char('h') => send(PA::FaceHistory),
                        _ => false,
                    };
                }
                // The retired view walks its own list and offers two verbs:
                // bring one back, or return to the faces the holder wears.
                if personas.show_retired {
                    let retired = personas.retired_faces.len();
                    return match key.code {
                        KeyCode::Up if retired > 0 => send(PA::Select(selected.saturating_sub(1))),
                        KeyCode::Down if retired > 0 => {
                            send(PA::Select((selected + 1).min(retired - 1)))
                        }
                        KeyCode::Char('x') if selected < retired => {
                            send(PA::ProfileReinstate(selected))
                        }
                        KeyCode::Char('z') => send(PA::ToggleRetired),
                        _ => false,
                    };
                }
                match key.code {
                    KeyCode::Char('z') => send(PA::ToggleRetired),
                    KeyCode::Char('x') if selected < count => send(PA::ProfileRetireArm(selected)),
                    KeyCode::Up if count > 0 => send(PA::Select(selected.saturating_sub(1))),
                    KeyCode::Down if count > 0 => send(PA::Select((selected + 1).min(count - 1))),
                    KeyCode::Enter if selected < count => send(PA::ProfileOpen(selected)),
                    KeyCode::Char('n') => send(PA::ProfileNew),
                    KeyCode::Char('e') if selected < count => send(PA::ProfileEdit(selected)),
                    KeyCode::Char('d') | KeyCode::Delete if selected < count => {
                        send(PA::ProfileDeleteArm(selected))
                    }
                    // `m` for *move*, on the tab where the face being moved is
                    // visible. A world's membership is edited from here and
                    // nowhere else — see `PersonaAction::FacePlaceOpen`.
                    KeyCode::Char('m') if selected < count => send(PA::FacePlaceOpen(selected)),
                    _ => false,
                }
            }
            PersonaTab::Worlds => {
                let count = personas.worlds.len();
                let selected = personas.world_selected;
                match key.code {
                    KeyCode::Up if count > 0 => send(PA::Select(selected.saturating_sub(1))),
                    KeyCode::Down if count > 0 => send(PA::Select((selected + 1).min(count - 1))),
                    KeyCode::Char('n') => send(PA::WorldNew),
                    KeyCode::Char('e') if selected < count => send(PA::WorldEdit(selected)),
                    KeyCode::Char('d') | KeyCode::Delete if selected < count => {
                        send(PA::WorldDeleteArm(selected))
                    }
                    _ => false,
                }
            }
            PersonaTab::Disclosures => {
                let count = personas.disclosures.len();
                let selected = personas.disclosure_selected;
                match key.code {
                    KeyCode::Up if count > 0 => send(PA::Select(selected.saturating_sub(1))),
                    KeyCode::Down if count > 0 => send(PA::Select((selected + 1).min(count - 1))),
                    // What a format carries belongs beside what left through
                    // it, not on a screen of its own nobody opens.
                    KeyCode::Char('f') => send(PA::RenderersOpen),
                    _ => false,
                }
            }
            PersonaTab::Communities => {
                let count = personas.memberships.len();
                let selected = personas.membership_selected;
                match key.code {
                    KeyCode::Up if count > 0 => send(PA::Select(selected.saturating_sub(1))),
                    KeyCode::Down if count > 0 => send(PA::Select((selected + 1).min(count - 1))),
                    KeyCode::Char('b') if selected < count => send(PA::BindOpen(selected)),
                    KeyCode::Char('c') if selected < count => send(PA::ComposeOpen(selected)),
                    KeyCode::Char('f') if selected < count => send(PA::LocalFacesOpen(selected)),
                    KeyCode::Char('k') if selected < count => send(PA::KnownHereOpen(selected)),
                    KeyCode::Char('p') if selected < count => send(PA::PeopleOpen(selected)),
                    KeyCode::Char('u') if selected < count => send(PA::UnbindArm(selected)),
                    _ => false,
                }
            }
        }
    }
}
