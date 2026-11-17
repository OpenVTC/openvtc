//! `VettingOutcome`: what a background job produced, applied on the loop thread.

use std::sync::Arc;

use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::vetting::applicant::{ChosenFace, SentCard};
use openvtc_core::vetting::mode::ModeFailure;
use openvtc_core::vetting::queries::QueryKind;
use vta_sdk::protocols::vetting::session;

use super::dispatch::card_mode;
use super::faces::{
    agent_credential_did, default_face_name, optional_claim_types, preview_refusal,
    required_claim_types,
};
use super::jobs::{CardFailure, Sent};
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::main_page::content::{
    CardPreview, FaceChoice, NewFaceForm, PoolRow, VettingMode,
};
use crate::state_handler::main_page::shorten_did;
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

/// How a vetting job went. Applied on the loop thread.
pub(crate) enum VettingOutcome {
    /// A document went out, or did not.
    Sent {
        /// Boxed: a desk state carries the card, and dwarfs every other outcome.
        sent: Box<Sent>,
        error: Option<String>,
    },
    /// The holder's faces, for the picker.
    Faces {
        application_id: String,
        result: Result<Vec<FaceChoice>, String>,
    },
    /// The pool, for the make-a-face form.
    Pool {
        application_id: String,
        required: Vec<String>,
        result: Result<Vec<PoolRow>, String>,
    },
    /// A value typed on the make-a-face form is an attribute now, or is not.
    AttributeSaved {
        application_id: String,
        claim_type: String,
        result: Result<PoolRow, String>,
    },
    /// A face is worn, or is not.
    FaceWorn {
        application_id: String,
        profile_id: String,
        name: String,
        error: Option<String>,
    },
    /// What a card would show.
    Previewed {
        application_id: String,
        session_id: String,
        result: Result<CardPreview, String>,
    },
    /// A card went out — with what it showed — or did not.
    CardSent {
        application_id: String,
        session_id: String,
        result: Result<(SentCard, Vec<session::v0_1::VettingCardClaim>), CardFailure>,
    },
}

impl VettingOutcome {
    /// Fold the result into the book and the page.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        let v = &mut state.main_page.content_panel.vetting;
        let (message, persist) = match self {
            VettingOutcome::Sent { sent, error } => {
                if let (Sent::Query { document_id, .. }, Some(e)) = (&*sent, &error)
                    && let VettingMode::Directory(view) = &mut v.mode
                    && view.pending.as_deref() == Some(document_id.as_str())
                {
                    view.pending = None;
                    view.pending_cursors = None;
                    view.error = Some(format!("Could not ask the community: {e}"));
                }
                sent_result(*sent, error, config)
            }
            VettingOutcome::Faces {
                application_id,
                result: Ok(faces),
            } => {
                if let Some(worn) = faces.iter().find(|f| f.worn) {
                    v.worn_faces
                        .insert(application_id.clone(), worn.name.clone());
                    // The agent is authoritative about what is worn, so a list
                    // is also the chance to pick up a face chosen before this
                    // was recorded, and to refresh a name that has changed.
                    if let Some(app) = config
                        .private
                        .vetting
                        .application_by_id_mut(&application_id)
                    {
                        app.face = Some(ChosenFace {
                            profile_id: worn.profile_id.clone(),
                            name: worn.name.clone(),
                        });
                    }
                }
                let message = if faces.is_empty() {
                    "You have no faces yet — Enter makes one, and asks for anything this \
                     community needs that you have not added."
                } else {
                    "Choose the face you show vetters."
                };
                // From the list, the card page, or the access-granted retry —
                // every place `f` is offered. Any other mode is something the
                // holder moved on to while the read was in flight, and must not
                // be replaced under them. With no faces the picker still opens:
                // its last row makes one, and skipping it left only a pointer
                // to another page.
                if matches!(
                    v.mode,
                    VettingMode::List
                        | VettingMode::SendCard { .. }
                        | VettingMode::HolderGrant { .. }
                ) {
                    let index = faces.iter().position(|f| f.worn).unwrap_or(0);
                    let required = config
                        .private
                        .vetting
                        .applications
                        .iter()
                        .find(|a| a.id == application_id)
                        .map(required_claim_types)
                        .unwrap_or_default();
                    v.mode = VettingMode::ChooseFace {
                        application_id,
                        faces,
                        index,
                        required,
                    };
                }
                // The application may have just been given its context.
                (message.to_string(), true)
            }
            VettingOutcome::Pool {
                application_id,
                required,
                result: Ok(pool),
            } => {
                // Open with the required claim types already ticked. The
                // community has said what the card needs, so leaving the
                // holder to work that out from a list of thirty attributes
                // would be withholding the one thing that makes this inline.
                // What is still missing is the form's own status line to say;
                // this message only says the read is done, so the two never
                // disagree or repeat each other.
                let app = config
                    .private
                    .vetting
                    .applications
                    .iter()
                    .find(|a| a.id == application_id);
                let optional = app.map(optional_claim_types).unwrap_or_default();
                let name = app.map_or_else(
                    || "Vetting".to_string(),
                    |a| default_face_name(config, &a.community),
                );
                let form = NewFaceForm::open(application_id, required, optional, pool, name);
                v.mode = VettingMode::NewFace(Box::new(form));
                (
                    "Your attributes are read. What this community's card needs is below."
                        .to_string(),
                    true,
                )
            }
            VettingOutcome::AttributeSaved {
                application_id,
                claim_type,
                result,
            } => {
                let words = openvtc_core::vetting::guide::claim_words(&claim_type);
                match result {
                    Ok(row) => {
                        // My Identity's listing no longer has everything in the
                        // pool. Re-read once the domain is free, as after its
                        // own writes.
                        state.main_page.content_panel.identity.refresh_queued = true;
                        match &mut v.mode {
                            VettingMode::NewFace(form) if form.application_id == application_id => {
                                form.saved(row);
                                (
                                    format!(
                                        "Saved your {words} to My Identity, and ticked it for \
                                         this face."
                                    ),
                                    true,
                                )
                            }
                            _ => (format!("Saved your {words} to My Identity."), true),
                        }
                    }
                    // The pool sits above every context, so the write meets the
                    // same holder refusal as the read, with the same answer.
                    Err(e) if crate::holder_grant::needs_holder_grant(&e) => {
                        v.mode = VettingMode::HolderGrant {
                            credential_did: agent_credential_did(config).map(str::to_string),
                        };
                        (format!("Could not save your {words}."), true)
                    }
                    Err(e) => match &mut v.mode {
                        // The reason goes on the form, beside the value the
                        // holder typed and can now retry; the status line only
                        // says that it failed.
                        VettingMode::NewFace(form) if form.application_id == application_id => {
                            form.saving = None;
                            form.error = Some(format!("Could not save it: {e}"));
                            (format!("Could not save your {words}."), true)
                        }
                        _ => (format!("Could not save your {words}: {e}"), true),
                    },
                }
            }
            VettingOutcome::Pool { result: Err(e), .. } => {
                // The same refusal the faces read has, for the same reason:
                // the pool is what a face is built over.
                if crate::holder_grant::needs_holder_grant(&e) {
                    v.mode = VettingMode::HolderGrant {
                        credential_did: agent_credential_did(config).map(str::to_string),
                    };
                    ("Could not read your attributes.".to_string(), true)
                } else {
                    (format!("Could not read your attributes: {e}"), true)
                }
            }
            VettingOutcome::Faces { result: Err(e), .. } => {
                // Faces are built over the holder's attribute pool, which sits
                // above every context — so the commonest way this fails is the
                // one refusal with a specific answer. It opens a view of its
                // own: the answer is a command, and the status line wrapped it
                // mid-DID, where it could be neither read nor selected.
                //
                // Everything else stays a status line. A failure we do not
                // recognise has no command to offer, so a view would be a
                // bigger frame around the same sentence.
                if crate::holder_grant::needs_holder_grant(&e) {
                    v.mode = VettingMode::HolderGrant {
                        credential_did: agent_credential_did(config).map(str::to_string),
                    };
                    ("Could not read your faces.".to_string(), true)
                } else {
                    (format!("Could not read your faces: {e}"), true)
                }
            }
            VettingOutcome::FaceWorn {
                application_id,
                profile_id,
                name,
                error: None,
            } => {
                // Persisted as well as cached: `worn_faces` is this run only,
                // and the application's own next step has to know a face was
                // chosen after a restart too.
                if let Some(app) = config
                    .private
                    .vetting
                    .application_by_id_mut(&application_id)
                {
                    app.face = Some(ChosenFace {
                        profile_id,
                        name: name.clone(),
                    });
                }
                // Back to the card that asked for a face, if this is its
                // application and the holder is still waiting on the list the
                // wear left them on.
                let back_to_card = v
                    .card_after_face
                    .take_if(|(card_application, _)| *card_application == application_id)
                    .filter(|_| matches!(v.mode, VettingMode::List));
                v.worn_faces.insert(application_id, name.clone());
                let message = format!(
                    "Vetters are shown your {name} face, and the community sees the same one \
                     when you join."
                );
                match back_to_card {
                    Some(card) => {
                        v.mode = card_mode(card);
                        (format!("{message} Enter previews the card."), true)
                    }
                    None => (message, true),
                }
            }
            VettingOutcome::FaceWorn {
                name,
                error: Some(e),
                ..
            } => (format!("Could not wear {name}: {e}"), true),
            VettingOutcome::Previewed {
                application_id,
                session_id,
                result: Ok(preview),
            } => {
                let message = match &preview.problem {
                    Some(problem) => format!("This face cannot make the card: {problem}"),
                    None => "This is what the card shows. Enter approves and sends it.".to_string(),
                };
                if let VettingMode::SendCard {
                    application_id: open_application,
                    session_id: open,
                    preview: shown,
                } = &mut v.mode
                    && *open == session_id
                    && *open_application == application_id
                {
                    *shown = Some(preview);
                }
                (message, true)
            }
            VettingOutcome::Previewed {
                application_id,
                result: Err(e),
                ..
            } => (preview_refusal(&e, &application_id, config), true),
            VettingOutcome::CardSent {
                application_id,
                session_id,
                result: Ok((card, claims)),
            } => {
                if matches!(&v.mode, VettingMode::SendCard { session_id: open, .. } if *open == session_id)
                {
                    v.mode = VettingMode::List;
                }
                config
                    .private
                    .tasks
                    .remove(&Arc::new(format!("vetting-session-{session_id}")));
                let recorded = config
                    .private
                    .vetting
                    .application_by_id_mut(&application_id)
                    .map(|app| app.record_sent_card(&session_id, card, &claims, Utc::now()));
                match recorded {
                    Some(Ok(())) => (
                        "Card sent — the vetter checks it against you and your documents."
                            .to_string(),
                        true,
                    ),
                    Some(Err(e)) => (
                        format!("Card sent, but it could not be recorded: {e}"),
                        true,
                    ),
                    None => ("Card sent, but the application is gone.".to_string(), true),
                }
            }
            VettingOutcome::CardSent {
                result: Err(CardFailure::StepUp),
                ..
            } => (
                "Your VTA wants you to approve this disclosure. Approve it on your device, then \
                 press Enter again."
                    .to_string(),
                false,
            ),
            VettingOutcome::CardSent {
                session_id,
                result: Err(CardFailure::Failed(e)),
                ..
            } => {
                // The preview may be spent; the next Enter asks for a new one.
                if let VettingMode::SendCard {
                    session_id: open,
                    preview,
                    ..
                } = &mut v.mode
                    && *open == session_id
                {
                    *preview = None;
                }
                (
                    format!("Could not send the card: {e}. Enter previews it again."),
                    true,
                )
            }
        };
        // Every outcome is a moment the desk may have changed — a statement
        // sent, a decline delivered — so a card that has served its purpose
        // is forgotten now rather than at the next hourly sweep.
        let pruned = config.private.vetting.prune(Utc::now());
        let persist = persist || pruned;
        dispatch_util::save_and_sync(
            &mut state.main_page,
            config,
            save,
            if persist {
                Persist::SaveAndSync(crate::state_handler::main_page::Panels::FROM_VETTING_BOOK)
            } else {
                Persist::SyncOnly(crate::state_handler::main_page::Panels::FROM_VETTING_BOOK)
            },
            |mp| &mut mp.content_panel.vetting.status_message,
            message.clone(),
            SyncLog::Plain(message),
        );
    }
}

/// Report a send: clear the inbox task the step answered, or undo the step and
/// say why. Returns the message and whether the book changed.
fn sent_result(sent: Sent, error: Option<String>, config: &mut Config) -> (String, bool) {
    let tasks = &mut config.private.tasks;
    let book = &mut config.private.vetting;
    let clear = |tasks: &mut openvtc_core::tasks::Tasks, id: String| {
        tasks.remove(&Arc::new(id));
    };
    {
        match (sent, error) {
            (Sent::Manifest { community }, None) => (
                format!(
                    "Asked {} for its vetting requirements.",
                    shorten_did(&community, 48)
                ),
                false,
            ),
            (Sent::Request { vetter, .. }, None) => (
                format!(
                    "Request sent to {} — it is answered only if your ticket is valid.",
                    shorten_did(&vetter, 48)
                ),
                false,
            ),
            (Sent::Session { request_id }, None) => {
                clear(tasks, format!("vetting-request-{request_id}"));
                ("Session sent — waiting for their card.".to_string(), true)
            }
            (Sent::Statement { request_id, .. }, None) => {
                clear(tasks, format!("vetting-card-{request_id}"));
                ("Statement signed and sent.".to_string(), true)
            }
            (Sent::Attestation { request_id, .. }, None) => {
                clear(tasks, format!("vetting-card-{request_id}"));
                (
                    "Attestation sent. The community will count it without learning it was you."
                        .to_string(),
                    true,
                )
            }
            (Sent::Decline { request_id, .. }, None) => {
                clear(tasks, format!("vetting-card-{request_id}"));
                clear(tasks, format!("vetting-request-{request_id}"));
                ("Declined.".to_string(), true)
            }
            (Sent::Withdrawal { .. }, None) => (
                "Withdrawal sent — the community confirms when it has recorded it.".to_string(),
                false,
            ),
            (
                Sent::Query {
                    kind: QueryKind::VetterResend,
                    ..
                },
                None,
            ) => (
                "Asked — if the community holds a vetter credential for you, it arrives under \
                 Tickets."
                    .to_string(),
                false,
            ),
            (Sent::Query { .. }, None) => (
                "Asked the community — waiting for its answer.".to_string(),
                false,
            ),
            (Sent::Profile { .. }, None) => (
                "Profile sent — waiting for the community to store it.".to_string(),
                true,
            ),
            (
                Sent::Query {
                    document_id,
                    community,
                    kind,
                },
                Some(e),
            ) => {
                book.forget_query(&document_id);
                (
                    format!(
                        "Could not ask {} for {}: {e}",
                        shorten_did(&community, 48),
                        kind.describe()
                    ),
                    false,
                )
            }
            (
                Sent::Profile {
                    document_id,
                    community,
                    persona,
                    previous,
                },
                Some(e),
            ) => {
                book.restore_profile(&community, persona, previous.map(|p| *p));
                book.forget_query(&document_id);
                (format!("Could not send your profile: {e}"), true)
            }
            (
                Sent::Request {
                    application_id,
                    document_id,
                    ..
                },
                Some(e),
            ) => {
                if let Some(app) = book.application_by_id_mut(&application_id) {
                    app.forget_unsent(&document_id);
                }
                (format!("Could not send the request: {e}"), true)
            }
            (
                Sent::Statement {
                    request_id,
                    statement_id,
                    previous,
                },
                Some(e),
            ) => {
                book.issued.retain(|s| s.id != statement_id);
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = previous;
                }
                (
                    format!("Could not send the statement, so it was not issued: {e}"),
                    true,
                )
            }
            (
                Sent::Attestation {
                    request_id,
                    previous,
                },
                Some(e),
            ) => {
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = previous;
                }
                (
                    format!(
                        "Could not send the attestation: {e}. The token it spent is gone — \
                         attesting again draws on the next one."
                    ),
                    true,
                )
            }
            (
                Sent::Decline {
                    request_id,
                    previous,
                },
                Some(e),
            ) => {
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = previous;
                }
                (format!("Could not send the decline: {e}"), true)
            }
            (Sent::Withdrawal { statement_id }, Some(e)) => {
                if let Some(s) = book.issued.iter_mut().find(|s| s.id == statement_id) {
                    s.withdrawal = None;
                }
                (format!("Could not send the withdrawal: {e}"), true)
            }
            // Asked in the background (start-up, the hourly sweep, a request
            // arriving), and asked again on its own — so the line says that,
            // rather than "try again" to someone who never asked.
            (Sent::Manifest { community }, Some(e)) => (
                {
                    book.mode_failed(&community, ModeFailure::Unsent(e.clone()), Utc::now());
                    format!(
                        "Could not yet ask {} what it requires ({e}) — asking again shortly.",
                        shorten_did(&community, 48)
                    )
                },
                false,
            ),
            (Sent::Session { .. }, Some(e)) => (format!("Could not send — try again: {e}"), false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::{CardPreview, FaceChoice, VettingMode};
    use crate::state_handler::save_coalesce::SaveScheduler;
    use crate::state_handler::state::State;
    use chrono::Utc;
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::applicant::{Application, RequestDraft};
    use vta_sdk::protocols::vetting::request;

    fn outcome(sent: Sent, error: Option<&str>) -> VettingOutcome {
        VettingOutcome::Sent {
            sent: Box::new(sent),
            error: error.map(ToString::to_string),
        }
    }

    /// A step-up refusal keeps the preview the holder approved, so pressing
    /// Enter after approving presents the same one; any other failure drops
    /// it, because the preview may already be spent.
    #[test]
    fn a_step_up_keeps_the_preview_and_a_failure_drops_it() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let preview = CardPreview {
            preview_id: "01PREVIEW".into(),
            claims: vec![("name.legal".into(), "Alice Example".into())],
            problem: None,
        };
        state.main_page.content_panel.vetting.mode = VettingMode::SendCard {
            application_id: "a".into(),
            session_id: "s".into(),
            preview: Some(preview.clone()),
        };
        let card_sent = |result| VettingOutcome::CardSent {
            application_id: "a".into(),
            session_id: "s".into(),
            result,
        };

        card_sent(Err(CardFailure::StepUp)).apply(&mut state, &mut config, &mut save);
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(&v.mode, VettingMode::SendCard { preview: Some(p), .. } if *p == preview));
        assert!(
            v.status_message
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("approve"))
        );

        card_sent(Err(CardFailure::Failed("preview expired".into()))).apply(
            &mut state,
            &mut config,
            &mut save,
        );
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::SendCard { preview: None, .. }
        ));
    }

    /// `f` on the card page opens the picker — its read is not dropped for the
    /// page not being the list — and wearing a face goes
    /// back to the card that asked for it, not to the list.
    #[test]
    fn a_face_chosen_from_the_card_returns_to_the_card() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let v = &mut state.main_page.content_panel.vetting;
        v.mode = VettingMode::SendCard {
            application_id: "a".into(),
            session_id: "s".into(),
            preview: None,
        };
        v.card_after_face = Some(("a".into(), "s".into()));

        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Ok(Vec::new()),
        }
        .apply(&mut state, &mut config, &mut save);
        // Opened even with no faces: its last row makes one.
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::ChooseFace { faces, index: 0, .. } if faces.is_empty()
        ));

        // Wearing leaves the page on the list while the job runs…
        state.main_page.content_panel.vetting.mode = VettingMode::List;
        VettingOutcome::FaceWorn {
            application_id: "a".into(),
            profile_id: "p".into(),
            name: "WORK".into(),
            error: None,
        }
        .apply(&mut state, &mut config, &mut save);
        // …and the answer puts the holder back on the card.
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(
            &v.mode,
            VettingMode::SendCard { application_id, session_id, preview: None }
                if application_id == "a" && session_id == "s"
        ));
        assert!(v.card_after_face.is_none());
    }

    /// The picker opens on the face already worn, and the page remembers it.
    #[test]
    fn the_face_picker_opens_on_the_worn_face() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let face = |id: &str, worn| FaceChoice {
            profile_id: id.into(),
            name: id.to_uppercase(),
            entries: 2,
            worn,
            claim_types: vec!["name.legal".into()],
        };
        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Ok(vec![face("home", false), face("work", true)]),
        }
        .apply(&mut state, &mut config, &mut save);
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(&v.mode, VettingMode::ChooseFace { index: 1, .. }));
        assert_eq!(v.worn_faces.get("a").map(String::as_str), Some("WORK"));
    }

    /// The pool is what a face is built over, so it meets the same refusal the
    /// faces read does — and must answer it the same way rather than passing
    /// the agent's paragraph through.
    #[test]
    fn the_pool_read_routes_the_holder_refusal_to_the_same_view() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        VettingOutcome::Pool {
            application_id: "a".into(),
            required: Vec::new(),
            result: Err("forbidden: requires an unscoped holder credential".into()),
        }
        .apply(&mut state, &mut config, &mut save);

        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::HolderGrant { .. }
        ));
    }

    /// The refusal with an answer opens a view, so the command it names gets a
    /// line to itself. As a status line it wrapped at the panel's width, which
    /// fell mid-DID.
    #[test]
    fn the_holder_refusal_opens_a_view_and_everything_else_does_not() {
        let mut save = SaveScheduler::new("test");

        let mut state = State::default();
        let mut config = test_config();
        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Err("forbidden: requires an unscoped holder credential".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::HolderGrant { .. }
        ));

        // A failure we do not recognise has no command to offer, so a view
        // would be a bigger frame around the same sentence — and inventing a
        // cause for it is what R6.4 forbids.
        let mut state = State::default();
        let mut config = test_config();
        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Err("connection refused".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::List
        ));
    }

    /// A request that never left is forgotten, so retrying is not shadowed by
    /// a record the vetter never saw.
    #[test]
    fn a_failed_request_is_forgotten() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let mut app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();
        app.prepare_request(
            "urn:uuid:r1",
            "did:key:zVetter",
            request::v0_1::Ticket::ShortCodeTicket(
                request::v0_1::ShortCodeTicket::try_from(
                    request::v0_1::ShortCodeTicket::builder().code("K7QF-2M9X"),
                )
                .unwrap(),
            ),
            RequestDraft::default(),
            Utc::now(),
        )
        .unwrap();
        let application_id = app.id.clone();
        config.private.vetting.applications.push(app);

        outcome(
            Sent::Request {
                application_id,
                document_id: "urn:uuid:r1".into(),
                vetter: "did:key:zVetter".into(),
            },
            Some("mediator unreachable"),
        )
        .apply(&mut state, &mut config, &mut save);

        assert!(config.private.vetting.applications[0].requests.is_empty());
        assert!(
            state
                .main_page
                .content_panel
                .vetting
                .status_message
                .as_ref()
                .map(|s| s.text.as_str())
                .is_some_and(|m| m.contains("unreachable"))
        );
    }
}
