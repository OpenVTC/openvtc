//! The face an application wears: listing, creating and wearing faces at the
//! VTA, saving attributes for them, and sending the vetting card.
//!
//! Each handler is a pure `plan_*` (no `.await`, no spawning, no saving) in the
//! shape of `dispatch::plan`. It reads `busy` and `has_vta` — whether a vetting
//! job holds the domain and whether a VTA session is connected — as the loop
//! found them (`dispatch::plan`'s inputs), says why when there is no session, derives
//! the application's context where the handler needs one, refuses with
//! `claimable` when the domain is held, and only then keeps a context derived
//! just now (saved by a `Step::MarkDirty`) and makes the page changes a started
//! job makes. What is left is a [`FaceWork`] for `effect::Step::Face`, which
//! spawns it against the loop's VTA session ([`spawn_face`]); a card being
//! sent is preceded by `effect::Step::CardKeys`, the persona's key lookup
//! ([`card_keys`]).

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context;
use openvtc_core::persona::claim_types::Registry;
use openvtc_core::persona::pool::PoolAttribute;
use openvtc_core::vetting::applicant::{Application, RequestState};
use openvtc_core::vetting::book::FALLBACK_REQUIRED_CLAIMS;
use vta_sdk::client::VtaClient;

use super::dispatch::{card_mode, panel, show};
use super::effect::{Abort, Step, Undo, VettingEffect};
use super::jobs::{CardJob, CardStep, FaceJob, Presenting};
use super::send::{Claim, claimable, resolver, spawn};
use crate::state_handler::main_page::content::{
    CardPreview, FaceChoice, NewFaceForm, NewFaceStep, PoolRow, VettingMode,
};
use crate::state_handler::main_page::sanitize_display;
use crate::state_handler::main_page::status::Status;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

/// What a failed card preview means, when we can tell.
///
/// One refusal has a specific cause and a specific answer: the face being worn
/// holds none of the claim types the vetter's session asked for. The agent says
/// so accurately — "none of the requested claim types are present in this
/// persona's profile" — in a sentence that names neither the claim types nor
/// the face nor the key that changes it, wrapped in two layers of protocol
/// framing. Everything else is passed through: a failure we cannot explain is
/// better verbatim than paraphrased into a guess (R6.4).
pub(super) fn preview_refusal(error: &str, application_id: &str, config: &Config) -> String {
    // The persona wears no face in the community's context at all. Making an
    // application does not choose one — `f` does — so this is the first card of
    // any application whose face was never picked, and the agent's sentence
    // names the persona's DID and nothing the holder can press.
    if error.contains("has no profile bound") {
        return "This application has no face yet, so there is no card to show. Press f to \
                choose the face vetters see — you come back here once it is worn."
            .to_string();
    }
    if !error.contains("none of the requested claim types are present") {
        return format!("Could not preview the card: {error}");
    }
    let app = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id);
    let wanted = app.map(required_claim_types).unwrap_or_default();
    let face = app.and_then(|a| a.face.as_ref()).map_or_else(
        || "The face you are wearing".to_string(),
        |f| f.name.clone(),
    );
    if wanted.is_empty() {
        return format!(
            "{face} holds none of the claims this vetter asked for. Press f to wear a face that \
             does — making a new one there asks for anything you have not added."
        );
    }
    format!(
        "{face} holds none of {}, which this community's card must carry. Press f to wear a \
         face that has them — making a new one there asks for anything you have not added.",
        wanted.join(", ")
    )
}

/// Plan opening the make-a-face form, reading the pool to fill its tick list.
///
/// The read is what makes this worth doing inline: the community has already
/// said which claim types it needs, so the form opens with the matching
/// attributes already ticked and the holder's decision is usually just a name.
pub(super) fn plan_open_new_face(
    state: &mut State,
    busy: bool,
    has_vta: bool,
    application_id: &str,
    required: Vec<String>,
) -> VettingEffect {
    if !connected(state, has_vta) || !claimable(state, busy) {
        return VettingEffect::none();
    }
    show(state, Status::progress("Reading your attributes…"));
    let registry = state.main_page.content_panel.identity.claim_types.clone();
    VettingEffect::face(FaceWork::Pool {
        application_id: application_id.to_string(),
        required,
        registry,
    })
}

/// Plan Enter on the make-a-face form: save a value typed in place, or create
/// the face and wear it.
///
/// What Enter does is decided by [`NewFaceForm::enter`], which the form's
/// status line describes — so a refusal is never a second message contradicting
/// the first, it is the form moving to the row the status line names.
///
/// Making the face is one step, not two. A face made here exists only to be
/// worn by this application — leaving it created but unworn would put the
/// holder back on the picker to do the thing they had just asked for.
pub(super) fn plan_create_face(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    has_vta: bool,
    mut form: NewFaceForm,
) -> VettingEffect {
    let (name, live_refs) = match form.enter() {
        NewFaceStep::Wait => {
            panel(state).mode = VettingMode::NewFace(Box::new(form));
            return VettingEffect::none();
        }
        NewFaceStep::Save(draft) => return plan_save_attribute(state, busy, has_vta, form, draft),
        NewFaceStep::Make { name, live_refs } => (name, live_refs),
    };
    if !connected(state, has_vta) {
        return VettingEffect::none();
    }
    let application_id = form.application_id.clone();
    let context = match application_context(config, &application_id) {
        Ok(found) => found,
        Err(e) => {
            show(state, Status::error(format!("Cannot make a face: {e}")));
            return VettingEffect::none();
        }
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    let save = keep_context(config, &application_id, &context);
    panel(state).mode = VettingMode::List;
    show(state, Status::progress(format!("Making {name}…")));
    saving_context(
        save,
        VettingEffect::face(FaceWork::Create {
            top_context_id: config.account.top_context_id.clone(),
            context_id: context.id,
            persona_did: context.join_did,
            application_id,
            name,
            live_refs,
        }),
    )
}

/// Plan saving a value typed on the make-a-face form as an attribute of its
/// own.
///
/// The same write My Identity makes (`pool::put`, self-asserted), so the value
/// lands in the pool as a real attribute that page lists and edits like any
/// other. The form stays open and waiting: when the write returns, the new
/// attribute is ticked and the holder is one Enter from the face.
fn plan_save_attribute(
    state: &mut State,
    busy: bool,
    has_vta: bool,
    mut form: NewFaceForm,
    draft: openvtc_core::persona::pool::AttributeDraft,
) -> VettingEffect {
    let started = connected(state, has_vta) && claimable(state, busy);
    if !started {
        // Not sent, so not saving: the form must not sit waiting on a write
        // that never left.
        form.saving = None;
    }
    let application_id = form.application_id.clone();
    panel(state).mode = VettingMode::NewFace(Box::new(form));
    if !started {
        return VettingEffect::none();
    }
    let registry = state.main_page.content_panel.identity.claim_types.clone();
    VettingEffect::face(FaceWork::AddAttribute {
        application_id,
        draft,
        registry,
    })
}

/// The claim types any open session names as optional, for the make-a-face
/// form to offer — never to pre-tick.
pub(super) fn optional_claim_types(app: &Application) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for request in &app.requests {
        if let RequestState::Session { session, .. } = &request.state {
            for claim in &session.optional_claims {
                if !out.contains(claim) {
                    out.push(claim.clone());
                }
            }
        }
    }
    out
}

/// What a face made for `community` is called until the holder renames it.
///
/// The community's agent name only once it has been verified (the cached
/// round-trip), never one read straight from a document: a face's name is
/// something the holder recognises it by, and an unverified name could put a
/// name of anyone's choosing there. Otherwise a plain word, so the field is
/// never blank and Enter is never refused for want of a name.
pub(super) fn default_face_name(config: &Config, community: &str) -> String {
    config
        .agent_name_for(community)
        .map(|name| sanitize_display(name, 64))
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Vetting".to_string())
}

/// A pool attribute as a row on the make-a-face form, its value painted the way
/// the Identity page paints it.
pub(super) fn pool_row(attribute: &PoolAttribute, registry: &Registry) -> PoolRow {
    PoolRow {
        label: sanitize_display(attribute.display_name(), 128),
        claim_type: attribute.claim_type.clone(),
        attribute_id: attribute.attribute_id.clone(),
        value: attribute
            .value
            .as_ref()
            .map(|_| sanitize_display(&attribute.display_value(registry, true), 128)),
    }
}

/// The claim types a card for this community must carry.
///
/// From the manifest when it has been read, and from the fallback set when it
/// has not — the same rule the identity block on the application already used,
/// lifted out so the face picker answers against the same list. A picker
/// judging faces by a different standard than the card is checked against would
/// be worse than one that says nothing.
pub(super) fn required_claim_types(app: &Application) -> Vec<String> {
    app.requirements
        .as_ref()
        .map(|r| {
            r.required_claims
                .iter()
                .flatten()
                .map(|c| c.as_str().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|claims| !claims.is_empty())
        .unwrap_or_else(|| {
            FALLBACK_REQUIRED_CLAIMS
                .iter()
                .map(ToString::to_string)
                .collect()
        })
}

/// The DID this install authenticates to its agent as, when it has one.
///
/// A BIP32 account has no agent credential at all — and, having no agent, will
/// not have produced a holder refusal in the first place.
pub(super) fn agent_credential_did(config: &Config) -> Option<&str> {
    match &config.key_backend {
        openvtc_core::config::KeyBackend::Vta { credential_did, .. } => Some(credential_did),
        openvtc_core::config::KeyBackend::Bip32 { .. } => None,
    }
}

/// What a card's disclosure tells the VTA it is for.
pub(super) const VETTING_PURPOSE: &str = "identity vetting";

/// Whether a VTA session is connected (`has_vta`), or say why there is none.
fn connected(state: &mut State, has_vta: bool) -> bool {
    if !has_vta {
        show(
            state,
            Status::error(
                "Faces live in your VTA, and it is not connected — try again once it is.",
            ),
        );
    }
    has_vta
}

/// A face or card job as a plan decides it. The VTA session it runs against
/// is the loop's, taken as the job is spawned ([`spawn_face`]); a card being
/// sent also takes the keys [`card_keys`] looked up.
pub(super) enum FaceWork {
    /// Read the holder's faces, and which one the application wears.
    List {
        context_id: String,
        persona_did: String,
        application_id: String,
    },
    /// Read the pool for the make-a-face form.
    Pool {
        application_id: String,
        required: Vec<String>,
        registry: Registry,
    },
    /// Save a value typed on the make-a-face form as an attribute.
    AddAttribute {
        application_id: String,
        draft: openvtc_core::persona::pool::AttributeDraft,
        registry: Registry,
    },
    /// Create a face and wear it.
    Create {
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        name: String,
        live_refs: Vec<String>,
    },
    /// Wear a face in the application's context.
    Wear {
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        face: FaceChoice,
    },
    /// One step of the card: a preview (`preview_id` is `None`), or the
    /// release and send of the preview `preview_id`.
    Card {
        context_id: String,
        vetter: String,
        /// A copy of the application, as the plan found it.
        application: Box<Application>,
        session_id: String,
        preview_id: Option<String>,
    },
}

/// The persona's keys a card is sent with.
pub(super) struct CardKeys {
    /// assertionMethod key — signs the card (a credential).
    signer: Secret,
    /// authentication key — signs the document that carries it.
    document_signer: Secret,
}

/// Look up `persona`'s keys for a card. The card is signed as the persona DID,
/// with the persona's own assertionMethod key — the same path every other
/// document this client signs takes.
pub(super) async fn card_keys(
    ctx: &mut ActionCtx<'_>,
    persona: PersonaId,
) -> Result<CardKeys, String> {
    let keys = ctx
        .config
        .get_persona_keys_for(persona, ctx.tdk)
        .await
        .map_err(|e| e.to_string())?;
    Ok(CardKeys {
        signer: keys.signing.secret.clone(),
        document_signer: keys.authentication.secret.clone(),
    })
}

/// Hand `work` to the background as a job against `client`, held as `claim`
/// says. A card being sent needs `keys`; without them nothing is spawned.
pub(super) fn spawn_face(
    ctx: &mut ActionCtx<'_>,
    client: VtaClient,
    work: FaceWork,
    keys: Option<CardKeys>,
    claim: Claim,
) {
    let job = match work {
        FaceWork::List {
            context_id,
            persona_did,
            application_id,
        } => FaceJob::List {
            client,
            context_id,
            persona_did,
            application_id,
        },
        FaceWork::Pool {
            application_id,
            required,
            registry,
        } => FaceJob::Pool {
            client,
            application_id,
            required,
            registry,
        },
        FaceWork::AddAttribute {
            application_id,
            draft,
            registry,
        } => FaceJob::AddAttribute {
            client,
            application_id,
            draft,
            registry,
        },
        FaceWork::Create {
            top_context_id,
            context_id,
            persona_did,
            application_id,
            name,
            live_refs,
        } => FaceJob::Create {
            client,
            top_context_id,
            context_id,
            persona_did,
            application_id,
            name,
            live_refs,
        },
        FaceWork::Wear {
            top_context_id,
            context_id,
            persona_did,
            application_id,
            face,
        } => FaceJob::Wear {
            client,
            top_context_id,
            context_id,
            persona_did,
            application_id,
            face,
        },
        FaceWork::Card {
            context_id,
            vetter,
            application,
            session_id,
            preview_id,
        } => {
            let step = match preview_id {
                None => CardStep::Preview,
                Some(preview_id) => {
                    // A plan sends a card only after its key lookup
                    // (`Step::CardKeys`), and a failed lookup stops the run,
                    // so the keys are always held here.
                    let Some(CardKeys {
                        signer,
                        document_signer,
                    }) = keys
                    else {
                        debug_assert!(false, "a card sent without its keys");
                        return;
                    };
                    CardStep::Present(Box::new(Presenting {
                        preview_id,
                        signer,
                        document_signer,
                        resolver: resolver(ctx),
                        service: ctx.didcomm_service.clone(),
                        listener_id: openvtc_core::didcomm::listener_id_for_did(
                            &application.join_did,
                            ctx.config,
                        ),
                    }))
                }
            };
            let job = CardJob {
                client,
                context_id,
                vetter,
                application: *application,
                session_id,
                step,
            };
            return spawn(ctx, job, claim);
        }
    };
    spawn(ctx, job, claim);
}

/// The VTA context an application's face is worn in, its join DID, and
/// whether it was derived just now ([`AppContext`]). Pure: a derived context
/// is kept on the application by [`keep_context`], once the job that uses it
/// is going ahead, so the membership reuses it when the join goes through.
pub(super) fn application_context(
    config: &Config,
    application_id: &str,
) -> Result<AppContext, String> {
    let app = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .ok_or("the application is gone")?;
    let join_did = app.join_did.clone();
    if let Some(id) = &app.context_id {
        return Ok(AppContext {
            id: id.clone(),
            join_did,
            derived: false,
        });
    }
    // A persona whose keys live in a sub-context is presented from it;
    // otherwise the community gets a context of its own.
    let top = config.account.top_context_id.as_str();
    let id = match config
        .account
        .personas
        .get(&app.persona)
        .map(|p| community_context::persona_context(p, top))
        .filter(|home| community_context::is_sub_context(home, top))
    {
        Some(home) => home.to_string(),
        None => openvtc_core::join::sequence::suggested_context(config, &app.community.clone()),
    };
    Ok(AppContext {
        id,
        join_did,
        derived: true,
    })
}

/// What [`application_context`] found.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct AppContext {
    pub(super) id: String,
    pub(super) join_did: String,
    /// Not yet kept on the application.
    pub(super) derived: bool,
}

/// Keep a derived context on the application, and return the save it owes
/// ([`Step::MarkDirty`]); one already kept owes nothing.
pub(super) fn keep_context(
    config: &mut Config,
    application_id: &str,
    context: &AppContext,
) -> Option<Step> {
    if !context.derived {
        return None;
    }
    let app = config
        .private
        .vetting
        .application_by_id_mut(application_id)?;
    app.context_id = Some(context.id.clone());
    Some(Step::MarkDirty)
}

/// `effect` with the save a context kept just now owes, first.
fn saving_context(save: Option<Step>, effect: VettingEffect) -> VettingEffect {
    let VettingEffect(steps) = effect;
    VettingEffect(save.into_iter().chain(steps).collect())
}

/// Plan `f`: read the holder's faces for the application the page is on.
///
/// From a card, the card's application — not whichever row the list behind it
/// last had selected — and the card is where it returns.
pub(super) fn plan_choose_face(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    has_vta: bool,
) -> VettingEffect {
    let v = panel(state);
    let id = match &v.mode {
        VettingMode::SendCard {
            application_id,
            session_id,
            ..
        } => {
            v.card_after_face = Some((application_id.clone(), session_id.clone()));
            Some(application_id.clone())
        }
        // A retry after granting access keeps whichever card sent it.
        VettingMode::HolderGrant { .. } => v
            .card_after_face
            .as_ref()
            .map(|(application_id, _)| application_id.clone())
            .or_else(|| v.applications.get(v.selected).map(|row| row.id.clone())),
        _ => {
            v.card_after_face = None;
            v.applications.get(v.selected).map(|row| row.id.clone())
        }
    };
    match id {
        Some(id) => plan_list_faces(state, config, busy, has_vta, &id),
        None => VettingEffect::none(),
    }
}

/// Plan reading the holder's faces, and which one the application wears.
fn plan_list_faces(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    has_vta: bool,
    application_id: &str,
) -> VettingEffect {
    if !connected(state, has_vta) {
        return VettingEffect::none();
    }
    let context = match application_context(config, application_id) {
        Ok(found) => found,
        Err(e) => {
            show(state, Status::error(format!("Cannot choose a face: {e}")));
            return VettingEffect::none();
        }
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    let save = keep_context(config, application_id, &context);
    show(state, Status::progress("Reading your faces…"));
    saving_context(
        save,
        VettingEffect::face(FaceWork::List {
            context_id: context.id,
            persona_did: context.join_did,
            application_id: application_id.to_string(),
        }),
    )
}

/// Plan wearing `face` in the application's context.
pub(super) fn plan_wear_face(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    has_vta: bool,
    application_id: &str,
    face: Option<FaceChoice>,
) -> VettingEffect {
    let Some(face) = face else {
        show(
            state,
            Status::warning("Make a face under My Identity first."),
        );
        return VettingEffect::none();
    };
    if face.worn {
        let v = panel(state);
        v.mode = v
            .card_after_face
            .take()
            .map_or(VettingMode::List, card_mode);
        show(
            state,
            Status::warning(format!(
                "{} is already the face you show vetters.",
                face.name
            )),
        );
        return VettingEffect::none();
    }
    if !connected(state, has_vta) {
        return VettingEffect::none();
    }
    let context = match application_context(config, application_id) {
        Ok(found) => found,
        Err(e) => {
            show(state, Status::error(format!("Cannot wear that face: {e}")));
            return VettingEffect::none();
        }
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    let save = keep_context(config, application_id, &context);
    panel(state).mode = VettingMode::List;
    show(state, Status::progress(format!("Wearing {}…", face.name)));
    saving_context(
        save,
        VettingEffect::face(FaceWork::Wear {
            top_context_id: config.account.top_context_id.clone(),
            context_id: context.id,
            persona_did: context.join_did,
            application_id: application_id.to_string(),
            face,
        }),
    )
}

/// Plan the card for `session_id`, in two steps: preview what the face would
/// show the vetter, then — once the holder has seen it — look up the
/// persona's keys, and release, sign and send.
pub(super) fn plan_send_card(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    has_vta: bool,
    application_id: &str,
    session_id: &str,
    preview: Option<CardPreview>,
) -> VettingEffect {
    let Some(application) = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .cloned()
    else {
        return VettingEffect::none();
    };
    let Some((vetter, expires_at)) = application
        .session(session_id)
        .map(|(vetter, s)| (vetter.to_string(), s.expires_at))
    else {
        show(state, Status::warning("That session has closed."));
        return VettingEffect::none();
    };
    if expires_at <= Utc::now() {
        show(
            state,
            Status::warning("The session has expired — ask the vetter to open another."),
        );
        return VettingEffect::none();
    }
    if let Some(problem) = preview.as_ref().and_then(|p| p.problem.clone()) {
        show(state, Status::warning(problem));
        return VettingEffect::none();
    }
    if !connected(state, has_vta) {
        return VettingEffect::none();
    }
    let context = match application_context(config, application_id) {
        Ok(found) => found,
        Err(e) => {
            show(state, Status::error(format!("Cannot send a card: {e}")));
            return VettingEffect::none();
        }
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    let save = keep_context(config, application_id, &context);
    let context_id = context.id;
    let persona = application.persona;
    let card = |preview_id| Step::Face {
        work: Box::new(FaceWork::Card {
            context_id,
            vetter,
            application: Box::new(application),
            session_id: session_id.to_string(),
            preview_id,
        }),
        claim: Claim::Held,
    };
    match preview {
        None => {
            show(
                state,
                Status::progress("Asking your VTA what your face shows this vetter…"),
            );
            saving_context(save, VettingEffect(vec![card(None)]))
        }
        Some(preview) => {
            // A key lookup that fails takes back a context kept for this card,
            // and the save it owes follows the lookup.
            let undo = if save.is_some() {
                vec![Undo::NoContext(application_id.to_string())]
            } else {
                Vec::new()
            };
            let mut steps = vec![Step::CardKeys {
                persona,
                abort: Abort::undoing("Could not sign the card", undo),
            }];
            steps.extend(save);
            steps.push(Step::Status(Status::progress(
                "Releasing and signing your card…",
            )));
            steps.push(card(Some(preview.preview_id)));
            VettingEffect(steps)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::outcome::VettingOutcome;
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::NewFaceFocus;
    use crate::state_handler::main_page::content::{
        NewFaceForm, NewFaceStep, PoolRow, VettingMode,
    };
    use crate::state_handler::main_page::status::Severity;
    use crate::state_handler::save_coalesce::SaveScheduler;
    use crate::state_handler::state::State;
    use crate::state_handler::vetting_actions::dispatch::{cycle, input};
    use chrono::Utc;
    use openvtc_core::config::Config;
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::applicant::{Application, ChosenFace};

    fn held(id: &str, claim_type: &str, value: &str) -> PoolRow {
        PoolRow {
            attribute_id: id.into(),
            claim_type: claim_type.into(),
            label: claim_type.to_uppercase(),
            value: Some(value.into()),
        }
    }

    /// Open the make-a-face form over `pool`, as the pool read does.
    fn open_form(config: &mut Config, application_id: &str, pool: Vec<PoolRow>) -> State {
        let mut state = State::default();
        let mut save = SaveScheduler::new("test");
        VettingOutcome::Pool {
            application_id: application_id.into(),
            required: vec!["name.legal".into()],
            result: Ok(pool),
        }
        .apply(&mut state, config, &mut save);
        state
    }

    fn form_of(state: &mut State) -> &mut NewFaceForm {
        match &mut state.main_page.content_panel.vetting.mode {
            VettingMode::NewFace(form) => form,
            _ => panic!("the form did not open"),
        }
    }

    /// The whole point of making the face *here*: the community has already
    /// said what its card needs, so the holder should not have to work that out
    /// again from a list of attributes. What it did not ask for stays unticked:
    /// a face shows what it holds, and showing more is the holder's choice.
    #[test]
    fn the_new_face_form_opens_with_only_the_required_claims_ticked() {
        let mut config = test_config();
        let mut state = open_form(
            &mut config,
            "a",
            vec![
                held("attr-email", "email.work", "a@work.example"),
                held("attr-name", "name.legal", "Alice Example"),
            ],
        );
        let form = form_of(&mut state);
        assert_eq!(form.ticked, vec!["attr-name".to_string()]);
        assert!(form.still_missing().is_empty());
        assert_eq!(form.extras().len(), 1, "the email is offered, unticked");
        // Unticking it is said against the selection, not the pool, so the
        // status line changes at the moment the choice is made.
        form.focus = NewFaceFocus::Asked(0);
        form.toggle();
        assert_eq!(form.still_missing(), vec!["name.legal"]);
        assert!(
            form.status().contains("choose your legal name"),
            "{}",
            form.status()
        );
    }

    /// A requirement already held needs nothing from the holder: the name is
    /// filled in and the claim ticked, so the first Enter makes the face.
    #[test]
    fn a_held_requirement_makes_the_face_on_the_first_enter() {
        let mut config = test_config();
        let mut state = open_form(
            &mut config,
            "a",
            vec![held("attr-name", "name.legal", "Alice Example")],
        );
        let form = form_of(&mut state);
        assert!(form.ready(), "{}", form.status());
        assert_eq!(
            form.status(),
            "1 of 1 required attribute ready — Enter: make the face and wear it"
        );
        match form.enter() {
            NewFaceStep::Make { name, live_refs } => {
                assert_eq!(name, "Vetting");
                assert_eq!(live_refs, vec!["attr-name".to_string()]);
            }
            other => panic!("expected the face to be made, got {other:?}"),
        }
    }

    /// The case that stranded people: nothing in the pool. The form asks for
    /// the value on the row that needs it, Enter saves it as a real attribute
    /// under the right type key, and the saved attribute comes back ticked —
    /// one more Enter makes the face. The holder never types `name.legal`.
    #[test]
    fn with_no_attributes_the_value_is_typed_saved_and_ticked_in_place() {
        let mut config = test_config();
        let mut state = open_form(&mut config, "a", Vec::new());
        let mut save = SaveScheduler::new("test");
        {
            let form = form_of(&mut state);
            assert_eq!(
                form.focus,
                NewFaceFocus::Asked(0),
                "opens on what is needed"
            );
            assert!(form.needs_input("name.legal"));
            assert!(
                form.status().contains("type your legal name below"),
                "{}",
                form.status()
            );
            // Enter with nothing typed sends nothing, and adds no second voice.
            assert!(matches!(form.enter(), NewFaceStep::Wait));
            assert!(form.error.is_none());
        }
        // Typed through the page's own input path, spaces and all.
        input(
            &mut state.main_page.content_panel.vetting.mode,
            "Alice Example".into(),
        );
        let draft = match form_of(&mut state).enter() {
            NewFaceStep::Save(draft) => draft,
            other => panic!("expected a save, got {other:?}"),
        };
        assert_eq!(draft.claim_type, "name.legal");
        assert_eq!(draft.value, serde_json::json!("Alice Example"));
        assert!(draft.attribute_id.is_none(), "a create, not an update");
        assert!(
            form_of(&mut state)
                .status()
                .starts_with("Saving your legal name"),
            "{}",
            form_of(&mut state).status()
        );
        // A second Enter while the write is out sends nothing.
        assert!(matches!(form_of(&mut state).enter(), NewFaceStep::Wait));

        VettingOutcome::AttributeSaved {
            application_id: "a".into(),
            claim_type: "name.legal".into(),
            result: Ok(held("attr-new", "name.legal", "Alice Example")),
        }
        .apply(&mut state, &mut config, &mut save);

        assert!(
            state.main_page.content_panel.identity.refresh_queued,
            "My Identity re-reads the pool it no longer matches"
        );
        let form = form_of(&mut state);
        assert_eq!(form.ticked, vec!["attr-new".to_string()]);
        assert!(form.saving.is_none());
        assert!(form.draft("name.legal").is_empty());
        assert!(form.ready(), "{}", form.status());
        assert!(matches!(
            form.enter(),
            NewFaceStep::Make { live_refs, .. } if live_refs == vec!["attr-new".to_string()]
        ));
    }

    /// A save the agent refuses leaves the typed value where it was, with the
    /// reason beside it, and the form ready to try again.
    #[test]
    fn a_refused_save_keeps_the_value_and_says_why() {
        let mut config = test_config();
        let mut state = open_form(&mut config, "a", Vec::new());
        let mut save = SaveScheduler::new("test");
        input(
            &mut state.main_page.content_panel.vetting.mode,
            "Alice Example".into(),
        );
        assert!(matches!(form_of(&mut state).enter(), NewFaceStep::Save(_)));
        VettingOutcome::AttributeSaved {
            application_id: "a".into(),
            claim_type: "name.legal".into(),
            result: Err("persona attribute write failed: timed out".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        let form = form_of(&mut state);
        assert!(form.saving.is_none());
        assert_eq!(form.draft("name.legal"), "Alice Example");
        assert!(
            form.error
                .as_deref()
                .is_some_and(|e| e.contains("timed out")),
            "{:?}",
            form.error
        );
        assert!(matches!(form.enter(), NewFaceStep::Save(_)), "retryable");
    }

    /// Two legal names: one is pre-ticked, and ←/→ or Space swaps which —
    /// never both, and never neither.
    #[test]
    fn several_attributes_of_a_required_type_are_chosen_between() {
        let mut config = test_config();
        let mut state = open_form(
            &mut config,
            "a",
            vec![
                held("attr-1", "name.legal", "Alice Example"),
                held("attr-2", "name.legal", "Alice B. Example"),
            ],
        );
        let v = &mut state.main_page.content_panel.vetting;
        let VettingMode::NewFace(form) = &mut v.mode else {
            panic!("the form did not open");
        };
        assert_eq!(form.ticked, vec!["attr-1".to_string()]);
        form.focus = NewFaceFocus::Asked(0);
        cycle(v, true);
        let VettingMode::NewFace(form) = &mut v.mode else {
            unreachable!()
        };
        assert_eq!(form.ticked, vec!["attr-2".to_string()]);
        form.toggle();
        assert_eq!(form.ticked, vec!["attr-1".to_string()], "Space steps too");
        form.pick(false);
        assert_eq!(form.ticked, vec!["attr-2".to_string()]);
        assert!(form.ready());
    }

    /// The face's name is the community's agent name only once that name has
    /// been verified; with none verified it is a plain word, never a name read
    /// from the community's own document.
    #[test]
    fn the_face_is_named_after_the_community_only_by_a_verified_name() {
        let community = "did:webvh:QmScid:club.example";
        let mut config = test_config();
        let app = Application::new(community, PersonaId::new(), "did:key:zJoin", Utc::now())
            .expect("application");
        let id = app.id.clone();
        config.private.vetting.applications.push(app);

        let mut state = open_form(&mut config, &id, Vec::new());
        assert_eq!(form_of(&mut state).name, "Vetting");

        config.set_cached_agent_name(community, Some("club.example/@club".into()), Utc::now());
        let mut state = open_form(&mut config, &id, Vec::new());
        assert_eq!(form_of(&mut state).name, "club.example/@club");
    }

    /// The card preview's one explicable refusal. The agent's sentence names
    /// neither the claims, nor the face, nor the key that changes it — and it
    /// arrives three steps after the choice that caused it.
    #[test]
    fn the_preview_refusal_names_the_claims_and_the_key() {
        let mut config = test_config();
        let mut app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();
        app.face = Some(ChosenFace {
            profile_id: "p1".into(),
            name: "OSS Developer".into(),
        });
        let id = app.id.clone();
        config.private.vetting.applications.push(app);

        let out = preview_refusal(
            "VTA Error: persona disclosure preview failed: protocol error: trust task failed \
             [malformedRequest]: validation error: none of the requested claim types are present \
             in this persona's profile",
            &id,
            &config,
        );
        // The face it is actually wearing, so there is no doubt which to change.
        assert!(out.contains("OSS Developer"), "{out}");
        // And the key that changes it.
        assert!(out.contains("Press f"), "{out}");
        // The agent's framing does not survive into the sentence.
        assert!(!out.contains("malformedRequest"), "{out}");
    }

    /// No face worn at all: making an application does not choose one, so the
    /// first card of an application whose face was never picked meets this.
    /// The agent's sentence names a DID; this one names the key.
    #[test]
    fn a_card_with_no_face_worn_says_to_choose_one() {
        let out = preview_refusal(
            "VTA Error: persona disclosure preview failed: not found: not found: persona \
             did:webvh:QmS:dids-wonderland.ic3.dev:march-issue has no profile bound, so there \
             is nothing to disclose",
            "no-such-application",
            &test_config(),
        );
        assert!(out.contains("no face yet"), "{out}");
        assert!(out.contains("Press f"), "{out}");
        assert!(!out.contains("did:webvh"), "{out}");
    }

    /// Anything else is passed through. A failure we cannot explain is better
    /// verbatim than paraphrased into a guess (R6.4).
    #[test]
    fn other_preview_failures_are_reported_as_they_came() {
        let config = test_config();
        let out = preview_refusal("connection refused", "no-such-application", &config);
        assert_eq!(out, "Could not preview the card: connection refused");
    }

    // ---- the plans ----

    const VTC: &str = "did:web:vtc.example";

    /// A config holding one application to [`VTC`], and a page listing it,
    /// selected. Returns the application's id.
    fn planned_application(config: &mut Config, state: &mut State) -> String {
        let app = Application::new(VTC, PersonaId::new(), "did:key:zJoin", Utc::now())
            .expect("application");
        let id = app.id.clone();
        config.private.vetting.applications.push(app);
        state.main_page.sync_from_config(config);
        state.main_page.content_panel.vetting.selected = 0;
        id
    }

    /// Give the application `id` an open session `s1` with a vetter.
    fn open_session(config: &mut Config, id: &str) {
        use openvtc_core::vetting::applicant::{OpenSession, OutboundRequest};
        let app = config
            .private
            .vetting
            .application_by_id_mut(id)
            .expect("the application");
        app.requests.push(OutboundRequest {
            document_id: "req-1".into(),
            vetter: "did:key:zVetter".into(),
            state: RequestState::Session {
                request_id: "r-1".into(),
                session: Box::new(OpenSession {
                    id: "s1".into(),
                    challenge: "challenge".into(),
                    domain: VTC.into(),
                    method: vta_sdk::protocols::vetting::VettingMethod::Video,
                    required_claims: vec!["name.legal".into()],
                    optional_claims: Vec::new(),
                    expires_at: Utc::now() + chrono::Duration::hours(1),
                    match_code: "0000".into(),
                    document: None,
                }),
                card: None,
            },
            eligibility: None,
            grant_status: None,
            sent_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }

    fn said(state: &mut State) -> Status {
        panel(state)
            .status_message
            .clone()
            .expect("the page says something")
    }

    fn context_of(config: &Config, id: &str) -> Option<String> {
        config
            .private
            .vetting
            .application_by_id(id)
            .and_then(|a| a.context_id.clone())
    }

    /// With no VTA session the plan says so before anything else: no context
    /// is derived and no busy check is made.
    #[test]
    fn a_face_plan_with_no_session_says_so_first() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);

        let VettingEffect(steps) = plan_choose_face(&mut state, &mut config, true, false);

        assert!(steps.is_empty());
        assert_eq!(
            said(&mut state),
            Status::error(
                "Faces live in your VTA, and it is not connected — try again once it is."
            )
        );
        assert_eq!(context_of(&config, &id), None);
    }

    /// Busy: refused, and the context is not kept — nothing started that
    /// uses it.
    #[test]
    fn a_face_plan_on_a_busy_domain_is_refused_and_keeps_no_context() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);

        let VettingEffect(steps) = plan_choose_face(&mut state, &mut config, true, true);

        assert!(steps.is_empty());
        assert_eq!(said(&mut state).severity, Severity::Warning);
        assert!(context_of(&config, &id).is_none());
    }

    /// Free: the context derived is kept and saved, then one held face job,
    /// the progress said.
    #[test]
    fn choosing_a_face_plans_the_list_read() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);

        let VettingEffect(steps) = plan_choose_face(&mut state, &mut config, false, true);

        assert!(context_of(&config, &id).is_some());
        let [
            Step::MarkDirty,
            Step::Face {
                work,
                claim: Claim::Held,
            },
        ] = &steps[..]
        else {
            panic!("one held face job");
        };
        assert!(matches!(&**work, FaceWork::List { application_id, .. } if *application_id == id));
        assert_eq!(said(&mut state), Status::progress("Reading your faces…"));
    }

    /// From a card, the card is remembered to come back to.
    #[test]
    fn choosing_a_face_from_a_card_remembers_it() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);
        panel(&mut state).mode = VettingMode::SendCard {
            application_id: id.clone(),
            session_id: "s1".into(),
            preview: None,
        };

        let _ = plan_choose_face(&mut state, &mut config, false, false);

        assert_eq!(panel(&mut state).card_after_face, Some((id, "s1".into())));
    }

    /// The face already worn changes nothing at the VTA: back to the card.
    #[test]
    fn wearing_the_worn_face_plans_nothing() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);
        panel(&mut state).card_after_face = Some((id.clone(), "s1".into()));
        let face = FaceChoice {
            profile_id: "p".into(),
            name: "Work".into(),
            entries: 1,
            worn: true,
            claim_types: Vec::new(),
        };

        let VettingEffect(steps) =
            plan_wear_face(&mut state, &mut config, false, true, &id, Some(face));

        assert!(steps.is_empty());
        assert!(matches!(
            panel(&mut state).mode,
            VettingMode::SendCard { .. }
        ));
        assert_eq!(context_of(&config, &id), None);
    }

    /// A save refused as busy leaves the form open and not waiting.
    #[test]
    fn a_refused_save_leaves_the_form_not_saving() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);
        let mut form = NewFaceForm::open(
            id,
            vec!["name.legal".into()],
            Vec::new(),
            Vec::new(),
            "Vetting".into(),
        );
        panel(&mut state).mode = VettingMode::NewFace(Box::new(form.clone()));
        input(&mut panel(&mut state).mode, "Alice Example".into());
        if let VettingMode::NewFace(typed) = &panel(&mut state).mode {
            form = (**typed).clone();
        }

        let VettingEffect(steps) = plan_create_face(&mut state, &mut config, true, true, form);

        assert!(steps.is_empty());
        let VettingMode::NewFace(form) = &panel(&mut state).mode else {
            panic!("the form stays open");
        };
        assert!(form.saving.is_none());
        assert_eq!(form.draft("name.legal"), "Alice Example");
    }

    /// A preview is one held card job; sending one looks the keys up first,
    /// then says so, then spawns.
    #[test]
    fn a_card_is_previewed_then_sent_after_its_key_lookup() {
        let mut config = test_config();
        let mut state = State::default();
        let id = planned_application(&mut config, &mut state);
        open_session(&mut config, &id);

        let VettingEffect(steps) =
            plan_send_card(&mut state, &mut config, false, true, &id, "s1", None);
        let [
            Step::MarkDirty,
            Step::Face {
                work,
                claim: Claim::Held,
            },
        ] = &steps[..]
        else {
            panic!("one held card job");
        };
        assert!(matches!(
            &**work,
            FaceWork::Card {
                preview_id: None,
                ..
            }
        ));
        assert_eq!(
            said(&mut state),
            Status::progress("Asking your VTA what your face shows this vetter…")
        );

        let preview = CardPreview {
            preview_id: "01PREVIEW".into(),
            claims: Vec::new(),
            problem: None,
        };
        let VettingEffect(steps) = plan_send_card(
            &mut state,
            &mut config,
            false,
            true,
            &id,
            "s1",
            Some(preview),
        );
        let [
            Step::CardKeys { abort, .. },
            Step::Status(progress),
            Step::Face {
                work,
                claim: Claim::Held,
            },
        ] = &steps[..]
        else {
            panic!("keys, then the status, then the card");
        };
        assert_eq!(abort, &Abort::say("Could not sign the card"));
        assert_eq!(
            progress,
            &Status::progress("Releasing and signing your card…")
        );
        assert!(matches!(
            &**work,
            FaceWork::Card { preview_id: Some(p), .. } if p == "01PREVIEW"
        ));
    }
}
