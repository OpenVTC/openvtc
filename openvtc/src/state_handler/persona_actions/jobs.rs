//! The background work the pane spawns: [`PersonaJob`] round-trips, the read of
//! every agent-served tab, and the re-reads that follow a write.

use crate::state_handler::main_page::content::AgentError;
use openvtc_core::persona::{
    binding, claim_types, contacts, correlation, disclosure, lifecycle,
    pool::{self, AttributeDraft},
    profile, world,
};
use vta_sdk::client::VtaClient;

use super::outcome::PersonaOutcome;
use crate::state_handler::persona_binding_refresh::{self, BindingTarget};
use crate::state_handler::state::State;

/// Re-read the faces made in a community after a write of one.
async fn local_faces_after_write(client: &VtaClient, context_id: String) -> PersonaOutcome {
    PersonaOutcome::LocalFacesRead {
        result: lifecycle::local_faces(client, &context_id)
            .await
            .map_err(|e| format!("{e}")),
        context_id,
    }
}

/// Re-read a community's contacts after a write of one.
///
/// The listing is the write's real answer: a put files a new revision, and
/// which one is current — and whether anything it superseded is still held —
/// is what the list says rather than what the caller assumed.
async fn people_after_write(client: &VtaClient, context_id: String) -> PersonaOutcome {
    PersonaOutcome::PeopleRead {
        result: contacts::list(client, &context_id)
            .await
            .map_err(|e| format!("{e}")),
        context_id,
    }
}

/// A single persona round-trip.
pub(crate) enum PersonaJob {
    AttributePut(AttributeDraft),
    /// Forget every version of one attribute but the current one. One-way.
    AttributePurge {
        attribute_id: String,
    },
    AttributeDelete {
        attribute_id: String,
        cascade: bool,
    },
    /// Fetch one attribute's value on its own (`s` on a sensitive row), so the
    /// bulk listing never has to carry every sensitive value into memory. The
    /// result is spliced into the in-memory row and the mask lifted.
    /// Read one attribute's value, for the mask the holder lifted.
    ///
    /// It carried the claim type too, because the read was a prefix listing
    /// filtered by id. `persona/attribute/get` takes the id alone.
    AttributeReveal {
        attribute_id: String,
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
        /// Carried for the question a `Worn` refusal asks again.
        name: String,
        unbind: bool,
    },
    ProfileRetire {
        profile_id: String,
    },
    /// Read the formats the agent can produce.
    RenderersRead,
    /// Read the contacts filed in one community.
    PeopleRead {
        context_id: String,
    },
    /// Read one contact in full, with what they said before.
    ContactRead {
        context_id: String,
        contact_id: String,
    },
    /// Record what someone told the holder.
    ContactPut {
        context_id: String,
        subject_did: String,
        known_by_persona: String,
        facts: Vec<openvtc_core::persona::contacts::ContactFact>,
        notes: Option<String>,
    },
    /// Forget a contact and every revision of it.
    ContactDelete {
        context_id: String,
        contact_id: String,
    },
    /// Read every persona with a binding record in one community.
    KnownHereRead {
        context_id: String,
    },
    /// Read the faces made inside one community.
    LocalFacesRead {
        context_id: String,
    },
    /// Make or replace a face that lives inside one community.
    LocalFacePut {
        context_id: String,
        name: String,
        values: Vec<lifecycle::ComposeValue>,
    },
    /// Delete a face made inside one community.
    LocalFaceDelete {
        context_id: String,
        profile_id: String,
    },
    /// Wear a face made here, as the persona used here.
    LocalFaceWear {
        context_id: String,
        persona_did: String,
        profile_id: String,
    },
    /// Make chosen values of a face made here reusable. One-way.
    Promote {
        context_id: String,
        profile_id: String,
        positions: Vec<u64>,
        expected_version: u64,
    },
    /// Make a face for one community and wear it there.
    Compose {
        context_id: String,
        persona_did: String,
        community: String,
        name: String,
        values: Vec<lifecycle::ComposeValue>,
    },
    ProfileReinstate {
        profile_id: String,
    },
    /// How far a face has spoken, for the delete prompt.
    ProfileSpoken {
        profile_id: String,
    },
    /// Where the opened face is worn and what it has done.
    FaceHistoryRead {
        profile_id: String,
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
    /// Create or replace one world.
    WorldPut(world::WorldDraft),
    WorldDelete {
        world_id: String,
        expected_version: Option<u64>,
    },
    /// Move one face into a world, or out of every world.
    ///
    /// Carries the world list it was decided against, because placing is two
    /// conditional writes and both need the versions that were on screen when
    /// the holder chose. A job that re-read first would be deciding against a
    /// list nobody looked at.
    FacePlace {
        worlds: Vec<world::World>,
        profile_id: String,
        into: Option<String>,
    },
    /// Decide what one persona presents in one context.
    Bind {
        context_id: String,
        persona_did: String,
        profile_id: Option<String>,
        community: String,
    },
}

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

impl crate::state_handler::background_dispatch::Job for PersonaReadJob {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::PersonaManage
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::PersonaManage(self.run().await)
    }
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
        // The bulk listing never carries sensitive values (card numbers, ids):
        // `include_sensitive: false`. A `sensitivity: high` attribute comes back
        // valueless and the pane renders "sensitive — press s"; the per-attribute
        // reveal (`s`) fetches that one value on its own via `pool::reveal`.
        let attributes = pool::list(&self.admin_vta, self.include_values, false)
            .await
            .map_err(AgentError::of);
        let profiles = profile::list(&self.admin_vta).await.map_err(AgentError::of);
        let retired = lifecycle::list_retired(&self.admin_vta)
            .await
            .map_err(AgentError::of);
        let worlds = world::list(&self.admin_vta).await.map_err(AgentError::of);
        let links = correlation::analyze(&self.admin_vta)
            .await
            .map_err(AgentError::of);
        let disclosures = match std::num::NonZeroU64::new(DISCLOSURE_PAGE) {
            Some(limit) => disclosure::history(&self.admin_vta, limit)
                .await
                .map_err(AgentError::of),
            None => Ok(Vec::new()),
        };
        let claim_types = match self.needs_claim_types {
            true => Some(
                claim_types::Registry::fetch(&self.admin_vta)
                    .await
                    .map(Box::new)
                    .map_err(AgentError::of),
            ),
            false => None,
        };
        let bindings = persona_binding_refresh::resolve_batch(self.admin_vta, self.targets).await;
        PersonaOutcome::Read {
            attributes,
            profiles,
            retired,
            worlds,
            links,
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

impl crate::state_handler::background_dispatch::Job for PersonaJobRun {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::PersonaManage
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::PersonaManage(self.run().await)
    }
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
            PersonaJob::AttributePurge { attribute_id } => {
                match pool::purge_versions(&client, &attribute_id, None).await {
                    Ok(purged) => PersonaOutcome::Deleted {
                        message: format!(
                            "Forgot {} earlier version{}.{}",
                            purged.versions.len(),
                            if purged.versions.len() == 1 { "" } else { "s" },
                            match purged.stale_pins {
                                0 => String::new(),
                                n => format!(
                                    " {n} face{} pinned one of them and now shows nothing for it \
                                     until you edit {}.",
                                    if n == 1 { "" } else { "s" },
                                    if n == 1 { "it" } else { "them" },
                                ),
                            }
                        ),
                    },
                    Err(e) => PersonaOutcome::Written {
                        verb: "Forgot the earlier versions",
                        error: Some(format!("{e}")),
                    },
                }
            }
            PersonaJob::AttributeReveal { attribute_id } => PersonaOutcome::AttributeRevealed {
                attribute_id: attribute_id.clone(),
                result: pool::reveal(&client, &attribute_id)
                    .await
                    .map_err(|e| format!("{e}")),
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
            PersonaJob::ProfileDelete {
                profile_id,
                name,
                unbind,
            } => match profile::delete(&client, &profile_id, unbind).await {
                Ok(profile::Deleted::Done) => PersonaOutcome::Written {
                    verb: "Deleted the face",
                    error: None,
                },
                Ok(profile::Deleted::Worn(worn)) => PersonaOutcome::ProfileWorn {
                    profile_id,
                    name,
                    worn,
                },
                Err(e) => PersonaOutcome::Written {
                    verb: "Deleted the face",
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::ProfileGet { profile_id, edit } => PersonaOutcome::ProfileRead {
                edit,
                result: profile::get(&client, &profile_id, !edit)
                    .await
                    .map_err(|e| format!("{e}")),
            },
            PersonaJob::ProfileRetire { profile_id } => {
                match lifecycle::retire(&client, &profile_id).await {
                    Ok(0) => PersonaOutcome::Deleted {
                        message:
                            "Retired the face. It was worn nowhere; it is kept, and z shows it."
                                .to_string(),
                    },
                    Ok(n) => PersonaOutcome::Deleted {
                        message: format!(
                            "Retired the face — taken off {n} communit{} and kept. z shows retired \
                         faces; x there reinstates.",
                            if n == 1 { "y" } else { "ies" }
                        ),
                    },
                    Err(e) => PersonaOutcome::Written {
                        verb: "Retired the face",
                        error: Some(format!("{e}")),
                    },
                }
            }
            PersonaJob::RenderersRead => PersonaOutcome::RenderersRead {
                result: disclosure::renderers(&client)
                    .await
                    .map_err(|e| format!("{e}")),
            },
            PersonaJob::PeopleRead { context_id } => PersonaOutcome::PeopleRead {
                result: contacts::list(&client, &context_id)
                    .await
                    .map_err(|e| format!("{e}")),
                context_id,
            },
            PersonaJob::ContactRead {
                context_id,
                contact_id,
            } => PersonaOutcome::ContactRead {
                result: contacts::get(&client, &context_id, &contact_id, true)
                    .await
                    .map_err(|e| format!("{e}")),
                context_id,
            },
            PersonaJob::ContactPut {
                context_id,
                subject_did,
                known_by_persona,
                facts,
                notes,
            } => match contacts::put(
                &client,
                &context_id,
                &subject_did,
                &known_by_persona,
                facts,
                notes.as_deref(),
            )
            .await
            {
                // The write's own answer is the listing after it: a put is a
                // new revision, and which of them is current is what the list
                // says rather than what the caller assumed.
                Ok(_) => people_after_write(&client, context_id).await,
                Err(e) => PersonaOutcome::ContactWritten {
                    context_id,
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::ContactDelete {
                context_id,
                contact_id,
            } => match contacts::delete(&client, &context_id, &contact_id).await {
                Ok(()) => people_after_write(&client, context_id).await,
                Err(e) => PersonaOutcome::ContactWritten {
                    context_id,
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::KnownHereRead { context_id } => PersonaOutcome::KnownHereRead {
                result: binding::list(&client, &context_id)
                    .await
                    .map_err(|e| format!("{e}")),
                context_id,
            },
            PersonaJob::LocalFacePut {
                context_id,
                name,
                values,
            } => match lifecycle::local_face_put(&client, &context_id, &name, values, None, None)
                .await
            {
                Ok(_) => local_faces_after_write(&client, context_id).await,
                Err(e) => PersonaOutcome::Written {
                    verb: "Made the face",
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::LocalFaceDelete {
                context_id,
                profile_id,
            } => {
                // `unbind` is deliberate: the holder answered a question that
                // said the face is taken off as it goes, and refusing here
                // would leave them with a delete that only works sometimes.
                match lifecycle::local_face_delete(&client, &context_id, &profile_id, true).await {
                    Ok(()) => local_faces_after_write(&client, context_id).await,
                    Err(e) => PersonaOutcome::Written {
                        verb: "Deleted the face",
                        error: Some(format!("{e}")),
                    },
                }
            }
            PersonaJob::LocalFaceWear {
                context_id,
                persona_did,
                profile_id,
            } => match binding::set_local(&client, &context_id, &persona_did, Some(&profile_id))
                .await
            {
                Ok(()) => local_faces_after_write(&client, context_id).await,
                Err(e) => PersonaOutcome::Written {
                    verb: "Put the face on",
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::LocalFacesRead { context_id } => PersonaOutcome::LocalFacesRead {
                result: lifecycle::local_faces(&client, &context_id)
                    .await
                    .map_err(|e| format!("{e}")),
                context_id,
            },
            PersonaJob::Promote {
                context_id,
                profile_id,
                positions,
                expected_version,
            } => match lifecycle::promote(
                &client,
                &context_id,
                &profile_id,
                &positions,
                expected_version,
            )
            .await
            {
                Ok(done) => PersonaOutcome::Deleted {
                    message: format!(
                        "Made reusable. The face is in your pool now, with the same persona{} \
                         wearing it.{}",
                        if done.rebound == 1 { "" } else { "s" },
                        if done.reused > 0 {
                            " A value was already kept, so it now shares that fact with \
                             whatever else shows it."
                        } else {
                            ""
                        }
                    ),
                },
                Err(e) => PersonaOutcome::Written {
                    verb: "Made the values reusable",
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::Compose {
                context_id,
                persona_did,
                community,
                name,
                values,
            } => match lifecycle::compose(&client, &context_id, &name, &persona_did, &values).await
            {
                Ok(made) => PersonaOutcome::Deleted {
                    message: format!(
                        "Made \"{name}\" and wore it in {community}. {}{}",
                        if made.local {
                            "It lives there alone — nothing you typed is in your other faces."
                        } else {
                            "It is in your pool, so it can be worn elsewhere too."
                        },
                        if made.reused > 0 {
                            format!(
                                " {} value{} already kept, so this face shares a fact with \
                                 whatever else shows it.",
                                made.reused,
                                if made.reused == 1 { " was" } else { "s were" }
                            )
                        } else {
                            String::new()
                        }
                    ),
                },
                Err(e) => PersonaOutcome::Written {
                    verb: "Made the face",
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::ProfileReinstate { profile_id } => PersonaOutcome::Written {
                verb: "Reinstated the face — wearable again, and worn nowhere until you wear it",
                error: lifecycle::reinstate(&client, &profile_id)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::ProfileSpoken { profile_id } => {
                let untell = profile::get(&client, &profile_id, false)
                    .await
                    .ok()
                    .and_then(|d| lifecycle::untell_words(d.disclosed_to));
                PersonaOutcome::Spoken { profile_id, untell }
            }
            PersonaJob::FaceHistoryRead { profile_id } => PersonaOutcome::FaceHistoryRead {
                result: lifecycle::history(&client, &profile_id)
                    .await
                    .map_err(|e| format!("{e}")),
                profile_id,
            },
            PersonaJob::WorldPut(draft) => PersonaOutcome::Written {
                verb: match draft.world_id.is_some() {
                    true => "Saved the world",
                    false => "Made the world",
                },
                error: world::put(&client, draft)
                    .await
                    .err()
                    .map(|e| format!("{e}")),
            },
            PersonaJob::WorldDelete {
                world_id,
                expected_version,
            } => match world::delete(&client, &world_id, expected_version).await {
                // The count finishes the sentence honestly. "Deleted the world"
                // on its own reads to almost everyone as though the faces in it
                // went too, and they did not: a world arranges, it does not
                // contain.
                Ok(deletion) if deletion.released_faces > 0 => PersonaOutcome::Deleted {
                    message: format!(
                        "Deleted the world. {} face{} kept — {} belong{} to no world now.",
                        deletion.released_faces,
                        if deletion.released_faces == 1 {
                            ""
                        } else {
                            "s"
                        },
                        if deletion.released_faces == 1 {
                            "it"
                        } else {
                            "they"
                        },
                        if deletion.released_faces == 1 {
                            "s"
                        } else {
                            ""
                        },
                    ),
                },
                Ok(_) => PersonaOutcome::Deleted {
                    message: "Deleted the world. Nothing else changed.".to_string(),
                },
                Err(e) => PersonaOutcome::Written {
                    verb: "Deleted the world",
                    error: Some(format!("{e}")),
                },
            },
            PersonaJob::FacePlace {
                worlds,
                profile_id,
                into,
            } => PersonaOutcome::Written {
                verb: match into.is_some() {
                    true => "Moved the face",
                    false => "Took the face out of its world",
                },
                error: world::place_face(&client, &worlds, &profile_id, into.as_deref())
                    .await
                    .err()
                    .map(|e| format!("{e}")),
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
