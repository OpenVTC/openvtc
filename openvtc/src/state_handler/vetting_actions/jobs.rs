//! The background jobs the page spawns: plain sends, face work at the VTA,
//! and the vetting card exchange.

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context;
use openvtc_core::config::context_path::parse_sub_context_id;
use openvtc_core::didcomm::Messaging;
use openvtc_core::persona::claim_types::Registry;
use openvtc_core::persona::disclosure::{self, PresentError};
use openvtc_core::persona::pool::PoolAttribute;
use openvtc_core::persona::{binding, pool, profile};
use openvtc_core::vetting::applicant::Application;
use openvtc_core::vetting::queries::QueryKind;
use openvtc_core::vetting::registry::VetterProfileRecord;
use openvtc_core::vetting::vetter::DeskState;
use openvtc_core::vetting::wire;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::vetting::VETTING_SESSION_RESPONSE_TYPE;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;

use super::faces::{VETTING_PURPOSE, pool_row};
use super::outcome::VettingOutcome;
use super::words::claim_text;
use crate::state_handler::main_page::content::{CardPreview, FaceChoice};
use crate::state_handler::main_page::sanitize_display;

// ============================================================================
// The background send
// ============================================================================

/// What was sent, and what undoing it takes if the send fails.
pub(crate) enum Sent {
    Manifest {
        community: String,
    },
    Request {
        application_id: String,
        document_id: String,
        vetter: String,
    },
    Session {
        request_id: String,
    },
    Statement {
        request_id: String,
        statement_id: String,
        previous: DeskState,
    },
    /// A hidden attestation, which has no statement id because it names nobody.
    Attestation {
        request_id: String,
        previous: DeskState,
    },
    Decline {
        request_id: String,
        previous: DeskState,
    },
    Withdrawal {
        statement_id: String,
    },
    /// A question to a community: its directory, or a resend of our grant.
    Query {
        document_id: String,
        community: String,
        kind: QueryKind,
    },
    /// Our vetter profile, and the record it replaced, for undoing.
    Profile {
        document_id: String,
        community: String,
        persona: PersonaId,
        previous: Option<Box<VetterProfileRecord>>,
    },
}

/// One vetting send. I/O only.
pub(crate) struct SendJob {
    pub(super) service: Messaging,
    pub(super) listener_id: String,
    pub(super) to: String,
    pub(super) message: Box<Message>,
    pub(super) sent: Sent,
}

impl crate::state_handler::background_dispatch::Job for SendJob {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::Vetting
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::Vetting(self.run().await)
    }
}

impl SendJob {
    pub(crate) async fn run(self) -> VettingOutcome {
        let result = openvtc_core::didcomm::send_message_via(
            &self.service,
            &self.message,
            &self.listener_id,
            &self.to,
        )
        .await;
        VettingOutcome::Sent {
            sent: Box::new(self.sent),
            error: result.err().map(|e| e.to_string()),
        }
    }
}

/// Reading or wearing a face. I/O only.
pub(crate) enum FaceJob {
    List {
        client: VtaClient,
        context_id: String,
        persona_did: String,
        application_id: String,
    },
    /// Read the pool so the make-a-face form has something to tick.
    Pool {
        client: VtaClient,
        application_id: String,
        required: Vec<String>,
        /// The agent's claim-type table, so a value is masked here exactly as
        /// the Identity page masks it.
        registry: Registry,
    },
    /// Save a value typed on the make-a-face form as a new attribute.
    AddAttribute {
        client: VtaClient,
        application_id: String,
        draft: openvtc_core::persona::pool::AttributeDraft,
        registry: Registry,
    },
    /// Create a face and wear it, in one step.
    Create {
        client: VtaClient,
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        name: String,
        live_refs: Vec<String>,
    },
    Wear {
        client: VtaClient,
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        face: FaceChoice,
    },
}

/// Fill in what each face would disclose, as claim types.
///
/// **Metadata only.** A profile's entries are attribute *ids*, so the claim
/// types come from one pool listing read without values (`include_values:
/// false`) and joined against them. Resolving each profile instead would
/// decrypt the whole pool to answer a question about names, which is the
/// reason `profile::list` does not do it either.
///
/// Every failure degrades to an empty list rather than failing the picker: a
/// face whose contents could not be read is still a face the holder may want to
/// wear, and the list already treats a failed binding read the same way. The
/// reads are sequential because a holder has a handful of faces, and each
/// carries the client's own timeout (R1.2).
async fn fill_claim_types(client: &VtaClient, faces: &mut [FaceChoice]) {
    let Ok(pool) = pool::list(client, false, false).await else {
        return;
    };
    let claim_of: std::collections::HashMap<&str, &str> = pool
        .iter()
        .map(|a| (a.attribute_id.as_str(), a.claim_type.as_str()))
        .collect();
    for face in faces.iter_mut() {
        let Ok(detail) = profile::get(client, &face.profile_id, false).await else {
            continue;
        };
        let mut seen = std::collections::HashSet::new();
        face.claim_types = detail
            .live_refs
            .iter()
            .filter_map(|id| claim_of.get(id.as_str()).map(|t| (*t).to_string()))
            // Two attributes of the same type — a work and a personal email —
            // are one claim type on the card. `dedup` would only catch them
            // when they happened to sit next to each other.
            .filter(|t| seen.insert(t.clone()))
            .collect();
    }
}

impl crate::state_handler::background_dispatch::Job for FaceJob {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::Vetting
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::Vetting(self.run().await)
    }
}

impl FaceJob {
    pub(crate) async fn run(self) -> VettingOutcome {
        match self {
            FaceJob::List {
                client,
                context_id,
                persona_did,
                application_id,
            } => {
                let result = match profile::list(&client).await {
                    Ok(profiles) => {
                        // What is worn now is a nicety for the picker; a failed
                        // read leaves nothing marked rather than failing the list.
                        let worn = binding::get(&client, &context_id, &persona_did)
                            .await
                            .ok()
                            .filter(|b| b.bound)
                            .and_then(|b| b.profile_id);
                        let mut faces: Vec<FaceChoice> = profiles
                            .into_iter()
                            .map(|p| FaceChoice {
                                worn: worn.as_deref() == Some(p.profile_id.as_str()),
                                name: sanitize_display(p.display_name(), 128),
                                entries: p.entry_count,
                                profile_id: p.profile_id,
                                claim_types: Vec::new(),
                            })
                            .collect();
                        fill_claim_types(&client, &mut faces).await;
                        Ok(faces)
                    }
                    Err(e) => Err(e.to_string()),
                };
                VettingOutcome::Faces {
                    application_id,
                    result,
                }
            }
            FaceJob::Pool {
                client,
                application_id,
                required,
                registry,
            } => {
                // Values, but not sensitive ones. The holder is choosing which
                // of their values a vetter will read, and the value is the
                // check they can make — two attributes both labelled
                // `name.legal` are told apart by what they say. A
                // `sensitivity: high` value stays in the agent
                // (`include_sensitive: false`), as on the Identity page's own
                // listing, and a masked type is painted masked.
                let result = pool::list(&client, true, false)
                    .await
                    .map(|attributes| {
                        attributes
                            .iter()
                            .map(|a| pool_row(a, &registry))
                            .collect::<Vec<_>>()
                    })
                    .map_err(|e| e.to_string());
                VettingOutcome::Pool {
                    application_id,
                    required,
                    result,
                }
            }
            FaceJob::AddAttribute {
                client,
                application_id,
                draft,
                registry,
            } => {
                let claim_type = draft.claim_type.clone();
                let written = PoolAttribute {
                    claim_type: draft.claim_type.clone(),
                    label: draft.label.clone(),
                    value: Some(draft.value.clone()),
                    ..PoolAttribute::default()
                };
                let result = match pool::put(&client, draft).await {
                    Ok(pool::AttributeEdit::Written(attribute_id)) => Ok(pool_row(
                        &PoolAttribute {
                            attribute_id,
                            ..written
                        },
                        &registry,
                    )),
                    Ok(pool::AttributeEdit::Refused(why)) => Err(why.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                VettingOutcome::AttributeSaved {
                    application_id,
                    claim_type,
                    result,
                }
            }
            FaceJob::Create {
                client,
                top_context_id,
                context_id,
                persona_did,
                application_id,
                name,
                live_refs,
            } => {
                // `other_entries` is empty because this creates: there is no
                // profile whose pinned or inline entries could be dropped. The
                // general editor has to carry them; here there is nothing yet
                // to carry.
                let created = profile::put(&client, None, &name, &live_refs, &[], None).await;
                let (profile_id, error) = match created {
                    Ok(id) => (id, None),
                    Err(e) => (String::new(), Some(e.to_string())),
                };
                // Wearing it is the point, so a face created but left unworn
                // would put the holder back on the picker to do what they had
                // just asked for. A failure to wear is still reported against
                // the face that now exists.
                let error = match error {
                    Some(e) => Some(e),
                    None => {
                        let slug = parse_sub_context_id(&context_id)
                            .map_or(context_id.as_str(), |(_, slug)| slug);
                        match community_context::ensure_context(
                            &client,
                            &top_context_id,
                            &context_id,
                            slug,
                        )
                        .await
                        {
                            Err(e) => Some(e.to_string()),
                            Ok(_) => {
                                binding::set(&client, &context_id, &persona_did, Some(&profile_id))
                                    .await
                                    .err()
                                    .map(|e| e.to_string())
                            }
                        }
                    }
                };
                VettingOutcome::FaceWorn {
                    error,
                    application_id,
                    profile_id,
                    name,
                }
            }
            FaceJob::Wear {
                client,
                top_context_id,
                context_id,
                persona_did,
                application_id,
                face,
            } => {
                // The context exists before a face is worn in it.
                let slug =
                    parse_sub_context_id(&context_id).map_or(context_id.as_str(), |(_, slug)| slug);
                let error = match community_context::ensure_context(
                    &client,
                    &top_context_id,
                    &context_id,
                    slug,
                )
                .await
                {
                    Err(e) => Some(e.to_string()),
                    Ok(_) => {
                        binding::set(&client, &context_id, &persona_did, Some(&face.profile_id))
                            .await
                            .err()
                            .map(|e| e.to_string())
                    }
                };
                VettingOutcome::FaceWorn {
                    error,
                    application_id,
                    profile_id: face.profile_id,
                    name: face.name,
                }
            }
        }
    }
}

/// Which half of the card's two steps a job runs.
pub(crate) enum CardStep {
    /// Ask what the face would show. Nothing leaves.
    Preview,
    /// Release what the preview showed, then sign, check and send the card.
    Present(Box<Presenting>),
}

/// What releasing and sending a card needs.
pub(crate) struct Presenting {
    pub(super) preview_id: String,
    /// assertionMethod key — signs the card (a credential).
    pub(super) signer: Secret,
    /// authentication key — signs the document that carries it.
    pub(super) document_signer: Secret,
    pub(super) resolver: TrustTaskVmResolver,
    pub(super) service: Messaging,
    pub(super) listener_id: String,
}

/// One step of sending a card. Works on a copy of the application; the
/// outcome carries back what the book has to record.
pub(crate) struct CardJob {
    pub(super) client: VtaClient,
    pub(super) context_id: String,
    pub(super) vetter: String,
    pub(super) application: Application,
    pub(super) session_id: String,
    pub(super) step: CardStep,
}

/// Why a card did not go.
pub(crate) enum CardFailure {
    /// The VTA wants a fresh approval; the preview is still good.
    StepUp,
    Failed(String),
}

fn failed(e: impl std::fmt::Display) -> CardFailure {
    CardFailure::Failed(e.to_string())
}

impl crate::state_handler::background_dispatch::Job for CardJob {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::Vetting
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::Vetting(self.run().await)
    }
}

impl CardJob {
    pub(crate) async fn run(self) -> VettingOutcome {
        let CardJob {
            client,
            context_id,
            vetter,
            mut application,
            session_id,
            step,
        } = self;
        let application_id = application.id.clone();
        match step {
            CardStep::Preview => {
                let requested = application.requested_claims(&session_id);
                let result = disclosure::preview(
                    &client,
                    &context_id,
                    &application.join_did,
                    &vetter,
                    requested,
                    VETTING_PURPOSE,
                )
                .await
                .map(|preview| CardPreview {
                    problem: application
                        .card_claims(&session_id, &preview.claims)
                        .err()
                        .map(|e| e.to_string()),
                    claims: preview
                        .claims
                        .iter()
                        .map(|c| {
                            (
                                sanitize_display(&c.claim_type, 64),
                                match &c.value {
                                    Some(value) => sanitize_display(&claim_text(value), 256),
                                    None => "(proved without its value)".to_string(),
                                },
                            )
                        })
                        .collect(),
                    preview_id: preview.preview_id,
                })
                .map_err(|e| e.to_string());
                VettingOutcome::Previewed {
                    application_id,
                    session_id,
                    result,
                }
            }
            CardStep::Present(presenting) => {
                let Presenting {
                    preview_id,
                    signer,
                    document_signer,
                    resolver,
                    service,
                    listener_id,
                } = *presenting;
                let result = async {
                    let challenge = application
                        .session(&session_id)
                        .map(|(_, s)| s.challenge.clone())
                        .ok_or_else(|| failed("the session has closed"))?;
                    let presented =
                        disclosure::present(&client, &context_id, &preview_id, Some(&challenge))
                            .await
                            .map_err(|e| match e {
                                PresentError::StepUpRequired => CardFailure::StepUp,
                                PresentError::Failed(message) => CardFailure::Failed(message),
                            })?;
                    let now = Utc::now();
                    let claims = application
                        .card_claims(&session_id, &presented.claims)
                        .map_err(failed)?;
                    let draft = application
                        .card_draft(&session_id, claims.clone(), now)
                        .map_err(failed)?;
                    let card = sign_card(draft, &signer).await.map_err(failed)?;
                    let sent = application
                        .record_card(&session_id, &card, &resolver, now)
                        .await
                        .map_err(|e| failed(format!("the card did not verify: {e}")))?;
                    // The card travels as it was signed. Parsing it into the
                    // published response and writing it back out is not
                    // guaranteed to be the same bytes, and its digest is what
                    // the vetter's statement names.
                    let mut document = wire::document(
                        VETTING_SESSION_RESPONSE_TYPE,
                        &application.join_did,
                        &vetter,
                        wire::new_id(),
                        &serde_json::json!({ "card": card }),
                    )
                    .map_err(failed)?;
                    document.thread_id = Some(session_id.clone());
                    wire::sign(&mut document, &document_signer)
                        .await
                        .map_err(failed)?;
                    let message = wire::to_message(&document).map_err(failed)?;
                    openvtc_core::didcomm::send_message_via(
                        &service,
                        &message,
                        &listener_id,
                        &vetter,
                    )
                    .await
                    .map_err(failed)?;
                    Ok((sent, claims))
                }
                .await;
                VettingOutcome::CardSent {
                    application_id,
                    session_id,
                    result,
                }
            }
        }
    }
}
