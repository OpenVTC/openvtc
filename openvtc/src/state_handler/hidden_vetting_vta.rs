//! Hidden-vetting work at the VTA, run off the loop.
//!
//! The person's VTA holds every PCS key and runs every engine operation
//! (`openvtc_core::vetting::pcs_vta`). Each call is a Trust Task round trip, and proving or
//! attesting can take the better part of a minute, so none of them runs on the loop: the loop
//! gathers what is owed into a [`PcsJob`], the job runs here in its own dispatch domain
//! ([`DispatchDomain::HiddenVetting`](super::background_dispatch::DispatchDomain::HiddenVetting)),
//! and its [`PcsOutcome`] comes back to the loop
//! (`vetting_actions::apply_pcs_outcome`), which records what the VTA said and sends the
//! community whatever the VTA built.

use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::book::{HiddenAttestJob, PcsInbound};
use openvtc_core::vetting::hidden::{Due, HiddenParams};
use openvtc_core::vetting::pcs_vta::{self, ApplicationView, PcsError, VetterView};
use openvtc_core::vetting::wire::pcs::{RootRequest, TokensRequest};
use vta_sdk::client::VtaClient;

/// One thing to ask the VTA.
#[derive(Debug, Clone)]
pub(crate) enum PcsWork {
    /// What it holds for a vetter's engine now (`vta/pcs/vetter/show`).
    VetterShow {
        community: String,
        persona: PersonaId,
        context_id: String,
    },
    /// Build what a vetter's schedule owes: an enrolment request or a draw.
    Owed {
        community: String,
        persona: PersonaId,
        context_id: String,
        /// The persona's DID: the member DID the engine is bound to.
        did: String,
        params: HiddenParams,
        owed: Due,
    },
    /// Hand it an answer a community or a vetter sent ([`PcsInbound`]), with what the call
    /// needs that the answer does not carry.
    Inbound {
        item: PcsInbound,
        /// The vetter engine's context, for a community's answer to a vetter.
        context_id: Option<String>,
        /// The parameters the engine runs under.
        params: Option<HiddenParams>,
        /// The VTA's handle for the application an attestation is for.
        vta_application: Option<String>,
    },
    /// Create an application's engine (`vta/pcs/applications/create`).
    Create {
        /// Our application's id.
        application: String,
        context_id: String,
        community: String,
        join_did: String,
        params: HiddenParams,
    },
    /// Attest for a request, after the human check (`vta/pcs/attest`).
    Attest {
        job: HiddenAttestJob,
        context_id: String,
        vetter_did: String,
        session_id: String,
    },
}

/// What the VTA answered for one [`PcsWork`].
#[derive(Debug)]
pub(crate) enum PcsDone {
    /// `VetterShow`: the engine, or `None` before the first enrolment created one.
    Viewed(Option<VetterView>),
    /// `Owed` enrolment: the request to send the community.
    Root(RootRequest),
    /// `Owed` draw: the request to send the community.
    Tokens(TokensRequest),
    /// `Inbound` enrolment answer taken in.
    Enrolled(VetterView),
    /// `Inbound` served draw taken in: how many tokens it added.
    Drawn(u64, VetterView),
    /// `Inbound` refused draw forgotten (`None`: the VTA held no such draw).
    Abandoned(Option<VetterView>),
    /// `Inbound` attestation verified and kept.
    Verified(ApplicationView),
    /// `Inbound` application deleted.
    Deleted,
    /// `Create`: the application.
    Created(ApplicationView),
    /// `Attest`: the `vetting/attestation/0.1` payload to send the applicant.
    Attested(serde_json::Value),
}

/// What one job did.
pub(crate) struct PcsOutcome {
    /// How many of the inbox's leading entries the job carried — the loop removes those it
    /// finished with, and keeps the rest for the next job.
    pub inbox_taken: usize,
    /// Each piece of work, with the VTA's answer.
    pub results: Vec<(PcsWork, Result<PcsDone, PcsError>)>,
}

/// One job's work: done in order, each whatever became of the one before. A VTA that cannot be
/// reached for one is not asked for the rest — they are owed again, unchanged, next time.
pub(crate) struct PcsJob {
    pub client: VtaClient,
    pub inbox_taken: usize,
    pub work: Vec<PcsWork>,
}

impl PcsJob {
    pub(crate) async fn run(self) -> PcsOutcome {
        let mut results = Vec::with_capacity(self.work.len());
        let mut unreachable: Option<PcsError> = None;
        for work in self.work {
            let result = match &unreachable {
                Some(e) => Err(e.clone()),
                None => work.run(&self.client).await,
            };
            if let Err(e @ PcsError::Unreachable(_)) = &result {
                unreachable.get_or_insert_with(|| e.clone());
            }
            results.push((work, result));
        }
        PcsOutcome {
            inbox_taken: self.inbox_taken,
            results,
        }
    }
}

impl PcsWork {
    async fn run(&self, client: &VtaClient) -> Result<PcsDone, PcsError> {
        match self {
            PcsWork::VetterShow {
                community,
                context_id,
                ..
            } => pcs_vta::vetter_show(client, context_id, community)
                .await
                .map(PcsDone::Viewed),
            PcsWork::Owed {
                community,
                context_id,
                did,
                params,
                owed,
                ..
            } => match owed {
                Due::Nothing => Ok(PcsDone::Viewed(None)),
                Due::Enrol { period } => pcs_vta::root_request(
                    client,
                    context_id,
                    community,
                    did,
                    params,
                    &format!("vetter/{period}"),
                )
                .await
                .map(PcsDone::Root),
                Due::Draw { label, tick, rate } => pcs_vta::tokens_request(
                    client, context_id, community, params, label, *tick, *rate,
                )
                .await
                .map(PcsDone::Tokens),
            },
            PcsWork::Inbound {
                item,
                context_id,
                params,
                vta_application,
            } => {
                let missing = |what: &str| {
                    PcsError::Unreadable(format!("nothing to take it in with: {what}"))
                };
                match item {
                    PcsInbound::Enrolled {
                        community, answer, ..
                    } => {
                        let context_id = context_id.as_deref().ok_or_else(|| missing("context"))?;
                        let params = params.as_ref().ok_or_else(|| missing("parameters"))?;
                        pcs_vta::root_accept(client, context_id, community, params, answer)
                            .await
                            .map(PcsDone::Enrolled)
                    }
                    PcsInbound::TokensServed {
                        community, answer, ..
                    } => {
                        let context_id = context_id.as_deref().ok_or_else(|| missing("context"))?;
                        let params = params.as_ref().ok_or_else(|| missing("parameters"))?;
                        pcs_vta::tokens_accept(client, context_id, community, params, answer)
                            .await
                            .map(|(n, view)| PcsDone::Drawn(n, view))
                    }
                    PcsInbound::DrawRefused {
                        community,
                        label,
                        tick,
                        ..
                    } => {
                        let context_id = context_id.as_deref().ok_or_else(|| missing("context"))?;
                        pcs_vta::tokens_abandon(client, context_id, community, label, *tick)
                            .await
                            .map(PcsDone::Abandoned)
                    }
                    PcsInbound::Attestation { attestation, .. } => {
                        let application = vta_application
                            .as_deref()
                            .ok_or_else(|| missing("the application at the VTA"))?;
                        let params = params.as_ref().ok_or_else(|| missing("parameters"))?;
                        pcs_vta::verify_attestation(client, application, params, attestation)
                            .await
                            .map(PcsDone::Verified)
                    }
                    PcsInbound::DeleteApplication { application_id } => {
                        pcs_vta::delete_application(client, application_id)
                            .await
                            .map(|()| PcsDone::Deleted)
                    }
                }
            }
            PcsWork::Create {
                context_id,
                community,
                join_did,
                params,
                ..
            } => pcs_vta::create_application(client, context_id, community, join_did, params)
                .await
                .map(PcsDone::Created),
            PcsWork::Attest {
                job, context_id, ..
            } => pcs_vta::attest(
                client,
                context_id,
                &job.community,
                &job.params,
                &job.applicant_id,
                job.meta.clone(),
                None,
            )
            .await
            .map(PcsDone::Attested),
        }
    }
}
