//! Verifying a hidden-vetting submission from PUBLIC data only, and turning it into the facts
//! VTI already counts (design §2).
//!
//! This half holds no secret: the helper key it uses is `hvk`, the token key is `tvk`, and both
//! are published in the manifest. The VTC service runs it beside its own state; so does the
//! applicant's client when it wants to know what the VTC will make of what it holds.
//!
//! **MIRRORED FILE.** Kept in step with `vti-vetting-pcs/src/verifier.rs` on the VTI `zkp-pcs`
//! branch. The VTC service is the one that matters; this copy is what the client checks against.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, NaiveTime, Utc};
use predicate_credential_system::{
    kiprf::verify_tag, pcs::PredicateCredentialSystem, sigma::FSProof,
};
use serde::Serialize;
use vta_sdk::{
    protocols::vetting::{VettingMethod, VettingRelationship, VettingRequirements},
    vetting::requirements::{Evaluation, StatementFacts, evaluate},
};

use crate::{
    ProtoError,
    meta::{ProofContext, StatementMeta, id_binding},
    scheme::{
        Base, E, Fr, G1, Helper, Hvk, Open, deployment_label, hidden_vetting_predicate, point_text,
        scalar_text, vetter_predicate,
    },
    token::{SpendOutcome, TokenSpend, TokenVerifier},
};
use predicate_credential_system::pcs::{IssuanceProof, SetupParams};

/// The hidden-vetting part of a join submission (`extensions.hiddenVetting`, design §8).
#[derive(Debug, Clone)]
pub struct Submission {
    pub id: G1,
    pub join_did: String,
    /// The binding of `id` to the join persona (§4.2), as the applicant computed it. The
    /// verifier recomputes it and compares; it never takes the applicant's word for it.
    pub id_binding: String,
    pub challenge: String,
    /// One per attestation in `proof`, in the same order.
    pub statements: Vec<(StatementMeta, TokenSpend)>,
    pub proof: IssuanceProof<E, Base>,
}

/// One row of `VettingFacts.statements`, as the VTC builds it today, with `issuer` = the tag.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementRecord {
    pub id: String,
    pub issuer: String,
    pub verified: bool,
    pub eligible: bool,
    pub revoked: bool,
    pub method: VettingMethod,
    pub declared_relationship: VettingRelationship,
    pub counted: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub evaluation: Evaluation,
    pub statements: Vec<StatementRecord>,
}

/// What the verifier keeps per statement of an application.
#[derive(Debug, Clone)]
pub(crate) struct Kept {
    pub facts: StatementFacts,
    pub tag: String,
    pub method: VettingMethod,
    pub relationship: VettingRelationship,
    pub failures: Vec<String>,
}

/// The published parameters a verifier needs, i.e. what a community's manifest carries.
pub struct VerifierParams {
    pub community: String,
    pub audience: String,
    pub requirements: VettingRequirements,
    pub requirements_digest: String,
}

pub struct Verifier {
    pub params: VerifierParams,
    open: Open,
    helper: Helper,
    hvk: Hvk,
    pub tokens: TokenVerifier,
    live_periods: Vec<String>,
    withdrawn: HashSet<(String, String)>,
    applications: HashMap<String, BTreeMap<String, Kept>>,
}

impl Verifier {
    /// From public parameters: the helper key, the token verifier, and the live vetter periods
    /// (current first).
    pub fn new(
        params: VerifierParams,
        hvk: Hvk,
        tokens: TokenVerifier,
        live_periods: Vec<String>,
    ) -> Result<Self, ProtoError> {
        let open = Open::setup(SetupParams::new(deployment_label(&params.community)))?;
        let helper = Self::helper_for(&open, &live_periods)?;
        Ok(Self {
            params,
            open,
            helper,
            hvk,
            tokens,
            live_periods,
            withdrawn: HashSet::new(),
            applications: HashMap::new(),
        })
    }

    /// The helper runs with an AllowList of the live vetter labels, never with `P ≡ 1`
    /// (`docs/operating-a-helper.md`).
    pub(crate) fn helper_for(open: &Open, periods: &[String]) -> Result<Helper, ProtoError> {
        let predicates: Vec<_> = periods.iter().map(|p| vetter_predicate(p)).collect();
        let policy = open.allow_list(predicates.iter())?;
        Ok(Helper::from_public_parameters(
            open.public_parameters().clone(),
            policy,
        )?)
    }

    pub fn open(&self) -> &Open {
        &self.open
    }
    pub fn hvk(&self) -> &Hvk {
        &self.hvk
    }
    pub fn live_periods(&self) -> &[String] {
        &self.live_periods
    }
    pub fn current_period(&self) -> &str {
        &self.live_periods[0]
    }

    /// Rotation and emergency drops both land here: the AllowList is rebuilt from the periods
    /// that are live now.
    pub fn set_live_periods(&mut self, periods: Vec<String>) -> Result<(), ProtoError> {
        self.helper = Self::helper_for(&self.open, &periods)?;
        self.live_periods = periods;
        Ok(())
    }

    /// `φ` of every live vetter label: what a client checks an attestation's class against.
    pub fn live_vetter_phis(&self) -> Result<Vec<Fr>, ProtoError> {
        self.live_periods
            .iter()
            .map(|p| Ok(self.open.enc_pred(&vetter_predicate(p))?))
            .collect()
    }

    /// Verify a submission, spend its tokens, and count. Records are kept per applicant `id`,
    /// so a resubmission after `requestMore` adds to what was already counted.
    ///
    /// The caller has already checked that the challenge is one it issued and unused.
    pub fn submit(&mut self, sub: &Submission, now: DateTime<Utc>) -> Result<Decision, ProtoError> {
        let n = sub.proof.attestations.len();
        if sub.statements.len() != n {
            return Err(ProtoError::CountMismatch {
                statements: sub.statements.len(),
                attestations: n,
            });
        }
        let id_text = point_text(&sub.id)?;
        let binding = id_binding(
            &id_text,
            &self.params.community,
            &self.params.requirements_digest,
            &sub.join_did,
        );
        if sub.id_binding != binding {
            return Err(ProtoError::AttestationRejected(
                "the identifier binding does not match this community and join DID".into(),
            ));
        }
        let app0 = ProofContext {
            challenge: sub.challenge.clone(),
            audience: self.params.audience.clone(),
            join_did: sub.join_did.clone(),
            id_binding: binding,
        }
        .context_bytes()?;
        let apps: Vec<Vec<u8>> = sub
            .statements
            .iter()
            .map(|(m, _)| m.context_bytes())
            .collect::<Result<_, _>>()?;
        let app_refs: Vec<&[u8]> = apps.iter().map(Vec::as_slice).collect();
        let f = hidden_vetting_predicate(u32::try_from(n).unwrap_or(u32::MAX));
        self.helper
            .check_proof_in_context(&self.hvk, &f, &sub.id, &sub.proof, &app_refs, &app0)
            .map_err(ProtoError::ProofRejected)?;

        // The proof holds: every attestation is from a holder of a live vetter label, the tags
        // are pairwise distinct, and each is bound to its metadata (its token serial included).
        for ((meta, spend), att) in sub.statements.iter().zip(&sub.proof.attestations) {
            let tag = point_text(&att.tag)?;
            let mut failures = Vec::new();
            let mut eligible = true;
            if meta.token_label != spend.label || meta.token_serial != scalar_text(&spend.serial)? {
                failures.push("token-mismatch".to_string());
                eligible = false;
            } else if !self.tokens.signature_ok(spend)? {
                failures.push("no-token".to_string());
                eligible = false;
            } else if self.tokens.record_spend(spend, &id_text, &tag)? == SpendOutcome::DoubleSpend
            {
                failures.push("token-double-spend".to_string());
                eligible = false;
            }
            if meta.requirements_digest != self.params.requirements_digest {
                failures.push("requirements-digest-mismatch".to_string());
                eligible = false;
            }
            if now.date_naive() > meta.valid_until {
                failures.push("expired".to_string());
                eligible = false;
            }
            let facts = StatementFacts {
                statement_id: meta.digest()?,
                vetter: tag.clone(),
                method: meta.method,
                claims_verified: meta.claims_verified.clone(),
                document_classes: Vec::new(),
                declared_relationship: meta.declared_relationship,
                identity_commitment: meta.identity_commitment.clone(),
                valid_from: DateTime::from_naive_utc_and_offset(
                    meta.valid_from.and_time(NaiveTime::MIN),
                    Utc,
                ),
                community_matches: meta.community == self.params.community,
                eligible,
                revoked: false,
            };
            self.applications
                .entry(id_text.clone())
                .or_default()
                .insert(
                    facts.statement_id.clone(),
                    Kept {
                        facts,
                        tag,
                        method: meta.method,
                        relationship: meta.declared_relationship,
                        failures,
                    },
                );
        }
        Ok(self.evaluate(&id_text, now))
    }

    /// Count an application as it stands now (withdrawals included).
    pub fn evaluate(&self, id_text: &str, now: DateTime<Utc>) -> Decision {
        let kept: Vec<Kept> = self
            .applications
            .get(id_text)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let facts: Vec<StatementFacts> = kept
            .iter()
            .map(|k| {
                let mut f = k.facts.clone();
                f.revoked = self
                    .withdrawn
                    .contains(&(id_text.to_string(), k.tag.clone()));
                f
            })
            .collect();
        let evaluation = evaluate(&self.params.requirements, &facts, now);
        let statements = kept
            .iter()
            .zip(&facts)
            .map(|(k, f)| {
                let mut failures = k.failures.clone();
                if let Some((_, reasons)) = evaluation
                    .not_counted
                    .iter()
                    .find(|(id, _)| *id == f.statement_id)
                {
                    failures.extend(reasons.iter().map(|r| r.code().to_string()));
                }
                failures.dedup();
                StatementRecord {
                    id: f.statement_id.clone(),
                    issuer: k.tag.clone(),
                    verified: true,
                    eligible: f.eligible,
                    revoked: f.revoked,
                    method: k.method,
                    declared_relationship: k.relationship,
                    counted: evaluation.counted.contains(&f.statement_id),
                    failures,
                }
            })
            .collect();
        Decision {
            evaluation,
            statements,
        }
    }

    /// Withdrawal of one statement by its tag (§4.4). The proof shows knowledge of the key
    /// behind the tag and nothing else, so the notice may come from a fresh sender (§13 C6).
    pub fn withdraw(&mut self, id: &G1, tag: &G1, proof: &FSProof<Fr>) -> Result<bool, ProtoError> {
        let s = self.open.tag_point(id)?;
        let ctx = withdraw_context(&self.params.community, &point_text(id)?);
        if !verify_tag(self.open.tag(), tag, &s, &ctx, proof) {
            return Ok(false);
        }
        self.withdrawn.insert((point_text(id)?, point_text(tag)?));
        Ok(true)
    }
}

pub fn withdraw_context(community: &str, id_text: &str) -> Vec<u8> {
    let mut ctx = b"openvtc/hidden-vetting/withdraw/0.1\0".to_vec();
    for part in [community, id_text] {
        ctx.extend((part.len() as u64).to_le_bytes());
        ctx.extend(part.as_bytes());
    }
    ctx
}
