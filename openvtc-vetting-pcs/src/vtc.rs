//! The VTC as PCS *helper*: issues vetter credentials and tokens, verifies proofs, and hands
//! VTI's counting rule the same `StatementFacts` it gets today, with the vetter's tag where the
//! vetter's DID used to be (design §2).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Mutex,
};

use chrono::{DateTime, NaiveTime, Utc};
use predicate_credential_system::{
    kiprf::verify_tag,
    pcs::{HelperSecretKey, IssuanceProof, PredicateCredentialSystem, RootRequest, SetupParams},
    sigma::FSProof,
};
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use vta_sdk::{
    protocols::vetting::{VettingMethod, VettingRelationship, VettingRequirements},
    vetting::requirements::{Evaluation, StatementFacts, evaluate},
};

use crate::{
    ProtoError,
    meta::{ProofContext, StatementMeta, id_binding},
    scheme::{
        Base, E, Fr, G1, Helper, Open, deployment_label, event_token_label,
        hidden_vetting_predicate, monthly_token_label, point_text, scalar_text, vetter_predicate,
    },
    token::{SpendOutcome, TokenIssuer, TokenSpend},
};

type Hvk = <Base as predicate_credential_system::cred::CredentialBase>::VerificationKey;

/// The join submission's hidden-vetting part (`submit/0.3 vettingProof`, design §8).
#[derive(Debug, Clone)]
pub struct Submission {
    pub id: G1,
    pub join_did: String,
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

/// What the VTC keeps per statement of an application: the facts it counted and its own
/// failure codes, keyed by the statement's metadata digest.
#[derive(Debug, Clone)]
struct Kept {
    facts: StatementFacts,
    tag: String,
    method: VettingMethod,
    relationship: VettingRelationship,
    failures: Vec<String>,
}

pub struct Vtc {
    pub community: String,
    audience: String,
    open: Open,
    helper: Helper,
    hvk: Hvk,
    hsk: HelperSecretKey<Base>,
    /// One lock per signing key (§13 C3).
    hsk_lock: Mutex<()>,
    /// Live vetter periods, current first.
    live_periods: Vec<String>,
    grants: HashSet<String>,
    /// member → PCS id, bound at first root issuance (§13 C2).
    bound_ids: HashMap<String, String>,
    issued: HashSet<(String, String)>,
    pub tokens: TokenIssuer,
    current_token_label: String,
    events: HashMap<String, HashSet<String>>,
    withdrawn: HashSet<(String, String)>,
    applications: HashMap<String, BTreeMap<String, Kept>>,
    challenges: HashSet<String>,
    requirements: VettingRequirements,
    requirements_digest: String,
}

impl Vtc {
    pub fn new<R: RngCore + CryptoRng>(
        community: &str,
        period: &str,
        requirements: serde_json::Value,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let open = Open::setup(SetupParams::new(deployment_label(community)))?;
        // hvk is long-lived: generated once, bound to the fixed pp.
        let (hvk, hsk) = open.helper_keygen(rng);
        let helper = Self::helper_for(&open, &[period.to_string()])?;
        let requirements_digest =
            vta_sdk::vetting::requirements::requirements_digest(&requirements)
                .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let requirements: VettingRequirements = serde_json::from_value(requirements)
            .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let mut tokens = TokenIssuer::new(community, rng)?;
        let current_token_label = monthly_token_label(period);
        tokens.open_label(&current_token_label);
        Ok(Self {
            community: community.to_string(),
            audience: community.to_string(),
            open,
            helper,
            hvk,
            hsk,
            hsk_lock: Mutex::new(()),
            live_periods: vec![period.to_string()],
            grants: HashSet::new(),
            bound_ids: HashMap::new(),
            issued: HashSet::new(),
            tokens,
            current_token_label,
            events: HashMap::new(),
            withdrawn: HashSet::new(),
            applications: HashMap::new(),
            challenges: HashSet::new(),
            requirements,
            requirements_digest,
        })
    }

    /// The helper runs with an AllowList of the live vetter labels, never with `P ≡ 1`.
    fn helper_for(open: &Open, periods: &[String]) -> Result<Helper, ProtoError> {
        let predicates: Vec<_> = periods.iter().map(|p| vetter_predicate(p)).collect();
        let policy = open.allow_list(predicates.iter())?;
        Ok(Helper::from_public_parameters(
            open.public_parameters().clone(),
            policy,
        )?)
    }

    // --- public parameters, as the manifest's `vetting.anonymity` would carry them ----------

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
    pub fn current_token_label(&self) -> &str {
        &self.current_token_label
    }
    pub fn requirements_digest(&self) -> &str {
        &self.requirements_digest
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    /// `φ` of every live vetter label: what a client checks an attestation's class against.
    pub fn live_vetter_phis(&self) -> Result<Vec<Fr>, ProtoError> {
        self.live_periods
            .iter()
            .map(|p| Ok(self.open.enc_pred(&vetter_predicate(p))?))
            .collect()
    }

    // --- vetters ----------------------------------------------------------------------------

    pub fn grant(&mut self, member: &str) {
        self.grants.insert(member.to_string());
    }

    /// Removal: the member gets no credential under any later label. Their credential under a
    /// live label still works until that label leaves the window, or until
    /// [`Self::drop_period`] (emergency).
    pub fn revoke(&mut self, member: &str) {
        self.grants.remove(member);
    }

    /// Root issuance under the CURRENT label, behind the grant check (§3, §13 C1–C3).
    pub fn issue_vetter_root<R: RngCore + CryptoRng>(
        &mut self,
        member: &str,
        id: &G1,
        request: &RootRequest<E, Base>,
        rng: &mut R,
    ) -> Result<
        <Base as predicate_credential_system::cred::CredentialBase>::PreCredential,
        ProtoError,
    > {
        if !self.grants.contains(member) {
            return Err(ProtoError::NotAVetter(member.to_string()));
        }
        let period = self.current_period().to_string();
        let id_text = point_text(id)?;
        match self.bound_ids.get(member) {
            Some(bound) if *bound != id_text => {
                return Err(ProtoError::IdentifierRebound(member.to_string()));
            }
            _ => {}
        }
        if self.issued.contains(&(member.to_string(), period.clone())) {
            return Err(ProtoError::AlreadyIssued {
                member: member.to_string(),
                label: format!("vetter/{period}"),
            });
        }
        let pre = {
            let _guard = self.hsk_lock.lock().expect("helper signing lock");
            self.helper.issue_root(
                &self.hvk,
                &self.hsk,
                &vetter_predicate(&period),
                id,
                request,
                rng,
            )?
        };
        self.bound_ids.insert(member.to_string(), id_text);
        self.issued.insert((member.to_string(), period));
        Ok(pre)
    }

    /// Epoch rotation: the new period becomes current, the previous one stays live, anything
    /// older leaves the AllowList. Same for the monthly token labels.
    pub fn rotate(&mut self, new_period: &str) -> Result<(), ProtoError> {
        let previous = self.current_period().to_string();
        self.live_periods = vec![new_period.to_string(), previous.clone()];
        self.helper = Self::helper_for(&self.open, &self.live_periods)?;
        let old_labels: Vec<String> = self
            .tokens
            .live_labels()
            .iter()
            .filter(|l| !l.starts_with("token/event/") && **l != monthly_token_label(&previous))
            .cloned()
            .collect();
        for l in old_labels {
            self.tokens.close_label(&l);
        }
        self.current_token_label = monthly_token_label(new_period);
        self.tokens.open_label(&self.current_token_label);
        Ok(())
    }

    /// Emergency: a period leaves the AllowList now, e.g. to make a removal immediate.
    pub fn drop_period(&mut self, period: &str) -> Result<(), ProtoError> {
        self.live_periods.retain(|p| p != period);
        self.helper = Self::helper_for(&self.open, &self.live_periods)?;
        Ok(())
    }

    // --- tokens -----------------------------------------------------------------------------

    /// One tick of the drip for `member` under `label` (monthly or event).
    pub fn drip<R: RngCore + CryptoRng>(
        &mut self,
        member: &str,
        tick: u32,
        label: &str,
        requests: &[crate::token::TokenRequest],
        rng: &mut R,
    ) -> Result<Vec<predicate_credential_system::cred::ps::PSPreCredential<E>>, ProtoError> {
        if !self.grants.contains(member) {
            return Err(ProtoError::NotAVetter(member.to_string()));
        }
        if let Some(event) = label.strip_prefix("token/event/")
            && !self.events.get(event).is_some_and(|g| g.contains(member))
        {
            return Err(ProtoError::EventRefused(format!(
                "{member} is not in event {event}"
            )));
        }
        self.tokens.issue(member, tick, label, requests, rng)
    }

    /// Event mode (§5.1): approved by someone outside the group, for a group of at least
    /// `floor` vetters who all hold live grants.
    pub fn approve_event(
        &mut self,
        event_id: &str,
        members: &[&str],
        approver: &str,
        floor: usize,
    ) -> Result<String, ProtoError> {
        if members.contains(&approver) {
            return Err(ProtoError::EventRefused(
                "a vetter cannot approve their own event mode".into(),
            ));
        }
        let group: HashSet<String> = members.iter().map(|m| (*m).to_string()).collect();
        if group.len() < floor {
            return Err(ProtoError::EventRefused(format!(
                "group of {} is below the floor of {floor}",
                group.len()
            )));
        }
        if let Some(m) = group.iter().find(|m| !self.grants.contains(*m)) {
            return Err(ProtoError::NotAVetter(m.clone()));
        }
        self.events.insert(event_id.to_string(), group);
        let label = event_token_label(event_id);
        self.tokens.open_label(&label);
        Ok(label)
    }

    /// The event's grace period is over: its tokens die.
    pub fn close_event(&mut self, event_id: &str) {
        self.tokens.close_label(&event_token_label(event_id));
        self.events.remove(event_id);
    }

    // --- admission --------------------------------------------------------------------------

    pub fn challenge<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> String {
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        let c: String = b.iter().map(|x| format!("{x:02x}")).collect();
        self.challenges.insert(c.clone());
        c
    }

    /// Verify a submission, spend its tokens, and count. Records are kept per applicant `id`,
    /// so a resubmission after `requestMore` adds to what was already counted.
    pub fn submit(&mut self, sub: &Submission, now: DateTime<Utc>) -> Result<Decision, ProtoError> {
        if !self.challenges.remove(&sub.challenge) {
            return Err(ProtoError::BadChallenge);
        }
        let n = sub.proof.attestations.len();
        if sub.statements.len() != n {
            return Err(ProtoError::CountMismatch {
                statements: sub.statements.len(),
                attestations: n,
            });
        }
        let id_text = point_text(&sub.id)?;
        let app0 = ProofContext {
            challenge: sub.challenge.clone(),
            audience: self.audience.clone(),
            join_did: sub.join_did.clone(),
            id_binding: id_binding(
                &id_text,
                &self.community,
                &self.requirements_digest,
                &sub.join_did,
            ),
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
        // are pairwise distinct, and each is bound to its metadata (including its token serial).
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
            if meta.requirements_digest != self.requirements_digest {
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
                community_matches: meta.community == self.community,
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
        let evaluation = evaluate(&self.requirements, &facts, now);
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
    /// behind the tag and nothing else; the notice may come from a fresh sender (§13 C6).
    pub fn withdraw(&mut self, id: &G1, tag: &G1, proof: &FSProof<Fr>) -> Result<bool, ProtoError> {
        let s = self.open.tag_point(id)?;
        let ctx = withdraw_context(&self.community, &point_text(id)?);
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
