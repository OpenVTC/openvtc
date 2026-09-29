//! The community side: the PCS *helper*. It owns what the [`Verifier`] does not — the helper
//! secret key, who holds a vetter grant, the member→id bindings, the token signing key and
//! event mode — and delegates every check on a submission to the verifier.
//!
//! In production this is `vtc-service` (VTI). The copy here is what the client tests against
//! and what the VTI branch mirrors.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use predicate_credential_system::{cred::CredentialBase, pcs::RootRequest, sigma::FSProof};
use rand::{CryptoRng, RngCore};
use vta_sdk::protocols::vetting::VettingRequirements;

use crate::{
    ProtoError,
    issuer::Issuer,
    scheme::{Base, E, Fr, G1, Hvk, Open, event_token_label, monthly_token_label, point_text},
    token::{TokenRequest, TokenVerifier},
    verifier::{Verifier, VerifierParams},
};

pub use crate::verifier::{Decision, StatementRecord, Submission, withdraw_context};

/// Three a tick unless the community says otherwise — the same default `vtc-service` carries.
pub const DEFAULT_DRIP_PER_TICK: usize = 3;

/// An event label's rate. Event mode exists because a vetter at a conference meets twenty
/// people in a day, and the ordinary drip would make them turn people away (§5.1); the point of
/// the separate label is that the higher rate ends with the event.
pub const DEFAULT_EVENT_DRIP_PER_TICK: usize = 20;

pub struct Vtc {
    pub community: String,
    /// Everything a submission is checked against: public parameters only.
    pub verifier: Verifier,
    /// The keys, and the signing they do. The same type `vtc-service` mints with, so what this
    /// object does in a test is what the service does in a deployment; the bookkeeping around
    /// it differs (in memory here, in a keyspace there) and nothing else.
    issuer: Issuer,
    /// The published drip rate: the most this community signs for one vetter in one tick.
    drip_rate: usize,
    /// The rate under an event label, which is the reason event labels exist.
    event_drip_rate: usize,
    grants: HashSet<String>,
    /// member → PCS id, bound at first root issuance (§13 C2).
    bound_ids: HashMap<String, String>,
    issued: HashSet<(String, String)>,
    current_token_label: String,
    events: HashMap<String, HashSet<String>>,
    challenges: HashSet<String>,
}

impl Vtc {
    pub fn new<R: RngCore + CryptoRng>(
        community: &str,
        period: &str,
        requirements: serde_json::Value,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let issuer = Issuer::generate(community, rng)?;
        let requirements_digest =
            vta_sdk::vetting::requirements::requirements_digest(&requirements)
                .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let requirements: VettingRequirements = serde_json::from_value(requirements)
            .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let mut token_verifier = TokenVerifier::new(community, issuer.tvk().clone(), [])?;
        let current_token_label = monthly_token_label(period);
        token_verifier.open_label(&current_token_label);
        let verifier = Verifier::new(
            VerifierParams {
                community: community.to_string(),
                audience: community.to_string(),
                requirements,
                requirements_digest,
            },
            issuer.hvk().clone(),
            token_verifier,
            vec![period.to_string()],
        )?;
        Ok(Self {
            community: community.to_string(),
            verifier,
            issuer,
            drip_rate: DEFAULT_DRIP_PER_TICK,
            event_drip_rate: DEFAULT_EVENT_DRIP_PER_TICK,
            grants: HashSet::new(),
            bound_ids: HashMap::new(),
            issued: HashSet::new(),
            current_token_label,
            events: HashMap::new(),
            challenges: HashSet::new(),
        })
    }

    /// Set this community's drip rate. Published, and enforced on every tick.
    #[must_use]
    pub fn with_drip_rate(mut self, tokens_per_tick: usize) -> Self {
        self.drip_rate = tokens_per_tick;
        self
    }

    pub fn drip_rate(&self) -> usize {
        self.drip_rate
    }

    /// Set the rate an event label drips at.
    #[must_use]
    pub fn with_event_drip_rate(mut self, tokens_per_tick: usize) -> Self {
        self.event_drip_rate = tokens_per_tick;
        self
    }

    pub fn event_drip_rate(&self) -> usize {
        self.event_drip_rate
    }

    /// The rate that applies to `label`: the event rate for an event label, the ordinary drip
    /// otherwise.
    pub fn quota_for(&self, label: &str) -> usize {
        if label.starts_with("token/event/") {
            self.event_drip_rate
        } else {
            self.drip_rate
        }
    }

    // --- public parameters, as the manifest's `vetting.anonymity` carries them --------------

    pub fn open(&self) -> &Open {
        self.verifier.open()
    }
    pub fn hvk(&self) -> &Hvk {
        self.issuer.hvk()
    }
    pub fn tvk(&self) -> &<Base as CredentialBase>::VerificationKey {
        self.verifier.tokens.tvk()
    }
    pub fn live_periods(&self) -> &[String] {
        self.verifier.live_periods()
    }
    pub fn current_period(&self) -> &str {
        self.verifier.current_period()
    }
    pub fn current_token_label(&self) -> &str {
        &self.current_token_label
    }
    pub fn requirements_digest(&self) -> &str {
        &self.verifier.params.requirements_digest
    }
    pub fn audience(&self) -> &str {
        &self.verifier.params.audience
    }
    pub fn live_vetter_phis(&self) -> Result<Vec<Fr>, ProtoError> {
        self.verifier.live_vetter_phis()
    }
    /// What this community publishes: the same view a member works from, so a test drives the
    /// code path a client does (`vetting.ext` of the manifest, design §8).
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be re-derived.
    pub fn params(&self) -> Result<crate::community::CommunityParams, ProtoError> {
        crate::community::CommunityParams::new(
            &self.community,
            self.hvk().clone(),
            self.tvk().clone(),
            self.live_periods()
                .iter()
                .map(|p| format!("vetter/{p}"))
                .collect(),
            self.token_verifier()
                .live_labels()
                .iter()
                .cloned()
                .collect(),
            self.drip_rate,
        )
    }

    /// The token side of the public parameters, and the spent set.
    pub fn token_verifier(&self) -> &TokenVerifier {
        &self.verifier.tokens
    }

    // --- vetters ----------------------------------------------------------------------------

    pub fn grant(&mut self, member: &str) {
        self.grants.insert(member.to_string());
    }

    /// Removal: no credential under any later label. What they hold stays valid until its
    /// label leaves the window, or until [`Self::drop_period`].
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
    ) -> Result<<Base as CredentialBase>::PreCredential, ProtoError> {
        if !self.grants.contains(member) {
            return Err(ProtoError::NotAVetter(member.to_string()));
        }
        let period = self.current_period().to_string();
        let id_text = point_text(id)?;
        if let Some(bound) = self.bound_ids.get(member)
            && *bound != id_text
        {
            return Err(ProtoError::IdentifierRebound(member.to_string()));
        }
        if self.issued.contains(&(member.to_string(), period.clone())) {
            return Err(ProtoError::AlreadyIssued {
                member: member.to_string(),
                label: format!("vetter/{period}"),
            });
        }
        let pre = self.issuer.issue_root(&period, id, request, rng)?;
        self.bound_ids.insert(member.to_string(), id_text);
        self.issued.insert((member.to_string(), period));
        Ok(pre)
    }

    /// Epoch rotation: the new period is current, the previous stays live, older ones leave the
    /// AllowList. Monthly token labels move with it.
    pub fn rotate(&mut self, new_period: &str) -> Result<(), ProtoError> {
        let previous = self.current_period().to_string();
        self.verifier
            .set_live_periods(vec![new_period.to_string(), previous.clone()])?;
        let old_labels: Vec<String> = self
            .verifier
            .tokens
            .live_labels()
            .iter()
            .filter(|l| !l.starts_with("token/event/") && **l != monthly_token_label(&previous))
            .cloned()
            .collect();
        for l in old_labels {
            self.verifier.tokens.close_label(&l);
        }
        self.current_token_label = monthly_token_label(new_period);
        self.verifier.tokens.open_label(&self.current_token_label);
        Ok(())
    }

    /// Emergency: a period leaves the AllowList now, e.g. to make a removal immediate.
    pub fn drop_period(&mut self, period: &str) -> Result<(), ProtoError> {
        let periods: Vec<String> = self
            .live_periods()
            .iter()
            .filter(|p| *p != period)
            .cloned()
            .collect();
        self.verifier.set_live_periods(periods)
    }

    // --- tokens -----------------------------------------------------------------------------

    /// One tick of the drip for `member` under `label` (monthly or event).
    pub fn drip<R: RngCore + CryptoRng>(
        &mut self,
        member: &str,
        tick: u32,
        label: &str,
        requests: &[TokenRequest],
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
        self.issuer.issue_tokens(
            &self.verifier.tokens,
            crate::issuer::DripOrder {
                member,
                tick,
                label,
                requests,
                quota: self.quota_for(label),
            },
            rng,
        )
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
        self.verifier.tokens.open_label(&label);
        Ok(label)
    }

    /// The event's grace period is over: its tokens die.
    pub fn close_event(&mut self, event_id: &str) {
        self.verifier
            .tokens
            .close_label(&event_token_label(event_id));
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

    /// Consume the challenge, then verify and count (the verifier does the rest).
    pub fn submit(&mut self, sub: &Submission, now: DateTime<Utc>) -> Result<Decision, ProtoError> {
        if !self.challenges.remove(&sub.challenge) {
            return Err(ProtoError::BadChallenge);
        }
        self.verifier.submit(sub, now)
    }

    pub fn evaluate(&self, id_text: &str, now: DateTime<Utc>) -> Decision {
        self.verifier.evaluate(id_text, now)
    }

    pub fn withdraw(&mut self, id: &G1, tag: &G1, proof: &FSProof<Fr>) -> Result<bool, ProtoError> {
        self.verifier.withdraw(id, tag, proof)
    }
}
