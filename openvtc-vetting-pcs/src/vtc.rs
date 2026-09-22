//! The community side: the PCS *helper*. It owns what the [`Verifier`] does not — the helper
//! secret key, who holds a vetter grant, the member→id bindings, the token signing key and
//! event mode — and delegates every check on a submission to the verifier.
//!
//! In production this is `vtc-service` (VTI). The copy here is what the client tests against
//! and what the VTI branch mirrors.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use chrono::{DateTime, Utc};
use predicate_credential_system::{
    cred::CredentialBase,
    pcs::{HelperSecretKey, PredicateCredentialSystem, RootRequest, SetupParams},
    sigma::FSProof,
};
use rand::{CryptoRng, RngCore};
use vta_sdk::protocols::vetting::VettingRequirements;

use crate::{
    ProtoError,
    scheme::{
        Base, E, Fr, G1, Hvk, Open, deployment_label, event_token_label, monthly_token_label,
        point_text, vetter_predicate,
    },
    token::{TokenIssuer, TokenRequest, TokenVerifier},
    verifier::{Verifier, VerifierParams},
};

pub use crate::verifier::{Decision, StatementRecord, Submission, withdraw_context};

pub struct Vtc {
    pub community: String,
    /// Everything a submission is checked against: public parameters only.
    pub verifier: Verifier,
    hvk: Hvk,
    hsk: HelperSecretKey<Base>,
    /// One lock per signing key (§13 C3).
    hsk_lock: Mutex<()>,
    grants: HashSet<String>,
    /// member → PCS id, bound at first root issuance (§13 C2).
    bound_ids: HashMap<String, String>,
    issued: HashSet<(String, String)>,
    tokens: TokenIssuer,
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
        let open = Open::setup(SetupParams::new(deployment_label(community)))?;
        // `hvk` is long-lived: generated once, bound to the fixed `pp` (§13 C1).
        let (hvk, hsk) = open.helper_keygen(rng);
        let requirements_digest =
            vta_sdk::vetting::requirements::requirements_digest(&requirements)
                .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let requirements: VettingRequirements = serde_json::from_value(requirements)
            .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let (tokens, mut token_verifier) = TokenIssuer::new(community, rng)?;
        let current_token_label = monthly_token_label(period);
        token_verifier.open_label(&current_token_label);
        let verifier = Verifier::new(
            VerifierParams {
                community: community.to_string(),
                audience: community.to_string(),
                requirements,
                requirements_digest,
            },
            hvk.clone(),
            token_verifier,
            vec![period.to_string()],
        )?;
        Ok(Self {
            community: community.to_string(),
            verifier,
            hvk,
            hsk,
            hsk_lock: Mutex::new(()),
            grants: HashSet::new(),
            bound_ids: HashMap::new(),
            issued: HashSet::new(),
            tokens,
            current_token_label,
            events: HashMap::new(),
            challenges: HashSet::new(),
        })
    }

    // --- public parameters, as the manifest's `vetting.anonymity` carries them --------------

    pub fn open(&self) -> &Open {
        self.verifier.open()
    }
    pub fn hvk(&self) -> &Hvk {
        &self.hvk
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
        let pre = {
            let _guard = self.hsk_lock.lock().expect("helper signing lock");
            self.verifier.open().issue_root(
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
        self.tokens
            .issue(&self.verifier.tokens, member, tick, label, requests, rng)
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
