//! The applicant's PCS engine (inside the applicant's VTA, design §13 C7): a fresh `usk` per
//! application, verification of every attestation on receipt (§13 C5), and the proof.

use predicate_credential_system::pcs::{PredicateCredentialSystem, UserSecretKey};
use rand::{CryptoRng, RngCore};

use crate::{
    ProtoError,
    meta::{ProofContext, StatementMeta, id_binding},
    scheme::{E, G1, hidden_vetting_predicate, point_text, scalar_text},
    token::{TokenParams, verify_spend},
    vetter::HiddenAttestation,
    vtc::{Submission, Vtc},
};

pub struct ApplicantEngine {
    usk: UserSecretKey<E>,
    id: G1,
    pub join_did: String,
    held: Vec<HiddenAttestation>,
}

impl ApplicantEngine {
    pub fn new<R: RngCore + CryptoRng>(
        vtc: &Vtc,
        join_did: &str,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let (id, usk) = vtc.open().user_keygen(rng)?;
        Ok(Self {
            usk,
            id,
            join_did: join_did.to_string(),
            held: Vec::new(),
        })
    }

    pub fn id(&self) -> &G1 {
        &self.id
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// A metadata template the vetter completes; the token fields are the vetter's to fill.
    pub fn statement_meta(&self, vtc: &Vtc, base: StatementMeta) -> StatementMeta {
        StatementMeta {
            community: vtc.community.clone(),
            requirements_digest: vtc.requirements_digest().to_string(),
            ..base
        }
    }

    /// Check an attestation on receipt, so `no-token` or a bad attestation shows up at the
    /// session and not at submit.
    pub fn receive(&mut self, vtc: &Vtc, att: HiddenAttestation) -> Result<(), ProtoError> {
        let app = att.meta.context_bytes()?;
        vtc.open()
            .check_attestation_in_context(vtc.hvk(), &self.id, &att.attestation, &app)
            .map_err(|e| ProtoError::AttestationRejected(e.to_string()))?;
        if !vtc.live_vetter_phis()?.contains(&att.attestation.phi) {
            return Err(ProtoError::AttestationRejected(
                "class is not a live vetter label".into(),
            ));
        }
        if att.meta.token_label != att.token.label
            || att.meta.token_serial != scalar_text(&att.token.serial)?
        {
            return Err(ProtoError::AttestationRejected(
                "token does not match its statement".into(),
            ));
        }
        let params = TokenParams::new(&vtc.community)?;
        if !verify_spend(&params, vtc.token_verifier().tvk(), &att.token)? {
            return Err(ProtoError::AttestationRejected(
                "token signature does not verify".into(),
            ));
        }
        self.held.push(att);
        Ok(())
    }

    /// Replace what a vetter refreshed: same tag, newer attestation.
    pub fn replace(&mut self, vtc: &Vtc, att: HiddenAttestation) -> Result<(), ProtoError> {
        let tag = att.attestation.tag;
        self.held.retain(|h| h.attestation.tag != tag);
        self.receive(vtc, att)
    }

    /// Build the submission from every held attestation that is still usable: its class is a
    /// live vetter label and its token label is live. One per tag (a proof refuses duplicates).
    pub fn submit<R: RngCore + CryptoRng>(
        &self,
        vtc: &Vtc,
        challenge: &str,
        rng: &mut R,
    ) -> Result<Submission, ProtoError> {
        let phis = vtc.live_vetter_phis()?;
        let mut usable: Vec<&HiddenAttestation> = Vec::new();
        for h in &self.held {
            let live = phis.contains(&h.attestation.phi)
                && vtc.token_verifier().live_labels().contains(&h.token.label);
            if live
                && !usable
                    .iter()
                    .any(|u| u.attestation.tag == h.attestation.tag)
            {
                usable.push(h);
            }
        }
        let atts: Vec<_> = usable.iter().map(|h| h.attestation.clone()).collect();
        let apps: Vec<Vec<u8>> = usable
            .iter()
            .map(|h| h.meta.context_bytes())
            .collect::<Result<_, _>>()?;
        let app_refs: Vec<&[u8]> = apps.iter().map(Vec::as_slice).collect();
        let id_text = point_text(&self.id)?;
        let binding = id_binding(
            &id_text,
            &vtc.community,
            vtc.requirements_digest(),
            &self.join_did,
        );
        let app0 = ProofContext {
            challenge: challenge.to_string(),
            audience: vtc.audience().to_string(),
            join_did: self.join_did.clone(),
            id_binding: binding.clone(),
        }
        .context_bytes()?;
        let f = hidden_vetting_predicate(u32::try_from(atts.len()).unwrap_or(u32::MAX));
        let (proof, _state) = vtc.open().prove_in_context(
            vtc.hvk(),
            &f,
            &self.id,
            &self.usk,
            &atts,
            &app_refs,
            &app0,
            rng,
        )?;
        Ok(Submission {
            id: self.id,
            join_did: self.join_did.clone(),
            id_binding: binding,
            challenge: challenge.to_string(),
            statements: usable
                .iter()
                .map(|h| (h.meta.clone(), h.token.clone()))
                .collect(),
            proof,
        })
    }
}
