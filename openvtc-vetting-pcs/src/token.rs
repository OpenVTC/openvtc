//! Attestation tokens (design §5.1, with §13 C1 and C3): Pointcheval–Sanders blind signatures
//! on secret serials, made with the PCS credential layer. No RSA, no new dependency.
//!
//! - One token key `(tvk, tsk)` per community, never `hvk`. A PS signature on `(s, φ)` under
//!   `hvk` would be a PCS credential whose "`usk`" the vetter knows.
//! - The period is in the token LABEL (`token/<period>`, `token/event/<id>`): `φ_token` is
//!   `EncPred` of that label under the token deployment.
//! - Drip: the vetter commits to fresh serials `C_i = g_1^{ρ_i} Y_1^{s_i}` with a proof of
//!   knowledge of each opening; the VTC blind-signs one at a time (C3), at most once per member
//!   per tick.
//! - Spend: the serial is revealed with a RE-RANDOMISED signature; the VTC checks it under a
//!   live label and records the serial in that label's spent set.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Mutex,
};

use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use predicate_credential_system::{
    cred::{
        CredentialBase,
        ps::{
            PSCredential, PSMessage, PSPreCredential, PSShownCredential, PSSigningKey,
            PSVerificationKey,
        },
    },
    pcs::{Predicate, PredicateCredentialSystem, SetupParams},
    serialization::to_bytes,
    sigma::{FSProof, GroupRelation, LinearEquation, fiat_shamir},
};
use rand::{CryptoRng, RngCore};

use crate::{
    ProtoError,
    scheme::{Base, E, Fr, G1, Open, scalar_text, token_deployment_label},
};

/// One committed serial with its proof of opening.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub commitment: G1,
    pub opening_proof: FSProof<Fr>,
}

/// A spent token as the applicant forwards it: the revealed serial and a re-randomised
/// signature.
#[derive(Debug, Clone)]
pub struct TokenSpend {
    pub label: String,
    pub serial: Fr,
    pub shown: PSShownCredential<E>,
}

/// What the spent set said about a spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendOutcome {
    /// First time this serial was seen.
    Fresh,
    /// Seen before with the same `(id, tag)`: a resubmission after `requestMore`.
    AlreadyCounted,
    /// Seen before with another `(id, tag)`. Recorded as an anomaly; the VTC cannot name who.
    DoubleSpend,
}

/// `φ_token` of a label, under the token deployment of a community.
pub struct TokenParams {
    open: Open,
}

impl TokenParams {
    pub fn new(community: &str) -> Result<Self, ProtoError> {
        Ok(Self {
            open: Open::setup(SetupParams::new(token_deployment_label(community)))?,
        })
    }

    pub fn phi(&self, label: &str) -> Result<Fr, ProtoError> {
        Ok(self
            .open
            .enc_pred(&Predicate::root(label.as_bytes().to_vec()))?)
    }
}

/// The statement `C = g_1^ρ Y_1^s` over the variables `(s, ρ)`, in that order.
fn opening_relation(tvk: &PSVerificationKey<E>, c: &G1) -> Result<GroupRelation<G1>, ProtoError> {
    let mut rel = GroupRelation::new();
    let s = rel.alloc_scalar();
    let rho = rel.alloc_scalar();
    rel.add_equation(LinearEquation::new(
        vec![(rho, G1::generator()), (s, tvk.y1)],
        *c,
    ))?;
    Ok(rel)
}

/// The context of an opening proof: the key, the label, who asks, for which tick, which slot.
/// A proof made for one request cannot be replayed into another.
fn opening_context(
    tvk: &PSVerificationKey<E>,
    label: &str,
    member: &str,
    tick: u32,
    index: usize,
    c: &G1,
) -> Result<Vec<u8>, ProtoError> {
    let mut ctx = b"openvtc/hidden-vetting/token-open/0.1\0".to_vec();
    for part in [
        to_bytes(tvk)?,
        label.as_bytes().to_vec(),
        member.as_bytes().to_vec(),
        tick.to_le_bytes().to_vec(),
        (index as u64).to_le_bytes().to_vec(),
        to_bytes(c)?,
    ] {
        ctx.extend((part.len() as u64).to_le_bytes());
        ctx.extend(part);
    }
    Ok(ctx)
}

// -------------------------------------------------------------------------------------------
// VTC side
// -------------------------------------------------------------------------------------------

pub struct TokenIssuer {
    params: TokenParams,
    tvk: PSVerificationKey<E>,
    tsk: PSSigningKey<E>,
    /// One lock per signing key: blind signing is sequential (§13 C3).
    sign_lock: Mutex<()>,
    live: BTreeSet<String>,
    served: HashSet<(String, String, u32)>,
    /// label → serial → (id, tag)
    spent: HashMap<String, HashMap<String, (String, String)>>,
    pub anomalies: Vec<String>,
}

impl TokenIssuer {
    pub fn new<R: RngCore + CryptoRng>(community: &str, rng: &mut R) -> Result<Self, ProtoError> {
        let (tvk, tsk) = Base::keygen(&(), rng);
        Ok(Self {
            params: TokenParams::new(community)?,
            tvk,
            tsk,
            sign_lock: Mutex::new(()),
            live: BTreeSet::new(),
            served: HashSet::new(),
            spent: HashMap::new(),
            anomalies: Vec::new(),
        })
    }

    pub fn tvk(&self) -> &PSVerificationKey<E> {
        &self.tvk
    }

    pub fn live_labels(&self) -> &BTreeSet<String> {
        &self.live
    }

    pub fn open_label(&mut self, label: &str) {
        self.live.insert(label.to_string());
    }

    /// Closing a label expires its tokens and drops its spent set: nothing under it can be
    /// spent any more, so nothing needs remembering.
    pub fn close_label(&mut self, label: &str) {
        self.live.remove(label);
        self.spent.remove(label);
    }

    /// Blind-sign one tick's drip for `member` under `label`. The caller has checked that
    /// `member` holds a live grant (and, for an event label, belongs to the event group).
    pub fn issue<R: RngCore + CryptoRng>(
        &mut self,
        member: &str,
        tick: u32,
        label: &str,
        requests: &[TokenRequest],
        rng: &mut R,
    ) -> Result<Vec<PSPreCredential<E>>, ProtoError> {
        if !self.live.contains(label) {
            return Err(ProtoError::LabelNotLive(label.to_string()));
        }
        let key = (member.to_string(), label.to_string(), tick);
        if self.served.contains(&key) {
            return Err(ProtoError::AlreadyServedThisTick {
                member: member.to_string(),
                tick,
            });
        }
        for (i, req) in requests.iter().enumerate() {
            let rel = opening_relation(&self.tvk, &req.commitment)?;
            let ctx = opening_context(&self.tvk, label, member, tick, i, &req.commitment)?;
            if !fiat_shamir::verify(&rel, &ctx, &req.opening_proof) {
                return Err(ProtoError::BadOpeningProof(i));
            }
        }
        let phi = self.params.phi(label)?;
        let _guard = self.sign_lock.lock().expect("token signing lock");
        let pres = requests
            .iter()
            .map(|req| Base::blind_issue(&(), &self.tsk, &req.commitment, &phi, rng))
            .collect::<Result<Vec<_>, _>>()?;
        self.served.insert(key);
        Ok(pres)
    }

    /// The signature check alone: valid under a live label. Also what the applicant's engine
    /// runs on receipt (§13 C5), with the public `tvk`.
    pub fn signature_ok(&self, spend: &TokenSpend) -> Result<bool, ProtoError> {
        if !self.live.contains(&spend.label) {
            return Ok(false);
        }
        verify_spend(&self.params, &self.tvk, spend)
    }

    /// Record a verified spend in its label's spent set.
    pub fn record_spend(
        &mut self,
        spend: &TokenSpend,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError> {
        let serial = scalar_text(&spend.serial)?;
        let set = self.spent.entry(spend.label.clone()).or_default();
        match set.get(&serial) {
            None => {
                set.insert(serial, (id.to_string(), tag.to_string()));
                Ok(SpendOutcome::Fresh)
            }
            Some((i, t)) if i == id && t == tag => Ok(SpendOutcome::AlreadyCounted),
            Some(_) => {
                self.anomalies.push(format!(
                    "serial {serial} under {} presented twice",
                    spend.label
                ));
                Ok(SpendOutcome::DoubleSpend)
            }
        }
    }
}

/// `Verify(tvk, (s, φ_label), σ')`.
pub fn verify_spend(
    params: &TokenParams,
    tvk: &PSVerificationKey<E>,
    spend: &TokenSpend,
) -> Result<bool, ProtoError> {
    let m = PSMessage::new(spend.serial, params.phi(&spend.label)?);
    Ok(Base::verify(
        &(),
        tvk,
        &m,
        &PSCredential::from(spend.shown.clone()),
    ))
}

// -------------------------------------------------------------------------------------------
// Vetter side (inside the vetter's VTA: the PCS engine)
// -------------------------------------------------------------------------------------------

struct Held {
    label: String,
    serial: Fr,
    minted_tick: u32,
    cred: PSCredential<E>,
    reserved: bool,
}

struct Pending {
    label: String,
    tick: u32,
    serial: Fr,
    rho: Fr,
}

/// The vetter's bucket.
pub struct TokenWallet {
    params: TokenParams,
    held: Vec<Held>,
    pending: Vec<Pending>,
}

/// A token set aside when a request is accepted (§5.2), identified by its serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub label: String,
    pub serial: Fr,
}

impl TokenWallet {
    pub fn new(community: &str) -> Result<Self, ProtoError> {
        Ok(Self {
            params: TokenParams::new(community)?,
            held: Vec::new(),
            pending: Vec::new(),
        })
    }

    /// Draw `r` serials for one tick and commit to them.
    pub fn prepare<R: RngCore + CryptoRng>(
        &mut self,
        tvk: &PSVerificationKey<E>,
        label: &str,
        member: &str,
        tick: u32,
        r: usize,
        rng: &mut R,
    ) -> Result<Vec<TokenRequest>, ProtoError> {
        self.pending.clear();
        let mut out = Vec::with_capacity(r);
        for i in 0..r {
            let (serial, rho) = (Fr::rand(rng), Fr::rand(rng));
            let c = Base::issuance_encoding(&(), tvk, &serial, &Fr::from(0u64), &rho)?;
            let rel = opening_relation(tvk, &c)?;
            let ctx = opening_context(tvk, label, member, tick, i, &c)?;
            let opening_proof = fiat_shamir::prove(&rel, &[serial, rho], &ctx, rng)?;
            out.push(TokenRequest {
                commitment: c,
                opening_proof,
            });
            self.pending.push(Pending {
                label: label.to_string(),
                tick,
                serial,
                rho,
            });
        }
        Ok(out)
    }

    /// Unblind the answers and keep them, failing closed on any that does not verify.
    pub fn receive(
        &mut self,
        tvk: &PSVerificationKey<E>,
        pres: &[PSPreCredential<E>],
    ) -> Result<(), ProtoError> {
        let pending = std::mem::take(&mut self.pending);
        if pending.len() != pres.len() {
            return Err(ProtoError::CountMismatch {
                statements: pending.len(),
                attestations: pres.len(),
            });
        }
        for (p, pre) in pending.into_iter().zip(pres) {
            let m = PSMessage::new(p.serial, self.params.phi(&p.label)?);
            let cred = Base::unblind(&(), tvk, &m, pre, &p.rho)?;
            if !Base::verify(&(), tvk, &m, &cred) {
                return Err(ProtoError::Pcs(
                    predicate_credential_system::Error::InvalidPreCredential,
                ));
            }
            self.held.push(Held {
                label: p.label,
                serial: p.serial,
                minted_tick: p.tick,
                cred,
                reserved: false,
            });
        }
        Ok(())
    }

    /// Tokens whose label is no longer live are gone (the FIFO of §5.1).
    pub fn expire(&mut self, live: &BTreeSet<String>) {
        self.held.retain(|h| live.contains(&h.label));
    }

    pub fn free(&self) -> usize {
        self.held.iter().filter(|h| !h.reserved).count()
    }

    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Reserve the NEWEST free token (§5.1 step 3), preferring `prefer_label` when given (an
    /// event label during its event).
    pub fn reserve(&mut self, prefer_label: Option<&str>) -> Option<Reservation> {
        let pick = self
            .held
            .iter_mut()
            .filter(|h| !h.reserved)
            .max_by_key(|h| (prefer_label.is_some_and(|l| l == h.label), h.minted_tick))?;
        pick.reserved = true;
        Some(Reservation {
            label: pick.label.clone(),
            serial: pick.serial,
        })
    }

    pub fn release(&mut self, r: &Reservation) {
        if let Some(h) = self.held.iter_mut().find(|h| h.serial == r.serial) {
            h.reserved = false;
        }
    }

    /// Spend a reservation: the token leaves the wallet as a re-randomised signature.
    pub fn spend<R: RngCore + CryptoRng>(
        &mut self,
        tvk: &PSVerificationKey<E>,
        r: &Reservation,
        rng: &mut R,
    ) -> Result<TokenSpend, ProtoError> {
        let pos = self
            .held
            .iter()
            .position(|h| h.serial == r.serial && h.reserved)
            .ok_or(ProtoError::AtCapacity { available_from: 0 })?;
        let h = self.held.remove(pos);
        let m = PSMessage::new(h.serial, self.params.phi(&h.label)?);
        let (shown, ()) = Base::rerand(&(), tvk, &m, &h.cred, rng)?;
        Ok(TokenSpend {
            label: h.label,
            serial: h.serial,
            shown,
        })
    }
}
