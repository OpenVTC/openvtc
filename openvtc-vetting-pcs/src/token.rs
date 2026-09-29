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
use serde::{Deserialize, Serialize};

use crate::{
    ProtoError,
    scheme::{Base, E, Fr, G1, Open, dec, enc, scalar_text, token_deployment_label},
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

/// Where spent serials are remembered. A serial that un-spends is a double spend, so the VTC
/// backs this with durable storage; the in-memory default is for tests and for a client that
/// is predicting a verdict.
pub trait SpentLedger: std::any::Any + Send {
    /// Record `(label, serial)` as spent by `(id, tag)`, and say what was there before.
    fn record(
        &mut self,
        label: &str,
        serial: &str,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError>;

    /// Forget everything under `label`: its tokens can no longer be spent, so nothing under it
    /// needs remembering.
    fn forget_label(&mut self, label: &str);

    /// For [`TokenVerifier::take_ledger`]; the blanket implementation below is the only one.
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

/// The default: one process, no durability.
#[derive(Default)]
pub struct MemoryLedger {
    /// label → serial → (id, tag)
    spent: HashMap<String, HashMap<String, (String, String)>>,
}

impl SpentLedger for MemoryLedger {
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }

    fn record(
        &mut self,
        label: &str,
        serial: &str,
        id: &str,
        tag: &str,
    ) -> Result<SpendOutcome, ProtoError> {
        let set = self.spent.entry(label.to_string()).or_default();
        match set.get(serial) {
            None => {
                set.insert(serial.to_string(), (id.to_string(), tag.to_string()));
                Ok(SpendOutcome::Fresh)
            }
            Some((i, t)) if i == id && t == tag => Ok(SpendOutcome::AlreadyCounted),
            Some(_) => Ok(SpendOutcome::DoubleSpend),
        }
    }

    fn forget_label(&mut self, label: &str) {
        self.spent.remove(label);
    }
}

/// What a VERIFIER needs about tokens: the public key, the live labels, and the spent set. The
/// VTC service holds one of these; so does anything that re-checks a submission from public
/// data alone (the fixture tests do).
pub struct TokenVerifier {
    params: TokenParams,
    tvk: PSVerificationKey<E>,
    live: BTreeSet<String>,
    spent: Box<dyn SpentLedger>,
    pub anomalies: Vec<String>,
}

/// The signing half: only the community that mints tokens has one. It takes the
/// [`TokenVerifier`] as an argument rather than owning it, so that one spent set and one set of
/// live labels serve both minting and verification.
pub struct TokenIssuer {
    tsk: PSSigningKey<E>,
    /// One lock per signing key: blind signing is sequential (§13 C3).
    sign_lock: Mutex<()>,
    served: HashSet<(String, String, u32)>,
}

impl TokenVerifier {
    /// From public data only: the token key and the labels that are live.
    pub fn new(
        community: &str,
        tvk: PSVerificationKey<E>,
        live: impl IntoIterator<Item = String>,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            params: TokenParams::new(community)?,
            tvk,
            live: live.into_iter().collect(),
            spent: Box::new(MemoryLedger::default()),
            anomalies: Vec::new(),
        })
    }

    /// Swap in a durable ledger (the VTC service does this at startup).
    #[must_use]
    pub fn with_ledger(mut self, ledger: Box<dyn SpentLedger>) -> Self {
        self.spent = ledger;
        self
    }

    /// Put a ledger in for one call.
    pub fn set_ledger(&mut self, ledger: Box<dyn SpentLedger>) {
        self.spent = ledger;
    }

    /// Take the ledger back out, leaving an empty in-memory one. A caller that has to write
    /// what was spent to storage gets it this way, and downcasts to its own type.
    pub fn take_ledger(&mut self) -> Box<dyn std::any::Any> {
        std::mem::replace(&mut self.spent, Box::new(MemoryLedger::default())).into_any()
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
        self.spent.forget_label(label);
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
        let outcome = self.spent.record(&spend.label, &serial, id, tag)?;
        if outcome == SpendOutcome::DoubleSpend {
            self.anomalies.push(format!(
                "serial {serial} under {} presented twice",
                spend.label
            ));
        }
        Ok(outcome)
    }
}

impl TokenIssuer {
    /// A fresh token key pair: the verifier half is returned with it, because the two are one
    /// key and the caller keeps them together.
    pub fn new<R: RngCore + CryptoRng>(
        community: &str,
        rng: &mut R,
    ) -> Result<(Self, TokenVerifier), ProtoError> {
        let (tvk, tsk) = Base::keygen(&(), rng);
        let verifier = TokenVerifier::new(community, tvk, [])?;
        Ok((
            Self {
                tsk,
                sign_lock: Mutex::new(()),
                served: HashSet::new(),
            },
            verifier,
        ))
    }

    /// Blind-sign one tick's drip for `member` under `label`. The caller has checked that
    /// `member` holds a live grant (and, for an event label, belongs to the event group).
    pub fn issue<R: RngCore + CryptoRng>(
        &mut self,
        verifier: &TokenVerifier,
        member: &str,
        tick: u32,
        label: &str,
        requests: &[TokenRequest],
        rng: &mut R,
    ) -> Result<Vec<PSPreCredential<E>>, ProtoError> {
        if !verifier.live.contains(label) {
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
            let rel = opening_relation(verifier.tvk(), &req.commitment)?;
            let ctx = opening_context(verifier.tvk(), label, member, tick, i, &req.commitment)?;
            if !fiat_shamir::verify(&rel, &ctx, &req.opening_proof) {
                return Err(ProtoError::BadOpeningProof(i));
            }
        }
        let phi = verifier.params.phi(label)?;
        let _guard = self.sign_lock.lock().expect("token signing lock");
        let pres = requests
            .iter()
            .map(|req| Base::blind_issue(&(), &self.tsk, &req.commitment, &phi, rng))
            .collect::<Result<Vec<_>, _>>()?;
        self.served.insert(key);
        Ok(pres)
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

/// One token the vetter holds, unspent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldToken {
    pub label: String,
    /// SECRET until spent: the serial is what the community records.
    pub serial: String,
    pub minted_tick: u32,
    pub credential: String,
}

impl HeldToken {
    pub fn of(
        label: &str,
        serial: &Fr,
        minted_tick: u32,
        cred: &PSCredential<E>,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            label: label.to_string(),
            serial: enc(serial)?,
            minted_tick,
            credential: enc(cred)?,
        })
    }

    pub fn parts(&self) -> Result<(Fr, PSCredential<E>), ProtoError> {
        Ok((
            dec::<Fr>(&self.serial)?,
            dec::<PSCredential<E>>(&self.credential)?,
        ))
    }
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

    /// The unspent tokens, for storage. A reserved token stores as unreserved: a reservation
    /// belongs to a session that did not survive the restart either.
    pub fn snapshot(&self) -> Result<Vec<HeldToken>, ProtoError> {
        self.held
            .iter()
            .map(|h| HeldToken::of(&h.label, &h.serial, h.minted_tick, &h.cred))
            .collect()
    }

    /// Restore a bucket from storage.
    pub fn restore(community: &str, tokens: &[HeldToken]) -> Result<Self, ProtoError> {
        let mut wallet = Self::new(community)?;
        for t in tokens {
            let (serial, cred) = t.parts()?;
            wallet.held.push(Held {
                label: t.label.clone(),
                serial,
                minted_tick: t.minted_tick,
                cred,
                reserved: false,
            });
        }
        Ok(wallet)
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
