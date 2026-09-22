//! The vetter's PCS engine, i.e. what runs inside the vetter's VTA (design §13 C7): the
//! stable `usk`, the root credentials per period, the token bucket, attest, refresh and
//! withdraw. openvtc would only drive these.

use std::collections::BTreeMap;

use predicate_credential_system::{
    kiprf::{KIPRF, prove_tag},
    pcs::{Credential, PredicateCredentialSystem, UserSecretKey},
    sigma::FSProof,
};
use rand::{CryptoRng, RngCore};

use crate::{
    ProtoError,
    meta::StatementMeta,
    scheme::{Base, E, Fr, G1, point_text, scalar_text, vetter_predicate},
    token::{Reservation, TokenWallet},
    vtc::{Vtc, withdraw_context},
};

/// An attestation as the applicant receives it (`vetting/attestation/0.1`).
#[derive(Debug, Clone)]
pub struct HiddenAttestation {
    pub attestation: predicate_credential_system::pcs::Attestation<E, Base>,
    pub meta: StatementMeta,
    pub token: crate::token::TokenSpend,
}

pub struct VetterEngine {
    pub member: String,
    usk: UserSecretKey<E>,
    id: G1,
    creds: BTreeMap<String, Credential<E, Base>>,
    wallet: TokenWallet,
    /// A limit below the community's drip, kept here and never sent anywhere (§5.1).
    pub personal_limit: Option<usize>,
    attested: usize,
    /// What was attested, so an attestation can be refreshed without a new session (§4.3).
    log: Vec<(G1, StatementMeta)>,
}

impl VetterEngine {
    /// A vetter's key pair: generated once, stable for life (§13 C2).
    pub fn new<R: RngCore + CryptoRng>(
        member: &str,
        vtc: &Vtc,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let (id, usk) = vtc.open().user_keygen(rng)?;
        Ok(Self {
            member: member.to_string(),
            usk,
            id,
            creds: BTreeMap::new(),
            wallet: TokenWallet::new(&vtc.community)?,
            personal_limit: None,
            attested: 0,
            log: Vec::new(),
        })
    }

    pub fn id(&self) -> &G1 {
        &self.id
    }

    /// Root request for the VTC's current period, with the SAME `usk` every time.
    pub fn enroll<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &mut Vtc,
        rng: &mut R,
    ) -> Result<(), ProtoError> {
        let period = vtc.current_period().to_string();
        let f = vetter_predicate(&period);
        let (request, state) = vtc
            .open()
            .root_request(vtc.hvk(), &f, &self.id, &self.usk, rng)?;
        let pre = vtc.issue_vetter_root(&self.member, &self.id, &request, rng)?;
        let cred = vtc.open().unblind(vtc.hvk(), &self.usk, &f, &pre, &state)?;
        self.creds.insert(period, cred);
        Ok(())
    }

    /// One scheduled drip fetch: unconditional, `r` tokens.
    pub fn drip<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &mut Vtc,
        tick: u32,
        label: &str,
        r: usize,
        rng: &mut R,
    ) -> Result<(), ProtoError> {
        let tvk = vtc.token_verifier().tvk().clone();
        let reqs = self
            .wallet
            .prepare(&tvk, label, &self.member, tick, r, rng)?;
        let pres = vtc.drip(&self.member, tick, label, &reqs, rng)?;
        self.wallet.receive(&tvk, &pres)?;
        self.wallet.expire(vtc.token_verifier().live_labels());
        Ok(())
    }

    /// Tokens whose label closed are gone.
    pub fn expire(&mut self, vtc: &Vtc) {
        self.wallet.expire(vtc.token_verifier().live_labels());
    }

    pub fn tokens_held(&self) -> usize {
        self.wallet.held()
    }

    pub fn tokens_free(&self) -> usize {
        self.wallet.free()
    }

    /// Accepting a `vetting/request` reserves a token (§5.2), or declines `atCapacity`.
    pub fn accept(
        &mut self,
        prefer_label: Option<&str>,
        next_tick: u32,
    ) -> Result<Reservation, ProtoError> {
        if self.personal_limit.is_some_and(|l| self.attested >= l) {
            return Err(ProtoError::AtCapacity {
                available_from: next_tick,
            });
        }
        self.wallet
            .reserve(prefer_label)
            .ok_or(ProtoError::AtCapacity {
                available_from: next_tick,
            })
    }

    pub fn decline(&mut self, r: &Reservation) {
        self.wallet.release(r);
    }

    /// Attest for `applicant_id` after the human check: spend the reserved token, bind its
    /// serial and the statement metadata into `ctx_j`, attest under the newest live period.
    pub fn attest<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &Vtc,
        reservation: &Reservation,
        applicant_id: &G1,
        meta: StatementMeta,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let period = vtc
            .live_periods()
            .iter()
            .find(|p| self.creds.contains_key(*p))
            .cloned()
            .ok_or(ProtoError::NoLiveCredential)?;
        let token = self
            .wallet
            .spend(vtc.token_verifier().tvk(), reservation, rng)?;
        self.attest_with_token(vtc, &period, token, applicant_id, meta, rng)
    }

    /// ADVERSARY HOOK for tests: attest with a token of the caller's choosing, e.g. one already
    /// spent. An honest engine never does this; the VTC's spent set is what stops it.
    #[doc(hidden)]
    pub fn attest_with_token<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &Vtc,
        period: &str,
        token: crate::token::TokenSpend,
        applicant_id: &G1,
        mut meta: StatementMeta,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let period = period.to_string();
        meta.token_label = token.label.clone();
        meta.token_serial = scalar_text(&token.serial)?;
        let app = meta.context_bytes()?;
        let attestation = vtc.open().attest_in_context(
            vtc.hvk(),
            &self.usk,
            &vetter_predicate(&period),
            &self.creds[&period],
            applicant_id,
            &app,
            rng,
        )?;
        self.attested += 1;
        self.log.push((*applicant_id, meta.clone()));
        Ok(HiddenAttestation {
            attestation,
            meta,
            token,
        })
    }

    /// Refresh after a rotation: the same statement, a fresh token, the current period. The
    /// tag is the same as before (§13 C2), so the two cannot count as two vetters.
    pub fn refresh<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &Vtc,
        applicant_id: &G1,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let (_, meta) = self
            .log
            .iter()
            .rev()
            .find(|(id, _)| id == applicant_id)
            .cloned()
            .ok_or(ProtoError::NoLiveCredential)?;
        let reservation = self.accept(None, 0)?;
        self.attested -= 1; // a refresh is not a new vetting
        self.attest(vtc, &reservation, applicant_id, meta, rng)
    }

    /// Withdraw one statement: the tag, and a proof of knowledge of the key behind it that
    /// does not link to this vetter's `id` (§4.4).
    pub fn withdraw<R: RngCore + CryptoRng>(
        &self,
        vtc: &Vtc,
        applicant_id: &G1,
        rng: &mut R,
    ) -> Result<(G1, FSProof<Fr>), ProtoError> {
        let prf = vtc.open().tag();
        let s = vtc.open().tag_point(applicant_id)?;
        let tag = prf
            .eval(self.usk.expose_scalar(), &s)
            .ok_or(predicate_credential_system::Error::UndefinedTag)?;
        let ctx = withdraw_context(&vtc.community, &point_text(applicant_id)?);
        let proof = prove_tag(prf, self.usk.expose_scalar(), &tag, &s, &ctx, rng)?;
        Ok((tag, proof))
    }
}
