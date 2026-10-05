//! The vetter's PCS engine, i.e. what runs inside the vetter's VTA (design §13 C7): the
//! stable `usk`, the root credentials per period, the token bucket, attest, refresh and
//! withdraw. openvtc would only drive these.

use std::collections::BTreeMap;

use predicate_credential_system::{
    kiprf::{KIPRF, prove_tag},
    pcs::{Credential, IssuanceState, PredicateCredentialSystem, UserSecretKey},
    sigma::FSProof,
};
use rand::{CryptoRng, RngCore};

use crate::{
    ProtoError,
    community::CommunityParams,
    issuer::{
        RootCredentialWire, RootRequestWire, TokenBatchRequestWire, TokenBatchWire,
        TokenRequestWire,
    },
    meta::StatementMeta,
    scheme::{Base, E, Fr, G1, point_text, scalar_text, vetter_predicate},
    snapshot::VetterSnapshot,
    token::{Reservation, TokenWallet},
    vtc::{Vtc, withdraw_context},
};

/// The blinding state of an enrolment in flight.
///
/// Named here so a caller can hold one across a round trip without depending on the PCS crate
/// directly. It is deliberately not serialisable: it is useless without the community's answer
/// and dangerous to keep past it.
pub type EnrolmentBlinding = IssuanceState<E, Base>;

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

    /// A vetter's key pair from a community's **published** parameters.
    ///
    /// [`Self::new`] takes a [`Vtc`], which only the community has. This is the same act on the
    /// other side of the wire: a member who has read a manifest and holds a vetter grant mints
    /// the key pair every tag of theirs will derive from, and enrols with it.
    ///
    /// `member` is the DID this vetter will sign its requests with. It is bound into the opening
    /// proofs the token drip sends and checked by the community against the signer, so it is not
    /// a display name and cannot be changed later without abandoning the wallet.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the key pair cannot be generated, or the wallet cannot be opened
    /// for this community.
    pub fn enrol_new<R: RngCore + CryptoRng>(
        member: &str,
        params: &CommunityParams,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let (id, usk) = params.open().user_keygen(rng)?;
        Ok(Self {
            member: member.to_string(),
            usk,
            id,
            creds: BTreeMap::new(),
            wallet: TokenWallet::new(params.community())?,
            personal_limit: None,
            attested: 0,
            log: Vec::new(),
        })
    }

    pub fn id(&self) -> &G1 {
        &self.id
    }

    /// The storable form, for openvtc's encrypted config. Carries `usk`, the key every tag of
    /// this vetter derives from: see [`crate::snapshot`].
    pub fn snapshot(&self) -> Result<VetterSnapshot, ProtoError> {
        let mut snap = VetterSnapshot::new(&self.member, &self.usk, &self.id)?;
        for (period, cred) in &self.creds {
            snap.put_credential(period, cred)?;
        }
        snap.tokens = self.wallet.snapshot()?;
        snap.pending = self.wallet.pending_snapshot()?;
        snap.personal_limit = self.personal_limit;
        for (id, meta) in &self.log {
            snap.record(id, meta)?;
        }
        Ok(snap)
    }

    /// Restore a vetter's engine from storage.
    pub fn restore(snap: &VetterSnapshot, community: &str) -> Result<Self, ProtoError> {
        let (usk, id) = snap.key()?;
        let mut creds = BTreeMap::new();
        for period in snap.credentials.keys() {
            if let Some(c) = snap.credential(period)? {
                creds.insert(period.clone(), c);
            }
        }
        let mut log = Vec::new();
        for (raw, meta) in &snap.log {
            let id: G1 = predicate_credential_system::serialization::from_bytes(
                &predicate_credential_system::serialization::from_multibase(raw)?,
            )?;
            log.push((id, meta.clone()));
        }
        let mut wallet = TokenWallet::restore(community, &snap.tokens)?;
        wallet.restore_pending(&snap.pending)?;
        Ok(Self {
            member: snap.member.clone(),
            usk,
            id,
            creds,
            wallet,
            personal_limit: snap.personal_limit,
            attested: 0,
            log,
        })
    }

    /// The vetter's half of enrolment: a blinded request for `period`, built with the SAME
    /// `usk` every time, and the blinding state that unblinds what comes back.
    ///
    /// Split from [`Self::accept_enrolment`] because the two halves are a round trip in a
    /// deployment — the request is what a Trust Task carries, and the community's answer comes
    /// back later. The community sees a commitment; it never sees the credential it made.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] if the request cannot be built, [`ProtoError::Serialization`] if it
    /// cannot be encoded.
    pub fn enrolment_request<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        period: &str,
        rng: &mut R,
    ) -> Result<(RootRequestWire, IssuanceState<E, Base>), ProtoError> {
        let f = vetter_predicate(period);
        let (request, state) =
            params
                .open()
                .root_request(params.hvk(), &f, &self.id, &self.usk, rng)?;
        Ok((
            RootRequestWire {
                label: format!("vetter/{period}"),
                id: point_text(&self.id)?,
                request: serde_json::to_value(&request)
                    .map_err(|e| ProtoError::Serialization(e.to_string()))?,
            },
            state,
        ))
    }

    /// Unblind the community's answer into this vetter's class credential.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if the answer cannot be decoded, [`ProtoError::Pcs`] if it
    /// does not unblind under the published key — which is what a wrong or swapped answer looks
    /// like from here.
    pub fn accept_enrolment(
        &mut self,
        params: &CommunityParams,
        answer: &RootCredentialWire,
        state: &IssuanceState<E, Base>,
    ) -> Result<(), ProtoError> {
        let period = answer.label.trim_start_matches("vetter/").to_string();
        let f = vetter_predicate(&period);
        let pre = crate::scheme::dec(&answer.pre_credential)?;
        let cred = params
            .open()
            .unblind(params.hvk(), &self.usk, &f, &pre, state)?;
        self.creds.insert(period, cred);
        Ok(())
    }

    /// The vetter's half of one scheduled drip fetch: `r` blinded serials for `tick`.
    ///
    /// Unconditional by design (§5.1) — a vetter asks on its schedule whether or not it has
    /// vetted anyone, because a fetch that tracked activity would report activity.
    ///
    /// # Errors
    /// [`ProtoError::Pcs`] or [`ProtoError::Serialization`] if a request cannot be built.
    pub fn drip_request<R: RngCore + CryptoRng>(
        &mut self,
        params: &CommunityParams,
        tick: u32,
        label: &str,
        r: usize,
        rng: &mut R,
    ) -> Result<TokenBatchRequestWire, ProtoError> {
        let reqs = self
            .wallet
            .prepare(params.tokens().tvk(), label, &self.member, tick, r, rng)?;
        Ok(TokenBatchRequestWire {
            label: label.to_string(),
            tick,
            requests: reqs
                .iter()
                .map(TokenRequestWire::of)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// Take a served batch into the wallet, and drop anything whose label has closed.
    ///
    /// # Errors
    /// [`ProtoError::Serialization`] if a token cannot be decoded, [`ProtoError::Pcs`] if one
    /// does not verify under the published token key.
    pub fn accept_drip(
        &mut self,
        params: &CommunityParams,
        served: &TokenBatchWire,
    ) -> Result<usize, ProtoError> {
        let pres = served
            .pre_credentials
            .iter()
            .map(|p| crate::scheme::dec(p))
            .collect::<Result<Vec<_>, _>>()?;
        self.wallet
            .receive(params.tokens().tvk(), &served.label, served.tick, &pres)?;
        self.wallet.expire(params.tokens().live_labels());
        Ok(pres.len())
    }

    /// Root request for the VTC's current period, with the SAME `usk` every time. The two
    /// halves above, against the in-process community object.
    pub fn enroll<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &mut Vtc,
        rng: &mut R,
    ) -> Result<(), ProtoError> {
        let period = vtc.current_period().to_string();
        let params = vtc.params()?;
        let (wire, state) = self.enrolment_request(&params, &period, rng)?;
        let request = serde_json::from_value(wire.request.clone())
            .map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let pre = vtc.issue_vetter_root(&self.member, &self.id, &request, rng)?;
        self.accept_enrolment(
            &params,
            &RootCredentialWire {
                label: wire.label.clone(),
                pre_credential: crate::scheme::enc(&pre)?,
            },
            &state,
        )
    }

    /// One scheduled drip fetch: unconditional, `r` tokens. The two halves above, against the
    /// in-process community object.
    pub fn drip<R: RngCore + CryptoRng>(
        &mut self,
        vtc: &mut Vtc,
        tick: u32,
        label: &str,
        r: usize,
        rng: &mut R,
    ) -> Result<(), ProtoError> {
        let params = vtc.params()?;
        let batch = self.drip_request(&params, tick, label, r, rng)?;
        let reqs = batch
            .requests
            .iter()
            .map(|r| r.to_request())
            .collect::<Result<Vec<_>, _>>()?;
        let pres = vtc.drip(&self.member, tick, label, &reqs, rng)?;
        self.accept_drip(
            &params,
            &TokenBatchWire {
                label: label.to_string(),
                tick,
                pre_credentials: pres
                    .iter()
                    .map(crate::scheme::enc)
                    .collect::<Result<Vec<_>, _>>()?,
            },
        )?;
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

    /// Drop the draw in flight for `(label, tick)`: the community refused it.
    pub fn forget_draw(&mut self, label: &str, tick: u32) {
        self.wallet.forget(label, tick);
    }

    /// The draws asked for and not yet answered, as `(label, tick)`.
    #[must_use]
    pub fn draws_in_flight(&self) -> Vec<(String, u32)> {
        self.wallet.in_flight()
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
        params: &CommunityParams,
        reservation: &Reservation,
        applicant_id: &G1,
        meta: StatementMeta,
        rng: &mut R,
    ) -> Result<HiddenAttestation, ProtoError> {
        let period = params
            .vetter_labels()
            .iter()
            .map(|l| l.trim_start_matches("vetter/").to_string())
            .find(|p| self.creds.contains_key(p))
            .ok_or(ProtoError::NoLiveCredential)?;
        let token = self.wallet.spend(params.tokens().tvk(), reservation, rng)?;
        self.attest_with_token(params, &period, token, applicant_id, meta, rng)
    }

    /// ADVERSARY HOOK for tests: attest with a token of the caller's choosing, e.g. one already
    /// spent. An honest engine never does this; the VTC's spent set is what stops it.
    #[doc(hidden)]
    pub fn attest_with_token<R: RngCore + CryptoRng>(
        &mut self,
        params: &CommunityParams,
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
        let attestation = params.open().attest_in_context(
            params.hvk(),
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
        params: &CommunityParams,
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
        self.attest(params, &reservation, applicant_id, meta, rng)
    }

    /// Withdraw one statement: the tag, and a proof of knowledge of the key behind it that
    /// does not link to this vetter's `id` (§4.4).
    pub fn withdraw<R: RngCore + CryptoRng>(
        &self,
        params: &CommunityParams,
        applicant_id: &G1,
        rng: &mut R,
    ) -> Result<(G1, FSProof<Fr>), ProtoError> {
        let prf = params.open().tag();
        let s = params.open().tag_point(applicant_id)?;
        let tag = prf
            .eval(self.usk.expose_scalar(), &s)
            .ok_or(predicate_credential_system::Error::UndefinedTag)?;
        let ctx = withdraw_context(params.community(), &point_text(applicant_id)?);
        let proof = prove_tag(prf, self.usk.expose_scalar(), &tag, &s, &ctx, rng)?;
        Ok((tag, proof))
    }
}
