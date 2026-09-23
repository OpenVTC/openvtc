//! The community's **minting** half: the two signing keys, and the two things they sign.
//!
//! Everything here is what [`crate::verifier::Verifier`] deliberately does not have. It is
//! split out from the bookkeeping on purpose: a vetter may hold one root credential per class
//! label and draw at most the published drip each tick, and *those facts belong in a store* —
//! `vtc-service` keeps them in a keyspace, where they survive a restart and cannot be lost by a
//! process that forgot. This type holds keys and signs; it counts nothing.
//!
//! # The keys are derived, not stored
//!
//! [`Issuer::derive`] produces both key pairs from one 32-byte secret, deterministically: a
//! service derives them from the master secret it already holds rather than minting a second
//! secret that must then be backed up, rotated and leaked separately. The stream is ChaCha20
//! over `SHA-256(info ‖ secret)`, which is specified rather than merely current, so the same
//! secret gives the same community keys on any machine and any build.
//!
//! The consequence to hold on to: **the master secret is the vetter class**. Change it and
//! `hvk` changes, every vetter's root credential stops verifying, and every submission already
//! in flight fails. A service must check the derived `hvk` against the one it published before
//! it issues anything — see `vtc-service`'s `pcs_issue::keys`.

use std::sync::Mutex;

use predicate_credential_system::{
    cred::{
        CredentialBase,
        ps::{PSPreCredential, PSVerificationKey},
    },
    pcs::{HelperSecretKey, PredicateCredentialSystem, RootRequest, SetupParams},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::{
    ProtoError,
    scheme::{Base, E, G1, Hvk, Open, deployment_label, key_text, vetter_predicate},
    token::{TokenIssuer, TokenRequest, TokenVerifier},
};

/// Domain separator for [`Issuer::derive`]. A change here is a key rotation for every
/// deployment that derives, so it is versioned.
pub const KEY_DERIVATION_INFO: &[u8] = b"vtc-vetting-pcs-keys/v1\0";

/// One tick of the drip, as the community is asked to serve it.
///
/// Grouped rather than passed loose because they travel together and mean nothing apart: the
/// quota that applies is a fact about the label, and the tick is what makes "once" checkable.
pub struct DripOrder<'a> {
    pub member: &'a str,
    pub tick: u32,
    pub label: &'a str,
    pub requests: &'a [TokenRequest],
    /// The published rate for this label — the ordinary drip, or an event's own.
    pub quota: usize,
}

/// The signing half of a community's hidden-vetting deployment.
///
/// One per community. Cheap to rebuild — `derive` is a key generation, not an I/O — so a
/// service may hold one for its lifetime or build one per request; both are correct.
pub struct Issuer {
    community: String,
    open: Open,
    hvk: Hvk,
    hsk: HelperSecretKey<Base>,
    tvk: PSVerificationKey<E>,
    /// The token signing key, behind its own lock: two signing keys, two locks (§13 C3). The
    /// `served` set inside it is a *second* guard on the once-a-tick rule, under the first one
    /// the caller keeps in its store — free, and it costs a restart's worth of memory.
    tokens: Mutex<TokenIssuer>,
    hsk_lock: Mutex<()>,
}

impl std::fmt::Debug for Issuer {
    /// Never the keys: a `{:?}` in a log line is how a signing key reaches a log file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("community", &self.community)
            .finish_non_exhaustive()
    }
}

impl Issuer {
    /// Both key pairs from one secret, deterministically. See the module docs for what that
    /// binds together.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be derived for `community`.
    pub fn derive(community: &str, secret: &[u8; 32]) -> Result<Self, ProtoError> {
        // The community is part of the seed, length-framed. Key generation itself does not read
        // the deployment label — `helper_keygen` samples from the stream — so two communities
        // derived from one master secret would otherwise share a key pair, and a helper that
        // serves two deployment labels with one key certifies, in each, the endorsers of the
        // other. The library binds the parameter digest into `hsk` and would catch the misuse;
        // this makes it unreachable instead.
        let mut h = Sha256::new();
        h.update(KEY_DERIVATION_INFO);
        h.update((community.len() as u64).to_le_bytes());
        h.update(community.as_bytes());
        h.update(secret);
        let seed: [u8; 32] = h.finalize().into();
        let mut rng = ChaCha20Rng::from_seed(seed);
        Self::generate(community, &mut rng)
    }

    /// Fresh keys from `rng`. The in-process community object and the tests use this; a service
    /// uses [`Self::derive`], so that a restart finds the same keys.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the deployment parameters cannot be derived for `community`.
    pub fn generate<R: RngCore + CryptoRng>(
        community: &str,
        rng: &mut R,
    ) -> Result<Self, ProtoError> {
        let open = Open::setup(SetupParams::new(deployment_label(community)))?;
        // `hvk` is long-lived and bound to the fixed `pp`; the epoch lives in the class label,
        // never in this key (§13 C1).
        let (hvk, hsk) = open.helper_keygen(rng);
        let (tokens, token_verifier) = TokenIssuer::new(community, rng)?;
        Ok(Self {
            community: community.to_string(),
            open,
            hvk,
            hsk,
            tvk: token_verifier.tvk().clone(),
            tokens: Mutex::new(tokens),
            hsk_lock: Mutex::new(()),
        })
    }

    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn open(&self) -> &Open {
        &self.open
    }
    pub fn hvk(&self) -> &Hvk {
        &self.hvk
    }
    pub fn tvk(&self) -> &PSVerificationKey<E> {
        &self.tvk
    }

    /// The two public keys as a community publishes them, multibase.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Serialization`] if a key cannot be encoded.
    pub fn public_text(&self) -> Result<(String, String), ProtoError> {
        Ok((key_text(&self.hvk)?, key_text(&self.tvk)?))
    }

    /// Sign one vetter's root request under `vetter/<period>`.
    ///
    /// This is the blind half: the request carries a commitment, and what comes back is a
    /// pre-credential the vetter unblinds. The issuer never sees the credential it made, which
    /// is why it cannot recognise the holder later.
    ///
    /// **It checks nothing about the member.** Whether they hold the role, whether they already
    /// have a credential under this label, and whether the identifier is the one they were
    /// bound to are all facts about a community's records, not about this key: the caller
    /// checks them, durably, before calling.
    ///
    /// `rng` is the issuance randomness. A service passes `OsRng`; a test passes a seeded one,
    /// which is what makes a wire fixture reproducible.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Pcs`] if the request does not verify under the deployment parameters.
    pub fn issue_root<R: RngCore + CryptoRng>(
        &self,
        period: &str,
        id: &G1,
        request: &RootRequest<E, Base>,
        rng: &mut R,
    ) -> Result<<Base as CredentialBase>::PreCredential, ProtoError> {
        let f = vetter_predicate(period);
        let _guard = self.hsk_lock.lock().expect("helper signing lock");
        Ok(self
            .open
            .issue_root(&self.hvk, &self.hsk, &f, id, request, rng)?)
    }

    /// Blind-sign one tick of the drip: at most `quota` tokens for `member` under `label`.
    ///
    /// `quota` is the community's published drip rate. It is enforced **here**, not by how many
    /// requests a vetter chooses to send: an unchecked batch is an unbounded one, and the whole
    /// point of a token is that it is scarce. The caller has already checked, durably, that
    /// this member holds the role and has not been served for this tick.
    ///
    /// # Errors
    ///
    /// - [`ProtoError::OverQuota`] if more than `quota` tokens were asked for.
    /// - [`ProtoError::LabelNotLive`] if `label` is not open.
    /// - [`ProtoError::BadOpeningProof`] if a request's opening proof does not verify.
    pub fn issue_tokens<R: RngCore + CryptoRng>(
        &self,
        verifier: &TokenVerifier,
        order: DripOrder<'_>,
        rng: &mut R,
    ) -> Result<Vec<PSPreCredential<E>>, ProtoError> {
        if order.requests.len() > order.quota {
            return Err(ProtoError::OverQuota {
                asked: order.requests.len(),
                quota: order.quota,
            });
        }
        let mut tokens = self.tokens.lock().expect("token signing lock");
        tokens.issue(
            verifier,
            order.member,
            order.tick,
            order.label,
            order.requests,
            rng,
        )
    }
}

// -------------------------------------------------------------------------------------------
// What crosses the boundary
// -------------------------------------------------------------------------------------------
//
// Enrolment and the drip are exchanges: a vetter asks, the community answers. The bodies are
// here rather than in a transport, because they are the same whichever transport carries them —
// a Trust Task today, a REST call in a test, a direct call in the reference run.
//
// Binary values travel as multibase base58btc over the crate's canonical encoding, the
// convention `wire` already uses.

/// A vetter's request for a root credential under a class label.
///
/// `request` is the blinded half and carries no identity; `id` is the vetter's PCS identifier,
/// which the community records so that the same member cannot enrol a second identifier and
/// count twice (§13 C2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootRequestWire {
    /// `vetter/<period>` — the label asked for, so a stale client's request is refused rather
    /// than silently served under the current one.
    pub label: String,
    pub id: String,
    /// The `RootRequest`, as the library serialises it.
    pub request: serde_json::Value,
}

/// The community's answer: the blind pre-credential, which the vetter unblinds into a
/// credential the community has never seen.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootCredentialWire {
    pub label: String,
    pub pre_credential: String,
}

/// One committed serial with its opening proof, on the wire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenRequestWire {
    pub commitment: String,
    pub opening_proof: String,
}

impl TokenRequestWire {
    /// # Errors
    /// [`ProtoError::Serialization`] if a value cannot be encoded.
    pub fn of(request: &TokenRequest) -> Result<Self, ProtoError> {
        Ok(Self {
            commitment: crate::scheme::enc(&request.commitment)?,
            opening_proof: crate::scheme::enc(&request.opening_proof)?,
        })
    }

    /// # Errors
    /// [`ProtoError::Serialization`] if a value cannot be decoded.
    pub fn to_request(&self) -> Result<TokenRequest, ProtoError> {
        Ok(TokenRequest {
            commitment: crate::scheme::dec(&self.commitment)?,
            opening_proof: crate::scheme::dec(&self.opening_proof)?,
        })
    }
}

/// One tick of the drip, asked for. The tick is the vetter's own schedule counter: it is what
/// makes "once per tick" a rule the community can enforce without knowing whether the vetter
/// has been busy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenBatchRequestWire {
    pub label: String,
    pub tick: u32,
    pub requests: Vec<TokenRequestWire>,
}

/// One tick of the drip, answered.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenBatchWire {
    pub label: String,
    pub tick: u32,
    pub pre_credentials: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMUNITY: &str = "did:webvh:QmScid:kernel.example";

    /// The property the whole derivation rests on: one secret, the same keys, every time.
    #[test]
    fn derivation_is_deterministic_and_secret_bound() {
        let a = Issuer::derive(COMMUNITY, &[7u8; 32]).unwrap();
        let b = Issuer::derive(COMMUNITY, &[7u8; 32]).unwrap();
        assert_eq!(a.public_text().unwrap(), b.public_text().unwrap());

        // A different secret is a different community key — the failure mode the service has to
        // detect before it issues anything.
        let c = Issuer::derive(COMMUNITY, &[8u8; 32]).unwrap();
        assert_ne!(a.public_text().unwrap(), c.public_text().unwrap());

        // And so is a different community, under the same secret: the deployment label is part
        // of the parameters the helper key is bound to.
        let d = Issuer::derive("did:webvh:QmOther:other.example", &[7u8; 32]).unwrap();
        assert_ne!(a.public_text().unwrap(), d.public_text().unwrap());
    }

    /// `hvk` and `tvk` are two keys, not one used twice (§5.1): a token signature made under
    /// the helper key would *be* a vetter credential whose secret the vetter knows.
    #[test]
    fn the_two_keys_are_different() {
        let issuer = Issuer::derive(COMMUNITY, &[1u8; 32]).unwrap();
        let (hvk, tvk) = issuer.public_text().unwrap();
        assert_ne!(hvk, tvk);
    }

    /// A vetter asking for more than the community's drip rate is refused, and the refusal
    /// happens before any signature: the quota is the cap, not the vetter's own restraint.
    #[test]
    fn a_batch_over_the_quota_is_refused_and_one_within_it_is_signed() {
        use crate::token::TokenWallet;
        use rand::{SeedableRng, rngs::StdRng};

        const LABEL: &str = "token/2026-09";
        let issuer = Issuer::derive(COMMUNITY, &[2u8; 32]).unwrap();
        let verifier = TokenVerifier::new(COMMUNITY, issuer.tvk().clone(), [LABEL.to_string()])
            .expect("verifier");
        let mut rng = StdRng::seed_from_u64(9);
        let mut wallet = TokenWallet::new(COMMUNITY).unwrap();

        let greedy = wallet
            .prepare(issuer.tvk(), LABEL, "member-1", 1, 8, &mut rng)
            .unwrap();
        assert_eq!(
            issuer.issue_tokens(
                &verifier,
                DripOrder {
                    member: "member-1",
                    tick: 1,
                    label: LABEL,
                    requests: &greedy,
                    quota: 3,
                },
                &mut rng
            ),
            Err(ProtoError::OverQuota { asked: 8, quota: 3 })
        );

        let within = wallet
            .prepare(issuer.tvk(), LABEL, "member-1", 2, 3, &mut rng)
            .unwrap();
        let pres = issuer
            .issue_tokens(
                &verifier,
                DripOrder {
                    member: "member-1",
                    tick: 2,
                    label: LABEL,
                    requests: &within,
                    quota: 3,
                },
                &mut rng,
            )
            .expect("three is within the drip rate");
        assert_eq!(pres.len(), 3);
        wallet
            .receive(issuer.tvk(), &pres)
            .expect("the tokens unblind under the published key");
        assert_eq!(wallet.free(), 3);
    }
}
