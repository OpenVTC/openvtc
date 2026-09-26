/*!
 * Personhood assertion — the member side of the VTC's personhood ceremony.
 *
 * A community that vets its members can mark them as people. The claim lands
 * as a `PersonhoodCredential` type on the member's VMC, which is what DTG
 * Credentials means by a PHC ("a PHC is simply a VMC issued by a VTC whose
 * governance enforces real human personhood and exactly one membership per
 * person"). Nothing here decides whether the member *is* a person — the
 * community's `personhood.rego` does, over the evidence this module presents.
 *
 * ## The ceremony
 *
 * 1. `vtc/members/personhood/challenge/0.1` → the community mints a
 *    single-use nonce with a ten-minute life.
 * 2. Out of band, two humans confirm they are talking about the same
 *    ceremony — see [`match_code`].
 * 3. `vtc/members/personhood/assert/0.1` → the member presents a signed VP
 *    carrying that nonce and whatever credentials the community's policy
 *    wants to see.
 *
 * Both verbs ride the same Trust Task document path as the join ceremony
 * ([`crate::join`]): DIDComm wraps the document in an authcrypt envelope, TSP
 * carries it bare. The sender is cryptographically proven either way, so no
 * separate holder-binding signature rides along.
 *
 * ## Why the challenge is written twice
 *
 * The published task says the presentation's `proof.challenge` must be the
 * paired `challengeId`, and that this is what "stops one captured and
 * replayed into another". In W3C Data Integrity that holds because the proof
 * options are canonicalised with the document, so `challenge` is signed.
 *
 * `affinidi_data_integrity` has no `challenge` proof option, and the VTC
 * verifies over the presentation with the whole `proof` block removed — so a
 * value written only to `proof.challenge` is **not covered by the
 * signature**, and swapping it on a captured presentation would go unnoticed.
 *
 * So [`build_presentation`] writes the challenge to `proof.challenge` (what
 * the spec names) *and* to top-level `nonce` (what the signature actually
 * covers), and the VTC requires both to agree. Do not "simplify" this by
 * dropping one: `proof.challenge` alone is unsigned, and `nonce` alone is
 * off-spec.
 */

use std::sync::Arc;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::Secret,
};
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::OpenVTCError;

/// `vtc/members/personhood/challenge/0.1`.
pub const PERSONHOOD_CHALLENGE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/personhood/challenge/0.1";

/// `vtc/members/personhood/assert/0.1`.
pub const PERSONHOOD_ASSERT_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/personhood/assert/0.1";

/// The community's reply to a challenge request.
///
/// Spelled out rather than built with `format!` because the inbound router
/// matches on it: a `const` can be compared directly, and the pair below is
/// pinned against the request types by a test so a typo cannot make a reply
/// simply never arrive.
pub const PERSONHOOD_CHALLENGE_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/personhood/challenge/0.1#response";

/// The community's reply to an assertion.
pub const PERSONHOOD_ASSERT_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/personhood/assert/0.1#response";

/// W3C VC Data Model 2.0 context — the presentation's `@context`.
const VC_V2_CONTEXT_URL: &str = "https://www.w3.org/ns/credentials/v2";

// ─── The spoken match code ───────────────────────────────────────────────

/// Domain separation for the match-code derivation. Must match the VTC's
/// `vtc_service::members::match_code::DOMAIN_TAG` byte for byte — the two
/// sides only agree because they compute the same digest over the same
/// input.
const MATCH_DOMAIN_TAG: &[u8] = b"vtc-personhood-match/v1\0";

/// Crockford base32 — no `I`, `L`, `O`, `U`, so nothing in a code is
/// confusable when it is said out loud.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in the code, excluding the separator.
const CODE_CHARS: usize = 8;

/// Bits drawn from the digest — the exact capacity of eight base32
/// characters.
const CODE_BITS: usize = CODE_CHARS * 5;

/// Derive the eight-character code for a challenge id, formatted
/// `XXXX-XXXX`.
///
/// The `challengeId` is a UUID: fine on a wire, hopeless read aloud. This is
/// what the two people in the room actually say to each other, and it is
/// **derived** from the challenge rather than transferred — anyone already
/// holding the id computes the same characters, and anyone who does not
/// cannot. Nothing on the VTC checks it; it proves nothing that
/// `proof.challenge` does not already prove. It exists so a human can tell
/// that the ceremony their client is about to answer is the one the
/// administrator in front of them just started, the way a Bluetooth pairing
/// code does.
///
/// The VTC returns the same value in the challenge reply's `ext` under
/// `org.openvtc.match-code`; [`match_code`] recomputing it locally means the
/// member's client can show it even when the reply's `ext` is absent, and
/// means a disagreement between the two is visible rather than silent.
pub fn match_code(challenge_id: &Uuid) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MATCH_DOMAIN_TAG);
    hasher.update(challenge_id.as_bytes());
    let digest = hasher.finalize();

    let mut out = String::with_capacity(CODE_CHARS + 1);
    for (i, bit_offset) in (0..CODE_BITS).step_by(5).enumerate() {
        let mut idx = 0u8;
        for bit in 0..5 {
            let abs = bit_offset + bit;
            let byte = digest[abs / 8];
            idx = (idx << 1) | ((byte >> (7 - (abs % 8))) & 1);
        }
        if i == 4 {
            out.push('-');
        }
        out.push(CROCKFORD[idx as usize] as char);
    }
    out
}

/// Read the match code the VTC sent in a challenge reply's `ext`, if it is
/// there.
///
/// Prefer comparing this against [`match_code`] rather than trusting either
/// alone: they are computed by different implementations from the same
/// challenge id, so a mismatch means the two sides disagree about the
/// derivation and the spoken confirmation is worthless. Absent is fine — an
/// older VTC simply does not send it.
pub fn match_code_from_reply(ext: &Value) -> Option<String> {
    ext.get("org.openvtc.match-code")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

// ─── Trust Task documents ────────────────────────────────────────────────

/// Everything needed to get a document from this member to that community.
///
/// Grouped rather than passed as loose arguments because both verbs need the
/// identical set, and a six-parameter tail of same-typed `&str` DIDs is one
/// transposed pair away from sending a member's presentation to their own
/// mediator's DID.
pub struct Route<'a> {
    pub atm: &'a ATM,
    pub profile: &'a Arc<ATMProfile>,
    /// The member acting — the authcrypt sender / TSP sender VID, and so the
    /// identity the community proves this request came from.
    pub member_did: &'a str,
    /// The community being addressed.
    pub vtc_did: &'a str,
    /// The member's own mediator, for the DIDComm leg.
    pub mediator_did: &'a str,
    /// The community's advertised TSP mediator, when it advertises `#tsp`.
    ///
    /// `Some` sends the bare Trust Task document over TSP; `None` wraps it
    /// in DIDComm. Discovery belongs to the caller — same rule as
    /// [`crate::join::submit_join_request`] — so a VTC that does not
    /// advertise `#tsp` degrades to DIDComm rather than failing.
    pub tsp_mediator_did: Option<&'a str>,
}

/// The DIDComm message carrying a personhood document to its community: the
/// binding envelope, with the document as the body and its id as the message
/// id — so the reply's `thid` and the document's `threadId` coincide.
fn didcomm_request(document_id: String, body: Value, member_did: &str, vtc_did: &str) -> Message {
    let now = Utc::now().timestamp().max(0) as u64;
    Message::build(
        document_id,
        crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(member_did.to_string())
    .to(vtc_did.to_string())
    .created_time(now)
    .finalize()
}

impl Route<'_> {
    /// Send a built document over whichever transport this route selects.
    async fn send(&self, body: Value, document_id: String) -> Result<(), OpenVTCError> {
        match self.tsp_mediator_did {
            Some(tsp_mediator) => {
                crate::tsp::send_trust_task(
                    self.atm,
                    self.profile,
                    &body,
                    self.vtc_did,
                    tsp_mediator,
                )
                .await?;
            }
            None => {
                // The binding envelope, not the task URI: a community refuses
                // a Trust Task typed as itself (`bindings/didcomm/0.2` §2–§4,
                // VTI #1687).
                let msg = didcomm_request(document_id, body, self.member_did, self.vtc_did);
                crate::pack_and_send(
                    self.atm,
                    self.profile,
                    &msg,
                    self.member_did,
                    self.vtc_did,
                    self.mediator_did,
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// Ask the community for a personhood challenge
/// (`vtc/members/personhood/challenge/0.1`).
///
/// Returns the correlation handle the VTC's reply threads on — the same
/// value on either transport, for the reason [`crate::join`] documents: the
/// DIDComm message id is set to the Trust Task document id, so DIDComm's
/// `thid` and TSP's `threadId` coincide.
///
/// The reply carries the `challengeId` to sign against and, from a VTC new
/// enough to send it, the match code in `ext`. Nothing is awaited here; the
/// reply arrives asynchronously like every other Trust Task response.
///
/// `subject_did` is who the challenge is for. A member asking for their own
/// is the ordinary case; an administrator may ask for another member's,
/// which is the in-person ceremony — the community mints it, the
/// administrator reads the code to the person in front of them, and that
/// person's own client answers it. Minting for someone else confers
/// nothing: the nonce is bound to the subject, and only a presentation
/// signed by the subject's key can spend it.
///
/// Signed with `signing_secret` under `proofPurpose: authentication` —
/// `vtc/members/personhood/challenge/0.1` declares `proof` REQUIRED
/// (trust-tasks 0.23) — the same key and purpose [`assert_personhood`]
/// signs the presentation with, since both are the member acting rather
/// than making a claim to be held to later.
pub async fn request_challenge(
    route: &Route<'_>,
    subject_did: &str,
    signing_secret: &Secret,
) -> Result<Uuid, OpenVTCError> {
    let request_id = Uuid::new_v4();
    let document_id = format!("urn:uuid:{request_id}");
    let body = build_challenge_request(
        route.member_did,
        route.vtc_did,
        &document_id,
        subject_did,
        signing_secret,
    )
    .await?;

    route.send(body, document_id).await?;

    Ok(request_id)
}

/// Build the signed `vtc/members/personhood/challenge/0.1` document —
/// split out from [`request_challenge`] so the signing can be tested
/// without a live [`Route`].
async fn build_challenge_request(
    member_did: &str,
    vtc_did: &str,
    document_id: &str,
    subject_did: &str,
    signing_secret: &Secret,
) -> Result<Value, OpenVTCError> {
    crate::trust_task_doc::build_signed_value_as(
        PERSONHOOD_CHALLENGE_TYPE,
        member_did,
        vtc_did,
        document_id,
        json!({ "did": subject_did }),
        signing_secret,
        "authentication",
    )
    .await
}

/// Build and sign the presentation the assert verb carries.
///
/// `credentials` are the whole signed VCs to present — `eddsa-jcs-2022`
/// credentials cannot be redacted, so each one is presented entire. Which of
/// them satisfy the community is the community's `personhood.rego` to
/// decide; presenting more than it needs discloses more than it needs, so
/// callers should pass what the community asked for rather than the wallet.
///
/// The challenge is written to both `nonce` and `proof.challenge` — see this
/// module's header for why neither alone is sufficient.
pub async fn build_presentation(
    signing_secret: &Secret,
    member_did: &str,
    challenge_id: &Uuid,
    credentials: Vec<Value>,
) -> Result<Value, OpenVTCError> {
    let challenge = challenge_id.to_string();

    // Sign over this exact shape minus `proof` — JCS canonicalisation is
    // sensitive to field presence, so the proof is inserted afterwards and
    // anything that must be signed has to be in here.
    let vp = json!({
        "@context": [VC_V2_CONTEXT_URL],
        "type": ["VerifiablePresentation"],
        "holder": member_did,
        "verifiableCredential": credentials,
        "nonce": challenge,
    });

    let proof = DataIntegrityProof::sign(
        &vp,
        signing_secret,
        SignOptions::new()
            .with_proof_purpose("authentication")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| OpenVTCError::Config(format!("sign personhood presentation: {e}")))?;

    let mut proof_value = serde_json::to_value(&proof)
        .map_err(|e| OpenVTCError::Config(format!("serialize presentation proof: {e}")))?;
    // `challenge` is not a field `DataIntegrityProof` carries, so it is
    // added to the serialised proof rather than set through `SignOptions`.
    // That is precisely why it is unsigned, and why `nonce` above exists.
    proof_value
        .as_object_mut()
        .ok_or_else(|| OpenVTCError::Config("proof did not serialize to an object".into()))?
        .insert("challenge".to_string(), Value::String(challenge));

    let mut signed = vp;
    signed
        .as_object_mut()
        .expect("presentation is an object")
        .insert("proof".to_string(), proof_value);
    Ok(signed)
}

/// Assert personhood (`vtc/members/personhood/assert/0.1`).
///
/// The community verifies the presentation against `member_did`'s resolved
/// key, consumes the challenge, runs its personhood policy, and — if it
/// allows — re-mints the member's VMC carrying `PersonhoodCredential` and
/// their role credential. The reply carries both.
///
/// The member is always the subject. The community refuses an assertion sent
/// by anyone else, because `assert/0.1` declares `actsAsSubject: true`: this
/// is the member exercising authority over their own personhood state.
pub async fn assert_personhood(
    route: &Route<'_>,
    signing_secret: &Secret,
    challenge_id: &Uuid,
    credentials: Vec<Value>,
) -> Result<Uuid, OpenVTCError> {
    let presentation =
        build_presentation(signing_secret, route.member_did, challenge_id, credentials).await?;

    let request_id = Uuid::new_v4();
    let document_id = format!("urn:uuid:{request_id}");
    // Signed with the same key — and the same proof purpose — that signed
    // the presentation inside it: `vtc/members/personhood/assert/0.1`
    // declares `proof` REQUIRED, and `signing_secret` is the persona's
    // authentication key (#key-2), which is listed only under
    // `authentication` in the DID document, not `assertionMethod`.
    let body = crate::trust_task_doc::build_signed_value_as(
        PERSONHOOD_ASSERT_TYPE,
        route.member_did,
        route.vtc_did,
        &document_id,
        json!({ "did": route.member_did, "presentation": presentation }),
        signing_secret,
        "authentication",
    )
    .await?;

    route.send(body, document_id).await?;

    Ok(request_id)
}

// ─── Replies ─────────────────────────────────────────────────────────────

/// Take the task-specific payload out of a VTC Trust Task reply body.
///
/// Same normalisation [`crate::messaging`] applies: anything dispatched
/// through the VTC's `dispatch_trust_task_core` comes back as the whole
/// `#response` document with the members nested under `payload`, while a
/// hand-built reply carries the bare body. None of the bare bodies has a
/// `payload` member, so the test is unambiguous — and it makes this
/// transport-agnostic, since a TSP frame carries the response document raw.
fn reply_payload(body: &Value) -> Value {
    match body.get("payload") {
        Some(payload) => payload.clone(),
        None => body.clone(),
    }
}

/// What the community answered a challenge request with.
#[derive(Debug, Clone)]
pub struct ChallengeReply {
    /// The nonce to sign against.
    pub challenge_id: Uuid,
    /// When the community stops accepting a presentation for it.
    pub expires_at: chrono::DateTime<Utc>,
    /// The code to say out loud, derived locally from [`Self::challenge_id`].
    pub match_code: String,
}

/// Parse a `members/personhood/challenge/0.1#response`.
///
/// When the community sends its own copy of the match code, it is compared
/// against the one derived here and a disagreement is an error rather than a
/// shrug. The two are computed by different implementations, so if they
/// differ, the spoken confirmation is worthless — and the failure is
/// otherwise invisible, because both sides still show eight plausible
/// characters and the people in the room just conclude they have the wrong
/// ceremony.
pub fn parse_challenge_reply(body: &Value) -> Result<ChallengeReply, OpenVTCError> {
    let payload = reply_payload(body);

    let challenge_id = payload
        .get("challengeId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OpenVTCError::Config("challenge reply has no challengeId".into()))?
        .parse::<Uuid>()
        .map_err(|e| OpenVTCError::Config(format!("challengeId is not a UUID: {e}")))?;

    let expires_at = payload
        .get("expiresAt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OpenVTCError::Config("challenge reply has no expiresAt".into()))?
        .parse::<chrono::DateTime<Utc>>()
        .map_err(|e| OpenVTCError::Config(format!("expiresAt is not a timestamp: {e}")))?;

    let derived = match_code(&challenge_id);
    if let Some(theirs) = payload.get("ext").and_then(match_code_from_reply)
        && theirs != derived
    {
        return Err(OpenVTCError::Config(format!(
            "match code disagreement: the community says {theirs}, this client derives \
             {derived} from the same challenge — the two implementations have drifted and \
             the spoken confirmation cannot be trusted"
        )));
    }

    Ok(ChallengeReply {
        challenge_id,
        expires_at,
        match_code: derived,
    })
}

/// What the community answered an assertion with: the flag, and the freshly
/// re-issued credentials that now carry it.
#[derive(Debug, Clone)]
pub struct AssertReply {
    pub did: String,
    /// Always `true` on success — the community answers a refusal with a
    /// `trust-task-error` document, not with `personhood: false`.
    pub personhood: bool,
    /// The re-minted VMC, carrying `PersonhoodCredential` in its `type`.
    pub vmc: Value,
    /// The re-minted role credential.
    pub role_vec: Value,
}

/// Parse a `members/personhood/assert/0.1#response`.
pub fn parse_assert_reply(body: &Value) -> Result<AssertReply, OpenVTCError> {
    let payload = reply_payload(body);
    Ok(AssertReply {
        did: payload
            .get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OpenVTCError::Config("assert reply has no did".into()))?
            .to_string(),
        personhood: payload
            .get("personhood")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        vmc: payload.get("vmc").cloned().unwrap_or(Value::Null),
        role_vec: payload.get("roleVec").cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {

    /// Over DIDComm a personhood document rides the binding envelope — a VTC
    /// refuses one typed as its task URI (VTI #1687) — with the document as the
    /// body and its id as the message id.
    #[test]
    fn a_personhood_document_rides_the_binding_envelope() {
        let body = serde_json::json!({ "type": PERSONHOOD_CHALLENGE_TYPE, "id": "urn:uuid:1" });
        let msg = didcomm_request(
            "urn:uuid:1".into(),
            body.clone(),
            "did:key:zMember",
            "did:key:zVtc",
        );
        assert_eq!(msg.typ, crate::capabilities::TRUST_TASK_ENVELOPE_TYPE);
        assert_eq!(msg.id, "urn:uuid:1");
        assert_eq!(msg.body, body);
        assert_eq!(msg.from.as_deref(), Some("did:key:zMember"));
    }

    use super::*;

    const MEMBER: &str = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";

    fn secret() -> Secret {
        Secret::from_multibase(
            // Deterministic test key; the DID above is its `did:key` form.
            "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
            Some(&format!("{MEMBER}#key-0")),
        )
        .expect("test secret")
    }

    /// Each response type is its request type plus `#response`. The inbound
    /// router matches these as constants, so a typo would not fail anything —
    /// the reply would simply never be routed, and the ceremony would hang
    /// with no error anywhere.
    #[test]
    fn response_types_are_their_request_types() {
        assert_eq!(
            PERSONHOOD_CHALLENGE_RESPONSE_TYPE,
            format!("{PERSONHOOD_CHALLENGE_TYPE}#response")
        );
        assert_eq!(
            PERSONHOOD_ASSERT_RESPONSE_TYPE,
            format!("{PERSONHOOD_ASSERT_TYPE}#response")
        );
    }

    /// The code is a pure function of the challenge id — that is the whole
    /// mechanism. If it ever stops being one, the administrator and the
    /// member see different characters and the spoken confirmation quietly
    /// stops meaning anything.
    #[test]
    fn match_code_is_deterministic() {
        let id = Uuid::parse_str("6f1c4f9e-7c2a-4f4b-9a3e-2b1d0c5e8a77").expect("uuid");
        assert_eq!(match_code(&id), match_code(&id));
    }

    /// Shape a human reads aloud, from an alphabet with nothing mishearable
    /// in it.
    #[test]
    fn match_code_is_four_dash_four_from_crockford() {
        let code = match_code(&Uuid::new_v4());
        assert_eq!(code.len(), CODE_CHARS + 1);
        assert_eq!(code.as_bytes()[4], b'-');
        for c in code.bytes().filter(|c| *c != b'-') {
            assert!(CROCKFORD.contains(&c), "{} is outside Crockford", c as char);
        }
        for c in *b"ILOU" {
            assert!(!CROCKFORD.contains(&c), "{} is confusable", c as char);
        }
    }

    /// **The cross-implementation pin.** This value was produced by the
    /// VTC's `vtc_service::members::match_code::derive`. The two sides agree
    /// only because they compute the same digest over the same bytes, and
    /// nothing else in either repo would catch them drifting — a changed
    /// domain tag or alphabet on either side yields eight plausible
    /// characters that simply never match, which reads to an operator as
    /// "the code is wrong" rather than "the code is broken".
    #[test]
    fn match_code_agrees_with_the_vtc() {
        let id = Uuid::parse_str("6f1c4f9e-7c2a-4f4b-9a3e-2b1d0c5e8a77").expect("uuid");
        assert_eq!(match_code(&id), "5CY1-GZEE");
    }

    /// The challenge must land in both places: `proof.challenge` because
    /// that is what the published task names, and `nonce` because that is
    /// what the signature covers. A presentation carrying only the first is
    /// replayable; one carrying only the second is off-spec.
    #[tokio::test]
    async fn presentation_carries_the_challenge_signed_and_unsigned() {
        let id = Uuid::new_v4();
        let vp = build_presentation(&secret(), MEMBER, &id, vec![])
            .await
            .expect("build presentation");

        assert_eq!(
            vp["nonce"].as_str(),
            Some(id.to_string().as_str()),
            "the signed copy of the challenge is missing"
        );
        assert_eq!(
            vp["proof"]["challenge"].as_str(),
            Some(id.to_string().as_str()),
            "the copy the published task names is missing"
        );
        assert_eq!(vp["holder"].as_str(), Some(MEMBER));
    }

    /// The presentation is signed under `proofPurpose: authentication`, not
    /// the Data-Integrity default of `assertionMethod` — VTI-KEY-022. The
    /// signing key this ceremony uses (`keys.authentication`, #key-2) is
    /// listed only under `authentication` in the DID document, so a peer
    /// enforcing the strict proof-purpose rule refuses a proof that claims
    /// any other purpose for it.
    #[tokio::test]
    async fn presentation_is_signed_under_authentication_proof_purpose() {
        let vp = build_presentation(&secret(), MEMBER, &Uuid::new_v4(), vec![])
            .await
            .expect("build presentation");

        assert_eq!(vp["proof"]["proofPurpose"].as_str(), Some("authentication"));
    }

    /// `vtc/members/personhood/challenge/0.1` also declares `proof` REQUIRED
    /// as of trust-tasks 0.23, and is signed the same way the assertion it
    /// pairs with is: with the authentication key, under `proofPurpose:
    /// authentication`.
    #[tokio::test]
    async fn challenge_request_is_signed_under_authentication_proof_purpose() {
        let doc = build_challenge_request(MEMBER, "did:key:zVtc", "urn:uuid:1", MEMBER, &secret())
            .await
            .expect("build challenge request");

        assert_eq!(
            doc["proof"]["proofPurpose"].as_str(),
            Some("authentication")
        );
    }

    const CHALLENGE: &str = "6f1c4f9e-7c2a-4f4b-9a3e-2b1d0c5e8a77";

    /// The reply as `vtc-service` actually sends it: the whole `#response`
    /// document, task members nested under `payload`.
    fn challenge_response_document(ext: Value) -> Value {
        json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000000",
            "type": format!("{PERSONHOOD_CHALLENGE_TYPE}#response"),
            "payload": {
                "challengeId": CHALLENGE,
                "expiresAt": "2026-08-24T10:15:00Z",
                "ext": ext,
            }
        })
    }

    #[test]
    fn challenge_reply_yields_the_nonce_and_the_spoken_code() {
        let reply = parse_challenge_reply(&challenge_response_document(
            json!({ "org.openvtc.match-code": "5CY1-GZEE" }),
        ))
        .expect("parse challenge reply");

        assert_eq!(reply.challenge_id.to_string(), CHALLENGE);
        assert_eq!(reply.match_code, "5CY1-GZEE");
    }

    /// A community that does not send its copy is fine — the code is derived
    /// locally, so an older VTC costs nothing.
    #[test]
    fn challenge_reply_without_the_community_copy_still_derives_the_code() {
        let mut doc = challenge_response_document(json!({}));
        doc["payload"]
            .as_object_mut()
            .expect("payload object")
            .remove("ext");

        let reply = parse_challenge_reply(&doc).expect("parse challenge reply");
        assert_eq!(reply.match_code, "5CY1-GZEE");
    }

    /// A community whose copy *disagrees* is not fine. Both sides would
    /// still show eight plausible characters, so without this the operator
    /// concludes they have the wrong ceremony rather than that the two
    /// implementations have drifted.
    #[test]
    fn challenge_reply_refuses_a_match_code_disagreement() {
        let err = parse_challenge_reply(&challenge_response_document(
            json!({ "org.openvtc.match-code": "0000-0000" }),
        ))
        .expect_err("a disagreement must not pass silently");

        assert!(
            err.to_string().contains("drifted"),
            "the error should name the cause, got: {err}"
        );
    }

    /// The bare-body shape, for a reply built outside the dispatcher.
    #[test]
    fn a_reply_without_a_payload_wrapper_is_read_whole() {
        let bare = json!({
            "did": MEMBER,
            "personhood": true,
            "vmc": { "type": ["VerifiableCredential", "MembershipCredential",
                              "PersonhoodCredential"] },
            "roleVec": { "type": ["VerifiableCredential", "EndorsementCredential"] },
        });
        let reply = parse_assert_reply(&bare).expect("parse assert reply");

        assert!(reply.personhood);
        assert_eq!(reply.did, MEMBER);
        assert_eq!(
            reply.vmc["type"][2].as_str(),
            Some("PersonhoodCredential"),
            "the re-minted VMC is what carries the claim"
        );
    }

    /// `nonce` is inside the signed body, so tampering with it invalidates
    /// the proof — which is the entire reason it carries the challenge.
    /// `proof.challenge` is outside it and cannot do this job alone.
    #[tokio::test]
    async fn the_signed_nonce_is_covered_by_the_proof() {
        let id = Uuid::new_v4();
        let vp = build_presentation(&secret(), MEMBER, &id, vec![])
            .await
            .expect("build presentation");

        let proof: DataIntegrityProof =
            serde_json::from_value(vp["proof"].clone()).expect("parse proof");
        let holder = secret();
        let pubkey = holder.get_public_bytes().to_vec();

        let mut tampered = vp.clone();
        tampered.as_object_mut().unwrap().remove("proof");
        assert!(
            proof
                .verify_with_public_key(
                    &tampered,
                    &pubkey,
                    affinidi_data_integrity::VerifyOptions::new()
                )
                .is_ok(),
            "the untampered presentation must verify"
        );

        tampered["nonce"] = Value::String(Uuid::new_v4().to_string());
        assert!(
            proof
                .verify_with_public_key(
                    &tampered,
                    &pubkey,
                    affinidi_data_integrity::VerifyOptions::new()
                )
                .is_err(),
            "swapping the nonce must break the proof — otherwise the challenge is not bound \
             to anything and a captured presentation is replayable"
        );
    }
}
