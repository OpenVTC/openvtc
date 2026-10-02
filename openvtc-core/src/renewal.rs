//! Renewing a membership (`vtc/members/renew/0.1`).
//!
//! A member asks its community to re-issue the membership credential (VMC) and
//! role credential (role VAC) it holds. The request carries no parameters: the
//! subject is the member that signed it, and the community answers only about
//! that member. The answer carries both credentials inline —
//! `{ did, vmc, roleVac, personhood, personhoodChanged }` — rather than as
//! separate `credential-exchange/issue` pushes, so this module verifies them
//! itself, to the same standard an issued credential is held to.
//!
//! ## Why a member renews
//!
//! The DTG Credentials v1 migration made every credential issued before it
//! non-conformant. Those are set aside on load
//! ([`RetiredCredential`]), and the membership is left without the credentials
//! it needs to present. Renewal is how the member gets conformant replacements:
//! storing them clears the notices through the same
//! [`CommunityRecord::clear_retired`](crate::config::account::CommunityRecord::clear_retired) path a pushed credential takes.
//!
//! ## What is checked before anything is stored
//!
//! - The reply is the community's signed operational document
//!   ([`crate::operational`]): issued by the community, under its
//!   `authentication` key, addressed to the persona that asked, fresh, and not
//!   seen before.
//! - Both credentials are conformant DTG v1 credentials
//!   ([`crate::dtg::parse_conformant`]) issued by the community to that
//!   persona: the VMC a `MembershipCredential` with `issuerScope: public`, the
//!   role VAC a community role credential ([`crate::dtg::community_roles`]:
//!   `issuerScope: public`, `authority.scope` the community, no parent).
//! - Both verify as issued credentials ([`verify_issued_credential`]): proof
//!   under the community's `assertionMethod`, validity window, revocation status
//!   (fails closed).
//! - The membership is one we hold, Active, with that community.
//!
//! The local shape checks come before the network-bound ones, so a malformed
//! reply never costs a resolve or a status-list fetch.
//!
//! ## The acknowledgement is owed again
//!
//! A re-issued grant has a different digest, so the member's acknowledgement of
//! the previous one no longer completes the membership edge (see
//! [`crate::members`]); the community drops it on renewal. The caller sends a
//! fresh one for the new grant, as the join flow does on admission.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use dtg_credentials::{DTGCredentialType, IssuerScope};
use serde_json::Value;
use trust_tasks_rs::specs::vtc::members::renew::v0_1 as renew;
use uuid::Uuid;

use crate::CredentialKind;
use crate::config::account::{Account, PersonaId, RetiredCredential};
use crate::errors::OpenVTCError;
use crate::issued_credential::{
    IssuedCredentialError, VerifiedIssuedCredential, verify_issued_credential,
};
use crate::operational::{OperationalError, SeenDocuments, VerifiedOperational};

/// `vtc/members/renew/0.1`.
pub const MEMBERS_RENEW_TYPE: &str = <renew::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The community's answer to a renewal.
pub const MEMBERS_RENEW_RESPONSE_TYPE: &str =
    <renew::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// `vtc/members/renew:notMember` — the community holds no membership for the
/// member that asked.
pub const RENEW_NOT_MEMBER: &str = renew::error_codes::NOT_MEMBER.code;

// ─── Outstanding requests ────────────────────────────────────────────────

/// Renewals we have asked for: request id → who asked whom, and when.
///
/// In memory, like the community-profile questions in [`crate::join`]: a
/// renewal is this process's, and an answer arriving after a restart is not
/// taken — the member asks again, which is harmless (renewal is idempotent on
/// the community's side, re-minting into the same status-list slot).
static PENDING: LazyLock<Mutex<HashMap<Uuid, Pending>>> = LazyLock::new(Default::default);

struct Pending {
    vtc_did: String,
    member_did: String,
    at: Instant,
}

/// How long a renewal waits for its answer.
const PENDING_TTL: Duration = Duration::from_secs(600);

/// Most renewals outstanding at once.
const MAX_PENDING: usize = 64;

/// The request id a reply's `thid` names. The request is sent with its
/// document id as the DIDComm message id (`urn:uuid:<id>`), and a community
/// may thread on either form.
fn request_id_of(thid: &str) -> Option<Uuid> {
    Uuid::parse_str(thid.strip_prefix("urn:uuid:").unwrap_or(thid)).ok()
}

/// Record that `member_did` asked `vtc_did` to renew, under `request_id` — the
/// id the reply threads on. [`request_renewal`] does this itself; it is exposed
/// for a caller that delivers the document by another route (and for tests of
/// the reply's handling).
pub fn record_request(request_id: Uuid, vtc_did: &str, member_did: &str) {
    if let Ok(mut pending) = PENDING.lock() {
        pending.retain(|_, p| p.at.elapsed() < PENDING_TTL);
        if pending.len() < MAX_PENDING {
            pending.insert(
                request_id,
                Pending {
                    vtc_did: vtc_did.to_string(),
                    member_did: member_did.to_string(),
                    at: Instant::now(),
                },
            );
        }
    }
}

fn forget(request_id: Uuid) {
    if let Ok(mut pending) = PENDING.lock() {
        pending.remove(&request_id);
    }
}

/// Whether `thid` answers a renewal we asked `vtc_did` for, still unanswered.
/// Does not consume it: a reply is taken ([`take_pending`]) only once it has
/// been verified.
#[must_use]
pub fn is_pending(vtc_did: &str, thid: &str) -> bool {
    let Some(id) = request_id_of(thid) else {
        return false;
    };
    PENDING.lock().is_ok_and(|pending| {
        pending
            .get(&id)
            .is_some_and(|p| p.vtc_did == vtc_did && p.at.elapsed() < PENDING_TTL)
    })
}

/// Take the renewal `thid` answers, if it is one we asked `vtc_did` for.
/// Returns the member DID that asked. Consumes it: a renewal is answered once.
#[must_use]
pub fn take_pending(vtc_did: &str, thid: &str) -> Option<String> {
    let id = request_id_of(thid)?;
    let mut pending = PENDING.lock().ok()?;
    match pending.get(&id) {
        Some(p) if p.vtc_did == vtc_did && p.at.elapsed() < PENDING_TTL => {
            pending.remove(&id).map(|p| p.member_did)
        }
        _ => None,
    }
}

// ─── The request ─────────────────────────────────────────────────────────

/// Ask the community to renew `route.member_did`'s membership
/// (`vtc/members/renew/0.1`).
///
/// The document has no parameters and is signed by `signer`, the persona's
/// **authentication** key: the task declares `proof` and `issuedAt` REQUIRED,
/// because the credentials it causes to be minted outlive the session that
/// asked for them. It rides the DIDComm binding envelope like every other
/// member verb ([`crate::members::submit_member_vmc`]).
///
/// Returns the request id the community's reply threads on. Nothing is awaited:
/// the reply arrives asynchronously and is verified by
/// [`verify_renewal_response`].
pub async fn request_renewal(
    route: &crate::members::Delivery<'_>,
    signer: &Secret,
) -> Result<Uuid, OpenVTCError> {
    let request_id = Uuid::new_v4();
    let document_id = format!("urn:uuid:{request_id}");
    let body = build_renew_request(route.member_did, route.vtc_did, &document_id, signer).await?;

    // Remembered before the send, so a reply quicker than the return from
    // the send still finds its request.
    record_request(request_id, route.vtc_did, route.member_did);
    if let Err(e) = crate::members::send_document(route, document_id, body).await {
        forget(request_id);
        return Err(e);
    }
    Ok(request_id)
}

/// Build the signed `vtc/members/renew/0.1` document — split out from
/// [`request_renewal`] so its shape can be tested without a mediator.
async fn build_renew_request(
    member_did: &str,
    vtc_did: &str,
    document_id: &str,
    signer: &Secret,
) -> Result<Value, OpenVTCError> {
    crate::trust_task_doc::build_signed_value(
        MEMBERS_RENEW_TYPE,
        member_did,
        vtc_did,
        document_id,
        renew::Payload::default(),
        signer,
    )
    .await
}

// ─── The reply ───────────────────────────────────────────────────────────

/// Why a renewal reply was not acted on. Names what failed, never a DID or the
/// credentials' contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenewalError {
    #[error("the renewal reply {0}")]
    Document(#[from] OperationalError),
    #[error("the renewal reply is not a vtc/members/renew/0.1 response")]
    Malformed,
    #[error("the renewal names a member other than the persona it was sent to")]
    WrongMember,
    #[error("the renewed membership credential is not a conformant community grant: {0}")]
    VmcShape(String),
    #[error("the renewed role credential is not a community role credential: {0}")]
    RoleShape(String),
    #[error("the renewed membership credential: {0}")]
    Vmc(IssuedCredentialError),
    #[error("the renewed role credential: {0}")]
    RoleVac(IssuedCredentialError),
    #[error("we hold no Active membership with that community for this persona")]
    NoMembership,
    #[error("the renewal reply was not checked")]
    NotChecked,
    #[error("the renewal reply's check did not finish (timed out or failed)")]
    CheckUnfinished,
}

/// A renewal reply whose document and credentials verified
/// ([`verify_renewal_response`]). The only way to obtain one outside tests, so
/// a caller holding one cannot have skipped a check.
#[derive(Debug, Clone)]
pub struct VerifiedRenewal {
    document: VerifiedOperational,
    did: String,
    vmc: VerifiedIssuedCredential,
    role_vac: VerifiedIssuedCredential,
    roles: Vec<String>,
    personhood: bool,
    personhood_changed: bool,
}

impl VerifiedRenewal {
    /// The reply document, for the caller to check against and commit to the
    /// replay set once it has been bound to a renewal we asked for.
    pub fn document(&self) -> &VerifiedOperational {
        &self.document
    }

    /// The member the community renewed — the persona the reply is addressed to.
    #[must_use]
    pub fn member_did(&self) -> &str {
        &self.did
    }
}

/// Parse the reply's payload as a `vtc/members/renew/0.1` response.
fn parse_response(document: &Value) -> Result<renew::Response, RenewalError> {
    let payload = document.get("payload").ok_or(RenewalError::Malformed)?;
    serde_json::from_value(payload.clone()).map_err(|_| RenewalError::Malformed)
}

/// The local checks on a renewal's credentials: conformant, issued by the
/// community to `member_did`, of the right kind and scope. Returns the roles the
/// role VAC confers.
fn check_shape(
    vmc: &Value,
    role_vac: &Value,
    community: &str,
    member_did: &str,
) -> Result<Vec<String>, RenewalError> {
    let grant = crate::dtg::parse_conformant(vmc).map_err(RenewalError::VmcShape)?;
    if grant.type_() != DTGCredentialType::Membership {
        return Err(RenewalError::VmcShape(
            "it is not a membership credential".into(),
        ));
    }
    if grant.issuer_scope() != IssuerScope::Public {
        return Err(RenewalError::VmcShape(
            "it does not declare issuerScope public".into(),
        ));
    }
    if grant.issuer() != community {
        return Err(RenewalError::VmcShape(
            "its issuer is not the community".into(),
        ));
    }
    if grant.subject() != member_did {
        return Err(RenewalError::WrongMember);
    }

    let vac = crate::dtg::parse_conformant(role_vac).map_err(RenewalError::RoleShape)?;
    if vac.issuer() != community {
        return Err(RenewalError::RoleShape(
            "its issuer is not the community".into(),
        ));
    }
    if vac.subject() != member_did {
        return Err(RenewalError::WrongMember);
    }
    // `community_roles` holds the VAC to the community role shape: an
    // `AuthorityCredential`, `issuerScope` public, `authority.scope` its own
    // issuer (the community), no parent, `role:<name>` actions.
    crate::dtg::community_roles(&vac).ok_or_else(|| {
        RenewalError::RoleShape(
            "it confers no role in the community's own scope (issuerScope public, \
             authority.scope the community, role:<name> actions)"
                .into(),
        )
    })
}

/// Verify a `vtc/members/renew/0.1#response` from `sender` before anything acts
/// on it. Records nothing; see [`VerifiedRenewal::document`].
///
/// `our_dids` are this account's persona DIDs: the reply must be addressed to
/// one of them, and must renew that one — a community's renewal of somebody
/// else is not ours to store.
///
/// # Errors
///
/// [`RenewalError`] naming the first check that failed.
pub async fn verify_renewal_response(
    document: &Value,
    sender: &str,
    our_dids: &[&str],
    resolver: &DIDCacheClient,
    now: DateTime<Utc>,
) -> Result<VerifiedRenewal, RenewalError> {
    // The payload's shape and the credentials' claims are checked before the
    // document's proof is: both are local, and a reply that fails them is
    // refused without resolving anything.
    let response = parse_response(document)?;
    let recipient = document
        .get("recipient")
        .and_then(Value::as_str)
        .ok_or(RenewalError::Document(OperationalError::NoRecipient))?;
    if response.did.as_str() != recipient {
        return Err(RenewalError::WrongMember);
    }
    let vmc = Value::Object(response.vmc);
    let role_vac = Value::Object(response.role_vac);
    let roles = check_shape(&vmc, &role_vac, sender, recipient)?;

    let verified = crate::operational::verify_operational(
        document,
        sender,
        our_dids,
        MEMBERS_RENEW_RESPONSE_TYPE,
        resolver,
        // The replay check is the caller's, at apply time, against the live set.
        &SeenDocuments::default(),
        now,
    )
    .await?;
    let vmc = verify_issued_credential(vmc, sender, resolver, now)
        .await
        .map_err(RenewalError::Vmc)?;
    let role_vac = verify_issued_credential(role_vac, sender, resolver, now)
        .await
        .map_err(RenewalError::RoleVac)?;
    Ok(VerifiedRenewal {
        document: verified,
        did: response.did.to_string(),
        vmc,
        role_vac,
        roles,
        personhood: response.personhood,
        personhood_changed: response.personhood_changed,
    })
}

/// What a renewal changed, for the member to be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalSummary {
    /// The membership renewed.
    pub persona: PersonaId,
    /// The roles the new role credential confers.
    pub roles: Vec<String>,
    /// Whether the new membership credential carries `PersonhoodCredential`.
    pub personhood: bool,
    /// Whether that changed with this renewal.
    pub personhood_changed: bool,
    /// How many pre-v1 credential notices the renewal answered.
    pub cleared_retired: usize,
    /// The join request this renewal closed, when it rescued an approved join
    /// whose credential never arrived: the membership is now `Active`, and the
    /// caller owes the community the acknowledgement that closes the request —
    /// the one a delivered credential would have produced.
    pub closed_join: Option<uuid::Uuid>,
}

/// Store a verified renewal on the membership it renews: the new VMC and role
/// VAC replace whatever the membership held under those kinds, and the
/// [`RetiredCredential`] notices for both are cleared — the same replacement a
/// pushed credential makes ([`crate::messaging::handle_credential_issue`]).
///
/// Personhood is not stored apart from the VMC: it *is* the VMC's
/// `PersonhoodCredential` type, so storing the new grant is what updates it.
/// [`RenewalSummary::personhood_changed`] says whether it moved.
///
/// The member's own acknowledgement (`member_vmc`) is left as it is: it names
/// the previous grant by digest, so it no longer completes the edge, and the
/// caller replaces it once a fresh one has been sent — the record keeps what
/// the member last sent until there is something newer to keep.
///
/// # Errors
///
/// [`RenewalError::WrongMember`] if the renewed DID is not one of our personas,
/// [`RenewalError::NoMembership`] if that persona holds no membership with
/// `from_did` that may be renewed ([`CommunityRecord::can_renew`]): an Active
/// one, or a join the community approved whose credential never arrived.
///
/// The second is activated here, as a delivered credential would have
/// activated it ([`crate::messaging::handle_credential_issue`]), and its
/// request id is returned in [`RenewalSummary::closed_join`].
///
/// [`CommunityRecord::can_renew`]: crate::config::account::CommunityRecord::can_renew
pub fn apply_renewal(
    account: &mut Account,
    renewal: &VerifiedRenewal,
    from_did: &str,
) -> Result<RenewalSummary, RenewalError> {
    let persona = account
        .persona_id_for_did(&renewal.did)
        .ok_or(RenewalError::WrongMember)?;
    let record = account
        .membership_mut(from_did, persona)
        .filter(|r| r.can_renew())
        .ok_or(RenewalError::NoMembership)?;
    let before = record.retired_credentials.len();
    record
        .credentials
        .insert(CredentialKind::Membership, renewal.vmc.value().clone());
    record.clear_retired(CredentialKind::Membership.config_key());
    record
        .credentials
        .insert(CredentialKind::Role, renewal.role_vac.value().clone());
    record.clear_retired(CredentialKind::Role.config_key());
    let cleared_retired = before - record.retired_credentials.len();
    // An approved join rescued by renewal: the membership credential is now
    // held, so it becomes Active exactly as on delivery, and the request it
    // closes is captured before `activate` replaces the Pending state.
    let closed_join = match record.status {
        crate::config::account::CommunityStatus::Pending { request_id } => {
            record.activate(chrono::Utc::now());
            Some(request_id)
        }
        _ => None,
    };
    Ok(RenewalSummary {
        persona,
        roles: renewal.roles.clone(),
        personhood: renewal.personhood,
        personhood_changed: renewal.personhood_changed,
        cleared_retired,
        closed_join,
    })
}

/// Record the acknowledgement the member sent for a renewed grant, clearing the
/// pre-v1 acknowledgement notice it answers.
pub fn store_acknowledgement(
    account: &mut Account,
    from_did: &str,
    persona: PersonaId,
    member_vmc: Value,
) {
    if let Some(record) = account.membership_mut(from_did, persona) {
        record.member_vmc = Some(member_vmc);
        record.clear_retired(RetiredCredential::MEMBER_ACKNOWLEDGEMENT);
    }
}

// ─── Refusals ────────────────────────────────────────────────────────────

/// How a community refused a renewal (a `trust-task-error` threaded on it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalRefusal {
    /// `vtc/members/renew:notMember` — the community holds no membership for
    /// the persona that asked.
    NotMember,
    /// Any other refusal, as the community put it.
    Other { code: String, detail: String },
}

impl RenewalRefusal {
    /// Read a `trust-task-error` document's code and message. Read loosely, as
    /// [`crate::messaging::handle_join_trust_task_error`] does: a strict parse
    /// of the framework payload would drop a refusal over a member that varies
    /// across framework versions.
    #[must_use]
    pub fn read(document: &Value) -> Self {
        let code = document
            .pointer("/payload/code")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if code == RENEW_NOT_MEMBER {
            return RenewalRefusal::NotMember;
        }
        RenewalRefusal::Other {
            code: code.to_string(),
            detail: document
                .pointer("/payload/message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }
    }
}

/// How a renewal ended, for the member to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// Renewed. `acknowledged` is whether the fresh acknowledgement went out.
    Renewed {
        summary: RenewalSummary,
        acknowledged: Result<(), String>,
    },
    /// The community refused it.
    Refused(RenewalRefusal),
    /// The reply could not be acted on.
    Failed(String),
}

impl RenewalOutcome {
    /// One line for the member: what happened and, where there is something to
    /// do about it, what.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            RenewalOutcome::Renewed {
                summary,
                acknowledged,
            } => {
                let mut line = "Membership renewed — the community re-issued your membership \
                                and role credentials"
                    .to_string();
                if !summary.roles.is_empty() {
                    line.push_str(&format!(" (role: {})", summary.roles.join(", ")));
                }
                line.push('.');
                if summary.personhood_changed {
                    line.push_str(if summary.personhood {
                        " Your membership now carries personhood."
                    } else {
                        " Your membership no longer carries personhood."
                    });
                }
                match acknowledged {
                    Ok(()) => line.push_str(" Your acknowledgement was sent."),
                    Err(e) => line.push_str(&format!(
                        " Sending your acknowledgement failed ({e}) — press m to send it."
                    )),
                }
                line
            }
            RenewalOutcome::Refused(RenewalRefusal::NotMember) => {
                "Renewal refused: the community says you are not a member. If you were \
                 removed, join again."
                    .to_string()
            }
            RenewalOutcome::Refused(RenewalRefusal::Other { code, detail }) => {
                match (code.is_empty(), detail.is_empty()) {
                    (true, true) => "Renewal refused by the community (no reason given).".into(),
                    (false, true) => format!("Renewal refused by the community [{code}]."),
                    (true, false) => format!("Renewal refused by the community: {detail}"),
                    (false, false) => {
                        format!("Renewal refused by the community [{code}]: {detail}")
                    }
                }
            }
            RenewalOutcome::Failed(e) => format!("Couldn't take the renewal: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::account::{CommunityRecord, PersonaRecord};
    use crate::proof_check::test_support::sign as sign_credential;
    use serde_json::json;

    /// A `did:key` community, so the end-to-end check resolves locally: its
    /// one key is listed under both `authentication` and `assertionMethod`.
    fn community_key(seed: u8) -> (Secret, String) {
        let mut key = Secret::generate_ed25519(None, Some(&[seed; 32]));
        let mb = key.get_public_keymultibase().unwrap();
        let did = format!("did:key:{mb}");
        key.id = format!("{did}#{mb}");
        (key, did)
    }

    const MEMBER: &str = "did:webvh:QmMember:example.com:alice";

    fn account(vtc: &str, active: bool) -> (Account, PersonaId) {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: MEMBER.to_string(),
                did_document: None,
                key_refs: Vec::new(),
                mediator_did: None,
                origin_context_id: String::new(),
                created_at: Utc::now(),
                label: None,
            },
        );
        let mut record = CommunityRecord::new_pending(
            vtc.to_string(),
            None,
            "openvtc/x".to_string(),
            pid,
            Uuid::new_v4(),
            Utc::now(),
        );
        if active {
            record.activate(Utc::now());
        }
        // What the v1 migration leaves behind: both community credentials and
        // the acknowledgement set aside on load.
        for kind in [
            "Membership",
            "Role",
            RetiredCredential::MEMBER_ACKNOWLEDGEMENT,
        ] {
            record.retired_credentials.push(RetiredCredential {
                kind: kind.to_string(),
                credential_id: None,
                reason: "pre-v1".to_string(),
                retired_at: Utc::now(),
            });
        }
        acct.add_membership(record);
        (acct, pid)
    }

    /// The reply as the community sends it: a signed `#response` document with
    /// the re-issued credentials, each signed under `assertionMethod`.
    async fn reply(key: &Secret, vtc: &str, member: &str, role: &str) -> Value {
        let vmc = sign_credential(crate::dtg::fixtures::grant(vtc, member), &[key]).await;
        let vac = sign_credential(crate::dtg::fixtures::role_vac(vtc, member, role), &[key]).await;
        crate::trust_task_doc::build_signed_value(
            MEMBERS_RENEW_RESPONSE_TYPE,
            vtc,
            member,
            format!("urn:uuid:{}", Uuid::new_v4()),
            json!({
                "did": member,
                "vmc": vmc,
                "roleVac": vac,
                "personhood": false,
                "personhoodChanged": false,
            }),
            key,
        )
        .await
        .expect("sign the reply")
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("resolver")
    }

    #[test]
    fn the_task_and_its_reply_are_the_renew_task() {
        assert_eq!(
            MEMBERS_RENEW_TYPE,
            "https://trusttasks.org/spec/vtc/members/renew/0.1"
        );
        assert_eq!(
            MEMBERS_RENEW_RESPONSE_TYPE,
            format!("{MEMBERS_RENEW_TYPE}#response")
        );
        assert_eq!(RENEW_NOT_MEMBER, "vtc/members/renew:notMember");
        // The reply has to pass the inbound gate, or it is dropped unseen.
        assert!(crate::didcomm::routes_inbound_type(
            MEMBERS_RENEW_RESPONSE_TYPE
        ));
    }

    /// The request takes no parameters, and is signed — the task declares
    /// `proof` and `issuedAt` REQUIRED — under `authentication`.
    #[tokio::test]
    async fn the_request_is_signed_and_carries_no_parameters() {
        let (key, did) = community_key(7);
        let doc = build_renew_request(&did, "did:example:vtc", "urn:uuid:1", &key)
            .await
            .expect("build");
        assert_eq!(doc["type"], MEMBERS_RENEW_TYPE);
        assert_eq!(doc["payload"], json!({}));
        assert_eq!(doc["issuer"], did.as_str());
        assert_eq!(doc["recipient"], "did:example:vtc");
        assert!(doc.get("issuedAt").is_some());
        assert_eq!(doc["proof"]["proofPurpose"], "authentication");
    }

    /// A reply is taken only for a renewal we asked that community for, and
    /// only once — on either form of the thread id.
    #[test]
    fn a_reply_is_bound_to_the_request_it_answers() {
        let id = Uuid::new_v4();
        record_request(id, "did:example:vtc", MEMBER);
        assert!(!is_pending("did:example:other", &id.to_string()));
        assert!(is_pending("did:example:vtc", &format!("urn:uuid:{id}")));
        assert_eq!(
            take_pending("did:example:vtc", &id.to_string()).as_deref(),
            Some(MEMBER)
        );
        assert!(take_pending("did:example:vtc", &id.to_string()).is_none());
    }

    /// **Success.** A verified renewal stores both credentials, clears the
    /// pre-v1 notices they answer, and reports the roles.
    #[tokio::test]
    async fn a_renewal_is_verified_stored_and_clears_the_retired_notices() {
        let (key, vtc) = community_key(11);
        let (mut acct, pid) = account(&vtc, true);
        let doc = reply(&key, &vtc, MEMBER, "vetter").await;

        let verified =
            verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
                .await
                .expect("the renewal verifies");
        assert_eq!(verified.member_did(), MEMBER);
        assert_eq!(verified.document().recipient(), MEMBER);

        let summary = apply_renewal(&mut acct, &verified, &vtc).expect("applies");
        assert_eq!(summary.persona, pid);
        assert_eq!(summary.roles, vec!["vetter".to_string()]);
        assert_eq!(summary.cleared_retired, 2);

        let record = acct.membership(&vtc, pid).unwrap();
        assert_eq!(
            record.credentials.get(&CredentialKind::Membership),
            Some(&doc["payload"]["vmc"])
        );
        assert_eq!(
            record.credentials.get(&CredentialKind::Role),
            Some(&doc["payload"]["roleVac"])
        );
        // The acknowledgement notice stays until a fresh one has been sent.
        assert_eq!(record.retired_credentials.len(), 1);
        assert_eq!(
            record.retired_credentials[0].kind,
            RetiredCredential::MEMBER_ACKNOWLEDGEMENT
        );
        store_acknowledgement(&mut acct, &vtc, pid, json!({ "id": "urn:uuid:ack" }));
        let record = acct.membership(&vtc, pid).unwrap();
        assert!(record.retired_credentials.is_empty());
        assert_eq!(record.member_vmc, Some(json!({ "id": "urn:uuid:ack" })));
    }

    /// A renewal of somebody else, or one addressed to another persona, is not
    /// ours to store.
    #[tokio::test]
    async fn a_renewal_of_another_member_is_refused() {
        let (key, vtc) = community_key(12);
        let doc = reply(&key, &vtc, "did:example:someone-else", "member").await;
        let err = verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            RenewalError::Document(OperationalError::WrongRecipient)
        );

        // The payload naming one member while the credentials name another.
        let mut doc = reply(&key, &vtc, MEMBER, "member").await;
        doc["payload"]["vmc"] = sign_credential(
            crate::dtg::fixtures::grant(&vtc, "did:example:someone-else"),
            &[&key],
        )
        .await;
        let err = verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
            .await
            .unwrap_err();
        assert_eq!(err, RenewalError::WrongMember);
    }

    /// The credentials are held to the DTG v1 grant and role shapes before
    /// anything is resolved: a pre-v1 VMC, or a VAC in someone else's scope,
    /// is refused.
    #[tokio::test]
    async fn non_conformant_credentials_are_refused() {
        let (key, vtc) = community_key(13);
        let mut doc = reply(&key, &vtc, MEMBER, "member").await;
        doc["payload"]["vmc"] = crate::dtg::fixtures::retired_role_endorsement(&vtc, MEMBER);
        let err = verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, RenewalError::VmcShape(_)), "{err:?}");

        let mut doc = reply(&key, &vtc, MEMBER, "member").await;
        doc["payload"]["roleVac"] = serde_json::to_value(
            dtg_credentials::DTGCredential::new_vac(
                vtc.clone(),
                IssuerScope::Public,
                MEMBER.into(),
                "did:example:elsewhere".into(),
                vec!["role:member".into()],
                Utc::now() - chrono::Duration::minutes(1),
                Utc::now() + chrono::Duration::days(1),
            )
            .unwrap(),
        )
        .unwrap();
        let err = verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, RenewalError::RoleShape(_)), "{err:?}");
    }

    /// A credential whose proof does not verify is not stored, however well
    /// shaped — here, one signed by a key that is not the community's.
    #[tokio::test]
    async fn a_credential_the_community_did_not_sign_is_refused() {
        let (key, vtc) = community_key(14);
        let (other, _) = community_key(15);
        let mut doc = reply(&key, &vtc, MEMBER, "member").await;
        doc["payload"]["vmc"] =
            sign_credential(crate::dtg::fixtures::grant(&vtc, MEMBER), &[&other]).await;
        // Re-sign the document over the swapped payload, so only the
        // credential's proof is wrong.
        let doc = crate::proof_check::test_support::sign_for(
            doc,
            &[&key],
            crate::proof_check::Purpose::Authentication,
        )
        .await;
        let err = verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, RenewalError::Vmc(_)), "{err:?}");
    }

    /// A renewal lands only on an Active membership we hold with that
    /// community.
    #[tokio::test]
    async fn a_renewal_needs_an_active_membership() {
        let (key, vtc) = community_key(16);
        let doc = reply(&key, &vtc, MEMBER, "member").await;
        let verified =
            verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
                .await
                .unwrap();

        let (mut pending, _) = account(&vtc, false);
        assert_eq!(
            apply_renewal(&mut pending, &verified, &vtc),
            Err(RenewalError::NoMembership)
        );
        let (mut elsewhere, _) = account("did:example:other-community", true);
        assert_eq!(
            apply_renewal(&mut elsewhere, &verified, &vtc),
            Err(RenewalError::NoMembership)
        );
    }

    /// The manual rescue for a lost delivery: a join the community approved
    /// whose credential never arrived is renewed, becomes Active as delivery
    /// would have made it, and reports the request it closed so the caller
    /// sends the acknowledgement that closes it. A Pending join nobody approved
    /// is still refused (above).
    #[tokio::test]
    async fn a_renewal_rescues_an_approved_join_whose_credential_never_arrived() {
        let (key, vtc) = community_key(17);
        let doc = reply(&key, &vtc, MEMBER, "member").await;
        let verified =
            verify_renewal_response(&doc, &vtc, &[MEMBER], &resolver().await, Utc::now())
                .await
                .unwrap();

        let (mut acct, pid) = account(&vtc, false);
        let request_id = {
            let record = acct.membership_mut(&vtc, pid).unwrap();
            assert!(record.mark_approved(Utc::now()));
            assert!(record.approved_awaiting_credential() && record.can_renew());
            match record.status {
                crate::config::account::CommunityStatus::Pending { request_id } => request_id,
                _ => unreachable!("the fixture is Pending"),
            }
        };

        let summary = apply_renewal(&mut acct, &verified, &vtc).expect("an approved join renews");
        assert_eq!(summary.closed_join, Some(request_id));
        let record = acct.membership(&vtc, pid).unwrap();
        assert!(record.status.is_active(), "{:?}", record.status);
        assert!(record.credentials.contains_key(&CredentialKind::Membership));
        assert!(!record.approved_awaiting_credential());

        // An Active renewal closes nothing.
        let (mut active, _) = account(&vtc, true);
        assert_eq!(
            apply_renewal(&mut active, &verified, &vtc)
                .unwrap()
                .closed_join,
            None
        );
    }

    /// **notMember.** The declared refusal is recognised, and tells the member
    /// what it means.
    #[test]
    fn not_member_is_recognised() {
        let doc = json!({
            "type": "https://trusttasks.org/spec/trust-task-error/0.1",
            "payload": { "code": RENEW_NOT_MEMBER, "message": "no ACL row" }
        });
        let refusal = RenewalRefusal::read(&doc);
        assert_eq!(refusal, RenewalRefusal::NotMember);
        let line = RenewalOutcome::Refused(refusal).describe();
        assert!(line.contains("not a member"), "{line}");

        let other = RenewalRefusal::read(&json!({
            "payload": { "code": "internal", "message": "status list not provisioned" }
        }));
        assert_eq!(
            RenewalOutcome::Refused(other).describe(),
            "Renewal refused by the community [internal]: status list not provisioned"
        );
    }

    #[test]
    fn a_renewal_says_what_changed() {
        let summary = RenewalSummary {
            persona: PersonaId::new(),
            roles: vec!["vetter".into()],
            personhood: true,
            personhood_changed: true,
            cleared_retired: 2,
            closed_join: None,
        };
        let line = RenewalOutcome::Renewed {
            summary: summary.clone(),
            acknowledged: Ok(()),
        }
        .describe();
        assert!(
            line.contains("renewed") && line.contains("vetter"),
            "{line}"
        );
        assert!(line.contains("now carries personhood"), "{line}");

        let line = RenewalOutcome::Renewed {
            summary,
            acknowledged: Err("mediator unreachable".into()),
        }
        .describe();
        assert!(line.contains("press m"), "{line}");
    }
}
