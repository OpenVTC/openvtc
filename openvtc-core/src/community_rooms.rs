//! Community data rooms — the member side of `vtc/rooms/{memberships,offers}/*`.
//!
//! A community that owns data rooms offers its members admission to them. The member
//! reaches those rooms from more than one surface: the community's member portal through
//! their wallet, `pnm`, and this client. **None of them keeps its own record of which
//! rooms the member accepted** (`vtc/rooms/memberships/list/0.2`, Surface item 1). Every
//! surface reads the same two:
//!
//! - the **community's** record — [`Request::Memberships`], every room it offered the
//!   member, `offered`, `admitted`, `suspended` or `removed`, and where the room itself
//!   stands: active, archived (read-only or closed), being removed, removed
//!   ([`RoomCondition`]);
//! - the **key holder's** custody — the member's VTA, `rooms/keys/list`: which rooms'
//!   groups it holds, for which member ([`held_rooms`]).
//!
//! and derives the same [`Standing`] from them. So a room accepted in the portal is joined
//! here, and an acceptance one surface began is finished by another: every step of
//! accepting answers a repeat with its first answer — the VTA returns the KeyPackage it
//! already holds (`rooms/keys/key-package/0.2`, [`prepare_acceptance`]), the community
//! answers an acceptance carrying it with the Welcome it kept, and the VTA answers a
//! Welcome it already processed `alreadyJoined` ([`join`]).
//!
//! # Carriage
//!
//! The community's tasks are signed with the persona's own `authentication` key and sent
//! over the persona's DIDComm or TSP channel, exactly like `git-ns/*`
//! ([`crate::git_ns`]); the community answers on the same route. The room tasks go to the
//! member's VTA, which holds the room keys and the credentials.
//!
//! # Renewals
//!
//! The community renews an admission by having the room issue fresh membership and
//! authority credentials, listed for the member in `vtc/rooms/offers/list/0.4`'s
//! `renewals` — on a schedule, and when a room archived with no access reopens, which is
//! what restores a `suspended` member. [`collect_renewals`] stores each in the VTA's vault
//! in place of the credential it renews, as `pnm rooms offers renew` does; a renewal
//! already held is left alone, so collecting again changes nothing.
//!
//! **Nothing here is persisted.** The community is the record and the VTA the custody;
//! a client that kept its own copy would be the one place the three disagree.

use crate::specs::vtc::rooms::memberships::list::v0_2 as memberships;
use crate::specs::vtc::rooms::offers::{accept::v0_1 as accept, list::v0_4 as offers};
use chrono::{DateTime, Utc};
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;

use crate::errors::OpenVTCError;

/// The generated `vtc/rooms/memberships/list/0.2` types: the member's record with the
/// room's own state (`roomState`, `roomAccess`, `purgeAt`) and the `suspended` state.
pub use memberships::RoomMembershipV2 as RoomMembership;
/// The generated `vtc/rooms/offers/list/0.4` types: the open offers, and the renewals of
/// admissions the member already holds ([`collect_renewals`]).
pub use offers::OfferV2 as Offer;
pub use offers::Renewal;

/// Every type this module sends or reads starts with this.
const TYPE_PREFIX: &str = "https://trusttasks.org/spec/vtc/rooms/";

/// Longest text from the community kept for display.
const MAX_PEER_TEXT: usize = 512;

// ****************************************************************************
// Requests
// ****************************************************************************

/// One request to the community, as the member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// `vtc/rooms/memberships/list/0.2`: the community's record of every room it offered
    /// the member, where each admission stands, and where each room does.
    Memberships { cursor: Option<String> },
    /// `vtc/rooms/offers/list/0.4`: the open offers, with the credentials an acceptance
    /// stores with the key holder.
    Offers { cursor: Option<String> },
    /// `vtc/rooms/offers/accept/0.1`: take up an offer — with the KeyPackage the member's
    /// VTA gave for it, on a sealed room.
    Accept {
        room_id: String,
        key_package: Option<String>,
    },
}

impl Request {
    /// The request's Type URI.
    #[must_use]
    pub fn type_uri(&self) -> &'static str {
        use trust_tasks_rs::Payload as _;
        match self {
            Request::Memberships { .. } => memberships::Payload::TYPE_URI,
            Request::Offers { .. } => offers::Payload::TYPE_URI,
            Request::Accept { .. } => accept::Payload::TYPE_URI,
        }
    }

    /// The payload, through the generated types: what the schema refuses fails here.
    fn payload(&self) -> Result<Value, OpenVTCError> {
        let bad =
            |e: &dyn std::fmt::Display| OpenVTCError::Config(format!("{}: {e}", self.type_uri()));
        let mut payload = serde_json::json!({});
        match self {
            Request::Memberships { cursor } | Request::Offers { cursor } => {
                if let Some(c) = cursor {
                    payload["cursor"] = Value::String(c.clone());
                }
            }
            Request::Accept {
                room_id,
                key_package,
            } => {
                payload["roomId"] = Value::String(room_id.clone());
                if let Some(kp) = key_package {
                    payload["keyPackage"] = Value::String(kp.clone());
                }
            }
        }
        match self {
            Request::Memberships { .. } => {
                serde_json::from_value::<memberships::Payload>(payload.clone())
                    .map_err(|e| bad(&e))?;
            }
            Request::Offers { .. } => {
                serde_json::from_value::<offers::Payload>(payload.clone()).map_err(|e| bad(&e))?;
            }
            Request::Accept { .. } => {
                serde_json::from_value::<accept::Payload>(payload.clone()).map_err(|e| bad(&e))?;
            }
        }
        Ok(payload)
    }
}

/// Build `request` as an addressed, dated, unsigned document from `issuer_did` (the
/// persona the community knows the member by) to `vtc_did`. Its fresh id is the
/// `threadId` the answer carries; sign it with [`crate::capabilities::sign_document`].
///
/// # Errors
///
/// A payload the schema refuses.
pub fn build(
    request: &Request,
    issuer_did: &str,
    vtc_did: &str,
) -> Result<TrustTask<Value>, OpenVTCError> {
    crate::trust_task_doc::build(
        request.type_uri(),
        issuer_did,
        vtc_did,
        format!("urn:uuid:{}", Uuid::new_v4()),
        request.payload()?,
    )
}

// ****************************************************************************
// Replies
// ****************************************************************************

/// The community's answer to one request.
#[derive(Clone, Debug)]
pub enum Reply {
    Memberships(Box<memberships::Response>),
    Offers(Box<offers::Response>),
    Accepted(Box<accept::Response>),
    /// A `trust-task-error`.
    Refused(Refusal),
    /// A response whose payload does not match the schema this client was built
    /// against — a contract mismatch, neither a refusal nor a lost message (R6.4).
    Unreadable {
        task: String,
        detail: String,
    },
}

/// Whether an inbound document type may be an answer to one of these requests.
#[must_use]
pub fn is_reply_type(typ: &str) -> bool {
    typ.starts_with(TYPE_PREFIX) || crate::messaging::is_trust_task_error_type(typ)
}

/// Classify a reply document, keyed by the thread it answers. `None` when it is neither
/// one of these responses nor a `trust-task-error`, or carries no `threadId`.
#[must_use]
pub fn parse_reply(doc: &TrustTask<Value>) -> Option<(String, Reply)> {
    use trust_tasks_rs::Payload as _;
    let thid = doc.thread_id.clone()?;
    if doc.type_uri.slug() == "trust-task-error" {
        return Some((
            thid,
            Reply::Refused(Refusal::from_error_payload(&doc.payload)),
        ));
    }
    if !doc.type_uri.is_response() {
        return None;
    }
    fn read<T: serde::de::DeserializeOwned>(
        payload: &Value,
        wrap: impl FnOnce(Box<T>) -> Reply,
        task: &str,
    ) -> Reply {
        match serde_json::from_value::<T>(payload.clone()) {
            Ok(r) => wrap(Box::new(r)),
            Err(e) => Reply::Unreadable {
                task: task.to_string(),
                detail: crate::display::sanitize_display(&e.to_string(), MAX_PEER_TEXT),
            },
        }
    }
    let p = &doc.payload;
    let uri = doc.type_uri.to_string();
    let reply = match uri.as_str() {
        u if u == memberships::Response::TYPE_URI => {
            read(p, Reply::Memberships, "vtc/rooms/memberships/list")
        }
        u if u == offers::Response::TYPE_URI => read(p, Reply::Offers, "vtc/rooms/offers/list"),
        u if u == accept::Response::TYPE_URI => read(p, Reply::Accepted, "vtc/rooms/offers/accept"),
        _ => return None,
    };
    Some((thid, reply))
}

/// A `trust-task-error` from the community.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: Option<String>,
}

impl Refusal {
    fn from_error_payload(payload: &Value) -> Self {
        Refusal {
            code: payload.get("code").and_then(Value::as_str).map_or_else(
                || "unknown".to_string(),
                |c| crate::display::sanitize_display(c, 128),
            ),
            message: payload
                .get("message")
                .and_then(Value::as_str)
                .map(|m| crate::display::sanitize_display(m.trim(), MAX_PEER_TEXT))
                .filter(|m| !m.is_empty()),
        }
    }

    /// Whether the community no longer keeps the Welcome for this member's acceptance
    /// (or was sent a different KeyPackage): the acceptance cannot be finished from here,
    /// and only an administrator re-admitting the member repairs it (Surface item 5).
    #[must_use]
    pub fn is_already_accepted(&self) -> bool {
        self.code == accept::error_codes::ALREADY_ACCEPTED.code
    }

    /// What happened and what to do about it.
    #[must_use]
    pub fn explain(&self) -> String {
        let detail = self
            .message
            .as_deref()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        match self.code.as_str() {
            c if c == memberships::error_codes::NOT_A_MEMBER.code
                || c == offers::error_codes::NOT_A_MEMBER.code
                || c == accept::error_codes::NOT_A_MEMBER.code =>
            {
                "The community does not count this persona as an active member.".to_string()
            }
            c if c == accept::error_codes::NOT_FOUND.code => {
                "That offer is no longer open — it may have been withdrawn. Refresh (r)."
                    .to_string()
            }
            c if c == accept::error_codes::OFFER_EXPIRED.code => {
                "That offer has expired; ask an administrator to offer the room again.".to_string()
            }
            c if c == accept::error_codes::ALREADY_ACCEPTED.code => {
                "Already accepted, and the community no longer keeps what this client needs to \
                 finish joining. Ask an administrator to remove and re-admit you."
                    .to_string()
            }
            c if c == accept::error_codes::ADMISSION_PENDING.code => {
                "The community could not yet confirm the admission. Accepting again is safe."
                    .to_string()
            }
            "unsupportedType" | "unsupportedVersion" => format!(
                "This community does not serve that request{detail} — it may predate the \
                 room record with room states (vtc/rooms/memberships/list/0.2): its VTC \
                 needs updating."
            ),
            "permissionDenied" => format!("The community refused{detail}."),
            other => format!("The community refused ({other}){detail}."),
        }
    }
}

// ****************************************************************************
// Standing — vtc/rooms/memberships/list/0.2 *One record, every surface*
// ****************************************************************************

/// What every surface shows for one room, from the community's state and the key
/// holder's custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Offered, not yet accepted.
    Offered,
    /// Admitted and openable: an `open` room, or a sealed one whose group the VTA holds.
    Joined,
    /// Admitted to a sealed room the VTA holds no group for, while the community keeps
    /// the Welcome: an acceptance begun somewhere to finish.
    Unfinished,
    /// Admitted to a sealed room the VTA holds no group for, after the community stopped
    /// keeping the Welcome: only an administrator re-admitting the member repairs it.
    NeedsReadmission,
    /// Admitted, but this client cannot read the key holder's custody (no VTA).
    Admitted,
    /// Admitted, but the room is closed to every member — archived with no access, or
    /// being removed — and the host refuses the member's credentials. Restored, by a
    /// renewal, if the room reopens.
    Suspended,
    /// Removed by an administrator, an offer withdrawn, or the room removed.
    Removed,
}

impl Standing {
    /// The table. `held` is `None` when the key holder could not be asked.
    #[must_use]
    pub fn of(room: &RoomMembership, held: Option<bool>) -> Self {
        use memberships::MemberStateV2 as S;
        let sealed = room.visibility != memberships::Visibility::Open;
        match (room.state, held) {
            (S::Offered, _) => Standing::Offered,
            (S::Removed, _) => Standing::Removed,
            (S::Suspended, _) => Standing::Suspended,
            (S::Admitted, _) if !sealed => Standing::Joined,
            (S::Admitted, Some(true)) => Standing::Joined,
            (S::Admitted, None) => Standing::Admitted,
            (S::Admitted, Some(false)) if room.repeat_accept_until.is_some() => {
                Standing::Unfinished
            }
            (S::Admitted, Some(false)) => Standing::NeedsReadmission,
        }
    }

    /// Whether accepting is what the member can do next.
    #[must_use]
    pub fn acceptable(self) -> bool {
        matches!(self, Standing::Offered | Standing::Unfinished)
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Standing::Offered => "offered",
            Standing::Joined => "joined",
            Standing::Unfinished => "accepted — finish joining",
            Standing::NeedsReadmission => "needs re-admission",
            Standing::Admitted => "admitted",
            Standing::Suspended => "suspended",
            Standing::Removed => "removed",
        }
    }
}

/// Where the room itself stands, as its owner set it (`roomState`, `roomAccess`,
/// `purgeAt`) — beside the member's own [`Standing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomCondition {
    /// Open as usual.
    Active,
    /// Archived read-only: members keep reading; nobody writes, nobody is admitted.
    ReadOnly,
    /// Archived with no access: every member's credentials are withdrawn until it reopens.
    Closed,
    /// Scheduled for removal (or being purged): its content is deleted at this time.
    Going(Option<DateTime<Utc>>),
    /// Removed: nothing of it is left at the host.
    Removed,
}

impl RoomCondition {
    #[must_use]
    pub fn of(room: &RoomMembership) -> Self {
        use memberships::{ArchiveAccess as A, RoomState as R};
        match room.room_state {
            R::Active => RoomCondition::Active,
            R::Archived if room.room_access == Some(A::ReadOnly) => RoomCondition::ReadOnly,
            R::Archived => RoomCondition::Closed,
            R::RemovalScheduled | R::Purging => RoomCondition::Going(room.purge_at),
            R::Removed => RoomCondition::Removed,
        }
    }

    /// Whether the room admits anyone: only an active room does.
    #[must_use]
    pub fn admits(self) -> bool {
        self == RoomCondition::Active
    }

    /// A short word for the room's state, or `None` while it is active.
    #[must_use]
    pub fn label(self) -> Option<&'static str> {
        match self {
            RoomCondition::Active => None,
            RoomCondition::ReadOnly => Some("read-only"),
            RoomCondition::Closed => Some("closed for now"),
            RoomCondition::Going(_) => Some("being removed"),
            RoomCondition::Removed => Some("room removed"),
        }
    }

    /// What it means for the member, in a sentence.
    #[must_use]
    pub fn explain(self) -> Option<String> {
        match self {
            RoomCondition::Active => None,
            RoomCondition::ReadOnly => Some(
                "Archived read-only: you can still read it; nothing can be written, and \
                 nobody new is admitted."
                    .into(),
            ),
            RoomCondition::Closed => Some(
                "Archived and closed: your access is withdrawn for now and is restored if the \
                 community reopens it. Nothing you already read is affected."
                    .into(),
            ),
            RoomCondition::Going(Some(at)) => Some(format!(
                "Being removed: its content is deleted on {}. Your access is withdrawn.",
                at.format("%Y-%m-%d %H:%M UTC")
            )),
            RoomCondition::Going(None) => Some(
                "Being removed: its content is being deleted. Your access is withdrawn.".into(),
            ),
            RoomCondition::Removed => {
                Some("Removed by the community: nothing of it is left to open.".into())
            }
        }
    }
}

/// A room's label for display: the community's words, cleaned for the terminal.
#[must_use]
pub fn display_label(room: &RoomMembership) -> String {
    crate::display::sanitize_display(room.label.as_str(), 128)
}

/// Whether the community's own offer is for a sealed tier.
#[must_use]
pub fn offer_is_sealed(offer: &Offer) -> bool {
    offer.visibility != offers::Visibility::Open
}

// ****************************************************************************
// The key holder's half — the member's VTA
// ****************************************************************************

/// The rooms whose groups the VTA holds for `member` (`rooms/keys/list`). Custody, never
/// membership.
///
/// # Errors
///
/// The VTA could not be asked, or refused.
pub async fn held_rooms(vta: &VtaClient, member: &str) -> Result<Vec<String>, VtaError> {
    let listed = vta.room_list(false).await?;
    Ok(listed
        .rooms
        .iter()
        .filter(|r| r.member.as_str() == member)
        .map(|r| r.room_id.to_string())
        .collect())
}

/// Where an acceptance stands once the key holder has been prepared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prepared {
    /// The VTA already holds the room's group for the member — joined from another
    /// surface. Nothing to accept.
    AlreadyJoined,
    /// An `open` room: accept with no KeyPackage.
    Open,
    /// A sealed room: accept with this KeyPackage. `already_minted` says another surface
    /// may already have sent it (key-package 0.2).
    KeyPackage {
        key_package: String,
        already_minted: bool,
    },
}

/// Prepare the key holder to accept `offer` as `member`: store the room's membership and
/// authority credentials in the VTA's vault, and on a sealed tier obtain the KeyPackage —
/// the one it already holds for this offer's invitation, or a new one.
///
/// # Errors
///
/// A credential the vault refused, or a VTA that could not be asked.
pub async fn prepare_acceptance(
    vta: &VtaClient,
    offer: &Offer,
    member: &str,
) -> Result<Prepared, String> {
    let room_id = offer.room_id.as_str();
    for (what, credential) in [
        ("membership", offer.credentials.membership.as_str()),
        ("authority", offer.credentials.authority.as_str()),
    ] {
        let body: Value = serde_json::from_str(credential)
            .map_err(|e| format!("the offer's {what} credential is not JSON: {e}"))?;
        vta.cred_vault_receive(body, None).await.map_err(|e| {
            format!("your VTA's credential vault refused the {what} credential: {e}")
        })?;
    }
    if !offer_is_sealed(offer) {
        return Ok(Prepared::Open);
    }
    let held = held_rooms(vta, member)
        .await
        .map_err(|e| format!("couldn't ask your VTA which rooms it holds: {e}"))?;
    if held.iter().any(|r| r == room_id) {
        return Ok(Prepared::AlreadyJoined);
    }
    let invitation = offer.credentials.invitation.as_str();
    match vta.room_key_package(room_id, invitation).await {
        Ok(kp) => Ok(Prepared::KeyPackage {
            key_package: kp.key_package.to_string(),
            already_minted: kp.already_minted,
        }),
        Err(e) => Err(format!("your VTA could not give a KeyPackage: {e}")),
    }
}

/// Store every renewal in `renewals` that the VTA does not hold yet, each credential in
/// place of the one it renews (`vtc/rooms/offers/list/0.4` `renewals`, as
/// `pnm rooms offers renew` stores one). Answers the rooms renewed now. A renewal whose
/// credentials the vault already holds is skipped, so collecting again changes nothing.
///
/// # Errors
///
/// A credential that is not JSON, a vault that refused or did not answer, or a vault that
/// holds two credentials of one kind for a room — it acts with neither, and nor can this
/// client choose; the error names the room.
pub async fn collect_renewals(
    vta: &VtaClient,
    renewals: &[Renewal],
    member: &str,
) -> Result<Vec<String>, String> {
    let mut renewed = Vec::new();
    for renewal in renewals {
        let room_id = renewal.room_id.as_str();
        let mut stored = false;
        for (what, type_tag, credential) in [
            (
                "membership",
                "MembershipCredential",
                renewal.credentials.membership.as_str(),
            ),
            (
                "authority",
                "AuthorityCredential",
                renewal.credentials.authority.as_str(),
            ),
        ] {
            let body: Value = serde_json::from_str(credential)
                .map_err(|e| format!("the renewal's {what} credential is not JSON: {e}"))?;
            let held = held_room_credential(vta, room_id, member, type_tag).await?;
            if held.as_ref().is_some_and(|(_, current)| *current == body) {
                continue;
            }
            vta.cred_vault_receive(body, held.as_ref().map(|(id, _)| id.as_str()))
                .await
                .map_err(|e| {
                    format!(
                        "your VTA's credential vault refused the renewed {what} credential for \
                         {room_id}: {e}"
                    )
                })?;
            stored = true;
        }
        if stored {
            renewed.push(room_id.to_string());
        }
    }
    Ok(renewed)
}

/// The vault handle and body of the `type_tag` credential `room_id` issued `member`, as the
/// VTA holds it: `None` when it holds none, and an error when it holds more than one.
async fn held_room_credential(
    vta: &VtaClient,
    room_id: &str,
    member: &str,
    type_tag: &str,
) -> Result<Option<(String, Value)>, String> {
    let found = vta
        .cred_vault_query(serde_json::json!({ "type": type_tag, "issuerDid": room_id }))
        .await
        .map_err(|e| format!("your VTA's credential vault did not answer a query: {e}"))?;
    let mut mine = Vec::new();
    for descriptor in found["credentials"].as_array().cloned().unwrap_or_default() {
        let Some(id) = descriptor["id"].as_str() else {
            continue;
        };
        let got = vta
            .cred_vault_get(id)
            .await
            .map_err(|e| format!("your VTA's credential vault did not return {id}: {e}"))?;
        // A room's credential is a Data Integrity credential: its body is a JSON object.
        let credential = serde_json::to_value(&got)
            .ok()
            .and_then(|v| v.get("credential").cloned())
            .filter(Value::is_object);
        let Some(credential) = credential else {
            continue;
        };
        let subject = credential
            .get("credentialSubject")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_str);
        if subject == Some(member) {
            mine.push((id.to_string(), credential));
        }
    }
    match mine.len() {
        0 => Ok(None),
        1 => Ok(mine.pop()),
        n => Err(format!(
            "your VTA holds {n} {type_tag}s that {room_id} issued you, and acts on the room \
             with none of them until one is left: remove the older one from its credential \
             vault"
        )),
    }
}

/// How a join from a Welcome ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joined {
    /// Joined now, at this room epoch.
    At(u64),
    /// The VTA had already joined from this Welcome — another surface handed it over
    /// first. Joined all the same (Surface item 4).
    Already,
}

/// Hand the Welcome the community answered with to the VTA, which joins the room's group.
///
/// # Errors
///
/// The VTA could not be asked, or refused for another reason than having joined already.
pub async fn join(
    vta: &VtaClient,
    room_id: &str,
    invitation: &str,
    welcome: &str,
    ratchet_tree: Option<&str>,
) -> Result<Joined, String> {
    match vta
        .idempotent(|| vta.room_welcome(room_id, invitation, welcome, ratchet_tree))
        .await
    {
        // The MLS epoch; the room's is one more.
        Ok(r) => Ok(Joined::At(r.epoch + 1)),
        Err(e) if e.to_string().contains("alreadyJoined") => Ok(Joined::Already),
        Err(e) => Err(format!("your VTA did not join from the Welcome: {e}")),
    }
}

/// When `until` is in the future, how long remains — for "finish within" hints.
#[must_use]
pub fn remaining(until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<chrono::Duration> {
    until.filter(|u| *u > now).map(|u| u - now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn room(state: &str, visibility: &str, repeat: bool) -> RoomMembership {
        let mut v = json!({
            "roomId": "did:webvh:example.com:rooms:board",
            "host": "did:example:community",
            "label": "Board pack",
            "visibility": visibility,
            "actions": ["read"],
            "validUntil": "2027-10-01T00:00:00Z",
            "state": state,
            "offeredAt": "2026-10-14T10:00:00Z",
            "roomState": "active",
        });
        if repeat {
            v["repeatAcceptUntil"] = json!("2026-10-24T10:00:00Z");
        }
        serde_json::from_value(v).unwrap()
    }

    /// `vtc/rooms/memberships/list/0.2`'s table, as `pnm rooms memberships` reads it too.
    #[test]
    fn standing_follows_the_one_record() {
        assert_eq!(
            Standing::of(&room("offered", "private", false), Some(false)),
            Standing::Offered
        );
        assert_eq!(
            Standing::of(&room("admitted", "open", false), Some(false)),
            Standing::Joined
        );
        assert_eq!(
            Standing::of(&room("admitted", "private", true), Some(true)),
            Standing::Joined
        );
        assert_eq!(
            Standing::of(&room("admitted", "private", true), Some(false)),
            Standing::Unfinished
        );
        assert_eq!(
            Standing::of(&room("admitted", "attributed", false), Some(false)),
            Standing::NeedsReadmission
        );
        assert_eq!(
            Standing::of(&room("admitted", "private", true), None),
            Standing::Admitted
        );
        assert_eq!(
            Standing::of(&room("removed", "private", false), Some(true)),
            Standing::Removed
        );
        assert_eq!(
            Standing::of(&room("suspended", "private", false), Some(true)),
            Standing::Suspended
        );
        assert!(Standing::Unfinished.acceptable());
        assert!(!Standing::Joined.acceptable());
        assert!(!Standing::Suspended.acceptable());
    }

    fn room_in(state: &str, room_state: &str, access: Option<&str>) -> RoomMembership {
        let mut v = json!({
            "roomId": "did:webvh:example.com:rooms:board", "host": "did:example:community",
            "label": "Board pack", "visibility": "open", "actions": ["read"],
            "validUntil": "2027-10-01T00:00:00Z", "state": state,
            "offeredAt": "2026-10-14T10:00:00Z", "roomState": room_state,
        });
        if let Some(a) = access {
            v["roomAccess"] = json!(a);
        }
        if room_state == "removalScheduled" {
            v["purgeAt"] = json!("2026-12-02T10:00:00Z");
        }
        if state == "suspended" {
            v["suspendedAt"] = json!("2026-11-02T10:00:00Z");
        }
        serde_json::from_value(v).unwrap()
    }

    /// The room's own state, as the community's record says it.
    #[test]
    fn the_room_condition_follows_its_state() {
        let active = RoomCondition::of(&room_in("admitted", "active", None));
        assert_eq!(active, RoomCondition::Active);
        assert!(active.admits() && active.label().is_none());
        let ro = RoomCondition::of(&room_in("admitted", "archived", Some("readOnly")));
        assert_eq!(ro, RoomCondition::ReadOnly);
        assert!(!ro.admits());
        let closed = RoomCondition::of(&room_in("suspended", "archived", Some("noAccess")));
        assert_eq!(closed, RoomCondition::Closed);
        let going = RoomCondition::of(&room_in("suspended", "removalScheduled", Some("noAccess")));
        assert!(matches!(going, RoomCondition::Going(Some(_))));
        assert!(going.explain().unwrap().contains("2026-12-02"));
        assert_eq!(going.label(), Some("being removed"));
        let gone = RoomCondition::of(&room_in("removed", "removed", None));
        assert_eq!(gone, RoomCondition::Removed);
    }

    #[test]
    fn requests_build_through_the_generated_types() {
        let doc = build(
            &Request::Memberships { cursor: None },
            "did:key:zAlice",
            "did:key:zVtc",
        )
        .unwrap();
        assert_eq!(
            doc.type_uri.to_string(),
            "https://trusttasks.org/spec/vtc/rooms/memberships/list/0.2"
        );
        let accept = build(
            &Request::Accept {
                room_id: "did:webvh:example.com:rooms:board".into(),
                key_package: Some("AAEAAgADAAQ".into()),
            },
            "did:key:zAlice",
            "did:key:zVtc",
        )
        .unwrap();
        assert_eq!(accept.payload["keyPackage"], "AAEAAgADAAQ");
        assert!(
            build(
                &Request::Memberships {
                    cursor: Some(String::new())
                },
                "did:key:zAlice",
                "did:key:zVtc"
            )
            .is_err(),
            "the schema refuses an empty cursor"
        );
    }

    #[test]
    fn replies_are_classified_by_thread() {
        let doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
            "type": "https://trusttasks.org/spec/vtc/rooms/memberships/list/0.2#response",
            "issuer": "did:key:zVtc",
            "recipient": "did:key:zAlice",
            "issuedAt": "2026-10-17T10:00:01Z",
            "threadId": "urn:uuid:00000000-0000-4000-8000-000000000001",
            "payload": { "items": [] }
        }))
        .unwrap();
        let (thid, reply) = parse_reply(&doc).unwrap();
        assert_eq!(thid, "urn:uuid:00000000-0000-4000-8000-000000000001");
        assert!(matches!(reply, Reply::Memberships(r) if r.items.is_empty()));
        assert!(is_reply_type(
            "https://trusttasks.org/spec/vtc/rooms/offers/accept/0.1#response"
        ));
        assert!(!is_reply_type(
            "https://trusttasks.org/spec/git-ns/view/0.6#response"
        ));
    }
}
