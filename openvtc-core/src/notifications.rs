//! Notifications — a persona's received `notifications/notify` and `notifications/relay`, and
//! the elections they tell the member of.
//!
//! A notification is a signed statement by an *originator*, addressed to one DID, that a thing
//! exists which the addressee — or the parties it stands for — may take part in (the VTI
//! specification's *Notifications* chapter, VTI-NTF-001 – 074; the kinds are its Appendix G).
//! It confers no authority and is no evidence that anyone may take part (VTI-NTF-004).
//!
//! # The hand-over (VTI-NTF-054)
//!
//! A notification addressed to a persona DID reaches **this client**, which holds the persona's
//! mediator socket, not the member's VTA. The client must hand every one to the VTA
//! (`vta/notifications/deposit/0.1`), so the VTA's own acceptance policy decides what is held:
//!
//! - **exactly as received** ([`Received::document`]): the JSON the transport delivered, never a
//!   value re-serialised from a typed form, never altered or re-signed — every reader after
//!   the VTA verifies the originator's proof and each relayer's over these bytes;
//! - **every one**, with no acceptance filter here: not depositing is declining, and declining is
//!   the VTA's decision, not this client's;
//! - **promptly**: the VTA applies the acceptance window and `expiresAt` at the time of the
//!   deposit (VTI-NTF-055), so a document held back is a delivery that arrived late.
//!
//! The sender is answered by this client with the receipt the task defines (`notificationId`,
//! `revision` of the innermost notification), **the same whatever the VTA does** with the
//! document (VTI-NTF-023): [`receipt_for`] reads it from the document as this client verified
//! it, never from the VTA's answer.
//!
//! Receiving a notification sends nothing to its originator, to any relayer or to the thing's
//! holder beyond that receipt, and never opens the thing (VTI-NTF-053). Opening is the member's
//! step, from the Elections panel.
//!
//! # The election kind (VTI-NTF-060 – 063)
//!
//! A community notifies a party of an election its own list will never show that party's
//! members; the party relays it to them. The member's view of their elections is the
//! community's list **and** the held notifications of the kind `election`
//! ([`list_elections`]), each shown only as notified — its community, identifier, audience and
//! period — until the member opens it by reading it from the community.

use serde_json::{Value, json};
use trust_tasks_rs::Payload as _;
use vta_sdk::client::VtaClient;

use crate::specs::notifications::{notify::v0_1 as notify, relay::v0_1 as relay};
use crate::specs::vta::notifications::list::v0_1 as held;

/// `notifications/notify/0.1`.
pub const NOTIFY_TYPE: &str = notify::Payload::TYPE_URI;
/// `notifications/relay/0.1`.
pub const RELAY_TYPE: &str = relay::Payload::TYPE_URI;

/// The registered kind for an election (Appendix G, VTI-NTF-060).
pub const KIND_ELECTION: &str = vta_sdk::notifications::KIND_ELECTION;

/// Longest text from a peer kept for display.
const MAX_PEER_TEXT: usize = 256;

/// The most pages of held notifications one listing reads (R1.4: bounded).
const MAX_LIST_PAGES: usize = 5;

/// Whether an inbound document of `typ` is a notification addressed to us: a notify or a relay
/// **request** (a receipt answering one of ours would be `#response`, and we send none).
#[must_use]
pub fn is_notification_type(typ: &str) -> bool {
    typ == NOTIFY_TYPE || typ == RELAY_TYPE
}

// ****************************************************************************
// The hand-over
// ****************************************************************************

/// A notification as it arrived for one of our personas.
#[derive(Clone, Debug)]
pub struct Received {
    /// The document exactly as the transport delivered it.
    pub document: Value,
    /// The transport-authenticated sender: the originator, or the last relayer.
    pub sender: String,
    /// The persona DID it was addressed to (the document's `recipient`).
    pub addressee: String,
    /// Whether it arrived over TSP, so the receipt goes back the same way.
    pub over_tsp: bool,
}

impl Received {
    /// The document's own `id`: the `threadId` of the receipt.
    #[must_use]
    pub fn document_id(&self) -> &str {
        self.document
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The document's `type`.
    #[must_use]
    pub fn type_uri(&self) -> &str {
        self.document
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

/// The addressee of a received notification document — its `recipient` — when the document
/// is a notify or a relay at all.
#[must_use]
pub fn addressee_of(document: &Value) -> Option<&str> {
    let typ = document.get("type").and_then(Value::as_str)?;
    if !is_notification_type(typ) {
        return None;
    }
    document.get("recipient").and_then(Value::as_str)
}

/// The `vta/notifications/deposit/0.1` payload: the document **exactly as received**.
#[must_use]
pub fn deposit_payload(context_id: &str, document: &Value) -> Value {
    json!({ "contextId": context_id, "document": document })
}

/// What a deposit came to. Only reachability matters to the sender's receipt: whatever the VTA
/// decided, the receipt is the same (VTI-NTF-054).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Deposited {
    /// The VTA answered with its receipt — held, declined or already held, never saying which.
    Answered,
    /// The VTA refused the document (`notAddressedHere`, `documentInvalid`, `permissionDenied`).
    Refused(String),
}

/// Hand `document` to the VTA, exactly as received, in `context_id`.
///
/// # Errors
///
/// The VTA could not be reached or did not answer in time: the document was **not** handed
/// over, and nothing should tell the sender it was.
pub async fn deposit(
    vta: &VtaClient,
    context_id: &str,
    document: &Value,
) -> Result<Deposited, String> {
    match vta
        .notifications_deposit_json(deposit_payload(context_id, document))
        .await
    {
        Ok(_) => Ok(Deposited::Answered),
        Err(vta_sdk::error::VtaError::Rejected { code, .. }) => Ok(Deposited::Refused(code)),
        Err(e) if is_refusal(&e) => Ok(Deposited::Refused(e.to_string())),
        Err(e) => Err(e.to_string()),
    }
}

/// Whether a VTA error is the VTA answering (a refusal), rather than no answer.
fn is_refusal(e: &vta_sdk::error::VtaError) -> bool {
    use vta_sdk::error::VtaError;
    matches!(
        e,
        VtaError::Forbidden(_)
            | VtaError::Auth(_)
            | VtaError::Validation(_)
            | VtaError::NotFound(_)
            | VtaError::Conflict(_)
            | VtaError::Gone(_)
            | VtaError::DidcommRemote { .. }
    )
}

/// The receipt a notify or relay is answered with: the innermost notification's
/// `notificationId` and `revision` (VTI-NTF-023), from the delivery as this client verified it.
#[must_use]
pub fn receipt_for(verified: &vta_sdk::notifications::VerifiedDelivery) -> Value {
    let n = verified.notification();
    json!({
        "notificationId": n.notification_id.as_str(),
        "revision": n.revision.get(),
    })
}

/// The receipt document: `<the received type>#response`, threaded on the received document,
/// from the addressee to the sender. Unsigned; [`crate::capabilities::sign_document`] signs it.
///
/// # Errors
///
/// A received document whose type or id cannot carry an answer.
pub fn receipt_document(
    received: &Received,
    receipt: Value,
) -> Result<trust_tasks_rs::TrustTask<Value>, crate::errors::OpenVTCError> {
    let typ = received.type_uri();
    if !is_notification_type(typ) || received.document_id().is_empty() {
        return Err(crate::errors::OpenVTCError::Config(
            "a notification without a type or an id cannot be answered".into(),
        ));
    }
    let mut doc = crate::trust_task_doc::build(
        &format!("{typ}#response"),
        &received.addressee,
        &received.sender,
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        receipt,
    )?;
    doc.thread_id = Some(received.document_id().to_string());
    Ok(doc)
}

// ****************************************************************************
// Notified elections
// ****************************************************************************

/// An election a held notification tells the member of — shown only as notified (VTI-NTF-063):
/// who holds it, its identifier, its audience and period. Nothing here says the member may
/// vote in it (VTI-NTF-004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifiedElection {
    /// The VTA's record of it (`vta/notifications/show`, `dismiss`).
    pub record_id: String,
    /// The community holding the election (`subject.heldBy`): the party to read it from.
    pub held_by: String,
    /// The election's identifier there (`subject.id`).
    pub election_id: String,
    /// The DID the election concerns (`audience`): under a credential roll, the party whose
    /// membership credential admits a voter.
    pub audience: String,
    /// Who said it exists.
    pub originator: String,
    /// The relayers it passed through, in order.
    pub relayed_by: Vec<String>,
    /// When voting opens, if stated.
    pub valid_from: Option<String>,
    /// When voting closes, if stated.
    pub valid_until: Option<String>,
    /// The task that opens it, as the notification names it.
    pub open_with: String,
}

impl NotifiedElection {
    /// Whether opening it would take presenting a membership: its audience is a party other
    /// than the community holding it (VTI-VOT-015, VTI-VOT-016).
    #[must_use]
    pub fn audience_is_another_party(&self) -> bool {
        !vta_sdk::did_scid::same_reference(&self.audience, &self.held_by)
    }

    /// Whether this view of `community`'s elections shows it: held by that community, or put
    /// to its members (its audience is that community).
    #[must_use]
    pub fn concerns(&self, community: &str) -> bool {
        vta_sdk::did_scid::same_reference(&self.held_by, community)
            || vta_sdk::did_scid::same_reference(&self.audience, community)
    }

    /// Whether the task the notification names to open it is one this client sends
    /// (`vtc/elections/show/0.6`).
    #[must_use]
    pub fn opens_with_a_served_version(&self) -> bool {
        self.open_with == vta_sdk::notifications::ELECTION_OPEN_WITH
    }
}

/// The notified elections out of one `vta/notifications/list/0.1` page, and its `nextCursor`.
///
/// # Errors
///
/// A page the schema refuses.
pub fn notified_elections(page: &Value) -> Result<(Vec<NotifiedElection>, Option<String>), String> {
    let r: held::Response = serde_json::from_value(page.clone())
        .map_err(|e| crate::display::sanitize_display(&e.to_string(), MAX_PEER_TEXT))?;
    let clean = |s: &str| crate::display::sanitize_display(s, 2048);
    let items = r
        .items
        .into_iter()
        .filter(|h| h.notification.kind.as_str() == KIND_ELECTION)
        .filter(|h| h.notification.status == held::Status::Available)
        .map(|h| NotifiedElection {
            record_id: clean(h.record_id.as_str()),
            held_by: clean(h.notification.subject.held_by.as_str()),
            election_id: clean(h.notification.subject.id.as_str()),
            audience: clean(h.notification.audience.as_str()),
            originator: clean(h.originator.as_str()),
            relayed_by: h.relayed_by.iter().map(|d| clean(d.as_str())).collect(),
            valid_from: h.notification.valid_from.map(|t| t.to_rfc3339()),
            valid_until: h.notification.valid_until.map(|t| t.to_rfc3339()),
            open_with: clean(h.notification.subject.open_with.as_str()),
        })
        .collect();
    Ok((items, r.next_cursor.map(|c| c.to_string())))
}

/// Every held notification of the kind `election` in `context_id` the VTA holds as active and
/// available — dismissed, withdrawn and lapsed ones left out — up to [`MAX_LIST_PAGES`] pages.
///
/// # Errors
///
/// The VTA refused, could not be reached, or answered a page this client cannot read.
pub async fn list_elections(
    vta: &VtaClient,
    context_id: &str,
) -> Result<Vec<NotifiedElection>, String> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_LIST_PAGES {
        let mut req = json!({ "contextId": context_id, "kind": KIND_ELECTION });
        if let Some(c) = &cursor {
            req["cursor"] = Value::String(c.clone());
        }
        let page = vta
            .notifications_list_json(req)
            .await
            .map_err(|e| e.to_string())?;
        let (items, next) = notified_elections(&page)?;
        all.extend(items);
        match next {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests;
