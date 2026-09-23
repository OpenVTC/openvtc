//! Contacts — what other people have told the holder about themselves.
//!
//! The mirror of [`disclosure`](super::disclosure): that module is what leaves,
//! this is what arrives. A contact is context-scoped and filed against one of
//! the holder's own personas, because "who was I when they told me this" is
//! part of the record — a contact filed against no persona is one the holder
//! cannot later reason about disclosing to.
//!
//! Writes are **revisions, not overwrites**. What they said in March survives
//! them changing it in April, which is why [`get`] can ask for the history and
//! why a superseded revision is worth showing rather than silently replacing.

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::persona::{ContactClaim, ContactDocument};

use crate::errors::OpenVTCError;

/// One row of [`list`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSummary {
    pub contact_id: String,
    pub subject_did: String,
    /// Which of the holder's personas knows them.
    pub known_by_persona: String,
    /// Their own display-name claim, when they disclosed one.
    ///
    /// `None` is drawn as such rather than falling back to the DID: the
    /// specification is explicit that a producer must not substitute one
    /// silently, and a DID rendered where a name goes reads as a name.
    pub display_name: Option<String>,
    pub claim_count: u64,
    pub rev: u64,
    pub received_at: String,
    /// The current revision superseded another the holder has not yet looked at.
    pub unseen_change: bool,
}

impl ContactSummary {
    fn from_wire(v: &Value) -> Self {
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Self {
            contact_id: s("contactId"),
            subject_did: s("subjectDid"),
            known_by_persona: s("knownByPersona"),
            display_name: v
                .get("displayName")
                .and_then(Value::as_str)
                .map(str::to_string),
            claim_count: v.get("claimCount").and_then(Value::as_u64).unwrap_or(0),
            rev: v.get("rev").and_then(Value::as_u64).unwrap_or(0),
            received_at: s("receivedAt"),
            unseen_change: v
                .get("unseenChange")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }

    /// What to draw in a list: their name if they gave one, else their DID
    /// said as a DID.
    #[must_use]
    pub fn label(&self) -> String {
        self.display_name
            .clone()
            .unwrap_or_else(|| self.subject_did.clone())
    }
}

/// One claim inside a contact's card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactFact {
    pub claim_type: String,
    pub value: String,
}

/// A contact read in full, optionally with what they said before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactDetail {
    pub summary: ContactSummary,
    pub facts: Vec<ContactFact>,
    pub notes: Option<String>,
    /// Earlier revisions, newest first. Empty unless asked for.
    pub earlier: Vec<ContactRevision>,
}

/// One superseded revision of a contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRevision {
    pub rev: u64,
    pub received_at: String,
    pub facts: Vec<ContactFact>,
}

fn facts_from(document: Option<&Value>) -> Vec<ContactFact> {
    document
        .and_then(|d| d.get("claims"))
        .and_then(Value::as_array)
        .map(|claims| {
            claims
                .iter()
                .map(|c| ContactFact {
                    claim_type: c
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    // A value is any JSON. Rendered rather than typed: this is
                    // someone else's card, and a number that arrives as a
                    // string is still what they said.
                    value: match c.get("value") {
                        Some(Value::String(s)) => s.clone(),
                        Some(other) => other.to_string(),
                        None => String::new(),
                    },
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The contacts filed in one context, newest first.
pub async fn list(
    client: &VtaClient,
    context_id: &str,
) -> Result<Vec<ContactSummary>, OpenVTCError> {
    let value = client
        .persona_contact_list(context_id, None, None, None, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona contact list failed: {e}")))?;
    let mut rows: Vec<ContactSummary> = value
        .get("contacts")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(ContactSummary::from_wire).collect())
        .unwrap_or_default();
    rows.sort_by(|a, b| b.received_at.cmp(&a.received_at));
    Ok(rows)
}

/// One contact, with every retained revision when `history` is set.
pub async fn get(
    client: &VtaClient,
    context_id: &str,
    contact_id: &str,
    history: bool,
) -> Result<ContactDetail, OpenVTCError> {
    let value = client
        .persona_contact_get(context_id, contact_id, None, history)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona contact get failed: {e}")))?;
    let summary = ContactSummary::from_wire(&value);
    let mut earlier: Vec<ContactRevision> = value
        .get("history")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|r| ContactRevision {
                    rev: r.get("rev").and_then(Value::as_u64).unwrap_or(0),
                    received_at: r
                        .get("receivedAt")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    facts: facts_from(r.get("document")),
                })
                .collect()
        })
        .unwrap_or_default();
    earlier.sort_by_key(|r| std::cmp::Reverse(r.rev));
    // The current revision comes back in `history` too on some agents. It is
    // the detail's own, not an earlier one.
    earlier.retain(|r| r.rev != summary.rev);
    Ok(ContactDetail {
        facts: facts_from(value.get("document")),
        notes: value
            .get("notes")
            .and_then(Value::as_str)
            .map(str::to_string),
        earlier,
        summary,
    })
}

/// Record what a peer disclosed, as a new revision.
pub async fn put(
    client: &VtaClient,
    context_id: &str,
    subject_did: &str,
    known_by_persona: &str,
    facts: Vec<ContactFact>,
    notes: Option<&str>,
) -> Result<String, OpenVTCError> {
    let document = ContactDocument {
        claims: facts
            .into_iter()
            .map(|f| ContactClaim {
                claim_type: f.claim_type,
                value: Value::String(f.value),
                // Typed as a string and nothing more: this is what the holder
                // typed off a card someone showed them, not a value the peer
                // signed, so claiming a type or a provenance for them would be
                // the wallet asserting something nobody said.
                value_type: None,
                label: None,
                provenance: None,
            })
            .collect(),
        card_version: None,
        publisher: None,
    };
    let value = client
        .persona_contact_put(
            context_id,
            subject_did,
            known_by_persona,
            document,
            Vec::new(),
            notes,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona contact put failed: {e}")))?;
    Ok(value
        .get("contactId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string())
}

/// Forget a contact, every retained revision with it.
pub async fn delete(
    client: &VtaClient,
    context_id: &str,
    contact_id: &str,
) -> Result<(), OpenVTCError> {
    client
        .persona_contact_delete(context_id, contact_id)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona contact delete failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A contact without a disclosed name is drawn by DID — and `label` says
    /// which it is, so a pane never presents a DID as though it were a name
    /// the person chose.
    #[test]
    fn a_contact_that_gave_no_name_is_not_given_one() {
        let row = ContactSummary::from_wire(&serde_json::json!({
            "contactId": "01C",
            "subjectDid": "did:key:zPeer",
            "knownByPersona": "did:key:zMe",
            "rev": 2,
            "receivedAt": "2026-09-07T10:00:00Z",
        }));
        assert_eq!(row.display_name, None);
        assert_eq!(row.label(), "did:key:zPeer");
    }

    /// Values are someone else's JSON: a string is shown as itself, anything
    /// else as what it is rather than as an empty cell.
    #[test]
    fn a_fact_of_any_shape_is_rendered() {
        let facts = facts_from(Some(&serde_json::json!({
            "claims": [
                { "type": "name.display", "value": "Ada" },
                { "type": "age.years", "value": 36 },
                { "type": "broken" },
            ]
        })));
        assert_eq!(facts[0].value, "Ada");
        assert_eq!(facts[1].value, "36");
        assert_eq!(facts[2].value, "");
    }
}
