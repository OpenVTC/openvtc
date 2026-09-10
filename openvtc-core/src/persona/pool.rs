//! The attribute pool — the attributes themselves, held once and projected many
//! times. **Holder-scoped**: above every trust context, and never readable
//! from inside one.
//!
//! # Values are opt-in, at every layer
//!
//! [`list`] takes `include_values` and defaults callers towards `false` for the
//! same reason the Trust Task does: "how many phone numbers do I hold" and "read
//! me the holder's identity" are different questions, and only one of them needs
//! plaintext. A picker needs type and label; a panel that renders values needs
//! the operator to have asked.
//!
//! # What this module will and will not author
//!
//! [`put`] writes **self-asserted** attributes only, and [`AttributeDraft`]
//! has no `provenance` field at all — the constraint is structural rather than
//! a default someone can pass a different value for.
//!
//! A credential-backed attribute names a `credentialId` and a `claimPath` into
//! it, and its value is re-derived from the credential rather than stored: an
//! editor that let a holder type over one would be manufacturing an attested
//! claim out of a typed string, which is precisely the escalation provenance
//! exists to prevent. A generated attribute is minted by the agent per verifier
//! and has no plaintext to edit at all. Both are returned by [`list`] — a
//! holder must see everything they hold — and both are refused by [`put`],
//! which returns [`AttributeEdit::refusal`] naming why. Changing one is a `pnm`
//! operation against its source.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::persona::{Provenance, ValueType};

use crate::errors::OpenVTCError;
use crate::persona::claim_types::{ClaimTypeDefaults, Registry};

/// Where an attribute's value came from, reduced to what a panel can act on.
///
/// The SDK's [`Provenance`] carries the credential id, claim path and proof
/// rung. None of those are editable here and all of them are long, so this
/// keeps the distinction that governs behaviour — may the holder retype the
/// value? — and drops the rest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceKind {
    /// The holder typed it. The only kind this module authors.
    #[default]
    SelfAsserted,
    /// Backed by a credential the holder holds; the value is derived from it.
    CredentialBacked,
    /// Minted by the agent, usually per verifier (a relay address, an alias).
    Generated,
}

impl ProvenanceKind {
    /// Parse the `provenance` member of a wire attribute.
    ///
    /// An unrecognised discriminator resolves to [`CredentialBacked`], not
    /// [`SelfAsserted`]: this value gates editing, and the safe answer for a
    /// provenance a newer VTA introduced is "this build does not know how to
    /// author it". Guessing the other way would let a future attested kind be
    /// overwritten with a typed string by a build that never heard of it.
    ///
    /// [`CredentialBacked`]: ProvenanceKind::CredentialBacked
    /// [`SelfAsserted`]: ProvenanceKind::SelfAsserted
    pub(crate) fn parse_wire(value: Option<&Value>) -> Self {
        match value.and_then(|p| p.get("kind")).and_then(Value::as_str) {
            Some("selfAsserted") => Self::SelfAsserted,
            Some("generated") => Self::Generated,
            _ => Self::CredentialBacked,
        }
    }

    /// Whether this build may rewrite the attribute's value. See the module
    /// header for why only one kind qualifies.
    #[must_use]
    pub fn is_editable_here(self) -> bool {
        matches!(self, Self::SelfAsserted)
    }

    /// What a person reads for this provenance
    /// (`design-docs/persona-vocabulary.md`). The spec's words stay in the
    /// type; they are kept off the screen.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SelfAsserted => "you said so",
            Self::CredentialBacked => "credential",
            Self::Generated => "made per verifier",
        }
    }

    /// Whether this value links the holder across everyone who sees it, said in
    /// the words the table uses.
    ///
    /// Always shown beside the label, because it is the half people miss: a
    /// credential is *provable* and carries the same issuer signature to every
    /// verifier, which is the more consequential of the two attributes and the less
    /// obvious one. Severity inverts intuition here — a credential shown whole
    /// links more than a value the holder simply asserted — so the words must
    /// not hide it.
    #[must_use]
    pub fn linkage(self) -> Option<&'static str> {
        match self {
            // Passed on, never proven, and no signature to join on.
            Self::SelfAsserted => None,
            Self::CredentialBacked => Some("same signature everywhere — links you"),
            Self::Generated => Some("different for everyone — cannot link you"),
        }
    }
}

/// One attribute in the holder's pool, as a panel needs it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PoolAttribute {
    /// Stable identifier — what a profile entry references.
    pub attribute_id: String,
    /// Vocabulary token: `name.legal`, `phone.mobile`. The store's own.
    pub claim_type: String,
    /// The holder's own words for their own picker. Never disclosed.
    pub label: Option<String>,
    /// `string` / `number` / `boolean` / `date` / `object`, as the VTA spells it.
    pub value_type: String,
    /// The value, present only when the read asked for values **and** the store
    /// could produce one.
    pub value: Option<Value>,
    pub provenance: ProvenanceKind,
    /// A credential-backed value that could not be re-derived. Distinct from an
    /// absent [`value`](Self::value), which usually just means the read did not
    /// ask for one.
    pub stale: bool,
    /// Why it went stale — `expired`, `revoked`, and so on, as the agent says
    /// it. Shown beside the word, never instead of it: "stale" alone tells a
    /// holder something is wrong without telling them what.
    pub stale_reason: Option<String>,
    /// Optimistic-concurrency token, passed back on edit so two editors cannot
    /// silently overwrite each other.
    pub version: u64,
    pub updated_at: String,
}

impl PoolAttribute {
    fn from_wire(value: &Value) -> Self {
        let str_field = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_default()
        };
        Self {
            attribute_id: str_field("attributeId"),
            claim_type: str_field("type"),
            label: value
                .get("label")
                .and_then(Value::as_str)
                .map(str::to_string),
            value_type: str_field("valueType"),
            value: value.get("value").cloned(),
            provenance: ProvenanceKind::parse_wire(value.get("provenance")),
            stale: value.get("stale").and_then(Value::as_bool).unwrap_or(false),
            stale_reason: value
                .get("staleReason")
                .and_then(Value::as_str)
                .map(str::to_string),
            version: value.get("version").and_then(Value::as_u64).unwrap_or(0),
            updated_at: str_field("updatedAt"),
        }
    }

    /// The name to show: the holder's label, else the vocabulary token. Never
    /// empty, so a row cannot render as a blank line.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self.label.as_deref() {
            Some(label) if !label.trim().is_empty() => label,
            _ if !self.claim_type.is_empty() => &self.claim_type,
            _ => "(unnamed attribute)",
        }
    }

    /// What this attribute's claim type says about showing its value.
    #[must_use]
    pub fn claim_defaults(&self, registry: &Registry) -> ClaimTypeDefaults {
        registry.resolve(&self.claim_type)
    }

    /// Whether [`display_value`](Self::display_value) is showing a reduced form
    /// of a value we are holding.
    ///
    /// The caller needs this to say *masked* rather than let the row read as
    /// empty: `••••••••` and "(no value)" are one glance apart, and one of them
    /// is a wrong answer about what the holder holds.
    #[must_use]
    pub fn is_masked(&self, registry: &Registry) -> bool {
        !self.stale && self.value.is_some() && self.claim_defaults(registry).masks_by_default()
    }

    /// The value as one line, or the reason there is none — masked when its
    /// claim type asks for that.
    ///
    /// Three readings kept apart on purpose, because collapsing any two of them
    /// misinforms the holder about their own data: we did not ask; we asked and
    /// the source could not answer; here it is. Masking adds a fourth — *we
    /// have it and are not painting it* — which is why it is
    /// [`is_masked`](Self::is_masked) rather than a fourth string here.
    #[must_use]
    pub fn display_value(&self, registry: &Registry, values_requested: bool) -> String {
        self.value_line(registry, values_requested, false)
    }

    /// The same line with the mask lifted, for a holder who asked for this one
    /// value.
    ///
    /// A separate method rather than a `reveal: bool` on
    /// [`display_value`](Self::display_value), so that reading a masked value
    /// in the clear is something a call site had to *name*. A boolean
    /// gets passed through, and the caller that ends up passing `true` is
    /// rarely the one that meant to.
    #[must_use]
    pub fn revealed_value(&self, registry: &Registry, values_requested: bool) -> String {
        self.value_line(registry, values_requested, true)
    }

    fn value_line(&self, registry: &Registry, values_requested: bool, reveal: bool) -> String {
        if self.stale {
            return match &self.stale_reason {
                Some(reason) => format!("stale · {reason} — can no longer be proven"),
                None => "stale — can no longer be proven".to_string(),
            };
        }
        let shown = |text: String| {
            if reveal {
                text
            } else {
                self.claim_defaults(registry).render(&text)
            }
        };
        match &self.value {
            Some(Value::String(s)) => shown(s.clone()),
            Some(other) => shown(other.to_string()),
            None if values_requested => "(no value)".to_string(),
            None => "(hidden)".to_string(),
        }
    }
}

/// What [`put`] needs to write a self-asserted attribute.
///
/// Carries no provenance: see the module header.
#[derive(Clone, Debug)]
pub struct AttributeDraft {
    /// `None` creates; `Some` updates that attribute.
    pub attribute_id: Option<String>,
    /// The version the editor was opened against, so a concurrent edit is
    /// refused rather than silently overwritten. `None` when creating.
    pub expected_version: Option<u64>,
    pub claim_type: String,
    pub label: Option<String>,
    pub value: Value,
    pub value_type: ValueType,
}

impl Default for AttributeDraft {
    /// An empty, self-asserted string attribute — what an editor opens on.
    /// [`ValueType`] has no `Default` of its own, and `String` is the only
    /// honest choice here: it is the one type a blank text field can hold
    /// without the form having to guess what the holder meant.
    fn default() -> Self {
        Self {
            attribute_id: None,
            expected_version: None,
            claim_type: String::new(),
            label: None,
            value: Value::Null,
            value_type: ValueType::String,
        }
    }
}

/// The outcome of an attempted write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttributeEdit {
    /// The attribute the VTA created or updated.
    Written(String),
    /// This build declined to author the change, with the reason to show.
    Refused(String),
}

impl AttributeEdit {
    /// The refusal a non-self-asserted attribute earns, worded for the panel.
    #[must_use]
    pub fn refusal(kind: ProvenanceKind) -> Self {
        Self::Refused(match kind {
            ProvenanceKind::CredentialBacked => {
                "This attribute comes from a credential — typing over it would turn something \
                 provable into something you said. Change it at its source, or replace the \
                 credential."
                    .to_string()
            }
            ProvenanceKind::Generated => {
                "Your agent makes this one per verifier — a different value for everyone, so \
                 there is no single value to edit."
                    .to_string()
            }
            ProvenanceKind::SelfAsserted => {
                "You said this one, so it is editable; nothing should have refused it.".to_string()
            }
        })
    }
}

/// Enumerate the pool.
///
/// `include_values` is the whole of the difference between a picker and a read
/// of the holder's identity — see the module header.
pub async fn list(
    client: &VtaClient,
    include_values: bool,
) -> Result<Vec<PoolAttribute>, OpenVTCError> {
    let value = client
        // `include_sensitive` is vta-sdk 0.34's second escalation, and it is
        // passed `include_values` rather than a constant on purpose. In this
        // client the two questions have one answer: the only caller is the
        // identity pane's `show_values` toggle, which is the holder saying
        // "show me what I hold" — and when it is on, the pane reveals masked
        // values whole from what this call returned. Passing `false` here would
        // not narrow that read, it would make every `sensitivity: high`
        // attribute come back valueless and render as "(no value)" under the
        // reveal — which is a *wrong answer* about what the holder holds, and
        // one glance away from "nothing is stored". Honouring the escalation
        // properly means the `s` reveal fetching that one value on its own, so
        // the default read stops carrying every card number into this process
        // while the reveal stays truthful. That is a pane change, not a
        // dependency bump.
        .persona_attribute_list(None, include_values, include_values, None, None, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona attribute list failed: {e}")))?;

    let mut attributes: Vec<PoolAttribute> = value
        .get("attributes")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(PoolAttribute::from_wire).collect())
        .unwrap_or_default();
    // Display order the holder can predict. The store returns insertion order,
    // which is the order things happened to be typed in — fine for a machine,
    // useless for finding "the work email" in a list of thirty.
    attributes.sort_by(|a, b| {
        a.claim_type
            .cmp(&b.claim_type)
            .then_with(|| a.display_name().cmp(b.display_name()))
    });
    Ok(attributes)
}

/// Create or update a self-asserted attribute.
///
/// A create is a `put` with no `attributeId`; the VTA mints one and returns it.
pub async fn put(client: &VtaClient, draft: AttributeDraft) -> Result<AttributeEdit, OpenVTCError> {
    let response = client
        .persona_attribute_put(
            &draft.claim_type,
            draft.value,
            draft.value_type,
            Provenance::SelfAsserted,
            draft.label.as_deref(),
            draft.attribute_id.as_deref(),
            draft.expected_version,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona attribute write failed: {e}")))?;

    Ok(AttributeEdit::Written(
        response
            .get("attributeId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or(draft.attribute_id)
            .unwrap_or_default(),
    ))
}

/// Remove an attribute.
///
/// Without `cascade` the VTA refuses while a profile still references it — the
/// alternative is profiles quietly presenting a dangling reference. The caller
/// is expected to surface that refusal and ask, rather than retrying with
/// `cascade` on the holder's behalf: cascading edits every profile that used
/// the attribute, and that is not a consequence to infer from a `d` keypress.
pub async fn delete(
    client: &VtaClient,
    attribute_id: &str,
    cascade: bool,
) -> Result<(), OpenVTCError> {
    client
        .persona_attribute_delete(attribute_id, cascade, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona attribute delete failed: {e}")))?;
    Ok(())
}

/// Parse the `valueType` string a [`PoolAttribute`] carries back into the typed
/// form [`put`] needs. Unknown types read as [`ValueType::String`], which is
/// what an editor can actually offer a text field for.
#[must_use]
pub fn value_type_from_str(s: &str) -> ValueType {
    match s {
        "number" => ValueType::Number,
        "boolean" => ValueType::Boolean,
        "date" => ValueType::Date,
        "object" => ValueType::Object,
        _ => ValueType::String,
    }
}

/// Turn typed text into the JSON value its declared type calls for.
///
/// Returns the parse failure as text a form can show next to the field. A
/// `number` field that quietly stored `"12"` as a string would present a value
/// no predicate proof could ever compare against.
pub fn parse_typed_value(text: &str, value_type: ValueType) -> Result<Value, String> {
    let trimmed = text.trim();
    match value_type {
        ValueType::String | ValueType::Date => Ok(Value::String(trimmed.to_string())),
        ValueType::Number => trimmed
            .parse::<f64>()
            .map_err(|_| format!("`{trimmed}` is not a number"))
            .and_then(|n| {
                serde_json::Number::from_f64(n)
                    .map(Value::Number)
                    .ok_or_else(|| format!("`{trimmed}` is not a finite number"))
            }),
        ValueType::Boolean => match trimmed.to_ascii_lowercase().as_str() {
            "true" | "yes" | "y" | "1" => Ok(Value::Bool(true)),
            "false" | "no" | "n" | "0" => Ok(Value::Bool(false)),
            _ => Err(format!("`{trimmed}` is not true or false")),
        },
        ValueType::Object => {
            serde_json::from_str(trimmed).map_err(|e| format!("not valid JSON: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::persona::claim_types::Registry;

    /// The compiled copy — spec 0.1 — as the table these tests resolve
    /// against. A unit test must not depend on what a live agent happens to
    /// serve, and every assertion below is about a token 0.1 declares.
    fn reg() -> Registry {
        Registry::vendored()
    }

    use super::*;

    fn wire(provenance: &str) -> Value {
        serde_json::json!({
            "attributeId": "01J8",
            "type": "email.work",
            "valueType": "string",
            "provenance": { "kind": provenance },
            "version": 3,
            "updatedAt": "2026-09-06T00:00:00Z",
        })
    }

    /// The three provenance kinds the panel branches on, round-tripped from the
    /// shape the VTA actually sends.
    #[test]
    fn provenance_parses_from_its_discriminator() {
        assert_eq!(
            PoolAttribute::from_wire(&wire("selfAsserted")).provenance,
            ProvenanceKind::SelfAsserted
        );
        assert_eq!(
            PoolAttribute::from_wire(&wire("generated")).provenance,
            ProvenanceKind::Generated
        );
        assert_eq!(
            PoolAttribute::from_wire(&wire("credentialBacked")).provenance,
            ProvenanceKind::CredentialBacked
        );
    }

    /// A provenance this build has never heard of must not become editable.
    ///
    /// The failure this guards is quiet and one-directional: a newer VTA adds
    /// an attested kind, an older build parses it as self-asserted, and the
    /// holder retypes an attested value into a typed one from a panel that
    /// believed it was allowed to.
    #[test]
    fn an_unknown_provenance_is_not_editable() {
        let attr = PoolAttribute::from_wire(&wire("someFutureKind"));
        assert!(!attr.provenance.is_editable_here());
        let missing = PoolAttribute::from_wire(&serde_json::json!({ "attributeId": "01J8" }));
        assert!(!missing.provenance.is_editable_here());
    }

    /// "We did not ask", "there is nothing", and "the source failed" are three
    /// different sentences. A holder reading their own pool has to be able to
    /// tell them apart — collapsing them is how a panel says "you hold no phone
    /// number" about a value it simply never requested.
    #[test]
    fn the_three_reasons_for_an_absent_value_read_differently() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        assert_eq!(attr.display_value(&reg(), false), "(hidden)");
        assert_eq!(attr.display_value(&reg(), true), "(no value)");
        attr.stale = true;
        assert!(
            attr.display_value(&reg(), true)
                .contains("can no longer be proven")
        );
        // The reason is shown beside the word, never instead of it: "stale"
        // alone says something is wrong without saying what.
        attr.stale_reason = Some("revoked".into());
        assert_eq!(
            attr.display_value(&reg(), true),
            "stale · revoked — can no longer be proven"
        );
    }

    /// A string value renders as itself, not as a quoted JSON string — the
    /// panel shows `Alice`, never `"Alice"`. An unmasked type, so the
    /// assertion is about the quoting and not about the mask.
    #[test]
    fn a_string_value_renders_unquoted() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        attr.claim_type = "name.given".into();
        attr.value = Some(Value::String("Alice".into()));
        assert_eq!(attr.display_value(&reg(), true), "Alice");
    }

    /// A typed field stores the type it declares. The number case is the one
    /// that matters: `"30"` and `30` compare differently, and a predicate proof
    /// over the string form can never be satisfied.
    #[test]
    fn typed_values_parse_to_their_declared_type() {
        assert_eq!(
            parse_typed_value("30", ValueType::Number).unwrap(),
            serde_json::json!(30.0)
        );
        assert_eq!(
            parse_typed_value(" yes ", ValueType::Boolean).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            parse_typed_value(r#"{"a":1}"#, ValueType::Object).unwrap(),
            serde_json::json!({"a": 1})
        );
        assert!(parse_typed_value("thirty", ValueType::Number).is_err());
        assert!(parse_typed_value("maybe", ValueType::Boolean).is_err());
    }

    /// A value whose type carries a mask style is masked, and reads back whole
    /// only when a caller asks for that one value.
    ///
    /// The pairing is the point: the mask has to be liftable, or a holder
    /// cannot check their own card number; and lifting it has to be a
    /// different call, or it is not a decision anyone made.
    #[test]
    fn a_masked_value_is_only_whole_when_it_is_asked_for() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        attr.claim_type = "payment.card".into();
        attr.value = Some(Value::String("4242424242424242".into()));

        assert!(attr.is_masked(&reg()));
        assert_eq!(attr.display_value(&reg(), true), "••••••••••••4242");
        assert_eq!(attr.revealed_value(&reg(), true), "4242424242424242");
    }

    /// A type whose style is `none` is shown as it is held. Masking every attribute
    /// would teach the reveal key as a reflex, and a reveal pressed by reflex
    /// protects nothing.
    #[test]
    fn a_value_with_no_mask_style_is_shown_whole() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        attr.claim_type = "name.given".into();
        attr.value = Some(Value::String("Alice".into()));
        assert!(!attr.is_masked(&reg()));
        assert_eq!(attr.display_value(&reg(), true), "Alice");
    }

    /// Sensitivity is not what triggers the mask — the style is. An email
    /// address is `normal` and still masked: worth hiding from the person
    /// behind you without being worth withholding from a listing.
    #[test]
    fn a_normal_type_with_a_style_is_still_masked() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        attr.value = Some(Value::String("alice@example.com".into()));
        assert!(attr.is_masked(&reg()));
        assert_eq!(attr.display_value(&reg(), true), "a•••@example.com");
        assert_eq!(attr.revealed_value(&reg(), true), "alice@example.com");
    }

    /// A vocabulary this build has never seen is masked, because nothing here
    /// knows what it holds. Same rule for the open `x:` namespace.
    #[test]
    fn an_unregistered_type_is_masked() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        attr.claim_type = "x:employer.badge".into();
        attr.value = Some(Value::String("A-1174".into()));
        assert!(attr.is_masked(&reg()));
        assert_eq!(attr.display_value(&reg(), true), "••••••••");
    }

    /// Masked and absent are different states, and a caller has to be able to
    /// tell them apart — `••••••••` and "(no value)" are one glance apart on a
    /// row, and one of them is a wrong answer about what the holder holds.
    #[test]
    fn masked_is_not_the_same_state_as_absent() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        attr.claim_type = "person.birthDate".into();
        assert!(!attr.is_masked(&reg()), "nothing held is nothing to mask");
        assert_eq!(attr.display_value(&reg(), true), "(no value)");
        assert_eq!(attr.display_value(&reg(), false), "(hidden)");

        attr.value = Some(Value::String("1990-01-01".into()));
        assert!(attr.is_masked(&reg()));
    }

    /// A stale value keeps saying it is stale. The reason it cannot be shown is
    /// not that it is masked, and a mask over it would hide the one thing the
    /// holder needs to act on.
    #[test]
    fn a_stale_masked_value_still_says_it_is_stale() {
        let mut attr = PoolAttribute::from_wire(&wire("credentialBacked"));
        attr.claim_type = "gov.id.passport".into();
        attr.value = Some(Value::String("P1234567".into()));
        attr.stale = true;
        attr.stale_reason = Some("revoked".into());

        assert!(!attr.is_masked(&reg()));
        assert_eq!(
            attr.display_value(&reg(), true),
            "stale · revoked — can no longer be proven"
        );
    }

    /// A label is what the holder sees; falling back to the vocabulary token
    /// keeps an unlabelled row identifiable rather than blank.
    #[test]
    fn display_name_falls_back_to_the_type() {
        let mut attr = PoolAttribute::from_wire(&wire("selfAsserted"));
        assert_eq!(attr.display_name(), "email.work");
        attr.label = Some("  ".into());
        assert_eq!(
            attr.display_name(),
            "email.work",
            "a blank label is no label"
        );
        attr.label = Some("Work email".into());
        assert_eq!(attr.display_name(), "Work email");
    }
}
