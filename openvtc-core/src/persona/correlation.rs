//! Links — where the holder's identities join up, and which of those joins
//! cross a part of their life.
//!
//! `persona/correlation/analyze` on the wire; **link** on screen, per
//! `design-docs/persona-vocabulary.md`. "Correlation" is never said to a
//! person: the sentence they need is *same person to anyone who sees both*.
//!
//! # Two axes, and reading either off the other loses one
//!
//! - [`Finding::severity`] is **how strongly** a disclosure would link the
//!   holder. It follows from provenance and proof rung and is true whatever the
//!   holder meant: a credential shown whole carries the same signature to
//!   everyone who sees it, and that is a fact about the value.
//! - [`Finding::crosses_worlds`] is **whether the holder would mind**. A value
//!   shared between two faces in the *same* world is linkage they arranged on
//!   purpose — a work email in every work face — and a pane that alarmed on it
//!   would teach people to dismiss the alarm. A value shared *across* worlds is
//!   the finding worth raising.
//!
//! So the pane leads with the second and qualifies with the first. Neither is a
//! restatement of the other, and a client that showed only `severity` would be
//! loudest about exactly the arrangements a holder had deliberately made.
//!
//! # Absent is not false
//!
//! `crossesFacets` is **absent** when the agent does not implement worlds at
//! all, which is a different answer from "this link stays inside one part of
//! your life". [`Finding::crosses_worlds`] keeps that as an `Option` and the
//! pane says nothing rather than guessing — a reassurance nobody computed is
//! worse than silence.

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;

use crate::errors::OpenVTCError;

/// How strongly a disclosure of this value would link the holder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Severity {
    /// Linkable, but not by a signature anyone else can match.
    #[default]
    Low,
    /// The same to everyone who sees it.
    High,
}

impl Severity {
    fn from_wire(token: &str) -> Self {
        match token {
            "high" => Self::High,
            _ => Self::Low,
        }
    }
}

/// What the holder can actually do about a link.
///
/// Kept as served rather than narrowed to the ones this build renders, because
/// the list is the point: a holder told "this links your personas" with no
/// action but to abandon the attribute has been given a warning rather than a
/// choice, and the honest fix — a credential re-issued against the persona
/// actually using it — stays invisible unless something names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    UseDifferentValue,
    ReissueCredentialToThisDid,
    CorrelateDeliberately,
    ProceedAndRecord,
}

impl Remedy {
    fn from_wire(token: &str) -> Option<Self> {
        match token {
            "useDifferentValue" => Some(Self::UseDifferentValue),
            "reissueCredentialToThisDid" => Some(Self::ReissueCredentialToThisDid),
            "correlateDeliberately" => Some(Self::CorrelateDeliberately),
            "proceedAndRecord" => Some(Self::ProceedAndRecord),
            // A remedy this build has never heard of. Dropped rather than
            // rendered as its raw token: an action a holder cannot take from
            // here, spelled in wire vocabulary, is not a choice.
            _ => None,
        }
    }

    /// What this remedy says to the holder, in the second person.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::UseDifferentValue => "hold a different value for one of them",
            Self::ReissueCredentialToThisDid => {
                "have the credential re-issued to the persona that uses it"
            }
            Self::CorrelateDeliberately => "decide the link is one you want",
            Self::ProceedAndRecord => "go ahead, and have it written down",
        }
    }
}

/// One link the agent found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Finding {
    /// The attribute this is about, when the finding is about one.
    pub attribute_id: Option<String>,
    pub severity: Severity,
    /// Plain-language cause, in the agent's words.
    ///
    /// Shown rather than summarised: a severity with no explanation is a
    /// warning a holder learns to dismiss.
    pub why: String,
    pub remedies: Vec<Remedy>,
    /// Whether this link spans two or more worlds.
    ///
    /// `None` means the agent does not implement worlds — **not** that the link
    /// stays inside one. See the module header.
    pub crosses_worlds: Option<bool>,
    /// How many places this value appears in.
    pub shared_with: usize,
}

impl Finding {
    fn from_wire(value: &Value) -> Self {
        Self {
            attribute_id: value
                .get("attributeId")
                .and_then(Value::as_str)
                .map(str::to_string),
            severity: value
                .get("severity")
                .and_then(Value::as_str)
                .map_or(Severity::Low, Severity::from_wire),
            why: value
                .get("why")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            remedies: value
                .get("remedies")
                .and_then(Value::as_array)
                .map(|xs| {
                    xs.iter()
                        .filter_map(Value::as_str)
                        .filter_map(Remedy::from_wire)
                        .collect()
                })
                .unwrap_or_default(),
            crosses_worlds: value.get("crossesFacets").and_then(Value::as_bool),
            shared_with: value
                .get("sharedWith")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
        }
    }

    /// Whether this is the finding worth raising: a link across parts of a life
    /// the holder said belong apart.
    #[must_use]
    pub fn crosses_a_world(&self) -> bool {
        self.crosses_worlds == Some(true)
    }

    /// The sentence this finding leads with.
    ///
    /// The cross-world case gets the vocabulary's own line, because it is the
    /// one a holder has to be able to recognise on sight and the words are
    /// fixed so they meet the same sentence on every surface.
    #[must_use]
    pub fn headline(&self) -> &'static str {
        match (self.crosses_a_world(), self.severity) {
            (true, _) => {
                "These two worlds share a value — anyone who sees both knows they are \
                          the same person."
            }
            (false, Severity::High) => {
                "Provable — and the same signature to everyone who sees it, so it links."
            }
            (false, Severity::Low) => "Same person to anyone who sees both.",
        }
    }
}

/// Ask the agent where the holder's identities link up.
///
/// The whole pool, not one attribute: the pane draws a marker per row and a
/// count above them, and asking per row would be one round-trip per attribute
/// for an answer the agent computes across all of them anyway.
///
/// Returns an empty list — not an error — when the agent does not serve the
/// task. Every other failure is returned: "we could not ask" and "nothing links"
/// are one glance apart, and of the two, a clean bill of health nobody computed
/// is the one that misleads (VTI R6.4).
pub async fn analyze(client: &VtaClient) -> Result<Vec<Finding>, OpenVTCError> {
    let value = match client.persona_correlation_analyze(None, None, None).await {
        Ok(value) => value,
        Err(VtaError::UnsupportedTaskType { .. }) => return Ok(Vec::new()),
        Err(e) => {
            return Err(OpenVTCError::Vta(format!(
                "persona correlation analyze failed: {e}"
            )));
        }
    };

    Ok(value
        .get("findings")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(Finding::from_wire).collect())
        .unwrap_or_default())
}

/// The finding for one attribute, if the agent raised one.
///
/// The cross-world finding wins when an attribute has more than one, because it
/// is the one the holder would act on: severity is true whatever they intended,
/// and this is the axis that says whether they would mind.
#[must_use]
pub fn for_attribute<'a>(findings: &'a [Finding], attribute_id: &str) -> Option<&'a Finding> {
    let mine = || {
        findings
            .iter()
            .filter(|f| f.attribute_id.as_deref() == Some(attribute_id))
    };
    mine()
        .find(|f| f.crosses_a_world())
        .or_else(|| mine().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(attribute: &str, crosses: Option<bool>, severity: &str) -> Value {
        let mut row = json!({
            "attributeId": attribute,
            "severity": severity,
            "why": "the same mobile number is in two faces",
            "remedies": ["useDifferentValue", "correlateDeliberately"],
            "sharedWith": [{ "profileId": "01P" }, { "profileId": "02P" }],
        });
        if let Some(c) = crosses {
            row["crossesFacets"] = json!(c);
        }
        row
    }

    fn parse(rows: Value) -> Vec<Finding> {
        rows.as_array()
            .unwrap()
            .iter()
            .map(Finding::from_wire)
            .collect()
    }

    /// A finding is read whole, remedies included — the remedies are the
    /// difference between a warning and a choice.
    #[test]
    fn a_finding_is_read_whole() {
        let f = &parse(json!([finding("01A", Some(true), "high")]))[0];
        assert_eq!(f.attribute_id.as_deref(), Some("01A"));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.shared_with, 2);
        assert_eq!(
            f.remedies,
            vec![Remedy::UseDifferentValue, Remedy::CorrelateDeliberately]
        );
        assert!(f.crosses_a_world());
    }

    /// An absent `crossesFacets` is not `false`.
    ///
    /// The agent does not implement worlds, which is a different answer from
    /// "this link stays inside one part of your life" — and a reassurance
    /// nobody computed is worse than silence.
    #[test]
    fn an_absent_answer_is_not_a_negative_one() {
        let f = &parse(json!([finding("01A", None, "low")]))[0];
        assert_eq!(f.crosses_worlds, None);
        assert!(!f.crosses_a_world());

        let explicit = &parse(json!([finding("01A", Some(false), "low")]))[0];
        assert_eq!(explicit.crosses_worlds, Some(false));
        assert!(!explicit.crosses_a_world());
    }

    /// Severity and crossing are two axes. A high-severity link *inside* one
    /// world is a strong link the holder arranged on purpose, and it does not
    /// get the cross-world sentence.
    #[test]
    fn the_two_axes_are_not_read_off_each_other() {
        let inside = &parse(json!([finding("01A", Some(false), "high")]))[0];
        let across = &parse(json!([finding("01A", Some(true), "low")]))[0];

        assert!(!inside.crosses_a_world());
        assert!(across.crosses_a_world());
        assert!(inside.headline().contains("same signature"));
        assert!(across.headline().contains("These two worlds"));
    }

    /// A remedy this build has never heard of is dropped, not printed in wire
    /// vocabulary: an action the holder cannot take from here is not a choice.
    #[test]
    fn an_unknown_remedy_is_dropped() {
        let mut row = finding("01A", Some(true), "low");
        row["remedies"] = json!(["useDifferentValue", "summonALawyer"]);
        let f = &parse(json!([row]))[0];
        assert_eq!(f.remedies, vec![Remedy::UseDifferentValue]);
    }

    /// The cross-world finding wins when one attribute has several, because it
    /// is the one the holder would act on.
    #[test]
    fn the_cross_world_finding_is_the_one_shown() {
        let findings = parse(json!([
            finding("01A", Some(false), "high"),
            finding("01A", Some(true), "low"),
            finding("02A", Some(false), "low"),
        ]));

        let chosen = for_attribute(&findings, "01A").expect("a finding for 01A");
        assert!(chosen.crosses_a_world());
        assert!(!for_attribute(&findings, "02A").unwrap().crosses_a_world());
        assert!(for_attribute(&findings, "03A").is_none());
    }
}
