//! What each of your personas actually says — the face one wears in a given
//! community's context. **Context-scoped**; see the [module header](super)
//! for the boundary this sits on the low side of.
//!
//! A membership already carries both halves of the key: a
//! `CommunityRecord::sub_context_id` is the VTA context, and the persona it
//! presents has the DID. Every row in the communities panel is a
//! `(context, persona)` pair, and that pair is exactly what
//! `persona/binding/get` is addressed by.
//!
//! # Thin on purpose
//!
//! A binding read reports **whether** a persona is bound, the profile's label,
//! and how many claims it carries. Never the claim contents. Those reach a
//! consumer only through `persona/disclosure/*`, after a preview a human can be
//! shown — a binding read that returned values would make that gate
//! decorative. So there is nothing here that renders an attribute, and adding
//! one would be reaching around the disclosure path rather than extending this
//! module. [`crate::persona::profile::get`] is where a holder looks at their
//! own values, above the boundary and before anything is pushed across it.
//!
//! # Reads are best-effort; [`set`] is not
//!
//! Same rule as [`crate::devices`]: a VTA that does not serve the persona slice,
//! or a call that times out, must never stop OpenVTC starting or a panel
//! drawing. A membership works whether or not we can say what it presents, and
//! [`BindingSummary::unknown`] is the honest thing to draw while we cannot —
//! distinct from "bound to nothing", which is an answer.
//!
//! [`set`] is the exception, and it has to be: it is a decision the holder just
//! made about what a community sees. A write that quietly failed would leave
//! them believing a persona presents something it does not, so its error is
//! returned rather than softened.

use serde::{Deserialize, Serialize};
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;

/// What one persona presents in one context.
///
/// [`bound`](Self::bound) is the field to read. Do not infer it from
/// [`profile_name`](Self::profile_name) being empty: a profile may legitimately
/// carry no label, and "unlabelled" and "unbound" are different answers to
/// different questions.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BindingSummary {
    /// Whether this persona presents anything at all in this context.
    pub bound: bool,
    /// The holder's own name for the bound face, if it has one. The agent
    /// returns it only to the holder — which OpenVTC is — and never to the
    /// community.
    pub profile_name: Option<String>,
    /// What the holder said this community may call the face — the only name
    /// the community itself is given. `None` when they chose none.
    #[serde(default)]
    pub label: Option<String>,
    /// Identifier of the bound profile.
    pub profile_id: Option<String>,
    /// How many claims the binding carries. `0` for an unbound persona — a
    /// count of nothing is still a count.
    pub claim_count: u64,
    /// When the binding was last written.
    pub bound_at: Option<String>,
    /// True when the agent could not be asked, as distinct from having
    /// answered "nothing is bound".
    ///
    /// Kept as a field rather than modelled as an absent `BindingSummary`,
    /// because a caller that has to unwrap an `Option` reaches for
    /// `unwrap_or_default()` and that would render "we could not ask" as
    /// "presents nothing" — a confident wrong answer about the user's own
    /// identity, which is the one thing this panel must not give.
    pub unknown: bool,
    /// A face worn by the same persona in the **parent** context, when it
    /// wears nothing here.
    ///
    /// Not part of the agent's answer, and **not something this community
    /// sees**: the VTA keys a binding on an exact `(context_id, persona_did)`
    /// pair and walks no hierarchy, and the `materialised_claims` a disclosure
    /// draws on go through that same exact lookup. It is carried because the
    /// alternative is a bare
    /// "wears: nothing" in front of a holder who has just configured a face and
    /// can see it on another surface, with nothing on screen to explain the
    /// difference.
    pub parent: Option<ParentBinding>,
}

/// What the same persona wears one context up.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ParentBinding {
    /// The context the binding was found in — the sub-context's parent.
    pub context_id: String,
    /// The bound profile's label, or its identifier when it has no label.
    pub label: String,
}

impl BindingSummary {
    /// The summary to draw when the agent could not be asked.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            unknown: true,
            ..Self::default()
        }
    }

    /// A one-line description for a panel row, in the words a person reads.
    ///
    /// A persona *wears* a face in a context — the on-screen vocabulary for what
    /// the wire calls binding a profile (`design-docs/persona-vocabulary.md`).
    /// The spec's words stay in the types; they are kept off the screen.
    ///
    /// Three distinct readings, deliberately worded so they cannot be confused:
    /// we do not know; we know nothing is worn; we know what is worn.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.unknown {
            return "wears: unknown".to_string();
        }
        if !self.bound {
            // A fourth reading, and the one a holder is most likely to arrive
            // at confused: nothing is worn *here*, but the same persona wears
            // something one context up. Saying only "nothing" is true and
            // useless — they can see the face on another surface and have no
            // way to tell why this one disagrees.
            return match &self.parent {
                Some(p) => format!(
                    "wears: nothing here — {} is worn in {}, which this community does not see",
                    p.label, p.context_id
                ),
                None => "wears: nothing".to_string(),
            };
        }
        let label = self
            .profile_name
            .clone()
            .or_else(|| self.profile_id.clone())
            .unwrap_or_else(|| "an unnamed face".to_string());
        let attributes = if self.claim_count == 1 {
            "1 attribute".to_string()
        } else {
            format!("{} attributes", self.claim_count)
        };
        // Two names, for two audiences: the first is the holder's own and the
        // community never sees it; the second is what the community is told.
        match &self.label {
            Some(shown) => format!("wears: {label} ({attributes}) — known here as “{shown}”"),
            None => format!("wears: {label} ({attributes})"),
        }
    }
}

/// Ask the agent what `persona_did` presents in `context_id`.
///
/// Errors are the caller's to log and move past; see the module header.
pub async fn get(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
) -> Result<BindingSummary, OpenVTCError> {
    let value = client
        .persona_binding_get(context_id, persona_did)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona binding read failed: {e}")))?;

    Ok(BindingSummary {
        bound: value
            .get("bound")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        profile_name: value
            .get("profileName")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        profile_id: value
            .get("profileId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        label: value
            .get("label")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        claim_count: value
            .get("claimCount")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        bound_at: value
            .get("boundAt")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        unknown: false,
        // Filled by `get_or_unknown` when this answer is "nothing", not here:
        // `get` reports one context, which is exactly what the agent was asked.
        parent: None,
    })
}

/// Ask what the same persona wears in `sub_context_id`'s **parent**.
///
/// Only ever called when the sub-context itself came back unbound, and only to
/// explain that answer rather than to change it. The VTA keys a binding on an
/// exact `(context_id, persona_did)` pair and walks no hierarchy — both
/// `binding_summary` and the `materialised_claims` a disclosure draws on read
/// through the same exact lookup — so a face worn in the parent is genuinely
/// **not** what this community sees. The panel says so in those words.
///
/// The parent is derived with [`context_path::parse_sub_context_id`], never by
/// hand: a top context may itself be nested, so the split is on the *last* `/`.
/// An id with no `/` is not a sub-context and has no parent to ask about.
///
/// Best-effort like every other binding read — a failure here must not turn a
/// perfectly good "wears: nothing" into an error.
///
/// [`context_path::parse_sub_context_id`]: crate::config::context_path::parse_sub_context_id
async fn worn_in_parent(
    client: &VtaClient,
    sub_context_id: &str,
    persona_did: &str,
) -> Option<ParentBinding> {
    let (parent, _) = crate::config::context_path::parse_sub_context_id(sub_context_id)?;
    let summary = get(client, parent, persona_did).await.ok()?;
    if !summary.bound {
        return None;
    }
    Some(ParentBinding {
        context_id: parent.to_string(),
        label: summary
            .profile_name
            .or(summary.profile_id)
            .unwrap_or_else(|| "an unnamed face".to_string()),
    })
}

/// Ask once, and fall back to [`BindingSummary::unknown`] rather than failing.
///
/// The form a panel wants: it has a row to draw either way, and the question is
/// only whether it can say anything true about what that row presents.
///
/// One extra round-trip, and only in one case: an *unbound* sub-context asks
/// its parent as well, so "wears: nothing" can say whether a face is worn a
/// level up. A bound context costs nothing extra, which is the common one.
pub async fn get_or_unknown(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
) -> BindingSummary {
    match get(client, context_id, persona_did).await {
        Ok(mut summary) => {
            if !summary.bound {
                summary.parent = worn_in_parent(client, context_id, persona_did).await;
            }
            summary
        }
        Err(e) => {
            tracing::debug!(
                context_id,
                persona_did,
                error = %e,
                "persona binding unavailable; drawing as unknown"
            );
            BindingSummary::unknown()
        }
    }
}

/// Decide what one persona presents in one context.
///
/// `profile_id: None` clears the binding — a persona that presents nothing is a
/// legitimate, common state (a throwaway persona), not an absence to be inferred,
/// so clearing is a first-class call rather than a delete.
///
/// This is the push across the boundary. The VTA resolves the profile *above*
/// the context and writes a materialised projection into it: the context
/// receives values, never pool identifiers, so nothing inside it can walk back
/// to the holder's other personas. That is why there is no "read the pool from a
/// context" counterpart to this function anywhere in the module.
///
/// `publicEntries` is deliberately sent empty. It publishes attributes on the
/// persona's own public surface, where every relying party sees one identical
/// value — a permanent correlation point, and the exact thing per-verifier
/// projection exists to avoid. Offering it behind a keystroke would make it the
/// accidental default; a holder who wants it can say so through `pnm`.
pub async fn set(
    client: &VtaClient,
    context_id: &str,
    persona_did: &str,
    profile_id: Option<&str>,
) -> Result<(), OpenVTCError> {
    // `binding/set` REPLACES the binding, label included, and OpenVTC has no
    // way to set one — so a face change sent without the current label would
    // silently take away the name the holder gave this community elsewhere
    // (`pnm`, the console). Read it and send it back. A failed read fails the
    // write rather than guessing: "unnamed" is not a safe default for a
    // decision the holder made.
    let label = match profile_id {
        // Taking the face off: the agent drops the label with it.
        None => None,
        Some(_) => get(client, context_id, persona_did).await?.label,
    };
    client
        .persona_binding_set(
            context_id,
            persona_did,
            profile_id,
            Vec::new(),
            label.as_deref(),
            None,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona binding write failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_not_the_same_as_unbound() {
        assert_eq!(BindingSummary::unknown().describe(), "wears: unknown");
        assert_eq!(BindingSummary::default().describe(), "wears: nothing");
    }

    /// "Nothing here" and "nothing anywhere" are different answers, and the
    /// holder most likely to be confused is the one looking at the first.
    ///
    /// The VTA keys a binding on an exact `(context_id, persona_did)` pair and
    /// walks no hierarchy, so a face worn in the parent context is genuinely
    /// not what this community sees — but a bare "wears: nothing" in front of
    /// someone who just configured that face, and can see it on another
    /// surface, is true and useless. The sentence has to carry both halves:
    /// there is a face, and this community does not see it.
    #[test]
    fn a_face_worn_one_level_up_is_named_rather_than_hidden_behind_nothing() {
        let summary = BindingSummary {
            parent: Some(ParentBinding {
                context_id: "openvtc".into(),
                label: "OSS Developer".into(),
            }),
            ..BindingSummary::default()
        };

        let line = summary.describe();
        assert!(line.contains("nothing here"), "{line}");
        assert!(line.contains("OSS Developer"), "{line}");
        assert!(line.contains("openvtc"), "{line}");
        assert!(
            line.contains("does not see"),
            "the community must not be implied to see it: {line}"
        );
    }

    /// A parent binding never turns an *unknown* into an answer.
    ///
    /// "We could not ask" outranks everything: reporting what a parent context
    /// wears while the context actually in question went unanswered would be a
    /// confident statement built on a failed read.
    #[test]
    fn a_parent_binding_does_not_override_unknown() {
        let summary = BindingSummary {
            parent: Some(ParentBinding {
                context_id: "openvtc".into(),
                label: "OSS Developer".into(),
            }),
            ..BindingSummary::unknown()
        };
        assert_eq!(summary.describe(), "wears: unknown");
    }

    /// And it never displaces a real answer either.
    #[test]
    fn a_bound_context_reports_what_it_wears_not_the_parent() {
        let summary = BindingSummary {
            bound: true,
            profile_name: Some("Work".into()),
            claim_count: 3,
            parent: Some(ParentBinding {
                context_id: "openvtc".into(),
                label: "OSS Developer".into(),
            }),
            ..BindingSummary::default()
        };
        assert_eq!(summary.describe(), "wears: Work (3 attributes)");
    }

    /// The distinction the `unknown` flag exists to preserve.
    ///
    /// `BindingSummary::default()` is a *known* empty answer. If "could not
    /// ask" were modelled as an absent value, the natural
    /// `unwrap_or_default()` would collapse the two and tell the user their
    /// persona presents nothing when the truth is that nobody asked.
    #[test]
    fn a_default_summary_never_reads_as_unknown() {
        assert!(!BindingSummary::default().unknown);
        assert!(BindingSummary::unknown().unknown);
    }

    #[test]
    fn a_bound_profile_is_described_by_label_and_count() {
        let s = BindingSummary {
            bound: true,
            profile_name: Some("work".into()),
            claim_count: 3,
            ..Default::default()
        };
        assert_eq!(s.describe(), "wears: work (3 attributes)");
    }

    /// The holder sees both names: their own, and what this community is told.
    /// Without the second, a holder cannot tell what the community calls them.
    #[test]
    fn a_labelled_binding_says_what_the_community_is_told() {
        let s = BindingSummary {
            bound: true,
            profile_name: Some("the divorce".into()),
            label: Some("Ada at the co-op".into()),
            claim_count: 2,
            ..Default::default()
        };
        assert_eq!(
            s.describe(),
            "wears: the divorce (2 attributes) — known here as “Ada at the co-op”"
        );
    }

    /// One claim is not "1 claims". Small, and the kind of thing that makes a
    /// panel look unfinished.
    #[test]
    fn a_single_fact_is_singular() {
        let s = BindingSummary {
            bound: true,
            profile_name: Some("gaming".into()),
            claim_count: 1,
            ..Default::default()
        };
        assert_eq!(s.describe(), "wears: gaming (1 attribute)");
    }

    /// A profile with no label falls back to its id, and then to a phrase —
    /// never to the empty string, which would render as "presents:  (2
    /// claims)".
    #[test]
    fn an_unlabelled_profile_still_describes_itself() {
        let by_id = BindingSummary {
            bound: true,
            profile_id: Some("01J8".into()),
            claim_count: 2,
            ..Default::default()
        };
        assert_eq!(by_id.describe(), "wears: 01J8 (2 attributes)");

        let bare = BindingSummary {
            bound: true,
            claim_count: 2,
            ..Default::default()
        };
        assert_eq!(bare.describe(), "wears: an unnamed face (2 attributes)");
    }
}
