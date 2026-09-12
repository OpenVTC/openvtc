//! What a community asks of someone who wants to join, in plain words.
//!
//! The requirements object is written for a policy engine: `minByMethod`,
//! `P120D`, `name.legal`. A person deciding whether to apply needs to read that
//! as sentences they can act on before anything about them is disclosed (design
//! §6.1, "informed non-application"). The same sentences appear on the join page
//! and the Vetting page, so they are made in one place.

use vta_sdk::protocols::vetting::{
    InvitationRequirement, VettingMethod, VettingRequirements, parse_iso8601_duration,
};

/// How a vetter meets an applicant, as the end of "a vetter can check you …".
#[must_use]
pub fn method_words(method: VettingMethod) -> &'static str {
    match method {
        VettingMethod::InPerson => "in person",
        VettingMethod::Video => "on a video call",
        VettingMethod::PriorAcquaintance => "because they already know you",
        _ => "another way",
    }
}

/// A claim type as a person says it: `name.legal` is "legal name".
#[must_use]
pub fn claim_words(claim_type: &str) -> String {
    match claim_type {
        "name.legal" => "legal name".to_string(),
        "name.preferred" => "preferred name".to_string(),
        "email.work" => "work email".to_string(),
        "email.personal" => "personal email".to_string(),
        "account.handle" => "account handle".to_string(),
        "url.homepage" => "homepage".to_string(),
        other => other.replace(['.', '_'], " "),
    }
}

/// An ISO 8601 duration as words: `P120D` is "120 days". Anything that does
/// not parse is shown as written rather than guessed at.
#[must_use]
pub fn duration_words(iso: &str) -> String {
    let Some(duration) = parse_iso8601_duration(iso) else {
        return iso.to_string();
    };
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if duration.num_days() >= 1 && duration.num_hours() % 24 == 0 {
        plural(duration.num_days(), "day")
    } else if duration.num_hours() >= 1 {
        plural(duration.num_hours(), "hour")
    } else {
        plural(duration.num_minutes().max(1), "minute")
    }
}

fn join_words(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// What `requirements` ask of an applicant, one sentence per line.
#[must_use]
pub fn describe_requirements(requirements: &VettingRequirements) -> Vec<String> {
    let mut lines = Vec::new();
    let n = requirements.min_statements;
    lines.push(format!(
        "{n} vetting statement{}, each from a different vetter the community has named",
        if n == 1 { "" } else { "s" }
    ));
    for (method, floor) in &requirements.min_by_method {
        lines.push(match method {
            VettingMethod::PriorAcquaintance => {
                format!("at least {floor} of them from a vetter who already knows you")
            }
            other => format!("at least {floor} of them {}", method_words(*other)),
        });
    }
    let meetings: Vec<String> = requirements
        .accepted_methods
        .iter()
        .filter(|m| **m != VettingMethod::PriorAcquaintance)
        .map(|m| method_words(*m).to_string())
        .collect();
    let knows_you = requirements
        .accepted_methods
        .contains(&VettingMethod::PriorAcquaintance);
    lines.push(match (meetings.is_empty(), knows_you) {
        (false, true) => format!(
            "a vetter checks you {}, or vouches for you if they already know you",
            meetings.join(" or ")
        ),
        (false, false) => format!("a vetter checks you {}", meetings.join(" or ")),
        (true, true) => "only vetters who already know you can vouch for you".to_string(),
        (true, false) => "the community names no way to be vetted".to_string(),
    });
    if !requirements.required_claims.is_empty() {
        let claims: Vec<String> = requirements
            .required_claims
            .iter()
            .map(|c| claim_words(c))
            .collect();
        lines.push(match &requirements.accepted_document_classes {
            Some(classes) if !classes.is_empty() => format!(
                "each vetter checks your {} against a document — one of: {}",
                join_words(&claims),
                classes.join(", ")
            ),
            _ => format!(
                "each vetter checks your {} — against whichever documents that vetter accepts",
                join_words(&claims)
            ),
        });
    }
    if let Some(age) = &requirements.max_statement_age {
        lines.push(format!(
            "a statement counts for {} after it is signed",
            duration_words(age)
        ));
    }
    if matches!(
        requirements.invitation,
        Some(InvitationRequirement::Required)
    ) {
        lines.push("you also need an invitation from the community".to_string());
    }
    if let Some(sla) = &requirements.decision_sla {
        lines.push(format!(
            "the community says it decides within {}",
            duration_words(sla)
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> VettingRequirements {
        serde_json::from_value(serde_json::json!({
            "version": "0.1",
            "statementType": vta_sdk::protocols::vetting::IDENTITY_VETTING_ENDORSEMENT_TYPE,
            "minStatements": 2,
            "minByMethod": { "inPerson": 1 },
            "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
            "requiredClaims": ["name.legal"],
            "maxStatementAge": "P120D",
            "invitation": "required",
            "decisionSla": "P14D",
            "eligibleVetters": { "role": "vetter" }
        }))
        .unwrap()
    }

    #[test]
    fn requirements_read_as_sentences() {
        assert_eq!(
            describe_requirements(&requirements()),
            vec![
                "2 vetting statements, each from a different vetter the community has named",
                "at least 1 of them in person",
                "a vetter checks you in person or on a video call, or vouches for you if they \
                 already know you",
                "each vetter checks your legal name — against whichever documents that vetter \
                 accepts",
                "a statement counts for 120 days after it is signed",
                "you also need an invitation from the community",
                "the community says it decides within 14 days",
            ]
        );
    }

    #[test]
    fn a_documentation_floor_is_named_when_the_community_sets_one() {
        let mut r = requirements();
        r.accepted_document_classes = Some(vec!["passport".into()]);
        r.required_claims.push("email.work".into());
        assert!(describe_requirements(&r).iter().any(|l| l
            == "each vetter checks your legal name and work email against a document — one of: \
                passport"));
    }

    #[test]
    fn durations_read_in_the_largest_whole_unit() {
        assert_eq!(duration_words("P1D"), "1 day");
        assert_eq!(duration_words("PT36H"), "36 hours");
        assert_eq!(duration_words("PT15M"), "15 minutes");
        assert_eq!(
            duration_words("soon"),
            "soon",
            "unparseable is shown as written"
        );
    }
}
