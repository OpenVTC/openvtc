//! What a community's member directory would disclose about someone who joins,
//! and to whom: the `directoryDisclosure` a `manifest/0.4` answer carries
//! (VTI-DIR-130), and the plain sentences an applicant is shown before they
//! submit.
//!
//! The statement is the generated `DirectoryDisclosure` (trust-tasks-tf #823),
//! as strict as its schema: a required member missing, a member it does not
//! name, an audience it does not list or a value outside its bounds makes the
//! statement unreadable, and an unreadable statement stops the join rather than
//! letting the person apply without seeing it.
//!
//! Every audience in a statement is the widest a value can ever reach. A member
//! and the community's own policy can only narrow it, so the sentences say "at
//! most" and never describe what any member has actually chosen to show.

pub use crate::specs::vtc::join_requests::manifest::v0_4::{
    Audience, DirectoryDisclosure, DisclosedField, FieldSource, Introductions, Listing,
    NewCardDefaultsSearch as Search,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An audience as a reader is told it. `public` especially: "public" read as a
/// word does not say the value leaves the community. An audience this client
/// does not know is said as the widest, so the page never understates.
#[must_use]
pub fn audience_words(audience: Audience) -> &'static str {
    match audience {
        Audience::Admins => "administrators only",
        Audience::Groups => "members who share a group with you",
        Audience::Connections => "members you have a verified connection with",
        Audience::Members => "every member",
        _ => "anyone, outside the community too",
    }
}

/// What a manifest said about the community's directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DirectoryStatement {
    /// A statement this client read.
    Stated(Box<DirectoryDisclosure>),
    /// A statement this client could not read, and why. A join must not go
    /// ahead on it: the person would apply without having seen the terms.
    Malformed(String),
}

/// By content: the generated statement does not implement `PartialEq`, and the
/// book needs to tell a changed statement from the same one read again.
impl PartialEq for DirectoryStatement {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Stated(a), Self::Stated(b)) => {
                serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
            }
            (Self::Malformed(a), Self::Malformed(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for DirectoryStatement {}

/// The member of a `manifest/0.4` payload that carries the statement.
pub const MANIFEST_MEMBER: &str = "directoryDisclosure";

/// Read the statement out of a manifest payload. `None` when it carries none,
/// which says nothing about whether the community has a directory: a 0.3
/// answer never carries one.
#[must_use]
pub fn read(payload: &Value) -> Option<DirectoryStatement> {
    let member = payload.get(MANIFEST_MEMBER)?;
    Some(
        match serde_json::from_value::<DirectoryDisclosure>(member.clone()) {
            Ok(d) if d.fields.iter().any(|f| f.default_visibility > f.ceiling) => {
                DirectoryStatement::Malformed(
                    "a field's default audience is wider than its ceiling".into(),
                )
            }
            Ok(d) => DirectoryStatement::Stated(Box::new(d)),
            Err(e) => DirectoryStatement::Malformed(e.to_string()),
        },
    )
}

/// The statement in words.
pub trait Describe {
    /// The statement in sentences, for a person deciding whether to apply.
    ///
    /// Field labels are the community's text, passed through `clean` (the
    /// caller's display sanitiser) before they reach a sentence.
    #[must_use]
    fn describe(&self, clean: impl Fn(&str) -> String) -> Vec<String>;
}

impl Describe for DirectoryDisclosure {
    fn describe(&self, clean: impl Fn(&str) -> String) -> Vec<String> {
        let mut out = Vec::new();
        let names = |pick: &dyn Fn(&DisclosedField) -> bool| -> Vec<String> {
            self.fields
                .iter()
                .filter(|f| pick(f))
                .map(|f| clean(&f.label))
                .collect()
        };

        // What a new card shows, before the member changes anything.
        let mut shown = Vec::new();
        for audience in [
            Audience::Public,
            Audience::Members,
            Audience::Connections,
            Audience::Groups,
        ] {
            let fields = names(&|f| f.default_visibility == audience);
            if !fields.is_empty() {
                shown.push(format!("{} to {}", list(&fields), audience_words(audience)));
            }
        }
        out.push(if shown.is_empty() {
            "A new card shows nothing to other members until you choose to.".to_string()
        } else {
            format!(
                "A new card shows {}; everything else only to administrators until you choose \
                 otherwise.",
                shown.join("; ")
            )
        });

        // The most any value can reach.
        let mut ceilings = Vec::new();
        for audience in [
            Audience::Public,
            Audience::Members,
            Audience::Connections,
            Audience::Groups,
            Audience::Admins,
        ] {
            let fields = names(&|f| f.ceiling == audience);
            if !fields.is_empty() {
                ceilings.push(format!("{} to {}", list(&fields), audience_words(audience)));
            }
        }
        if !ceilings.is_empty() {
            out.push(format!("At most, you can show {}.", ceilings.join("; ")));
        }

        let admin = names(&|f| f.source == FieldSource::Admin);
        if !admin.is_empty() {
            out.push(format!(
                "The community writes {} about you; you can read {} but not change {}.",
                list(&admin),
                if admin.len() == 1 { "it" } else { "them" },
                if admin.len() == 1 { "it" } else { "them" },
            ));
        }
        let credential = names(&|f| f.source == FieldSource::Credential);
        if !credential.is_empty() {
            out.push(format!(
                "{} {} filled from a credential you choose to present.",
                list(&credential),
                if credential.len() == 1 { "is" } else { "are" },
            ));
        }

        out.push(membership_identifier_sentence(self));
        out.push(discoverability_sentence(self));

        out.push(if self.admin_notes {
            "Administrators may keep notes about you. Notes are never on your card and never \
             reach another member; you can ask for the notes about you."
                .to_string()
        } else {
            "Administrators do not keep notes about members.".to_string()
        });
        if let Some(groups) = &self.groups {
            out.push(format!(
                "If you join a group you will hold a credential, valid for {} at a time, that \
                 shows you are in it and that you can present outside the community. One \
                 already issued stays valid until it expires, even after you leave the group.",
                duration_words(&groups.credential_validity)
            ));
        }
        out.push(if self.external_cards {
            "You may choose to publish a card outside the community, carrying what you show \
             to anyone. A new card is never published outside."
                .to_string()
        } else {
            "Your card is never published outside the community.".to_string()
        });
        out.push(
            "Each of these is the widest it can reach — you can always show less after joining."
                .to_string(),
        );
        out
    }
}

fn membership_identifier_sentence(d: &DirectoryDisclosure) -> String {
    match d.membership_identifiers {
        Audience::Admins => "The DID you join with is seen only by administrators.".into(),
        wider => format!(
            "The DID you join with is seen by administrators; you may choose to show it to \
                 {} at most. A new card shows it only to administrators.",
            audience_words(wider)
        ),
    }
}

fn discoverability_sentence(d: &DirectoryDisclosure) -> String {
    let listing = match d.new_card.listing {
        Listing::Listed => "A new card is listed when members browse the directory",
        Listing::Findable => {
            "A new card is not listed when members browse, but a search can find it"
        }
        // Hidden, or a listing this client does not know: the narrowest
        // claim it can make is that members may not find it.
        _ => "A new card is hidden from members' browsing and searches",
    };
    let search = match (d.new_card.listing, d.new_card.search) {
        (Listing::Listed | Listing::Findable, Search::ByName) => ", and a search matches your name",
        (Listing::Listed | Listing::Findable, Search::ExactNickname) => {
            ", and only a search for your exact nickname finds it"
        }
        (Listing::Listed | Listing::Findable, Search::Off) => ", and searches do not find it",
        _ => "",
    };
    let introductions = match d.new_card.introductions {
        None => String::new(),
        Some(Introductions::Off) => " Nobody may ask to be introduced to you.".into(),
        Some(i) => format!(
            " {} may ask the community to introduce them to you.",
            match i {
                Introductions::Anyone => "Any member who can find you",
                Introductions::Groups => "Members who share a group with you",
                Introductions::Connections => "Members you have a verified connection with",
                _ => "Any member who can find you",
            }
        ),
    };
    format!("{listing}{search}. You can always hide your card.{introductions}")
}

/// `a`, `a and b`, `a, b and c`.
fn list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// An ISO 8601 duration in weeks, days, hours, minutes and seconds, in words;
/// anything else as given.
fn duration_words(duration: &str) -> String {
    let Some(rest) = duration.strip_prefix('P') else {
        return duration.to_string();
    };
    let mut parts = Vec::new();
    let mut number = String::new();
    let mut in_time = false;
    for c in rest.chars() {
        match c {
            '0'..='9' => number.push(c),
            'T' if number.is_empty() => in_time = true,
            unit => {
                let Ok(n) = number.parse::<u64>() else {
                    return duration.to_string();
                };
                number.clear();
                let word = match (unit, in_time) {
                    ('W', false) => "week",
                    ('D', false) => "day",
                    ('H', true) => "hour",
                    ('M', true) => "minute",
                    ('S', true) => "second",
                    _ => return duration.to_string(),
                };
                parts.push(format!("{n} {word}{}", if n == 1 { "" } else { "s" }));
            }
        }
    }
    if parts.is_empty() || !number.is_empty() {
        return duration.to_string();
    }
    list(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The working-group example from `vtc/directory/disclosure/0.1`.
    fn example() -> Value {
        json!({
            "fields": [
                { "key": "displayName", "label": "Name", "type": "text", "source": "member",
                  "ceiling": "public", "defaultVisibility": "members", "searchable": true },
                { "key": "pronouns", "label": "Pronouns", "type": "text", "source": "member",
                  "ceiling": "members", "defaultVisibility": "admins", "searchable": false },
                { "key": "bio", "label": "About", "type": "longText", "source": "member",
                  "ceiling": "public", "defaultVisibility": "admins", "searchable": false },
                { "key": "role", "label": "Role", "type": "text", "source": "derived",
                  "ceiling": "members", "defaultVisibility": "members", "searchable": false },
                { "key": "did", "label": "Membership DID", "type": "did", "source": "derived",
                  "ceiling": "members", "defaultVisibility": "admins", "searchable": false },
                { "key": "org.example.chapter", "label": "Chapter", "type": "enum",
                  "source": "admin", "ceiling": "members", "defaultVisibility": "members",
                  "searchable": false, "facet": true }
            ],
            "newCard": { "listing": "listed", "search": "byName", "introductions": "anyone" },
            "membershipIdentifiers": "members",
            "adminNotes": true,
            "groups": { "credentialValidity": "P30D" },
            "externalCards": false,
            "statementDigest": "zQmUeLYeywAWrRgAw5k8dtbYMxU8gq7zvZCh5K6ykjt8ZYw"
        })
    }

    fn stated(statement: Value) -> DirectoryDisclosure {
        match read(&json!({ MANIFEST_MEMBER: statement })) {
            Some(DirectoryStatement::Stated(d)) => *d,
            other => panic!("expected a statement, got {other:?}"),
        }
    }

    fn malformed(statement: Value) -> bool {
        matches!(
            read(&json!({ MANIFEST_MEMBER: statement })),
            Some(DirectoryStatement::Malformed(_))
        )
    }

    #[test]
    fn a_manifest_without_a_statement_carries_none() {
        assert_eq!(read(&json!({ "criteria": [] })), None);
    }

    #[test]
    fn the_spec_example_reads_and_is_said_in_words() {
        let words = stated(example()).describe(str::to_string).join("\n");
        assert!(
            words.contains("A new card shows Name, Role and Chapter to every member"),
            "{words}"
        );
        assert!(
            words.contains("Name and About to anyone, outside the community too"),
            "{words}"
        );
        assert!(
            words.contains("The community writes Chapter about you"),
            "{words}"
        );
        assert!(
            words.contains("you may choose to show it to every member"),
            "{words}"
        );
        assert!(words.contains("valid for 30 days at a time"), "{words}");
        assert!(words.contains("Administrators may keep notes"), "{words}");
        assert!(
            words.contains("never published outside the community"),
            "{words}"
        );
        assert!(
            !words.contains("public"),
            "the raw audience never shows: {words}"
        );
    }

    #[test]
    fn a_missing_member_or_unknown_audience_is_malformed() {
        let mut missing = example();
        missing.as_object_mut().unwrap().remove("adminNotes");
        assert!(malformed(missing));

        let mut unknown = example();
        unknown["membershipIdentifiers"] = json!("everyone");
        assert!(malformed(unknown));

        let mut field = example();
        field["fields"][0]["ceiling"] = json!("world");
        assert!(malformed(field));

        let mut extra = example();
        extra["surprise"] = json!(true);
        assert!(malformed(extra));

        let mut wider = example();
        wider["fields"][1]["defaultVisibility"] = json!("public");
        assert!(malformed(wider));
    }

    #[test]
    fn durations_read_as_words() {
        assert_eq!(duration_words("P30D"), "30 days");
        assert_eq!(duration_words("P1W"), "1 week");
        assert_eq!(duration_words("P2W3D"), "2 weeks and 3 days");
        assert_eq!(duration_words("PT12H"), "12 hours");
        assert_eq!(duration_words("P1Y"), "P1Y");
    }
}
