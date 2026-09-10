//! Which family an attribute's claim type belongs to — the groups the pane
//! lays the pool out in.
//!
//! # Why a family at all
//!
//! The attributes tab draws every attribute the holder keeps as one row in one
//! list. At five rows that is a list; at thirty it is a wall, and a wall is
//! where the answer to "what does this person actually keep about themselves"
//! goes to hide. Grouping restores the shape of the pool at a glance — who you
//! are, how to reach you, what is already public, what your agent gates — and
//! costs nothing but a heading.
//!
//! # Only what the registry declares gets classified
//!
//! [`Family::of`] reads the *served* table's roots and refuses to invent
//! anything beyond them. A token the registry has never declared resolves to
//! [`Family::Unregistered`] — never to a family guessed from its spelling — for
//! the same reason
//! [`Registry::resolve`](crate::persona::claim_types::Registry::resolve) will
//! not walk a prefix into a *looser* treatment: a local rule that groups
//! `profile.github` under some invented "profile" family is a statement about a
//! vocabulary nobody has agreed to.
//!
//! And a root the agent *does* declare but this build has no words for is
//! [`Family::Declared`], not `Unregistered`. The distinction is the one an
//! operator needs: telling them their own extension type is unknown to their
//! own agent sends them to debug a file that is working.

use crate::persona::claim_types::Registry;

/// The namespace the registry leaves open. Unregistered by construction.
const EXTENSION_PREFIX: &str = "x:";

/// The groups the pool is laid out in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// Names, and what is true of the holder as a person.
    Identity,
    /// An address someone can arrive at.
    Contact,
    /// Handles, pages and roles others can already see.
    Public,
    /// Types the registry marks `release: stepUp`.
    Gated,
    /// Declared by this agent, in a family this build has no words for.
    Declared,
    /// Declared by nobody.
    Unregistered,
}

impl Family {
    /// Top to bottom, the order the pane lays the groups out in.
    ///
    /// Roughly how closely a value identifies the person, so the list reads as
    /// a gradient rather than an alphabet. [`Unregistered`](Family::Unregistered)
    /// sits last because its size is a question rather than a fact about the
    /// holder.
    #[must_use]
    pub fn all() -> [Family; 6] {
        [
            Family::Identity,
            Family::Contact,
            Family::Public,
            Family::Gated,
            Family::Declared,
            Family::Unregistered,
        ]
    }

    /// The roots this build has words for.
    ///
    /// Deliberately **not** a claim about what the agent serves: a maintainer
    /// may declare a family this build has never heard of, and
    /// [`Declared`](Family::Declared) is the honest answer for one.
    #[must_use]
    pub fn placed_roots() -> [&'static str; 10] {
        [
            "name", "person", "email", "phone", "address", "account", "url", "org", "payment",
            "gov",
        ]
    }

    /// The family of a claim type.
    ///
    /// Matched on the **root segment only**, and only when the registry
    /// declares that root. `payment.giftCard` is [`Gated`](Family::Gated)
    /// because `payment` is a declared family entry; `profile.github` is
    /// [`Unregistered`](Family::Unregistered) when no `profile` entry exists.
    ///
    /// `x:` is tested first, so `x:name.legal` cannot borrow `name`'s group —
    /// exactly as it cannot borrow `name`'s mask.
    #[must_use]
    pub fn of(claim_type: &str, registry: &Registry) -> Family {
        if claim_type.starts_with(EXTENSION_PREFIX) {
            return Family::Unregistered;
        }
        let root = claim_type.split('.').next().unwrap_or_default();
        if !registry.registered_roots().contains(root) {
            return Family::Unregistered;
        }
        match root {
            "name" | "person" => Family::Identity,
            "email" | "phone" | "address" => Family::Contact,
            "account" | "url" | "org" => Family::Public,
            "payment" | "gov" => Family::Gated,
            _ => Family::Declared,
        }
    }

    /// The group heading, in the words of `design-docs/persona-vocabulary.md`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Family::Identity => "Who you are",
            Family::Contact => "How to reach you",
            Family::Public => "Where you already appear",
            // Not "sensitive" and not "protected": the registry marks these
            // `release: stepUp`, so the agent refuses a disclosure until the
            // holder approves that particular one. That is an agent behaviour
            // worth naming, and it is the only claim this label makes.
            Family::Gated => "Your agent asks first",
            Family::Declared => "Your agent's own",
            Family::Unregistered => "Not in the registry",
        }
    }

    /// One line under the heading, saying what the group *is*.
    ///
    /// Never what it protects: the mask defends a screen and a heading defends
    /// nothing.
    #[must_use]
    pub fn note(self) -> &'static str {
        match self {
            Family::Identity => "names, and what is true of you as a person",
            Family::Contact => "an address someone can arrive at",
            Family::Public => "handles, pages and roles others can already see",
            // The console says "a disclosure needs your approval each time"
            // here, and that word is one `persona-vocabulary.md` retires — the
            // agreed phrase for this journey is *letting it leave*. Same fact,
            // in the words the table fixes; the banned-word test in
            // `identity_panel` is what caught the borrowed string.
            Family::Gated => {
                "the registry gates these — your agent asks you again before one of them leaves"
            }
            // The third answer, and it arrived with deployment extension types
            // (VTI #1327). Saying "not in the registry" would be false about
            // the very rows an operator had just added, which is the one place
            // they would go looking to check their work.
            Family::Declared => {
                "declared by this agent rather than by the shared registry — it decides how these \
                 are treated"
            }
            Family::Unregistered => {
                "your agent's claim-type table does not declare these, so they are treated as the \
                 most private kind"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_0_1() -> Registry {
        Registry::vendored()
    }

    /// Each placed root lands in the group this build has words for.
    #[test]
    fn a_registered_root_lands_in_its_group() {
        let r = spec_0_1();
        assert_eq!(Family::of("name.legal", &r), Family::Identity);
        assert_eq!(Family::of("person.birthDate", &r), Family::Identity);
        assert_eq!(Family::of("email.work", &r), Family::Contact);
        assert_eq!(Family::of("phone.mobile", &r), Family::Contact);
        assert_eq!(Family::of("address.postal", &r), Family::Contact);
        assert_eq!(Family::of("account.handle", &r), Family::Public);
        assert_eq!(Family::of("org.role", &r), Family::Public);
        assert_eq!(Family::of("url.homepage", &r), Family::Public);
        assert_eq!(Family::of("payment.card", &r), Family::Gated);
        assert_eq!(Family::of("gov.id.passport", &r), Family::Gated);
    }

    /// A new token in a declared family groups with it, the same walk the mask
    /// takes: `payment.giftCard` is gated because `payment` is declared.
    #[test]
    fn a_new_token_groups_with_its_declared_root() {
        assert_eq!(Family::of("payment.giftCard", &spec_0_1()), Family::Gated);
    }

    /// A token nothing declares is unregistered, not guessed at from its
    /// spelling. `profile` is the live example: spec 0.1 has no such entry, so
    /// inventing a "profile" family here would put a heading on a vocabulary
    /// nobody has agreed to.
    #[test]
    fn an_undeclared_root_is_never_guessed_at() {
        let r = spec_0_1();
        assert_eq!(Family::of("profile.github", &r), Family::Unregistered);
        assert_eq!(Family::of("employer", &r), Family::Unregistered);
        assert_eq!(Family::of("medical.condition", &r), Family::Unregistered);
    }

    /// The open namespace never borrows a group, exactly as it never borrows a
    /// mask.
    #[test]
    fn an_extension_token_never_borrows_a_group() {
        let r = spec_0_1();
        assert_eq!(Family::of("x:name.legal", &r), Family::Unregistered);
        assert_eq!(Family::of("x:payment.card", &r), Family::Unregistered);
    }

    /// A root the *agent* declares and this build has no words for is the
    /// agent's own, not unregistered.
    ///
    /// The difference is the whole reason the two labels exist: telling an
    /// operator their extension type is unknown to their own agent sends them
    /// to debug a file that is working.
    #[test]
    fn a_root_only_the_agent_declares_is_its_own() {
        let served = Registry::from_wire(&serde_json::json!({
            "registryVersion": "0.1",
            "entries": [
                { "type": "name", "sensitivity": "normal", "release": "consent", "mask": "none" },
                { "type": "profile", "sensitivity": "normal", "release": "consent", "mask": "none" },
                { "type": "employer", "sensitivity": "normal", "release": "consent", "mask": "none" }
            ],
            "unregistered": { "sensitivity": "high", "release": "consent", "mask": "full" },
            "strictness": {
                "sensitivity": ["high", "normal"],
                "release": ["stepUp", "consent"],
                "mask": ["full", "last2", "last4", "emailLocal", "none"]
            }
        }));

        assert_eq!(Family::of("profile.github", &served), Family::Declared);
        assert_eq!(Family::of("employer", &served), Family::Declared);
        // …and a root nobody declares is still unregistered against the same
        // table, so `Declared` has not become a catch-all.
        assert_eq!(
            Family::of("medical.condition", &served),
            Family::Unregistered
        );
        assert_eq!(Family::of("name.given", &served), Family::Identity);
    }

    /// Every root this build claims to have placed actually resolves to a group
    /// other than the two "we have no words" answers. A root added to
    /// [`Family::placed_roots`] and forgotten in [`Family::of`] would otherwise
    /// read as unregistered while claiming to be placed.
    #[test]
    fn every_placed_root_is_actually_placed() {
        let r = spec_0_1();
        for root in Family::placed_roots() {
            let family = Family::of(root, &r);
            assert!(
                !matches!(family, Family::Declared | Family::Unregistered),
                "{root} claims to be placed but resolves to {family:?}"
            );
        }
    }

    /// Every family has a heading and a line, and no two share a heading — a
    /// duplicate would merge two groups on screen while the code kept them
    /// apart.
    #[test]
    fn every_family_has_its_own_words() {
        let mut labels: Vec<&str> = Family::all().iter().map(|f| f.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "two families share a heading");
        for family in Family::all() {
            assert!(!family.note().is_empty(), "{family:?} has no line");
        }
    }
}
