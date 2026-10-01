//! DTG Credentials conformance, in one place.
//!
//! Every DTG credential this client issues, receives, verifies, stores or shows
//! is held to the DTG Credentials Core Specification (the frozen v1 context,
//! a top-level `issuerScope`, exactly one concrete type) and, for a statement,
//! to the DTG VSC predicate registry. Three decisions live here rather than at
//! the call sites, so no two of them can disagree:
//!
//! 1. **Which `issuerScope` a credential this client issues declares** —
//!    [`MEMBER_IDENTIFIER_SCOPE`], [`relationship_issuer_scope`] and
//!    [`PERSONA_ANNOTATION_SCOPE`]. A declaration is about the issuer's own
//!    identifier only, and it has to stay true for as long as the identifier is
//!    used, so each is chosen from what OpenVTC actually does with that
//!    identifier rather than from what a single exchange needs.
//! 2. **Whether a credential is conformant at all** — [`parse_conformant`]. A
//!    credential under the retired pre-v1 context, without `issuerScope`, or of a
//!    retired type (the endorsement and witness credential types, now statements
//!    under a predicate) is refused, with no alias.
//!    That is also the test stored state is held to on load
//!    ([`crate::config::account::RetiredCredential`]).
//! 3. **What a statement says** — [`describe_statement`]. A VSC is classified by
//!    its `credentialSubject.predicate`, never by a type string, and a predicate
//!    this client does not know is shown as its IRI rather than refused or
//!    guessed at.

use dtg_credentials::{DTGCredential, DTGCredentialType, StatementObject};
use serde_json::Value;

pub use dtg_credentials::{
    DTG_CONTEXT_V1, ENDORSES_V1, IssuerScope, PRESENTED_V1, PredicateAcceptList, VETTED_V1,
    W3C_VC_V2_CONTEXT, WITNESSED_V1,
};

// ---------------------------------------------------------------------------
// issuerScope: what this client declares
// ---------------------------------------------------------------------------

/// The scope a member declares for the identifier it uses **with a community**:
/// the persona DID a membership names.
///
/// `directed`, always, and deliberately not `pairwise`. In OpenVTC the member
/// identifier of a community is an account persona (`CommunityRecord::persona_ref`),
/// and a persona is by construction a set-of-counterparties identifier:
///
/// - the community's other members see it — it issues relationship
///   credentials under it when the community declares
///   `relationshipIdentifierDefault: attributed`, it vets applicants under it
///   (`vetted/1` requires at least `directed`), and it presents it to them in a
///   vetter-eligibility presentation;
/// - one persona may be worn in several communities (a persona is chosen per
///   join, not minted per join).
///
/// A `pairwise` declaration would have to stay true for the lifetime of the
/// membership, and none of those uses is one this client can rule out when it
/// acknowledges a grant. DTG Credentials, *Choosing a scope*: an identifier a
/// member "also uses with other members is `directed`", and a persona is
/// "ordinarily asserted" under a `directed` identifier.
///
/// Used for the member-issued VMC ([`crate::members::build_member_vmc`]) and the
/// vetter's Vetting Statement ([`crate::vetting::VettingBook::statement_draft`]),
/// both of which are issued under that same persona DID.
pub const MEMBER_IDENTIFIER_SCOPE: IssuerScope = IssuerScope::Directed;

/// The scope a persona annotation (VPC) declares for its issuer, the DID under
/// which the persona is asserted: `directed`, since a persona exists to be
/// recognised across counterparties the holder chooses (DTG Credentials §VPC).
pub const PERSONA_ANNOTATION_SCOPE: IssuerScope = IssuerScope::Directed;

/// The scope a relationship credential (VRC) declares for its issuer — the
/// identifier **this relationship uses** on our side (`Relationship::our_did`).
///
/// | our identifier in the relationship | community `relationshipIdentifierDefault` that seeds it | `issuerScope` |
/// |---|---|---|
/// | a relationship DID minted for this one counterparty | `pairwise` (or undeclared) | `pairwise` |
/// | the persona DID                                      | `attributed`                | `directed` |
///
/// The community's `relationshipIdentifierDefault` only seeds the
/// new-relationship form (the member may toggle it per relationship), so the
/// scope is read from the identifier the relationship actually ended up with,
/// not from the default: a declaration is about the identifier in `issuer`, and
/// only that identifier's use decides whether `pairwise` is true. A persona DID
/// in a relationship is the legible graph an `attributed` community asks for —
/// the same identifier recognised by every counterparty the persona relates to,
/// which is `directed`, never `pairwise`.
#[must_use]
pub fn relationship_issuer_scope(issuer_is_persona: bool) -> IssuerScope {
    if issuer_is_persona {
        IssuerScope::Directed
    } else {
        IssuerScope::Pairwise
    }
}

// ---------------------------------------------------------------------------
// Conformance
// ---------------------------------------------------------------------------

/// Parse `value` as a conformant DTG credential: the W3C v2 context first and
/// [`DTG_CONTEXT_V1`] second, a declared `issuerScope`, `VerifiableCredential`,
/// `DTGCredential` and exactly one concrete subtype, and — for a statement —
/// its predicate profile.
///
/// The proof is set aside first: this answers "is this a DTG credential of the
/// current specification", not "is it genuine". Whether the proof verifies is
/// [`crate::issued_credential`]'s question, asked separately.
///
/// # Errors
///
/// A sentence naming what is non-conformant, e.g. the retired context or type.
pub fn parse_conformant(value: &Value) -> Result<DTGCredential, String> {
    let mut unsigned = value.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("proof");
    } else {
        return Err("not a JSON object".to_string());
    }
    serde_json::from_value::<DTGCredential>(unsigned).map_err(|e| e.to_string())
}

/// `None` when `value` is a conformant DTG credential, otherwise why it is not.
#[must_use]
pub fn nonconformance(value: &Value) -> Option<String> {
    parse_conformant(value).err()
}

/// The roles a **community role credential** confers: a VAC (`AuthorityCredential`)
/// the community issued in its own scope — `authority.scope` is its `issuer`,
/// `issuerScope` is `public`, no `authority.parent` — carrying `role:<name>`
/// actions. `None` for anything else, including a VAC someone attenuated.
///
/// This is the shape `vtc/join-requests/decide`, `vtc/members/*` and
/// `vtc/vetting/vetters/grant` deliver a role in, and the one
/// `vta_sdk::vetting::eligibility` accepts from a vetter.
#[must_use]
pub fn community_roles(credential: &DTGCredential) -> Option<Vec<String>> {
    if credential.type_() != DTGCredentialType::Authority
        || credential.issuer_scope() != IssuerScope::Public
    {
        return None;
    }
    let authority = credential.credential().authority()?;
    if authority.scope != credential.issuer() || authority.parent.is_some() {
        return None;
    }
    let roles: Vec<String> = authority
        .actions
        .iter()
        .filter_map(|a| vta_sdk::protocols::vetting::role_of_action(a))
        .map(str::to_string)
        .collect();
    (!roles.is_empty()).then_some(roles)
}

// ---------------------------------------------------------------------------
// Statements (VSCs): classified and shown by predicate
// ---------------------------------------------------------------------------

/// The predicates this client accepts in a statement it acts on: the four core
/// profiles of the DTG VSC predicate registry. Fails closed — a statement under
/// any other predicate is shown (see [`describe_statement`]) but never counted.
#[must_use]
pub fn core_accept_list() -> PredicateAcceptList {
    PredicateAcceptList::from_iris([ENDORSES_V1, WITNESSED_V1, VETTED_V1, PRESENTED_V1])
        .expect("the core predicate IRIs are absolute NFC IRIs")
}

/// A short human label for a registry predicate this client knows, or `None`.
#[must_use]
pub fn predicate_label(predicate: &str) -> Option<&'static str> {
    Some(match predicate {
        ENDORSES_V1 => "endorses",
        WITNESSED_V1 => "witnessed",
        VETTED_V1 => "vetted (identity vetting)",
        PRESENTED_V1 => "presented",
        _ => return None,
    })
}

/// What a statement says, for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementSummary {
    /// The predicate IRI, verbatim.
    pub predicate: String,
    /// [`predicate_label`], or the IRI itself for a predicate this client does
    /// not know.
    pub label: String,
    /// Whether the predicate is one of the core profiles this client knows.
    pub known: bool,
    /// The object, one line: an id, a digest, or the value's JSON.
    pub object: String,
}

/// Summarise a statement credential. `None` for any other credential type.
///
/// Degrades rather than refuses: a statement under a predicate this client has
/// never heard of still shows its predicate IRI and its object, because a
/// holder should be able to see what they hold even where this client cannot
/// act on it.
#[must_use]
pub fn describe_statement(credential: &DTGCredential) -> Option<StatementSummary> {
    let statement = credential.statement()?;
    let known = predicate_label(&statement.predicate);
    let object = match &statement.object {
        StatementObject::Id(id) => format!("id {id}"),
        StatementObject::DigestMultibase(digest) => format!("digest {digest}"),
        StatementObject::Value(value) => {
            let text = value.to_string();
            if text.chars().count() > 160 {
                format!("{}…", text.chars().take(159).collect::<String>())
            } else {
                text
            }
        }
    };
    Some(StatementSummary {
        predicate: statement.predicate.clone(),
        label: known.map_or_else(|| statement.predicate.clone(), str::to_string),
        known: known.is_some(),
        object,
    })
}

/// One line saying what a credential is — `Membership`, `Role: vetter`,
/// `Statement: vetted (identity vetting)`, … — for the credential views.
/// A non-conformant document says so rather than being described as whatever
/// its `type` array claims.
#[must_use]
pub fn describe(value: &Value) -> String {
    let credential = match parse_conformant(value) {
        Ok(c) => c,
        Err(_) => return "Non-conformant (pre-v1) credential".to_string(),
    };
    match credential.type_() {
        DTGCredentialType::Membership => "Membership".to_string(),
        DTGCredentialType::Authority => match community_roles(&credential) {
            Some(roles) => format!("Role: {}", roles.join(", ")),
            None => "Authority".to_string(),
        },
        DTGCredentialType::Statement => match describe_statement(&credential) {
            Some(s) => format!("Statement: {}", s.label),
            None => "Statement".to_string(),
        },
        DTGCredentialType::Relationship => "Relationship".to_string(),
        DTGCredentialType::Invitation => "Invitation".to_string(),
        DTGCredentialType::Persona => "Persona".to_string(),
        DTGCredentialType::Delegation => "Delegation".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Conformant DTG credentials for tests, built through `dtg-credentials` so
    //! they cannot drift from the specification the way hand-written JSON did.

    use chrono::{Duration, Utc};
    use dtg_credentials::DTGCredential;
    use serde_json::{Value, json};

    /// The pre-v1 DTG context. Named once, here, for the tests that prove it is
    /// refused; nothing outside a test may emit or accept it.
    pub(crate) const RETIRED_CONTEXT: &str = "https://firstperson.network/credentials/dtg/v1";

    /// A pre-v1 role credential exactly as a VTC used to deliver it: the
    /// retired context and type, no `issuerScope`. Only ever used to prove it is
    /// refused or set aside.
    pub(crate) fn retired_role_endorsement(community: &str, member: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2", RETIRED_CONTEXT],
            "type": ["VerifiableCredential", "DTGCredential", "EndorsementCredential"],
            "id": "urn:uuid:5b0c9d1e-0000-4000-8000-000000000001",
            "issuer": community,
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": { "id": member, "endorsement": {
                "type": "CommunityRole", "role": "vetter", "communityDid": community
            } }
        })
    }

    /// A community-issued VMC (`issuerScope` public), unsigned.
    pub(crate) fn grant(community: &str, member: &str) -> Value {
        serde_json::to_value(DTGCredential::new_vmc(
            community.to_string(),
            member.to_string(),
            Utc::now() - Duration::minutes(1),
            Some(Utc::now() + Duration::days(365)),
            false,
        ))
        .expect("serialise")
    }

    /// A community role VAC conferring `role:<role>`, unsigned.
    pub(crate) fn role_vac(community: &str, member: &str, role: &str) -> Value {
        serde_json::to_value(
            DTGCredential::new_community_role_vac(
                community.to_string(),
                member.to_string(),
                role,
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::days(365),
            )
            .expect("a role VAC")
            .with_max_attenuation(0)
            .expect("a VAC"),
        )
        .expect("serialise")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_relationship_scope_follows_the_identifier_it_uses() {
        assert_eq!(relationship_issuer_scope(false), IssuerScope::Pairwise);
        assert_eq!(relationship_issuer_scope(true), IssuerScope::Directed);
        // `vetted/1` needs at least `directed`, which the member identifier meets.
        assert!(MEMBER_IDENTIFIER_SCOPE.satisfies(IssuerScope::Directed));
    }

    #[test]
    fn the_retired_context_and_types_are_nonconformant() {
        let old = fixtures::retired_role_endorsement("did:example:c", "did:example:m");
        assert!(nonconformance(&old).is_some());
        // The retired context alone is enough, on an otherwise current credential.
        let mut relabelled = fixtures::grant("did:example:c", "did:example:m");
        relabelled["@context"][1] = json!(fixtures::RETIRED_CONTEXT);
        assert!(nonconformance(&relabelled).is_some());
        assert_eq!(describe(&old), "Non-conformant (pre-v1) credential");

        let grant = fixtures::grant("did:example:c", "did:example:m");
        assert_eq!(nonconformance(&grant), None);
        assert_eq!(grant["issuerScope"], "public");
        assert_eq!(grant["@context"][1], DTG_CONTEXT_V1);
        assert_eq!(describe(&grant), "Membership");
    }

    #[test]
    fn a_community_role_vac_names_its_roles() {
        let vac = fixtures::role_vac("did:example:c", "did:example:m", "vetter");
        let parsed = parse_conformant(&vac).unwrap();
        assert_eq!(community_roles(&parsed), Some(vec!["vetter".to_string()]));
        assert_eq!(describe(&vac), "Role: vetter");

        // A VAC granting authority in someone else's scope is not a role grant.
        let other = DTGCredential::new_vac(
            "did:example:c".into(),
            IssuerScope::Public,
            "did:example:m".into(),
            "did:example:elsewhere".into(),
            vec!["role:vetter".into()],
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::days(1),
        )
        .unwrap();
        assert_eq!(community_roles(&other), None);
    }

    #[test]
    fn an_unknown_predicate_degrades_to_its_iri() {
        let vsc = DTGCredential::new_vsc(
            "did:example:i".into(),
            IssuerScope::Directed,
            "did:example:s".into(),
            "https://example.org/predicates/likes/1",
            StatementObject::Value(json!({ "what": "tea" })),
            chrono::Utc::now(),
            None,
        )
        .unwrap();
        let summary = describe_statement(&vsc).unwrap();
        assert!(!summary.known);
        assert_eq!(summary.label, "https://example.org/predicates/likes/1");
        assert_eq!(summary.object, r#"{"what":"tea"}"#);
        assert!(core_accept_list().accept(&vsc).is_err(), "fails closed");
    }
}
