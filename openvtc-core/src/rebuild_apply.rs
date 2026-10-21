//! Turn a [`crate::rebuild::RebuildPlan`] into an account.
//!
//! The write half of recovery. [`rebuild::plan`](crate::rebuild::plan) works out
//! what a Trust Context holds and verifies it; this turns that into the
//! [`Account`] and `key_info` a working profile needs.
//!
//! # The part that decides whether recovery works at all
//!
//! A rebuilt persona is only useful if OpenVTC can *sign* as it, and that needs
//! `key_info`: a map from each verification-method id in the DID document to
//! the VTA key that backs it. At mint time that mapping is free — the DID
//! creation response hands back `signing_key_id` and `ka_key_id` alongside the
//! DID. A rebuild has neither; it has a list of DIDs and a list of keys, and has
//! to re-establish the correspondence.
//!
//! [`vta_sdk::did_secrets::select_secret_kid`] is the VTA's own rule for that
//! question, so it is what gets used rather than a second implementation that
//! could disagree — the same discipline the project applies to `didwebvh-rs` and
//! `agent-names`. A key belongs to a persona when the store's `key_id` is a
//! verification-method id of that persona's DID, or when its label is.
//!
//! # A persona whose keys cannot be mapped is reported, not shipped broken
//!
//! If a VTA stores keys under opaque ids with free-text labels, the
//! correspondence cannot be re-established and that persona cannot sign. Such a
//! persona is **excluded and reported** rather than written into the account as
//! a record that will fail on first use — the same choice
//! [`crate::config::integrity`] makes for a degraded load, and for the same
//! reason: a broken persona in the account is worse than a named absence.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    CredentialKind,
    config::{
        KeyTypes,
        account::{Account, CommunityRecord, CommunityStatus, PersonaId, PersonaRecord, VtcDid},
        secured_config::{KeyInfoConfig, KeySourceMaterial},
    },
    rebuild::RebuildPlan,
};

/// A VTA key as far as the rebuild is concerned.
///
/// Deliberately not `vta_sdk::keys::KeyRecord`: the mapping is pure logic and
/// worth testing without a VTA, so the caller narrows the SDK type to this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCandidate {
    /// The VTA's own identifier — what `get_key_secret` is called with.
    pub key_id: String,
    /// Free-text label, which on some deployments is where the
    /// verification-method id actually lives.
    pub label: Option<String>,
    /// What the key is for, used to type the resulting `key_info` entry.
    pub key_type: KeyPurposeHint,
    /// When the VTA minted it.
    pub created_at: DateTime<Utc>,
}

/// Which OpenVTC key slot a VTA key fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurposeHint {
    /// Ed25519 — signing and authentication.
    Signing,
    /// X25519 — key agreement.
    Encryption,
}

impl From<KeyPurposeHint> for KeyTypes {
    fn from(hint: KeyPurposeHint) -> Self {
        match hint {
            KeyPurposeHint::Signing => KeyTypes::PersonaSigning,
            KeyPurposeHint::Encryption => KeyTypes::PersonaEncryption,
        }
    }
}

/// Why a persona found at the VTA could not be rebuilt into a usable record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonaSkipReason {
    /// No VTA key could be matched to any verification method of this DID, so
    /// the persona could not sign, encrypt or connect.
    NoKeysMapped,
    /// Keys were found but not a signing one, which every persona needs.
    NoSigningKey,
}

impl PersonaSkipReason {
    /// One line for the user.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            PersonaSkipReason::NoKeysMapped => {
                "none of the VTA's keys could be matched to it".to_string()
            }
            PersonaSkipReason::NoSigningKey => "it has no signing key".to_string(),
        }
    }
}

/// A persona present at the VTA but left out of the rebuilt account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPersona {
    /// The persona's DID.
    pub did: String,
    /// Why it was skipped.
    pub reason: PersonaSkipReason,
}

/// The result of applying a plan.
#[derive(Clone, Debug, Default)]
pub struct RebuiltAccount {
    /// The account, ready to be persisted.
    pub account: Account,
    /// `key_info` entries, keyed by verification-method id.
    pub key_info: HashMap<String, KeyInfoConfig>,
    /// Personas found at the VTA but not usable — reported, never silently
    /// dropped.
    pub skipped: Vec<SkippedPersona>,
}

impl RebuiltAccount {
    /// One line describing what was actually rebuilt.
    #[must_use]
    pub fn summary(&self) -> String {
        fn plural(n: usize, one: &str, many: &str) -> String {
            format!("{n} {}", if n == 1 { one } else { many })
        }
        let mut s = format!(
            "{}, {}",
            plural(self.account.personas.len(), "persona", "personas"),
            plural(
                self.account.memberships().count(),
                "membership",
                "memberships"
            )
        );
        if !self.skipped.is_empty() {
            s.push_str(&format!(
                " ({} skipped)",
                plural(self.skipped.len(), "persona", "personas")
            ));
        }
        s
    }
}

/// Which verification-method ids of `did` the given keys back.
///
/// Uses the SDK's own [`select_secret_kid`](vta_sdk::did_secrets::select_secret_kid)
/// so OpenVTC and the VTA cannot disagree about what counts as a match.
fn keys_for_did<'a>(did: &str, keys: &'a [KeyCandidate]) -> Vec<(String, &'a KeyCandidate)> {
    keys.iter()
        .filter_map(|k| {
            vta_sdk::did_secrets::select_secret_kid(did, &k.key_id, k.label.as_deref())
                .map(|vm_id| (vm_id, k))
        })
        .collect()
}

/// Build an account and `key_info` from a verified plan.
///
/// `keys` is every active key the VTA holds for the context. `now` stamps
/// records the VTA gives no timestamp for.
///
/// Pure — no network, no disk. The caller decides whether to persist the result
/// (D5: a rebuild into a profile that already has state must be diffed and
/// confirmed, never applied silently).
#[must_use]
pub fn apply(plan: &RebuildPlan, keys: &[KeyCandidate], now: DateTime<Utc>) -> RebuiltAccount {
    let mut account = Account {
        top_context_id: plan.top_context_id.clone(),
        ..Account::default()
    };
    let mut key_info: HashMap<String, KeyInfoConfig> = HashMap::new();
    let mut skipped = Vec::new();

    // did → persona id, so memberships can be attached to the persona their
    // credential names.
    let mut persona_ids: HashMap<String, PersonaId> = HashMap::new();

    for persona in &plan.personas {
        let mapped = keys_for_did(&persona.did, keys);
        if mapped.is_empty() {
            warn!(did = %persona.did, "rebuild: no VTA key maps to this persona");
            skipped.push(SkippedPersona {
                did: persona.did.clone(),
                reason: PersonaSkipReason::NoKeysMapped,
            });
            continue;
        }
        if !mapped
            .iter()
            .any(|(_, k)| k.key_type == KeyPurposeHint::Signing)
        {
            warn!(did = %persona.did, "rebuild: persona has no signing key");
            skipped.push(SkippedPersona {
                did: persona.did.clone(),
                reason: PersonaSkipReason::NoSigningKey,
            });
            continue;
        }

        let persona_id = PersonaId::new();
        persona_ids.insert(persona.did.clone(), persona_id);

        for (vm_id, key) in &mapped {
            key_info.insert(
                vm_id.clone(),
                KeyInfoConfig {
                    path: KeySourceMaterial::VtaManaged {
                        key_id: key.key_id.clone(),
                    },
                    purpose: KeyTypes::from(key.key_type),
                    create_time: key.created_at,
                },
            );
        }

        account.personas.insert(
            persona_id,
            PersonaRecord {
                persona_id,
                did: persona.did.clone(),
                // Resolved on first load rather than guessed here — the load
                // path already falls back to a network resolve when absent,
                // and a wrong cached document is worse than none.
                did_document: None,
                did_locator: None,
                key_refs: Vec::new(),
                mediator_did: persona.mediator_did.clone(),
                origin_context_id: persona.context_id.clone(),
                // The VTA does not record when OpenVTC first knew about the
                // persona, only when the DID was minted; `now` is honest about
                // this being a rebuild rather than inventing a past date.
                created_at: now,
                // Labels are local and do not survive (see `known_gaps`).
                label: None,
                extra: serde_json::Map::new(),
            },
        );
    }

    for membership in &plan.memberships {
        let Some(&persona_id) = persona_ids.get(&membership.persona_did) else {
            // Its persona was skipped, so the membership has nothing to hang
            // off. `plan` already verified the credential; this is the
            // downstream consequence of a key-mapping failure, not a second
            // trust decision.
            warn!(
                vtc = %membership.vtc_did,
                "rebuild: membership's persona was not rebuilt — skipping"
            );
            continue;
        };

        let vtc_did = VtcDid::from(membership.vtc_did.clone());
        let mut record = CommunityRecord::new_pending(
            vtc_did.clone(),
            None,
            // The sub-context naming convention; the real one is restored with
            // the rest of the soft state once E2 lands.
            format!(
                "{}/{}",
                plan.top_context_id,
                short_tail(&membership.vtc_did)
            ),
            persona_id,
            uuid::Uuid::new_v4(),
            now,
        );
        // Active by construction: the community signed a membership credential
        // for this persona, which is what being a member *is*.
        record.status = CommunityStatus::Active;
        record.member_since = Some(now);
        record
            .credentials
            .insert(CredentialKind::Membership, membership.credential.clone());

        account.communities.entry(vtc_did).or_default().push(record);
    }

    RebuiltAccount {
        account,
        key_info,
        skipped,
    }
}

/// Last path segment of a DID, used to name a sub-context.
///
/// A did:scid names a sub-context by its SCID: the identity, never its `?src=`
/// locator, whose `?` and `/` have no place in a context id (VTI-KEY-160).
fn short_tail(did: &str) -> String {
    let did = vta_sdk::did_scid::identity(did);
    did.rsplit(':').next().unwrap_or(&did).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rebuild::{RebuiltMembership, RebuiltPersona};

    #[test]
    fn a_did_scid_community_names_its_sub_context_by_its_scid() {
        assert_eq!(
            short_tail("did:scid:vh:1:QmV?src=vtc.example.com/acme"),
            "QmV"
        );
        assert_eq!(short_tail("did:scid:vh:1:QmV"), "QmV");
        assert_eq!(short_tail(VTC), "acme");
    }

    const ALICE: &str = "did:webvh:QmA:example.com:alice";
    const BOB: &str = "did:webvh:QmB:example.com:bob";
    const VTC: &str = "did:webvh:QmV:vtc.example.com:acme";

    fn key(id: &str, label: Option<&str>, purpose: KeyPurposeHint) -> KeyCandidate {
        KeyCandidate {
            key_id: id.to_string(),
            label: label.map(str::to_string),
            key_type: purpose,
            created_at: Utc::now(),
        }
    }

    /// Keys as a VTA that stores them under verification-method ids.
    fn keys_for(did: &str) -> Vec<KeyCandidate> {
        vec![
            key(&format!("{did}#key-0"), None, KeyPurposeHint::Signing),
            key(&format!("{did}#key-1"), None, KeyPurposeHint::Encryption),
        ]
    }

    fn persona(did: &str) -> RebuiltPersona {
        RebuiltPersona {
            did: did.to_string(),
            context_id: "openvtc".to_string(),
            mediator_did: Some("did:webvh:QmM:mediator.example.com".to_string()),
        }
    }

    fn plan_with(
        personas: Vec<RebuiltPersona>,
        memberships: Vec<RebuiltMembership>,
    ) -> RebuildPlan {
        RebuildPlan {
            top_context_id: "openvtc".to_string(),
            personas,
            memberships,
            rejected: Vec::new(),
            other_credential_count: 0,
        }
    }

    #[test]
    fn a_persona_with_mapped_keys_is_rebuilt() {
        let out = apply(
            &plan_with(vec![persona(ALICE)], vec![]),
            &keys_for(ALICE),
            Utc::now(),
        );

        assert_eq!(out.account.personas.len(), 1);
        assert!(out.skipped.is_empty());

        let rebuilt = out.account.personas.values().next().expect("one persona");
        assert_eq!(rebuilt.did, ALICE);
        assert_eq!(rebuilt.origin_context_id, "openvtc");
        assert!(rebuilt.mediator_did.is_some());

        // Both verification methods must be backed, or the persona cannot both
        // sign and receive.
        assert_eq!(out.key_info.len(), 2);
        assert!(out.key_info.contains_key(&format!("{ALICE}#key-0")));
        assert!(out.key_info.contains_key(&format!("{ALICE}#key-1")));
    }

    /// The mapping is what makes a rebuilt persona usable, so it has to point
    /// at the VTA's own key id — not the verification-method id.
    #[test]
    fn key_info_points_at_the_vta_key_id() {
        let keys = vec![key(
            "vta-key-abc",
            Some(&format!("{ALICE}#key-0")),
            KeyPurposeHint::Signing,
        )];
        let out = apply(&plan_with(vec![persona(ALICE)], vec![]), &keys, Utc::now());

        let entry = out
            .key_info
            .get(&format!("{ALICE}#key-0"))
            .expect("mapped via label");
        match &entry.path {
            KeySourceMaterial::VtaManaged { key_id } => assert_eq!(key_id, "vta-key-abc"),
            other => panic!("expected a VTA-managed key, got {other:?}"),
        }
    }

    /// A persona whose keys cannot be matched would fail on first use. Better a
    /// named absence than a broken record in the account.
    #[test]
    fn a_persona_with_no_mappable_keys_is_skipped_and_reported() {
        let keys = vec![key(
            "opaque-1",
            Some("some free text"),
            KeyPurposeHint::Signing,
        )];
        let out = apply(&plan_with(vec![persona(ALICE)], vec![]), &keys, Utc::now());

        assert!(out.account.personas.is_empty());
        assert_eq!(out.skipped.len(), 1);
        assert_eq!(out.skipped[0].did, ALICE);
        assert_eq!(out.skipped[0].reason, PersonaSkipReason::NoKeysMapped);
    }

    #[test]
    fn a_persona_with_only_an_encryption_key_is_skipped() {
        let keys = vec![key(
            &format!("{ALICE}#key-1"),
            None,
            KeyPurposeHint::Encryption,
        )];
        let out = apply(&plan_with(vec![persona(ALICE)], vec![]), &keys, Utc::now());
        assert_eq!(out.skipped[0].reason, PersonaSkipReason::NoSigningKey);
    }

    /// One persona's keys must never be attributed to another.
    #[test]
    fn keys_are_not_mixed_between_personas() {
        let mut keys = keys_for(ALICE);
        keys.extend(keys_for(BOB));
        let out = apply(
            &plan_with(vec![persona(ALICE), persona(BOB)], vec![]),
            &keys,
            Utc::now(),
        );

        assert_eq!(out.account.personas.len(), 2);
        assert_eq!(out.key_info.len(), 4);
        for (vm_id, entry) in &out.key_info {
            let did = vm_id.split('#').next().expect("vm id");
            match &entry.path {
                KeySourceMaterial::VtaManaged { key_id } => {
                    assert!(key_id.starts_with(did), "{key_id} attributed to {did}");
                }
                other => panic!("expected VtaManaged, got {other:?}"),
            }
        }
    }

    /// A membership is active by construction — the community signed a
    /// credential for this persona, which is what being a member is.
    #[test]
    fn a_verified_membership_is_rebuilt_active_and_keeps_its_credential() {
        let vmc = serde_json::json!({ "id": "vmc-1", "issuer": VTC });
        let out = apply(
            &plan_with(
                vec![persona(ALICE)],
                vec![RebuiltMembership {
                    vtc_did: VTC.to_string(),
                    persona_did: ALICE.to_string(),
                    credential: vmc.clone(),
                }],
            ),
            &keys_for(ALICE),
            Utc::now(),
        );

        let membership = out.account.memberships().next().expect("one membership");
        assert!(membership.status.is_active());
        assert_eq!(
            membership.credentials.get(&CredentialKind::Membership),
            Some(&vmc),
            "the rebuilt record must carry its own proof"
        );
        // And it must point at the persona the credential named.
        let persona_id = out
            .account
            .personas
            .values()
            .find(|p| p.did == ALICE)
            .expect("alice")
            .persona_id;
        assert_eq!(membership.persona_ref, persona_id);
    }

    /// A membership whose persona was skipped has nothing to hang off.
    #[test]
    fn a_membership_for_a_skipped_persona_is_dropped() {
        let out = apply(
            &plan_with(
                vec![persona(ALICE)],
                vec![RebuiltMembership {
                    vtc_did: VTC.to_string(),
                    persona_did: ALICE.to_string(),
                    credential: serde_json::json!({}),
                }],
            ),
            // No mappable keys, so Alice is skipped.
            &[key("opaque", None, KeyPurposeHint::Signing)],
            Utc::now(),
        );
        assert!(out.account.personas.is_empty());
        assert_eq!(out.account.memberships().count(), 0);
        assert_eq!(out.skipped.len(), 1);
    }

    /// Two memberships in one community, one per persona — the multi-membership
    /// model must survive a rebuild.
    #[test]
    fn two_personas_may_hold_memberships_in_one_community() {
        let mut keys = keys_for(ALICE);
        keys.extend(keys_for(BOB));
        let out = apply(
            &plan_with(
                vec![persona(ALICE), persona(BOB)],
                vec![
                    RebuiltMembership {
                        vtc_did: VTC.to_string(),
                        persona_did: ALICE.to_string(),
                        credential: serde_json::json!({ "id": "a" }),
                    },
                    RebuiltMembership {
                        vtc_did: VTC.to_string(),
                        persona_did: BOB.to_string(),
                        credential: serde_json::json!({ "id": "b" }),
                    },
                ],
            ),
            &keys,
            Utc::now(),
        );
        assert_eq!(out.account.memberships().count(), 2);
        assert_eq!(
            out.account.communities.len(),
            1,
            "one community, two members"
        );
    }

    #[test]
    fn the_summary_reports_skips_as_well_as_successes() {
        let mut keys = keys_for(ALICE);
        keys.push(key("opaque", None, KeyPurposeHint::Signing));
        let out = apply(
            &plan_with(
                vec![persona(ALICE), persona(BOB)],
                vec![RebuiltMembership {
                    vtc_did: VTC.to_string(),
                    persona_did: ALICE.to_string(),
                    credential: serde_json::json!({}),
                }],
            ),
            &keys,
            Utc::now(),
        );
        assert_eq!(out.summary(), "1 persona, 1 membership (1 persona skipped)");
    }

    #[test]
    fn an_empty_plan_produces_an_empty_account() {
        let out = apply(&plan_with(vec![], vec![]), &[], Utc::now());
        assert!(out.account.personas.is_empty());
        assert!(out.key_info.is_empty());
        assert!(out.skipped.is_empty());
        assert_eq!(out.account.top_context_id, "openvtc");
    }
}
