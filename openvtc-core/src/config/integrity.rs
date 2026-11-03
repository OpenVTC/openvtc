//! What could not be loaded, and why — so a partial profile still starts.
//!
//! # The failure this exists for
//!
//! A profile is persisted in two writes, not one: [`Config::save`](crate::config::Config::save) writes the
//! public config file (carrying the encrypted account, and with it the persona
//! records) and *then* writes the `SecuredConfig` blob (carrying `key_info`,
//! which maps each DID verification method to its key) to the OS credential
//! store. They are not atomic. A crash, a full disk, or a credential store that
//! refuses the second write leaves a persona recorded in the account with no
//! key material recorded for it.
//!
//! Until now that was **fatal for the entire profile**: key rehydration
//! returned `Err` on the first verification method it could not find, the error
//! propagated out of the persona loop, and the whole load failed. One
//! half-written persona took down every other persona, every community, and
//! every relationship in the account — and the message named a verification
//! method id, which tells the user nothing about what to do.
//!
//! The rule now is that **a fault is isolated to the persona that has it**.
//! Everything that can be loaded is loaded, what cannot is recorded here, and
//! the user is shown this report and must acknowledge it before continuing.
//!
//! # What this deliberately does not do
//!
//! It does not repair, and it does not delete. A degraded persona's record
//! stays in the account exactly as it was: it is skipped for this session, not
//! removed. Quietly dropping it would turn a recoverable inconsistency —
//! `key_info` may still be present in a backup, or the persona's keys may still
//! be at the VTA — into permanent loss, on the one code path taken by a user
//! whose profile is already damaged.

use crate::config::account::PersonaId;
use serde::{Deserialize, Serialize};

/// Why one persona could not be brought up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradedReason {
    /// The account records this persona, but `key_info` has no entry for one of
    /// its verification methods — the signature of a half-completed save.
    MissingKeyInfo {
        /// The verification method id with no key recorded.
        key_id: String,
    },
    /// `key_info` points at a VTA-managed key the VTA would not return.
    KeyUnavailable {
        /// The store or VTA's own message.
        detail: String,
    },
    /// The VTA answered and refused the key: this account is not permitted it
    /// (`forbidden`), or the VTA no longer holds it (`notFound` / `gone`).
    ///
    /// Distinct from [`Self::KeyUnavailable`] because restarting does not fix
    /// it. The usual cause is a persona whose VTA context was deleted or
    /// replaced — its record came back (from a backup, or from account state
    /// synced off the VTA) but the keys and the authority over them did not.
    KeyNotAccessible {
        /// The VTA's own message.
        detail: String,
    },
    /// The persona's DID document could not be resolved and none was cached.
    DocumentUnresolvable {
        /// The resolver's own message.
        detail: String,
    },
    /// Keys and document were fine, but the messaging profile would not build,
    /// so the persona has no listener.
    MessagingUnavailable {
        /// The messaging layer's own message.
        detail: String,
    },
}

impl DegradedReason {
    /// One line explaining the reason in the user's terms.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            DegradedReason::MissingKeyInfo { key_id } => {
                format!("no key material recorded for {key_id}")
            }
            DegradedReason::KeyUnavailable { detail } => {
                format!("its keys could not be retrieved: {detail}")
            }
            DegradedReason::KeyNotAccessible { detail } => {
                format!("the VTA refused its keys to this account: {detail}")
            }
            DegradedReason::DocumentUnresolvable { detail } => {
                format!("its DID document could not be resolved: {detail}")
            }
            DegradedReason::MessagingUnavailable { detail } => {
                format!("its messaging profile could not be built: {detail}")
            }
        }
    }

    /// Whether this looks like an interrupted write rather than a transient
    /// fault. The distinction matters to the user: one is "you lost something
    /// and here is what", the other is "try again when you are back online".
    #[must_use]
    pub fn is_incomplete_write(&self) -> bool {
        matches!(self, DegradedReason::MissingKeyInfo { .. })
    }

    /// Whether retrying — reconnecting, coming back online — could fix this
    /// without any user action beyond restarting.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            DegradedReason::KeyUnavailable { .. } | DegradedReason::DocumentUnresolvable { .. }
        )
    }
}

/// A persona present in the account that could not be brought up this session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedPersona {
    /// Stable persona id, as recorded in the account.
    pub persona_id: PersonaId,
    /// The persona's DID.
    pub did: String,
    /// The user's own label for it, if any.
    pub label: Option<String>,
    /// When the account says it was created — the newest degraded persona is
    /// almost always the one a crash interrupted.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Why it could not be loaded.
    pub reason: DegradedReason,
}

/// Everything the load could not bring up, gathered rather than thrown.
///
/// Empty on a healthy profile, which is the case worth optimising for: callers
/// check [`is_clean`](Self::is_clean) and otherwise show the report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadIntegrity {
    /// Personas recorded in the account that are not usable this session.
    pub degraded_personas: Vec<DegradedPersona>,
    /// Community memberships whose persona is one of the above, and which are
    /// therefore inert until that persona is recovered.
    pub stranded_memberships: Vec<StrandedMembership>,
    /// `key_info` entries belonging to no persona in the account — the mirror
    /// image of a half-written save (keys landed, account did not). Harmless in
    /// itself, but it is evidence of the same interrupted write, and of a
    /// persona the user may believe they created.
    pub orphaned_key_ids: Vec<String>,
}

/// A membership that cannot be used because its persona could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrandedMembership {
    /// The community's DID.
    pub vtc_did: String,
    /// The persona the membership presents.
    pub persona_id: PersonaId,
    /// Community name if the record carried one.
    pub label: Option<String>,
}

impl LoadIntegrity {
    /// True when nothing was degraded — the normal case.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.degraded_personas.is_empty()
            && self.stranded_memberships.is_empty()
            && self.orphaned_key_ids.is_empty()
    }

    /// True when at least one fault looks like an interrupted write rather than
    /// a transient network or store problem. Drives the wording: a user who
    /// crashed mid-create needs to know something is gone, not to retry.
    #[must_use]
    pub fn has_incomplete_write(&self) -> bool {
        !self.orphaned_key_ids.is_empty()
            || self
                .degraded_personas
                .iter()
                .any(|p| p.reason.is_incomplete_write())
    }

    /// True when the VTA refused a persona's keys outright — a fault no
    /// restart fixes, and one that needs saying differently from a network
    /// blip (VTI R6.4).
    #[must_use]
    pub fn has_inaccessible_keys(&self) -> bool {
        self.degraded_personas
            .iter()
            .any(|p| matches!(p.reason, DegradedReason::KeyNotAccessible { .. }))
    }

    /// True when every fault could clear on its own — worth saying, because it
    /// turns "you have lost a persona" into "try again in a moment".
    #[must_use]
    pub fn is_all_transient(&self) -> bool {
        !self.degraded_personas.is_empty()
            && self.orphaned_key_ids.is_empty()
            && self
                .degraded_personas
                .iter()
                .all(|p| p.reason.is_transient())
    }

    /// One line for the activity log and the status bar.
    #[must_use]
    pub fn headline(&self) -> String {
        let personas = self.degraded_personas.len();
        let memberships = self.stranded_memberships.len();
        let mut parts = Vec::new();
        if personas > 0 {
            parts.push(format!(
                "{personas} persona{} unavailable",
                if personas == 1 { "" } else { "s" }
            ));
        }
        if memberships > 0 {
            parts.push(format!(
                "{memberships} membership{} inactive",
                if memberships == 1 { "" } else { "s" }
            ));
        }
        if !self.orphaned_key_ids.is_empty() {
            parts.push(format!(
                "{} orphaned key record{}",
                self.orphaned_key_ids.len(),
                if self.orphaned_key_ids.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }
        if parts.is_empty() {
            "Configuration loaded".to_string()
        } else {
            format!("Loaded with problems: {}", parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn persona(reason: DegradedReason) -> DegradedPersona {
        DegradedPersona {
            persona_id: PersonaId(Uuid::nil()),
            did: "did:webvh:Qm:example.com:alice".to_string(),
            label: Some("Alice".to_string()),
            created_at: chrono::Utc::now(),
            reason,
        }
    }

    #[test]
    fn a_healthy_load_is_clean() {
        assert!(LoadIntegrity::default().is_clean());
        assert_eq!(LoadIntegrity::default().headline(), "Configuration loaded");
    }

    /// The mid-create crash: the account has the persona, `key_info` does not.
    /// This must read as loss, not as something to retry.
    #[test]
    fn missing_key_info_reads_as_an_interrupted_write() {
        let integrity = LoadIntegrity {
            degraded_personas: vec![persona(DegradedReason::MissingKeyInfo {
                key_id: "did:webvh:Qm:example.com:alice#key-1".to_string(),
            })],
            ..Default::default()
        };
        assert!(!integrity.is_clean());
        assert!(integrity.has_incomplete_write());
        assert!(!integrity.is_all_transient());
        assert!(integrity.headline().contains("1 persona unavailable"));
    }

    /// A VTA that is merely unreachable is not data loss, and must not be
    /// described as though it were.
    #[test]
    fn an_unreachable_vta_is_transient_not_loss() {
        let integrity = LoadIntegrity {
            degraded_personas: vec![persona(DegradedReason::KeyUnavailable {
                detail: "connection refused".to_string(),
            })],
            ..Default::default()
        };
        assert!(integrity.is_all_transient());
        assert!(!integrity.has_incomplete_write());
    }

    /// A VTA that answered and refused the key is not a bad moment: telling
    /// the user to restart once they are back online sends them round a loop
    /// that never ends.
    #[test]
    fn a_refused_key_is_neither_transient_nor_an_interrupted_write() {
        let integrity = LoadIntegrity {
            degraded_personas: vec![persona(DegradedReason::KeyNotAccessible {
                detail: "forbidden: key is not within the caller's scope".to_string(),
            })],
            ..Default::default()
        };
        assert!(!integrity.is_all_transient());
        assert!(!integrity.has_incomplete_write());
        assert!(integrity.has_inaccessible_keys());
    }

    /// Orphaned keys are the mirror image of the same interrupted write, so
    /// they count as one even with no degraded persona to point at.
    #[test]
    fn orphaned_keys_alone_still_signal_an_interrupted_write() {
        let integrity = LoadIntegrity {
            orphaned_key_ids: vec!["did:webvh:Qm:example.com:ghost#key-1".to_string()],
            ..Default::default()
        };
        assert!(!integrity.is_clean());
        assert!(integrity.has_incomplete_write());
        assert!(!integrity.is_all_transient());
        assert!(integrity.headline().contains("1 orphaned key record"));
    }

    #[test]
    fn headline_counts_every_category() {
        let integrity = LoadIntegrity {
            degraded_personas: vec![
                persona(DegradedReason::MissingKeyInfo {
                    key_id: "a".to_string(),
                }),
                persona(DegradedReason::KeyUnavailable {
                    detail: "b".to_string(),
                }),
            ],
            stranded_memberships: vec![StrandedMembership {
                vtc_did: "did:webvh:Qm:vtc.example.com:community".to_string(),
                persona_id: PersonaId(Uuid::nil()),
                label: Some("Example".to_string()),
            }],
            orphaned_key_ids: vec!["x".to_string(), "y".to_string()],
        };
        let headline = integrity.headline();
        assert!(headline.contains("2 personas unavailable"), "{headline}");
        assert!(headline.contains("1 membership inactive"), "{headline}");
        assert!(headline.contains("2 orphaned key records"), "{headline}");
    }
}
