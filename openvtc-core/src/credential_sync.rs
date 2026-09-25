//! Put the credentials this account holds into the VTA's credential vault.
//!
//! # Why this exists
//!
//! A `MembershipCredential` arrives over DIDComm and is stored in the local
//! `CommunityRecord` — and, until now, nowhere else. Invitations were pushed to
//! the VTA's credential vault on receipt; membership credentials were not.
//!
//! That is what made membership recovery restore nothing. [`crate::rebuild`]
//! reconstructs a membership *from* its credential, which is the right design —
//! the credential is what the community signed, and it names both the community
//! and the persona. But the credential has to be somewhere a rebuild can find
//! it, and a local config file is precisely the thing a rebuild exists because
//! you no longer have.
//!
//! A VMC also simply *belongs* in the credential store. It is a signed artifact
//! of exactly the kind that vault holds, and keeping it only in a config file
//! was the anomaly.
//!
//! # One pass, run on connect
//!
//! The message-dispatch path that ingests a credential has no VTA session, so
//! rather than threading one through, this runs as a sync: everything held
//! locally that the vault does not have is pushed. That covers a fresh join, a
//! credential received while the VTA was unreachable, and the back-fill of
//! every membership from before this existed — one mechanism instead of three.
//!
//! # Published Trust Tasks only
//!
//! - `spec/vault/credentials/query/0.1` to see what the vault already holds.
//!   **Filtered** — the vault refuses a filterless query by design, because
//!   running one would be a wallet enumeration.
//! - `spec/vault/credentials/receive/0.1` to store one.
//!
//! Both are dispatched Trust Tasks; neither is a bespoke route.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde_json::Value;
use tracing::{debug, warn};
use vta_sdk::client::VtaClient;

use crate::issued_credential::verify_issued_credential;
use crate::{CredentialKind, config::Config};

/// What a sync pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Credentials pushed to the vault this pass.
    pub stored: usize,
    /// Credentials already held by the vault, left alone.
    pub already_held: usize,
    /// Credentials that could not be pushed. Non-fatal — the local copy is
    /// still authoritative today, so a failure costs recoverability, not the
    /// membership itself.
    pub failed: usize,
    /// Credentials held locally whose proof did not verify against the issuing
    /// community's DID document, and so were not pushed. A credential stored
    /// before issued credentials were verified on receipt can land here.
    pub unverified: usize,
}

impl SyncReport {
    /// True when the pass had nothing to do — the common case once an account
    /// has been synced.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.stored == 0 && self.failed == 0 && self.unverified == 0
    }
}

/// Ensure every membership credential this account holds is also in the vault.
///
/// Idempotent: the vault keys a received credential on the VC's own `id`, so
/// re-receiving one overwrites rather than duplicating. The query pass exists
/// only to avoid pointless writes on every launch.
///
/// Best-effort throughout. The local copy remains the source of truth today, so
/// a vault that will not answer costs future recoverability rather than
/// anything working now.
///
/// Each credential's proof is verified before it is pushed, so the vault only
/// ever receives what the community actually signed — a recovery restores from
/// the vault, and must not inherit a credential this client never checked.
pub async fn sync_membership_credentials(
    config: &Config,
    client: &VtaClient,
    resolver: &DIDCacheClient,
) -> SyncReport {
    let held: Vec<(String, String, Value)> = config
        .account
        .memberships()
        .filter_map(|c| {
            let vc = c.credentials.get(&CredentialKind::Membership)?;
            // Without an id there is nothing to compare against, and the vault
            // would mint a fresh one on every pass — storing a duplicate each
            // launch. Skip rather than churn.
            let id = vc.get("id").and_then(Value::as_str)?;
            Some((id.to_string(), c.vtc_did.clone(), vc.clone()))
        })
        .collect();

    if held.is_empty() {
        return SyncReport::default();
    }

    // Filtered, because the vault refuses to enumerate. `purpose` is the
    // vault's own semantic classification and what its index is keyed on, so
    // it does not depend on how an issuer spelled its `type` array.
    let in_vault = match client.cred_vault_query(held_query_filter()).await {
        Ok(listing) => held_ids(&listing),
        Err(e) => {
            // Not fatal, and not a reason to skip the push: `receive` is
            // idempotent, so the worst case is re-storing what is already
            // there.
            debug!("could not read held membership credentials ({e}); storing regardless");
            Vec::new()
        }
    };

    let mut report = SyncReport::default();
    for (id, vtc_did, credential) in held {
        if in_vault.iter().any(|held| held == &id) {
            report.already_held += 1;
            continue;
        }
        let credential = match verify_issued_credential(
            credential,
            &vtc_did,
            resolver,
            chrono::Utc::now(),
        )
        .await
        {
            Ok(verified) => verified.into_value(),
            Err(e) => {
                warn!(reason = %e, "a held membership credential did not verify; not storing it");
                report.unverified += 1;
                continue;
            }
        };
        match client.cred_vault_receive(credential, None).await {
            Ok(_) => {
                debug!(id = %id, "stored a membership credential in the vault");
                report.stored += 1;
            }
            Err(e) => {
                warn!(id = %id, "could not store a membership credential: {e}");
                report.failed += 1;
            }
        }
    }
    report
}

/// The filter used to see which membership credentials the vault already holds.
///
/// Factored out so the "must carry a filter" contract is testable without a
/// VTA. See `rebuild::membership_query_filter` for why `purpose`.
fn held_query_filter() -> Value {
    serde_json::json!({ "purpose": "membership" })
}

/// Credential ids from a `query/0.1` response.
///
/// The response carries body-free descriptors; only the `id` is needed here.
/// Tolerant about the envelope key because the response is consumed untyped,
/// and reading a full vault as empty would mean re-storing everything on every
/// launch.
fn held_ids(listing: &Value) -> Vec<String> {
    let array = if let Some(arr) = listing.as_array() {
        arr.clone()
    } else {
        ["credentials", "items", "results"]
            .iter()
            .find_map(|k| listing.get(*k).and_then(Value::as_array))
            .cloned()
            .unwrap_or_default()
    };
    array
        .into_iter()
        .filter_map(|d| {
            d.get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| d.as_str().map(str::to_string))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_with_nothing_to_do_is_a_noop() {
        assert!(SyncReport::default().is_noop());
        assert!(
            SyncReport {
                stored: 0,
                already_held: 4,
                failed: 0,
                unverified: 0,
            }
            .is_noop(),
            "an already-synced account must not report activity every launch"
        );
        assert!(
            !SyncReport {
                unverified: 1,
                ..SyncReport::default()
            }
            .is_noop(),
            "a credential that did not verify is worth reporting"
        );
    }

    #[test]
    fn stores_and_failures_are_both_worth_reporting() {
        assert!(
            !SyncReport {
                stored: 1,
                already_held: 0,
                failed: 0,
                unverified: 0,
            }
            .is_noop()
        );
        assert!(
            !SyncReport {
                stored: 0,
                already_held: 0,
                failed: 1,
                unverified: 0,
            }
            .is_noop(),
            "a failure costs future recoverability and must be visible"
        );
    }

    /// **Contract regression guard**, mirroring the one in `rebuild`: the vault
    /// refuses a filterless query as a wallet enumeration, so the sync's own
    /// query must carry a filter too.
    #[test]
    fn the_sync_query_carries_a_filter() {
        let filter = held_query_filter();
        let obj = filter.as_object().expect("an object");
        assert!(
            !obj.is_empty(),
            "a filterless vault query is refused by contract"
        );
        assert_eq!(
            obj.get("purpose").and_then(Value::as_str),
            Some("membership")
        );
    }

    #[test]
    fn ids_are_read_from_whichever_envelope_the_vault_used() {
        for key in ["credentials", "items", "results"] {
            let listing = serde_json::json!({ key: [{ "id": "vmc-1" }] });
            assert_eq!(held_ids(&listing), vec!["vmc-1".to_string()], "key {key}");
        }
        assert_eq!(
            held_ids(&serde_json::json!([{ "id": "vmc-1" }])),
            vec!["vmc-1".to_string()]
        );
    }

    /// Reading a full vault as empty would re-store everything every launch,
    /// so an unrecognised envelope must be visibly empty rather than guessed at.
    #[test]
    fn an_unrecognised_envelope_yields_nothing() {
        assert!(held_ids(&serde_json::json!({ "unexpected": [{ "id": "x" }] })).is_empty());
    }

    #[test]
    fn a_descriptor_without_an_id_is_skipped() {
        let listing = serde_json::json!({ "credentials": [{ "types": ["X"] }, { "id": "ok" }] });
        assert_eq!(held_ids(&listing), vec!["ok".to_string()]);
    }
}
