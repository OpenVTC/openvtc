//! Two devices, one in-memory app-state store with the VTA's version,
//! precondition and tombstone semantics.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::app_state::{
    AppStateListResponse, AppStateRecord, AppStateWrite, WriteResult,
};

use super::*;
use crate::config::KeyTypes;
use crate::config::account::{
    Account, CommunityRecord, DecisionEvidence, KeyRef, PersonaId, PersonaRecord,
};
use crate::config::protected_config::{Contact, ProtectedConfig};
use crate::config::secured_config::{KeyInfoConfig, KeySourceMaterial};

const CTX: &str = "openvtc-acct";
const VTC: &str = "did:webvh:scid:vtc.example.com";

#[derive(Default)]
struct Inner {
    counter: u64,
    /// key -> (version, deleted, value)
    records: BTreeMap<String, (u64, bool, Option<Value>)>,
    reaped_through: u64,
    max_bytes: Option<usize>,
    unsupported: bool,
}

/// The store, behind a lock so both "devices" share it.
#[derive(Clone, Default)]
struct MemStore(Arc<Mutex<Inner>>);

/// Records per page, small so paging is exercised.
const MEM_PAGE: usize = 2;

fn record(key: &str, version: u64, deleted: bool, value: Option<Value>) -> AppStateRecord {
    serde_json::from_value(json!({
        "contextId": CTX, "namespace": NAMESPACE, "key": key, "version": version,
        "deleted": deleted, "value": value, "updatedAt": "2026-10-11T00:00:00Z",
    }))
    .map(|mut r: AppStateRecord| {
        // `value: null` on a tombstone must read as absent.
        if deleted {
            r.value = None;
        }
        r
    })
    .expect("record")
}

fn page(
    mut all: Vec<AppStateRecord>,
    cursor: Option<&str>,
    high_watermark: u64,
) -> AppStateListResponse {
    let start: usize = cursor.map_or(0, |c| c.parse().expect("cursor"));
    let rest = all.split_off(start.min(all.len()));
    let truncated = rest.len() > MEM_PAGE;
    let records: Vec<_> = rest.into_iter().take(MEM_PAGE).collect();
    serde_json::from_value(json!({
        "records": records,
        "truncated": truncated,
        "cursor": truncated.then(|| (start + MEM_PAGE).to_string()),
        "highWatermark": high_watermark,
    }))
    .expect("page")
}

impl MemStore {
    fn check(&self) -> Result<(), SyncError> {
        if self.0.lock().unwrap().unsupported {
            Err(SyncError::Unsupported)
        } else {
            Ok(())
        }
    }

    fn live(&self, key: &str) -> Option<Value> {
        let inner = self.0.lock().unwrap();
        inner
            .records
            .get(key)
            .filter(|(_, deleted, _)| !deleted)
            .and_then(|(_, _, v)| v.clone())
    }

    /// Drop every tombstone, as the VTA's retention sweep does.
    fn reap(&self) {
        let mut inner = self.0.lock().unwrap();
        inner.reaped_through = inner.counter;
        inner.records.retain(|_, (_, deleted, _)| !*deleted);
    }
}

impl AppStateStore for MemStore {
    async fn changes_since(
        &self,
        _context_id: &str,
        since: u64,
        cursor: Option<&str>,
    ) -> Result<AppStateListResponse, SyncError> {
        self.check()?;
        let inner = self.0.lock().unwrap();
        if since < inner.reaped_through {
            return Err(SyncError::WatermarkTooOld);
        }
        let mut all: Vec<_> = inner
            .records
            .iter()
            .filter(|(_, (v, _, _))| *v > since)
            .map(|(k, (v, d, val))| record(k, *v, *d, val.clone()))
            .collect();
        all.sort_by_key(|r| r.version);
        Ok(page(all, cursor, inner.counter))
    }

    async fn snapshot(
        &self,
        _context_id: &str,
        cursor: Option<&str>,
    ) -> Result<AppStateListResponse, SyncError> {
        self.check()?;
        let inner = self.0.lock().unwrap();
        let all: Vec<_> = inner
            .records
            .iter()
            .filter(|(_, (_, d, _))| !d)
            .map(|(k, (v, d, val))| record(k, *v, *d, val.clone()))
            .collect();
        Ok(page(all, cursor, inner.counter))
    }

    async fn put_many(
        &self,
        _context_id: &str,
        writes: Vec<AppStateWrite>,
    ) -> Result<Vec<WriteResult>, SyncError> {
        self.check()?;
        let mut inner = self.0.lock().unwrap();
        let mut out = Vec::new();
        for w in writes {
            let current = inner.records.get(&w.key).cloned();
            let live_version = current
                .as_ref()
                .filter(|(_, d, _)| !d)
                .map_or(0, |(v, _, _)| *v);
            let result = |outcome: &str, extra: Value| -> WriteResult {
                let mut v = json!({ "key": w.key, "outcome": outcome });
                v.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().cloned().unwrap_or_default());
                serde_json::from_value(v).expect("result")
            };
            if let Some(expected) = w.expected_version
                && expected != live_version
            {
                let (cv, cd, cval) = current.unwrap_or((0, true, None));
                out.push(result(
                    "conflict",
                    json!({ "currentVersion": cv, "currentDeleted": cd, "currentValue": cval }),
                ));
                continue;
            }
            let value = w.value.clone().expect("whole-value writes only");
            if let Some(max) = inner.max_bytes {
                let size = value.to_string().len();
                if size > max {
                    out.push(result(
                        "tooLarge",
                        json!({ "limitBytes": max, "actualBytes": size }),
                    ));
                    continue;
                }
            }
            inner.counter += 1;
            let version = inner.counter;
            inner
                .records
                .insert(w.key.clone(), (version, false, Some(value)));
            out.push(result("written", json!({ "version": version })));
        }
        Ok(out)
    }

    async fn delete(
        &self,
        _context_id: &str,
        key: &str,
        expected_version: u64,
    ) -> Result<DeleteOutcome, SyncError> {
        self.check()?;
        let mut inner = self.0.lock().unwrap();
        match inner.records.get(key).cloned() {
            Some((v, false, _)) if v != expected_version => Ok(DeleteOutcome::Conflict),
            Some((_, false, _)) => {
                inner.counter += 1;
                let version = inner.counter;
                inner.records.insert(key.to_string(), (version, true, None));
                Ok(DeleteOutcome::Deleted)
            }
            _ => Ok(DeleteOutcome::Deleted),
        }
    }
}

/// One install: the synced parts of its config, and its sync bookkeeping.
#[derive(Default)]
struct Device {
    account: Account,
    private: ProtectedConfig,
    key_info: HashMap<String, KeyInfoConfig>,
    state: SyncState,
}

impl Device {
    fn parts(&mut self) -> (SyncParts<'_>, &mut SyncState) {
        (
            SyncParts {
                account: &mut self.account,
                private: &mut self.private,
                key_info: &mut self.key_info,
            },
            &mut self.state,
        )
    }

    async fn load(&mut self, store: &MemStore) -> SyncReport {
        let (mut parts, state) = self.parts();
        sync_at_load(store, &mut parts, state, CTX).await
    }

    /// One runtime cycle: plan on the "loop", exchange, absorb.
    async fn live(&mut self, store: &MemStore) -> SyncReport {
        let mut report = SyncReport::default();
        let (mut parts, state) = self.parts();
        let out = outgoing(&parts.view(), state);
        let ex = exchange(store, CTX, state.watermark, out).await;
        absorb(&mut parts, state, ex, ApplyMode::Live, &mut report);
        report
    }

    fn pending(&self) -> Outgoing {
        let view = SyncView {
            account: &self.account,
            private: &self.private,
            key_info: &self.key_info,
        };
        outgoing(&view, &self.state)
    }

    fn membership(&self) -> &CommunityRecord {
        self.account.memberships().next().expect("a membership")
    }

    fn membership_mut(&mut self) -> &mut CommunityRecord {
        self.account.memberships_mut().next().expect("a membership")
    }
}

fn persona(label: &str) -> PersonaRecord {
    PersonaRecord {
        extra: serde_json::Map::new(),
        persona_id: PersonaId::new(),
        did: format!("did:webvh:scid:example.com:{label}"),
        did_document: None,
        key_refs: vec![KeyRef {
            key_id: format!("key-{label}"),
            purpose: KeyTypes::PersonaSigning,
            created_at: Utc::now(),
        }],
        mediator_did: None,
        origin_context_id: format!("{CTX}/{label}"),
        created_at: Utc::now(),
        label: Some(label.to_string()),
    }
}

/// A device holding one persona and one membership that has ended (so it may
/// be archived), with one VTA-managed key and one contact.
fn seeded() -> Device {
    let mut d = Device::default();
    d.account.top_context_id = CTX.to_string();
    let p = persona("alice");
    let mut c = CommunityRecord::new_pending(
        VTC.to_string(),
        Some("Example".to_string()),
        format!("{CTX}/example"),
        p.persona_id,
        Uuid::new_v4(),
        Utc::now(),
    );
    c.reject(DecisionEvidence::default());
    d.account.personas.insert(p.persona_id, p);
    d.account.add_membership(c);
    d.key_info.insert(
        "did:webvh:scid:example.com:alice#key-1".to_string(),
        KeyInfoConfig {
            path: KeySourceMaterial::VtaManaged {
                key_id: "vta-key-1".to_string(),
            },
            create_time: Utc::now(),
            purpose: KeyTypes::PersonaSigning,
        },
    );
    let did = Arc::new("did:key:z6Mkbob".to_string());
    let bob = Arc::new(Contact {
        did: did.clone(),
        alias: Some("bob".to_string()),
    });
    d.private.contacts.contacts.insert(did, bob.clone());
    d.private.contacts.aliases.insert("bob".to_string(), bob);
    d
}

#[tokio::test]
async fn a_fresh_device_pulls_the_whole_account_at_load() {
    let store = MemStore::default();
    let mut a = seeded();
    let report = a.load(&store).await;
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.pushed, 4, "persona, membership, key and contact");

    let mut b = Device::default();
    let report = b.load(&store).await;
    assert!(report.error.is_none());
    assert_eq!(report.pulled, 4);
    assert_eq!(b.account.personas.len(), 1);
    assert_eq!(b.membership().vtc_did, VTC);
    assert_eq!(b.key_info.len(), 1);
    assert!(
        b.private.contacts.find_contact("bob").is_some(),
        "alias index rebuilt"
    );

    // Nothing left to say on either side.
    assert!(b.pending().is_empty());
    assert!(a.pending().is_empty());
}

#[tokio::test]
async fn archiving_on_one_device_reaches_a_running_other() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let mut b = Device::default();
    b.load(&store).await;

    let persona = a.membership().persona_ref;
    a.account
        .archive_membership(VTC, persona)
        .expect("an ended membership may be archived");
    let report = a.live(&store).await;
    assert_eq!(report.pushed, 1);

    let report = b.live(&store).await;
    assert_eq!(report.pulled, 1);
    assert!(report.changed.contains(&RecordKind::Membership));
    assert!(b.membership().archived, "the archive crossed devices");
    assert!(report.conflicts.is_empty());
}

#[tokio::test]
async fn edits_to_different_fields_on_two_devices_both_survive() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let mut b = Device::default();
    b.load(&store).await;

    a.membership_mut().archived = true;
    b.membership_mut().favourite = true;
    a.live(&store).await;
    // B's push loses the race, comes back with A's archive, and merges it.
    let report = b.live(&store).await;
    assert!(b.membership().archived && b.membership().favourite);
    assert!(report.conflicts.is_empty());
    // The merged record goes up on B's next cycle, and A takes it.
    b.live(&store).await;
    a.live(&store).await;
    assert!(a.membership().archived && a.membership().favourite);
}

#[tokio::test]
async fn the_same_field_edited_on_both_is_reported_and_converges() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let mut b = Device::default();
    b.load(&store).await;

    a.membership_mut().display_name = Some("From A".to_string());
    b.membership_mut().display_name = Some("From B".to_string());
    a.live(&store).await;
    let report = b.live(&store).await;
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(b.membership().display_name.as_deref(), Some("From A"));
}

#[tokio::test]
async fn a_new_persona_waits_for_the_next_launch_on_a_running_device() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let mut b = Device::default();
    b.load(&store).await;

    let p = persona("carol");
    let id = p.persona_id;
    a.account.personas.insert(id, p);
    a.live(&store).await;

    let report = b.live(&store).await;
    assert_eq!(report.deferred, 1);
    assert!(
        !b.account.personas.contains_key(&id),
        "not under a running session"
    );
    assert!(
        b.pending().is_empty(),
        "a deferred record is not pushed back as a deletion"
    );

    let report = b.load(&store).await;
    assert!(b.account.personas.contains_key(&id), "applied at launch");
    assert!(b.state.deferred.is_empty());
    assert!(report.error.is_none());
}

#[tokio::test]
async fn a_deletion_propagates() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let mut b = Device::default();
    b.load(&store).await;

    let mut logs = crate::logs::Logs::default();
    a.private.contacts.remove_contact(&mut logs, "bob");
    let report = a.live(&store).await;
    assert_eq!(report.removed, 1);

    b.live(&store).await;
    assert!(b.private.contacts.find_contact("bob").is_none());
    assert!(b.private.contacts.aliases.is_empty());
}

#[tokio::test]
async fn reaped_tombstones_fall_back_to_a_snapshot() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let mut b = Device::default();
    b.load(&store).await;

    let mut logs = crate::logs::Logs::default();
    a.private.contacts.remove_contact(&mut logs, "bob");
    a.live(&store).await;
    // B was away long enough for the tombstone to be reaped.
    store.reap();

    let report = b.load(&store).await;
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(
        b.private.contacts.find_contact("bob").is_none(),
        "the snapshot's absence of the record reads as its deletion"
    );
    assert_eq!(b.account.personas.len(), 1, "live records are untouched");
}

#[tokio::test]
async fn a_locally_held_key_never_leaves_the_device() {
    use secrecy::SecretString;
    let store = MemStore::default();
    let mut a = seeded();
    a.key_info.insert(
        "imported".to_string(),
        KeyInfoConfig {
            path: KeySourceMaterial::Imported {
                seed: SecretString::from("z-secret".to_string()),
            },
            create_time: Utc::now(),
            purpose: KeyTypes::PersonaSigning,
        },
    );
    a.load(&store).await;
    let inner = store.0.lock().unwrap();
    let text = serde_json::to_string(&inner.records.values().collect::<Vec<_>>()).unwrap();
    assert!(!text.contains("z-secret"));
    assert!(!text.contains("Imported"));
}

#[tokio::test]
async fn a_record_too_large_is_reported_once_and_not_reoffered() {
    let store = MemStore::default();
    store.0.lock().unwrap().max_bytes = Some(600);
    let mut a = seeded();
    a.membership_mut().display_name = Some("x".repeat(2_000));
    let report = a.load(&store).await;
    assert_eq!(report.rejected.len(), 1, "{:?}", report.rejected);
    assert!(store.live(&membership_key_of(&a)).is_none());

    let out = a.pending();
    assert!(
        out.puts
            .iter()
            .all(|(k, _, _)| !k.starts_with("v1/membership/"))
    );

    // A change to the record offers it again.
    a.membership_mut().display_name = Some("short".to_string());
    let out = a.pending();
    assert!(
        out.puts
            .iter()
            .any(|(k, _, _)| k.starts_with("v1/membership/"))
    );
}

fn membership_key_of(d: &Device) -> String {
    let local = records::project(&SyncView {
        account: &d.account,
        private: &d.private,
        key_info: &d.key_info,
    });
    local
        .keys()
        .find(|k| k.starts_with("v1/membership/"))
        .cloned()
        .expect("membership key")
}

#[tokio::test]
async fn a_vta_without_the_store_is_named_and_changes_nothing() {
    let store = MemStore::default();
    store.0.lock().unwrap().unsupported = true;
    let mut a = seeded();
    let report = a.load(&store).await;
    assert_eq!(report.error, Some(SyncError::Unsupported));
    assert_eq!(report.pushed, 0);
    assert!(!report.error.unwrap().is_transient());
}

#[tokio::test]
async fn a_record_from_a_newer_build_is_held_not_applied() {
    let store = MemStore::default();
    let mut a = seeded();
    a.load(&store).await;
    let key = membership_key_of(&a);
    {
        let mut inner = store.0.lock().unwrap();
        inner.counter += 1;
        let v = inner.counter;
        inner.records.insert(
            key.clone(),
            (
                v,
                false,
                Some(json!({ "schemaVersion": 99, "data": { "whatever": true } })),
            ),
        );
    }
    let report = a.live(&store).await;
    assert_eq!(report.unreadable.len(), 1);
    assert!(a.state.deferred.contains_key(&key));
    assert_eq!(a.membership().vtc_did, VTC, "local copy untouched");
}
