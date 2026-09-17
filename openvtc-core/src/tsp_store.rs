/*!
 * Durable backing for TSP Rev 3 relationship state.
 *
 * Rev 3 §7.2.2 gates application traffic on a recorded relationship: a peer the
 * endpoint holds none with has its messages dropped. The SDK records that state
 * into whatever `RelationshipStore` the ATM is built with, and the default is
 * in-memory — wiped on restart. After a restart, every peer that still holds the
 * relationship the endpoint forgot has its traffic silently dropped until it is
 * re-formed. Persisting the store is what closes that window.
 *
 * The SDK already solves the store itself: `PersistentRelationshipStore` keeps
 * the FSM, the per-facet key layout and the (de)serialisation, and delegates raw
 * bytes to a three-method `RelationshipKv`. This module is that backend — an
 * in-memory map OpenVTC mirrors into the encrypted `ProtectedConfig`, alongside
 * (but deliberately separate from) the DIDComm [`crate::relationships`] model,
 * which is a different kind of relationship keyed and stored its own way.
 *
 * ## Why an in-memory map with a persisted mirror, not a file the KV writes
 *
 * The KV is written by the SDK's background tasks — the inbound dispatcher
 * records an invite, a send forms one — which run off the single-mutator loop.
 * Writing straight to disk from there would fight the loop's coalesced-save
 * ownership of the config file. So a write lands in a shared in-memory map and
 * raises a `Notify`; the loop drains that notify, snapshots the map into
 * `ProtectedConfig` and saves on its own schedule. Hydration runs the other way
 * at load, before any listener connects, so the SDK sees existing relationships
 * and does not re-invite a peer it is already bidirectional with.
 */

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use affinidi_messaging_sdk::protocols::tsp::RelationshipState;
use affinidi_messaging_sdk::{PersistentRelationshipStore, RelationshipKv, RelationshipStore};
use affinidi_tdk::messaging::errors::ATMError;
use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};

/// The opaque relationship key/value store, as persisted inside `ProtectedConfig`.
///
/// Keys and values are `PersistentRelationshipStore`'s own binary encoding —
/// OpenVTC never interprets them. They are base64url-encoded here only so the map
/// serialises as JSON string keys and values. A [`BTreeMap`] keeps the on-disk
/// order deterministic, so a config that has not changed round-trips
/// byte-identically (the R20 invariant the whole encrypted tier holds to).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TspRelationships {
    /// `base64url(key)` → `base64url(value)`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: BTreeMap<String, String>,
}

impl TspRelationships {
    /// Whether any relationship is stored. Used by `#[serde(skip_serializing_if)]`
    /// so a config that has never spoken TSP round-trips exactly as before.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn from_map(map: &HashMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            entries: map
                .iter()
                .map(|(k, v)| (B64.encode(k), B64.encode(v)))
                .collect(),
        }
    }

    fn to_map(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        // A row that will not decode is dropped rather than failing the load: the
        // whole config would otherwise be unopenable over one corrupt relationship
        // record, and the peer holding the other half re-forms it on next contact.
        self.entries
            .iter()
            .filter_map(|(k, v)| Some((B64.decode(k).ok()?, B64.decode(v).ok()?)))
            .collect()
    }
}

/// The shared, in-memory relationship map plus its dirty signal.
///
/// Cloned into every listener's KV so all identities read and write one map, and
/// held by [`TspStoreHandle`] for the loop's hydrate/snapshot. `Clone` is an
/// `Arc` bump on each side.
#[derive(Clone)]
struct SharedKv {
    map: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    dirty: Arc<Notify>,
}

#[async_trait::async_trait]
impl RelationshipKv for SharedKv {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        Ok(self.map.read().await.get(key).cloned())
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
        self.map.write().await.insert(key.to_vec(), value.to_vec());
        // Coalescing: many writes before the loop next waits collapse into one
        // wakeup, which is exactly the coalesced-save behaviour we want.
        self.dirty.notify_one();
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        self.map.write().await.remove(key);
        self.dirty.notify_one();
        Ok(())
    }

    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ATMError> {
        Ok(self
            .map
            .read()
            .await
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

/// A handle to one durable TSP relationship store.
///
/// One per [`crate::didcomm::Messaging`]. [`Self::relationship_store`] is cloned
/// into every listener's ATM so all identities share it; [`Self::hydrate`] and
/// [`Self::snapshot`] are how the single-mutator loop loads it at startup and
/// persists it into `ProtectedConfig`, driven by [`Self::dirty`].
#[derive(Clone)]
pub struct TspStoreHandle {
    shared: SharedKv,
}

impl TspStoreHandle {
    /// A fresh, empty store. Populated by [`Self::hydrate`] at startup.
    pub fn new() -> Self {
        Self {
            shared: SharedKv {
                map: Arc::new(RwLock::new(HashMap::new())),
                dirty: Arc::new(Notify::new()),
            },
        }
    }

    /// The `Arc<dyn RelationshipStore>` to inject into an ATM via
    /// [`with_relationship_store`]. Every call wraps the *same* underlying map, so
    /// what one identity records another identity — and the loop — reads.
    ///
    /// [`with_relationship_store`]:
    /// affinidi_messaging_sdk::config::ATMConfigBuilder::with_relationship_store
    pub fn relationship_store(&self) -> Arc<dyn RelationshipStore> {
        Arc::new(PersistentRelationshipStore::new(self.shared.clone()))
    }

    /// Raised whenever a background write changes the store. Coalesces many writes
    /// into one wakeup; the loop waits on it and persists on its own schedule.
    pub fn dirty(&self) -> Arc<Notify> {
        self.shared.dirty.clone()
    }

    /// Load persisted relationships into the store, replacing whatever it holds.
    ///
    /// Called once at startup, **before any listener connects**, so the SDK sees
    /// the relationships that survived the last run rather than starting empty and
    /// re-inviting peers it is already bidirectional with.
    pub async fn hydrate(&self, persisted: &TspRelationships) {
        *self.shared.map.write().await = persisted.to_map();
    }

    /// A serialisable snapshot for the loop to write into `ProtectedConfig` before
    /// a save.
    pub async fn snapshot(&self) -> TspRelationships {
        let guard = self.shared.map.read().await;
        TspRelationships::from_map(&guard)
    }

    /// The relationship state for one `(our_vid, their_vid)` pair, read through the
    /// SDK's own decoder rather than by re-implementing its key layout here (the
    /// same discipline the `didwebvh-rs` / `agent-names` rules state: a private
    /// on-disk encoding is the library's to own). Returns
    /// [`RelationshipState::None`] for a pair the store has never seen.
    ///
    /// Cheap — it reads the in-memory map, no network — so the UI refresh can call
    /// it per candidate pair.
    pub async fn state_for(&self, our_vid: &str, their_vid: &str) -> RelationshipState {
        PersistentRelationshipStore::new(self.shared.clone())
            .get(our_vid, their_vid)
            .await
            .unwrap_or_default()
    }
}

impl Default for TspStoreHandle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The persisted mirror is exactly what the store holds: hydrate a snapshot
    /// back and the map is identical. This is the round trip a restart makes.
    #[tokio::test]
    async fn snapshot_then_hydrate_round_trips() {
        let a = TspStoreHandle::new();
        let store = a.relationship_store();
        // Drive a write through the real store surface so the key/value bytes are
        // the SDK's own encoding, not a shape this test made up.
        store
            .set(
                "did:webvh:example:us",
                "did:webvh:example:them",
                affinidi_messaging_sdk::protocols::tsp::RelationshipState::Pending,
            )
            .await
            .expect("set");

        let snap = a.snapshot().await;
        assert!(!snap.is_empty(), "a recorded relationship must persist");

        // A fresh handle (a restart) hydrated from the snapshot reads the same
        // state back.
        let b = TspStoreHandle::new();
        b.hydrate(&snap).await;
        let restored = b.relationship_store();
        let state = restored
            .get("did:webvh:example:us", "did:webvh:example:them")
            .await
            .expect("get");
        assert_eq!(
            state,
            affinidi_messaging_sdk::protocols::tsp::RelationshipState::Pending,
            "the relationship state must survive a snapshot/hydrate cycle"
        );
    }

    /// An empty store serialises to an empty mirror, so a config that has never
    /// spoken TSP gains no bytes.
    #[tokio::test]
    async fn empty_store_is_empty_mirror() {
        let h = TspStoreHandle::new();
        assert!(h.snapshot().await.is_empty());
        assert_eq!(
            serde_json::to_string(&h.snapshot().await).expect("serialise"),
            "{}",
            "an unused store must round-trip to an empty object"
        );
    }

    /// A corrupt row does not sink the whole load — it is dropped and the rest
    /// hydrates.
    #[tokio::test]
    async fn undecodable_row_is_skipped_not_fatal() {
        let mut snap = TspRelationships::default();
        snap.entries
            .insert("not valid base64!!".to_string(), "also bad".to_string());
        let map = snap.to_map();
        assert!(map.is_empty(), "an undecodable row is skipped");
    }
}
