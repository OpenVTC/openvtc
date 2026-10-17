//! Keep this account's OpenVTC state at the VTA, so every device that opens
//! the same context sees the same communities, relationships, contacts and witnessings.
//!
//! # Why
//!
//! Until this existed the VTA held keys, DIDs and credentials, and *nothing*
//! else: archive a community on one machine and the other never heard of it,
//! because the flag lived only in each machine's encrypted config file. The
//! VTA's application-state store (`vta/app-state/*`, VTI #1029) is the home the
//! design (`docs/design/vta-authoritative-state.md`, step 5) was waiting on.
//!
//! # Shape
//!
//! The local config stays the source every read comes from — nothing waits on
//! the network (D8c). The synced parts of it are projected into one record per
//! item ([`records`]) in the `openvtc` namespace of the account's top context.
//! [`SyncState`], persisted in the protected tier, remembers the last version
//! of each record this device agreed with the VTA on (its *base*) and the
//! change-feed watermark.
//!
//! A sync is: pull every change since the watermark, merge each into the local
//! config against its base (the `merge` module), then push every record whose local
//! value no longer matches its base, each conditional on that base's version.
//! A push that lost a race comes back carrying the winner's value, which is
//! merged the same way and pushed again next time. Nothing is clobbered
//! silently: a field both sides changed takes the VTA's value and is reported.
//!
//! # When
//!
//! - **At load**, before personas are hydrated, so a persona, relationship or
//!   key reference another device created comes up with everything else.
//! - **While running**, after each save and on a timer. Changes that a running
//!   session cannot take in — a new persona, a relationship, TSP state,
//!   vetting — are held in [`SyncState::deferred`] and applied at the next
//!   launch ([`RecordKind::applies_live`]).
//!
//! # What does not sync (D9)
//!
//! Tasks, the activity log, kept inbound messages and replay records are
//! per-installation. Secrets never travel: the store is "not for secrets" by
//! its own specification, so only VTA-managed key *references* are synced and
//! the hidden-vetting engine stays local.

mod merge;
pub mod records;
pub mod store;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vta_sdk::protocols::app_state::{AppStateListResponse, AppStateWrite, WriteOutcome};

pub use records::{RecordKind, SyncParts, SyncView};
pub use store::{AppStateStore, DeleteOutcome, SyncError};

/// The app-state namespace OpenVTC writes under.
pub const NAMESPACE: &str = "openvtc";

/// The record envelope version this build writes and understands. A record
/// from a newer build is held, untouched, until a build that understands it
/// runs.
pub const RECORD_SCHEMA_VERSION: u64 = 1;

/// The most change-feed pages one sync reads. A bound, not an expectation —
/// an account needs a handful — so a VTA that keeps answering `truncated`
/// cannot keep the sync looping (R1.4).
const MAX_PAGES: usize = 500;

/// Push-and-merge rounds at load. One is the normal case; a second only when
/// a push lost a race. Bounded so two devices fighting cannot stall a launch.
const LOAD_ROUNDS: usize = 3;

/// The last version of a record this device and the VTA agreed on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaseRecord {
    /// The record's version at the VTA.
    pub version: u64,
    /// Its value (the envelope's `data`).
    pub value: Value,
}

/// A record as the VTA holds it: a change to apply.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteRecord {
    /// The record key.
    pub key: String,
    /// Its version.
    pub version: u64,
    /// Whether it is a tombstone.
    #[serde(default)]
    pub deleted: bool,
    /// The stored envelope; `None` for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// Sync bookkeeping, persisted in the protected tier.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncState {
    /// The context these records live in. A different context — a recovered
    /// or re-provisioned account — starts the bookkeeping afresh.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub context_id: String,
    /// The change-feed position this device has applied through.
    #[serde(default)]
    pub watermark: u64,
    /// Per record, the last version this device agreed with the VTA on.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub base: BTreeMap<String, BaseRecord>,
    /// Changes pulled but not yet applied: kinds a running session cannot take
    /// in, records from a newer build, and values this build could not read.
    /// Retried at every launch.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deferred: BTreeMap<String, RemoteRecord>,
    /// Records the VTA refused as too large, by the digest of the value it
    /// refused, so the same value is not offered again on every sync.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rejected: BTreeMap<String, String>,
    /// What the load-time sync did, for the runtime to report. Not saved.
    #[serde(skip)]
    pub load_report: Option<SyncReport>,
}

impl SyncState {
    /// Nothing recorded — keeps an unsynced config byte-identical on save.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.context_id.is_empty()
            && self.watermark == 0
            && self.base.is_empty()
            && self.deferred.is_empty()
            && self.rejected.is_empty()
    }

    /// Start afresh if these records belong to another context.
    pub fn bind_context(&mut self, context_id: &str) {
        if self.context_id != context_id {
            *self = SyncState {
                context_id: context_id.to_string(),
                load_report: self.load_report.take(),
                ..SyncState::default()
            };
        }
    }
}

/// What a sync did.
#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    /// Changes from another device applied here.
    pub pulled: usize,
    /// Records written to the VTA.
    pub pushed: usize,
    /// Records deleted at the VTA.
    pub removed: usize,
    /// Fields both sides changed; each took the VTA's value.
    pub conflicts: Vec<String>,
    /// Changes held for the next launch.
    pub deferred: usize,
    /// Records the VTA would not store, and why.
    pub rejected: Vec<String>,
    /// Records this build could not read.
    pub unreadable: Vec<String>,
    /// The kinds of local state a pulled change altered.
    pub changed: BTreeSet<RecordKind>,
    /// Why the sync stopped short, if it did.
    pub error: Option<SyncError>,
    /// Whether the sync bookkeeping moved (a version learned, the watermark
    /// advanced) even if no local state did.
    pub bookkeeping: bool,
    /// Witnessings rebuilt from the VTA's own list (`vta/witness/list`): the VTA
    /// stored the VWC, and this device never kept the record
    /// ([`crate::witness::reconcile`]).
    pub recovered_witnessings: usize,
}

impl SyncReport {
    /// Whether anything in the config changed — local state or the sync
    /// bookkeeping — so the caller knows to save.
    #[must_use]
    pub fn touched(&self) -> bool {
        self.pulled > 0
            || self.pushed > 0
            || self.removed > 0
            || self.deferred > 0
            || self.bookkeeping
            || self.recovered_witnessings > 0
    }

    /// Activity-log lines worth showing. Empty for a quiet sync.
    #[must_use]
    pub fn log_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.pulled > 0 {
            lines.push(format!(
                "Applied {} change(s) made on another device",
                self.pulled
            ));
        }
        if self.recovered_witnessings > 0 {
            lines.push(format!(
                "Recovered {} witnessing(s) your VTA holds that this device had not kept",
                self.recovered_witnessings
            ));
        }
        for c in &self.conflicts {
            lines.push(format!(
                "Changed on this device and another at once: {c} — kept the other device's value"
            ));
        }
        if self.deferred > 0 {
            lines.push(format!(
                "{} change(s) from another device will apply when OpenVTC next starts",
                self.deferred
            ));
        }
        for r in &self.rejected {
            lines.push(format!("Not synced to the VTA: {r}"));
        }
        for u in &self.unreadable {
            lines.push(format!(
                "Could not read a synced record ({u}); kept for a newer build"
            ));
        }
        if let Some(e) = &self.error {
            lines.push(e.explain());
        }
        lines
    }
}

/// How a pulled change may be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// Before the session is built: everything applies.
    Load,
    /// Into a running session: only [`RecordKind::applies_live`] kinds.
    Live,
}

/// What a sync will write.
#[derive(Clone, Debug, Default)]
pub struct Outgoing {
    /// `(key, value, expected_version)`; `0` means "create only".
    pub puts: Vec<(String, Value, u64)>,
    /// `(key, expected_version)`.
    pub deletes: Vec<(String, u64)>,
}

impl Outgoing {
    /// Nothing to write.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.deletes.is_empty()
    }
}

/// What the network half of a sync came back with.
#[derive(Debug, Default)]
pub struct Exchange {
    /// Changes pulled, in feed order.
    pulled: Vec<RemoteRecord>,
    /// The watermark to adopt once `pulled` is applied; `None` if the pull did
    /// not complete.
    watermark: Option<u64>,
    /// Set when the pull was a snapshot: every live key, so a base record
    /// missing from it is known to be deleted.
    snapshot_keys: Option<BTreeSet<String>>,
    /// Push outcomes: `(key, value pushed, result)`.
    puts: Vec<(String, Value, vta_sdk::protocols::app_state::WriteResult)>,
    /// Delete outcomes.
    deletes: Vec<(String, DeleteOutcome)>,
    /// Why it stopped short.
    error: Option<SyncError>,
}

fn envelope(data: &Value) -> Value {
    json!({ "schemaVersion": RECORD_SCHEMA_VERSION, "data": data })
}

enum Opened {
    Data(Value),
    Newer(u64),
    Malformed,
}

fn open(envelope: Option<&Value>) -> Opened {
    let Some(env) = envelope else {
        return Opened::Malformed;
    };
    let version = env
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if version > RECORD_SCHEMA_VERSION {
        return Opened::Newer(version);
    }
    match env.get("data") {
        Some(d) if version >= 1 => Opened::Data(d.clone()),
        _ => Opened::Malformed,
    }
}

fn digest(v: &Value) -> String {
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}

/// Every record whose local value differs from what the VTA last agreed to.
#[must_use]
pub fn outgoing(view: &SyncView<'_>, state: &SyncState) -> Outgoing {
    let local = records::project(view);
    let mut out = Outgoing::default();
    for (key, value) in &local {
        if state.deferred.contains_key(key) {
            continue;
        }
        let base = state.base.get(key);
        if base.is_some_and(|b| &b.value == value) {
            continue;
        }
        if state.rejected.get(key) == Some(&digest(value)) {
            continue;
        }
        out.puts
            .push((key.clone(), value.clone(), base.map_or(0, |b| b.version)));
    }
    for (key, base) in &state.base {
        if !local.contains_key(key) && !state.deferred.contains_key(key) {
            out.deletes.push((key.clone(), base.version));
        }
    }
    out
}

fn remote(r: vta_sdk::protocols::app_state::AppStateRecord) -> RemoteRecord {
    RemoteRecord {
        key: r.key,
        version: r.version,
        deleted: r.deleted,
        value: r.value,
    }
}

/// Read the whole feed (or snapshot) after `since`.
async fn pull<S: AppStateStore>(store: &S, context_id: &str, since: u64, ex: &mut Exchange) {
    let mut snapshot = false;
    let mut cursor: Option<String> = None;
    let mut first_watermark: Option<u64> = None;
    let mut keys = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let page: Result<AppStateListResponse, SyncError> = if snapshot {
            store.snapshot(context_id, cursor.as_deref()).await
        } else {
            store
                .changes_since(context_id, since, cursor.as_deref())
                .await
        };
        let page = match page {
            Ok(p) => p,
            Err(SyncError::WatermarkTooOld) if !snapshot => {
                // Deletions we never saw have been reaped. Start over from a
                // snapshot, which lists every live record; a base record
                // missing from it was deleted.
                snapshot = true;
                cursor = None;
                first_watermark = None;
                ex.pulled.clear();
                continue;
            }
            Err(e) => {
                ex.error = Some(e);
                return;
            }
        };
        // The counter is read before the scan, so the first page's value can
        // only be at or below everything listed: adopting it re-delivers at
        // worst, and a re-delivered change is skipped by version.
        if first_watermark.is_none() {
            first_watermark = Some(page.high_watermark.unwrap_or(since));
        }
        for r in page.records {
            if snapshot {
                keys.insert(r.key.clone());
            }
            ex.pulled.push(remote(r));
        }
        match (page.truncated, page.cursor) {
            (true, Some(c)) => cursor = Some(c),
            _ => {
                ex.watermark = first_watermark;
                if snapshot {
                    ex.snapshot_keys = Some(keys);
                }
                return;
            }
        }
    }
    ex.error = Some(SyncError::Contract(format!(
        "the change feed did not end within {MAX_PAGES} pages"
    )));
}

/// The network half of a sync: pull, then push `out`. Runs without the
/// config, so it can be spawned off the runtime loop.
pub async fn exchange<S: AppStateStore>(
    store: &S,
    context_id: &str,
    since: u64,
    out: Outgoing,
) -> Exchange {
    let mut ex = Exchange::default();
    pull(store, context_id, since, &mut ex).await;
    if ex.error.is_some() {
        return ex;
    }
    for batch in out.puts.chunks(store::PUT_BATCH) {
        let writes = batch
            .iter()
            .map(|(key, value, expected)| {
                let mut w = AppStateWrite::new(key.clone());
                w.value = Some(envelope(value));
                w.expected_version = Some(*expected);
                w
            })
            .collect();
        match store.put_many(context_id, writes).await {
            Ok(results) => {
                for result in results {
                    if let Some((_, value, _)) = batch.iter().find(|(k, _, _)| *k == result.key) {
                        ex.puts.push((result.key.clone(), value.clone(), result));
                    }
                }
            }
            Err(e) => {
                ex.error = Some(e);
                return ex;
            }
        }
    }
    for (key, expected) in out.deletes {
        match store.delete(context_id, &key, expected).await {
            Ok(outcome) => ex.deletes.push((key, outcome)),
            Err(e) => {
                ex.error = Some(e);
                return ex;
            }
        }
    }
    ex
}

/// Write one new record straight to the VTA, create-only, ahead of the local save that will
/// also hold it (R2.1): for state the VTA has just committed elsewhere — a witnessing, whose VWC
/// is already in the vault — so a crash before the save does not leave it unlisted. The next
/// sync learns the record's version (its create-only push conflicts with this write and merges
/// as identical), and a device that never saved it pulls it.
///
/// # Errors
///
/// The store's, unchanged. The caller logs it: the local save and the next sync still carry the
/// record.
pub async fn put_new<S: AppStateStore>(
    store: &S,
    context_id: &str,
    key: &str,
    value: &Value,
) -> Result<WriteOutcome, SyncError> {
    let mut w = AppStateWrite::new(key.to_string());
    w.value = Some(envelope(value));
    w.expected_version = Some(0);
    let results = store.put_many(context_id, vec![w]).await?;
    results
        .into_iter()
        .find(|r| r.key == key)
        .map(|r| r.outcome)
        .ok_or_else(|| SyncError::Contract(format!("no result for `{key}`")))
}

/// Merge pulled changes into the config.
pub fn apply_remote(
    parts: &mut SyncParts<'_>,
    state: &mut SyncState,
    mut incoming: Vec<RemoteRecord>,
    mode: ApplyMode,
    report: &mut SyncReport,
) {
    // Latest version of each key only; the feed may carry several.
    incoming.sort_by_key(|r| r.version);
    let mut latest: BTreeMap<String, RemoteRecord> = BTreeMap::new();
    for r in incoming {
        latest.insert(r.key.clone(), r);
    }
    let local = records::project(&parts.view());

    for (key, rec) in latest {
        if state
            .base
            .get(&key)
            .is_some_and(|b| rec.version <= b.version)
        {
            continue;
        }
        let Some(kind) = RecordKind::of_key(&key) else {
            // A newer build's kind. Not ours to interpret, and nothing here
            // would push it back, so it is simply left at the VTA.
            continue;
        };
        let remote_data = if rec.deleted {
            None
        } else {
            match open(rec.value.as_ref()) {
                Opened::Data(d) => Some(d),
                Opened::Newer(v) => {
                    report
                        .unreadable
                        .push(format!("a {} written in format {v}", kind.noun()));
                    state.deferred.insert(key.clone(), rec);
                    continue;
                }
                Opened::Malformed => {
                    report
                        .unreadable
                        .push(format!("a malformed {}", kind.noun()));
                    state.deferred.insert(key.clone(), rec);
                    continue;
                }
            }
        };
        if mode == ApplyMode::Live && !applies_live(kind, remote_data.as_ref(), parts) {
            if state.deferred.insert(key.clone(), rec).is_none() {
                report.deferred += 1;
            }
            continue;
        }

        let mut conflicts = Vec::new();
        let base = state.base.get(&key).map(|b| &b.value);
        let here = local.get(&key);
        let merged = merge::merge3(base, here, remote_data.as_ref(), "", &mut conflicts);
        if merged.as_ref() != here {
            if let Err(e) = records::apply(parts, &key, merged.as_ref()) {
                report.unreadable.push(format!("a {}: {e}", kind.noun()));
                state.deferred.insert(key.clone(), rec);
                continue;
            }
            report.changed.insert(kind);
            report.pulled += 1;
        }
        if !conflicts.is_empty() {
            report
                .conflicts
                .push(format!("a {} ({})", kind.noun(), conflicts.join(", ")));
        }
        state.deferred.remove(&key);
        match remote_data {
            Some(value) => {
                state.base.insert(
                    key,
                    BaseRecord {
                        version: rec.version,
                        value,
                    },
                );
            }
            None => {
                state.base.remove(&key);
            }
        }
    }
}

/// Whether a pulled change of `kind` can go into a running session. A
/// membership can, unless it presents a persona this session has not loaded.
fn applies_live(kind: RecordKind, data: Option<&Value>, parts: &SyncParts<'_>) -> bool {
    if !kind.applies_live() {
        return false;
    }
    if kind == RecordKind::Membership
        && let Some(persona) = data.and_then(|d| d.get("persona_ref"))
    {
        return parts
            .account
            .personas
            .keys()
            .any(|id| serde_json::to_value(id).ok().as_ref() == Some(persona));
    }
    true
}

/// Fold an [`Exchange`] back into the config: apply what was pulled, adopt the
/// watermark, and record what the push did. Returns whether a push lost a race
/// (another round would push the merged value).
pub fn absorb(
    parts: &mut SyncParts<'_>,
    state: &mut SyncState,
    ex: Exchange,
    mode: ApplyMode,
    report: &mut SyncReport,
) -> bool {
    let mut pulled = ex.pulled;
    if let (Some(keys), Some(watermark)) = (&ex.snapshot_keys, ex.watermark) {
        for key in state.base.keys() {
            if !keys.contains(key) {
                pulled.push(RemoteRecord {
                    key: key.clone(),
                    version: watermark,
                    deleted: true,
                    value: None,
                });
            }
        }
    }
    if !pulled.is_empty() || !ex.puts.is_empty() || !ex.deletes.is_empty() {
        report.bookkeeping = true;
    }
    apply_remote(parts, state, pulled, mode, report);
    if let Some(w) = ex.watermark
        && w != state.watermark
    {
        state.watermark = w;
        report.bookkeeping = true;
    }

    let mut lost_race = false;
    let mut raced = Vec::new();
    for (key, value, result) in ex.puts {
        match result.outcome {
            WriteOutcome::Written => {
                state.rejected.remove(&key);
                if let Some(version) = result.version {
                    state.base.insert(key, BaseRecord { version, value });
                    report.pushed += 1;
                }
            }
            WriteOutcome::Conflict => {
                lost_race = true;
                raced.push(RemoteRecord {
                    key,
                    version: result.current_version.unwrap_or(0),
                    deleted: result.current_deleted.unwrap_or(false),
                    value: result.current_value,
                });
            }
            WriteOutcome::TooLarge => {
                let kind = RecordKind::of_key(&key).map_or("record", RecordKind::noun);
                report.rejected.push(format!(
                    "a {kind} is {} bytes, over this VTA's {}-byte limit",
                    result.actual_bytes.unwrap_or(0),
                    result.limit_bytes.unwrap_or(0)
                ));
                state.rejected.insert(key, digest(&value));
            }
            WriteOutcome::NotFound | WriteOutcome::Skipped => {}
        }
    }
    // A lost race carries the winner's value: merge it now, so the next push
    // sends the merged record against the winner's version.
    apply_remote(parts, state, raced, mode, report);

    for (key, outcome) in ex.deletes {
        match outcome {
            DeleteOutcome::Deleted => {
                state.base.remove(&key);
                report.removed += 1;
            }
            // Edited elsewhere since we last saw it; the next pull brings the
            // edit, and an edit outranks a deletion it raced.
            DeleteOutcome::Conflict => lost_race = true,
        }
    }

    if let Some(e) = ex.error {
        report.error = Some(e);
    }
    lost_race
}

/// The whole sync, as run at load: apply what earlier runs deferred, then
/// pull, merge and push until the VTA and this device agree (or the round
/// bound is reached). Never fails the load — the outcome is in the report.
pub async fn sync_at_load<S: AppStateStore>(
    store: &S,
    parts: &mut SyncParts<'_>,
    state: &mut SyncState,
    context_id: &str,
) -> SyncReport {
    let mut report = SyncReport::default();
    if context_id.is_empty() {
        return report;
    }
    state.bind_context(context_id);

    let deferred: Vec<RemoteRecord> = std::mem::take(&mut state.deferred).into_values().collect();
    if !deferred.is_empty() {
        report.bookkeeping = true;
    }
    apply_remote(parts, state, deferred, ApplyMode::Load, &mut report);

    for _ in 0..LOAD_ROUNDS {
        let out = outgoing(&parts.view(), state);
        let ex = exchange(store, context_id, state.watermark, out).await;
        let lost_race = absorb(parts, state, ex, ApplyMode::Load, &mut report);
        if report.error.is_some() || !lost_race {
            break;
        }
    }
    report
}

#[cfg(test)]
mod tests;
