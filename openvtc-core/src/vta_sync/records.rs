//! The account model as app-state records, and back.
//!
//! [`project`] turns the synced parts of the config into one JSON value per
//! record key; [`apply`] writes one record's value (or its deletion) back into
//! the config. Everything in between — diffing, merging, versioning — happens
//! on that JSON, so the engine never needs to know what a membership is.
//!
//! **One key per record, never one blob (D8a).** A blob grows without bound
//! against the VTA's per-record cap, and last-write-wins on a blob loses
//! unrelated edits. Keys hash their identifiers so a DID or a credential id
//! can never produce an over-long or ambiguous key; the value carries the
//! identifier itself.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::agent_name::CachedAgentName;
use crate::config::account::{Account, CommunityRecord, PersonaRecord};
use crate::config::protected_config::{Contact, ProtectedConfig};
use crate::config::secured_config::{KeyInfoConfig, KeySourceMaterial};
use crate::relationships::Relationship;
use crate::vetting::VettingBook;
use crate::vrc::Vrcs;
use crate::witness::WitnessRecord;

/// What a record holds. The key prefix names it, so a record from a newer
/// build with a kind this one does not know is recognisable as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordKind {
    /// An account persona ([`PersonaRecord`]).
    Persona,
    /// A community membership ([`CommunityRecord`]), with its flags.
    Membership,
    /// A DIDComm pairwise relationship.
    Relationship,
    /// A contact.
    Contact,
    /// A verified agent name. Only positive lookups are synced: a negative is
    /// a note about this run's network, and is pruned at every launch anyway.
    AgentName,
    /// One row of the durable TSP relationship store.
    Tsp,
    /// A relationship credential we issued.
    VrcIssued,
    /// A relationship credential we received.
    VrcReceived,
    /// A reference to a VTA-managed key. Only the VTA key id travels — a key
    /// whose material is held locally is never synced.
    Key,
    /// Vetting state, minus the hidden-vetting engine, which carries secrets.
    Vetting,
    /// A completed witnessing ([`WitnessRecord`]): the VWC's vault handle and the outcome
    /// evidence a personhood assertion presents beside it.
    Witnessing,
}

impl RecordKind {
    /// Every kind, for iteration.
    pub const ALL: [RecordKind; 11] = [
        RecordKind::Persona,
        RecordKind::Membership,
        RecordKind::Relationship,
        RecordKind::Contact,
        RecordKind::AgentName,
        RecordKind::Tsp,
        RecordKind::VrcIssued,
        RecordKind::VrcReceived,
        RecordKind::Key,
        RecordKind::Vetting,
        RecordKind::Witnessing,
    ];

    fn prefix(self) -> &'static str {
        match self {
            RecordKind::Persona => "v1/persona/",
            RecordKind::Membership => "v1/membership/",
            RecordKind::Relationship => "v1/relationship/",
            RecordKind::Contact => "v1/contact/",
            RecordKind::AgentName => "v1/agent-name/",
            RecordKind::Tsp => "v1/tsp/",
            RecordKind::VrcIssued => "v1/vrc-issued/",
            RecordKind::VrcReceived => "v1/vrc-received/",
            RecordKind::Key => "v1/key/",
            RecordKind::Vetting => "v1/vetting",
            RecordKind::Witnessing => "v1/witnessing/",
        }
    }

    /// The kind a record key names, or `None` for a kind this build does not
    /// know (a newer build's record, which is left alone).
    #[must_use]
    pub fn of_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| key.starts_with(k.prefix()))
    }

    /// Whether a change of this kind can be applied to a running session.
    ///
    /// The rest are hydrated at load — a persona needs its keys fetched and a
    /// messaging profile registered, a relationship needs its profile, the TSP
    /// store is owned by the live messaging layer, and vetting holds in-flight
    /// protocol state beside what it persists. Changing those under a running
    /// session would leave the config describing something the runtime does
    /// not have, so they wait for the next launch.
    #[must_use]
    pub fn applies_live(self) -> bool {
        matches!(
            self,
            RecordKind::Membership
                | RecordKind::Contact
                | RecordKind::AgentName
                | RecordKind::VrcIssued
                | RecordKind::VrcReceived
                | RecordKind::Witnessing
        )
    }

    /// A short human name, for the activity log.
    #[must_use]
    pub fn noun(self) -> &'static str {
        match self {
            RecordKind::Persona => "persona",
            RecordKind::Membership => "community membership",
            RecordKind::Relationship => "relationship",
            RecordKind::Contact => "contact",
            RecordKind::AgentName => "agent name",
            RecordKind::Tsp => "TSP relationship",
            RecordKind::VrcIssued | RecordKind::VrcReceived => "relationship credential",
            RecordKind::Key => "key reference",
            RecordKind::Vetting => "vetting state",
            RecordKind::Witnessing => "witnessing",
        }
    }
}

/// A stable, fixed-length key segment for an identifier.
fn h(id: &str) -> String {
    hex::encode(&Sha256::digest(id.as_bytes())[..16])
}

fn persona_key(p: &PersonaRecord) -> String {
    format!("{}{}", RecordKind::Persona.prefix(), p.persona_id)
}

fn membership_key(c: &CommunityRecord) -> String {
    format!(
        "{}{}/{}",
        RecordKind::Membership.prefix(),
        h(&c.vtc_did),
        c.persona_ref
    )
}

fn simple_key(kind: RecordKind, id: &str) -> String {
    format!("{}{}", kind.prefix(), h(id))
}

/// A witnessing's key, by its session id — what a personhood assertion selects it by.
fn witnessing_key(r: &WitnessRecord) -> String {
    simple_key(RecordKind::Witnessing, &r.witnessed.session_id)
}

/// A witnessing as the record it syncs as: `(key, value)`. The value is the local record whole,
/// evidence included — as a VRC record carries its credential — because the VTA's vault keeps
/// that evidence where no client task can read it back.
#[must_use]
pub fn witnessing_record(r: &WitnessRecord) -> Option<(String, Value)> {
    Some((witnessing_key(r), to_json(r)?))
}

fn vrc_key(kind: RecordKind, remote: &str, id: &str) -> String {
    format!("{}{}/{}", kind.prefix(), h(remote), h(id))
}

/// The synced parts of a config, borrowed.
///
/// `account` is separate from `private` because at runtime the live account is
/// [`crate::config::Config::account`], and the copy in the protected tier is
/// only refreshed on save.
pub struct SyncView<'a> {
    /// The live account.
    pub account: &'a Account,
    /// The protected tier.
    pub private: &'a ProtectedConfig,
    /// Key references (the secured tier's `key_info`).
    pub key_info: &'a HashMap<String, KeyInfoConfig>,
}

/// The synced parts of a config, mutably — what [`apply`] writes into.
pub struct SyncParts<'a> {
    /// The live account.
    pub account: &'a mut Account,
    /// The protected tier.
    pub private: &'a mut ProtectedConfig,
    /// Key references (the secured tier's `key_info`).
    pub key_info: &'a mut HashMap<String, KeyInfoConfig>,
}

impl SyncParts<'_> {
    /// A read-only view of the same parts.
    #[must_use]
    pub fn view(&self) -> SyncView<'_> {
        SyncView {
            account: self.account,
            private: self.private,
            key_info: self.key_info,
        }
    }
}

/// Serialize, or `None` if a value will not serialize (which none of these
/// types fail at; an `Option` keeps a surprise from taking the sync down).
fn to_json<T: serde::Serialize>(v: &T) -> Option<Value> {
    serde_json::to_value(v).ok()
}

/// The vetting book as synced: everything it persists except this install's
/// view of its hidden-vetting engines and the work it owes them — the
/// vetter's schedules (`hidden_vetter`), each application's engine summary
/// (`hidden_app`), and the answers queued for the VTA (`pcs_inbox`). The
/// engines are the VTA's and carry no secret here, but each install drives
/// them on its own schedule. `hidden_state` — a PCS `usk`, from builds that
/// ran the engine locally — is stripped too, should a record carry one: app
/// state is not for secrets.
fn vetting_json(book: &VettingBook) -> Option<Value> {
    let mut v = to_json(book)?;
    if let Value::Object(map) = &mut v {
        map.remove("hidden_vetter");
        map.remove("pcs_inbox");
        if let Some(Value::Array(applications)) = map.get_mut("applications") {
            for application in applications {
                if let Value::Object(application) = application {
                    application.remove("hidden_app");
                    application.remove("hidden_state");
                }
            }
        }
        if map.is_empty() {
            return None;
        }
    }
    Some(v)
}

fn vrc_records(kind: RecordKind, vrcs: &Vrcs, out: &mut BTreeMap<String, Value>) {
    for (remote, by_id) in vrcs.keys().zip(vrcs.values()) {
        for (id, vrc) in by_id {
            if let Some(credential) = to_json(vrc.as_ref()) {
                out.insert(
                    vrc_key(kind, remote, id),
                    json!({ "remote": remote.as_str(), "id": id.as_str(), "credential": credential }),
                );
            }
        }
    }
}

/// Every synced record of `view`, keyed by record key.
#[must_use]
pub fn project(view: &SyncView<'_>) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();

    for p in view.account.personas.values() {
        if let Some(v) = to_json(p) {
            out.insert(persona_key(p), v);
        }
    }
    for c in view.account.memberships() {
        if let Some(v) = to_json(c) {
            out.insert(membership_key(c), v);
        }
    }
    for (p_did, r) in &view.private.relationships.relationships {
        if let Some(r) = to_json(r) {
            out.insert(
                simple_key(RecordKind::Relationship, p_did),
                json!({ "pDid": p_did.as_str(), "relationship": r }),
            );
        }
    }
    for c in view.private.contacts.contacts.values() {
        if let Some(v) = to_json(c.as_ref()) {
            out.insert(simple_key(RecordKind::Contact, &c.did), v);
        }
    }
    for (did, entry) in &view.private.agent_names {
        if entry.name.is_some()
            && let Some(e) = to_json(entry)
        {
            out.insert(
                simple_key(RecordKind::AgentName, did),
                json!({ "did": did, "entry": e }),
            );
        }
    }
    for (k, v) in view.private.tsp_relationships.entries() {
        out.insert(
            simple_key(RecordKind::Tsp, k),
            json!({ "key": k, "value": v }),
        );
    }
    vrc_records(RecordKind::VrcIssued, &view.private.vrcs_issued, &mut out);
    vrc_records(
        RecordKind::VrcReceived,
        &view.private.vrcs_received,
        &mut out,
    );
    for (name, info) in view.key_info {
        if matches!(info.path, KeySourceMaterial::VtaManaged { .. })
            && let Some(i) = to_json(info)
        {
            out.insert(
                simple_key(RecordKind::Key, name),
                json!({ "name": name, "info": i }),
            );
        }
    }
    if let Some(v) = vetting_json(&view.private.vetting) {
        out.insert(RecordKind::Vetting.prefix().to_string(), v);
    }
    for r in &view.private.witnessings.0 {
        if let Some((key, value)) = witnessing_record(r) {
            out.insert(key, value);
        }
    }
    out
}

fn str_field<'v>(v: &'v Value, field: &str) -> Result<&'v str, String> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing `{field}`"))
}

fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

/// Write one record into `parts`: `Some` inserts or replaces it, `None`
/// removes whatever local item the key names.
///
/// # Errors
///
/// A value that does not decode as its kind. Nothing is changed in that case.
pub fn apply(parts: &mut SyncParts<'_>, key: &str, value: Option<&Value>) -> Result<(), String> {
    let Some(kind) = RecordKind::of_key(key) else {
        return Err("unknown record kind".to_string());
    };
    match kind {
        RecordKind::Persona => match value {
            Some(v) => {
                let p: PersonaRecord = decode(v)?;
                if persona_key(&p) != key {
                    return Err("persona id does not match its key".to_string());
                }
                parts.account.personas.insert(p.persona_id, p);
            }
            None => parts.account.personas.retain(|_, p| persona_key(p) != key),
        },
        RecordKind::Membership => {
            let incoming: Option<CommunityRecord> = value.map(decode).transpose()?;
            if let Some(c) = &incoming
                && membership_key(c) != key
            {
                return Err("membership does not match its key".to_string());
            }
            for list in parts.account.communities.values_mut() {
                list.retain(|c| membership_key(c) != key);
            }
            if let Some(c) = incoming {
                parts
                    .account
                    .communities
                    .entry(c.vtc_did.clone())
                    .or_default()
                    .push(c);
            }
            parts.account.communities.retain(|_, list| !list.is_empty());
        }
        RecordKind::Relationship => match value {
            Some(v) => {
                let p_did = str_field(v, "pDid")?;
                if simple_key(kind, p_did) != key {
                    return Err("relationship does not match its key".to_string());
                }
                let r: Relationship = decode(v.get("relationship").unwrap_or(&Value::Null))?;
                parts
                    .private
                    .relationships
                    .relationships
                    .insert(Arc::new(p_did.to_string()), r);
            }
            None => parts
                .private
                .relationships
                .relationships
                .retain(|p_did, _| simple_key(kind, p_did) != key),
        },
        RecordKind::Contact => {
            let incoming: Option<Contact> = value.map(decode).transpose()?;
            if let Some(c) = &incoming
                && simple_key(kind, &c.did) != key
            {
                return Err("contact does not match its key".to_string());
            }
            let contacts = &mut parts.private.contacts;
            contacts
                .contacts
                .retain(|did, _| simple_key(kind, did) != key);
            if let Some(c) = incoming {
                contacts.contacts.insert(c.did.clone(), Arc::new(c));
            }
            contacts.aliases = contacts
                .contacts
                .values()
                .filter_map(|c| c.alias.clone().map(|a| (a, c.clone())))
                .collect();
        }
        RecordKind::AgentName => match value {
            Some(v) => {
                let did = str_field(v, "did")?;
                if simple_key(kind, did) != key {
                    return Err("agent name does not match its key".to_string());
                }
                let entry: CachedAgentName = decode(v.get("entry").unwrap_or(&Value::Null))?;
                parts.private.agent_names.insert(did.to_string(), entry);
            }
            None => parts
                .private
                .agent_names
                .retain(|did, e| e.name.is_none() || simple_key(kind, did) != key),
        },
        RecordKind::Tsp => match value {
            Some(v) => {
                let k = str_field(v, "key")?;
                if simple_key(kind, k) != key {
                    return Err("TSP row does not match its key".to_string());
                }
                let row = str_field(v, "value")?;
                parts
                    .private
                    .tsp_relationships
                    .entries_mut()
                    .insert(k.to_string(), row.to_string());
            }
            None => parts
                .private
                .tsp_relationships
                .entries_mut()
                .retain(|k, _| simple_key(kind, k) != key),
        },
        RecordKind::VrcIssued | RecordKind::VrcReceived => {
            let vrcs = if kind == RecordKind::VrcIssued {
                &mut parts.private.vrcs_issued
            } else {
                &mut parts.private.vrcs_received
            };
            apply_vrc(vrcs, kind, key, value)?;
        }
        RecordKind::Key => match value {
            Some(v) => {
                let name = str_field(v, "name")?;
                if simple_key(kind, name) != key {
                    return Err("key reference does not match its key".to_string());
                }
                let info: KeyInfoConfig = decode(v.get("info").unwrap_or(&Value::Null))?;
                // Only a reference ever arrives this way. A record claiming to
                // carry key material is refused, never stored as a secret.
                if !matches!(info.path, KeySourceMaterial::VtaManaged { .. }) {
                    return Err("a synced key must be VTA-managed".to_string());
                }
                parts.key_info.insert(name.to_string(), info);
            }
            None => parts.key_info.retain(|name, info| {
                !matches!(info.path, KeySourceMaterial::VtaManaged { .. })
                    || simple_key(kind, name) != key
            }),
        },
        RecordKind::Vetting => {
            let mut book: VettingBook = match value {
                Some(v) => decode(v)?,
                None => VettingBook::default(),
            };
            // What this install drives its hidden-vetting engines with is not
            // synced; keep this install's. A local applicant engine that does
            // arrive — written by a build that synced one — was dropped on
            // decode, and says nothing about this install's application.
            let local = &mut parts.private.vetting;
            book.hidden_vetter = std::mem::take(&mut local.hidden_vetter);
            book.pcs_inbox = std::mem::take(&mut local.pcs_inbox);
            book.pcs_due = local.pcs_due;
            for application in &mut book.applications {
                let here = local
                    .applications
                    .iter_mut()
                    .find(|here| here.id == application.id);
                application.hidden_app = here.as_ref().and_then(|h| h.hidden_app.clone());
                application.local_engine_dropped = here.is_some_and(|h| h.local_engine_dropped);
            }
            parts.private.vetting = book;
        }
        RecordKind::Witnessing => {
            let incoming: Option<WitnessRecord> = value.map(decode).transpose()?;
            if let Some(r) = &incoming
                && witnessing_key(r) != key
            {
                return Err("witnessing does not match its key".to_string());
            }
            let list = &mut parts.private.witnessings.0;
            list.retain(|r| witnessing_key(r) != key);
            if let Some(r) = incoming {
                // Kept oldest first, which is how the relationships view lists them.
                let at = list.partition_point(|here| here.witnessed_at <= r.witnessed_at);
                list.insert(at, r);
            }
        }
    }
    Ok(())
}

/// Insert or remove one VRC. `Vrcs` keeps its map private and re-checks
/// conformance on decode, so the change goes through its JSON form — which is
/// also what keeps a non-conformant credential from slipping in this way.
fn apply_vrc(
    vrcs: &mut Vrcs,
    kind: RecordKind,
    key: &str,
    value: Option<&Value>,
) -> Result<(), String> {
    let mut whole = to_json(vrcs).ok_or("credentials will not serialize")?;
    let map = whole
        .as_object_mut()
        .and_then(|o| o.entry("vrcs").or_insert_with(|| json!({})).as_object_mut())
        .ok_or("unexpected credential store shape")?;
    for (remote, by_id) in map.iter_mut() {
        if let Some(by_id) = by_id.as_object_mut() {
            by_id.retain(|id, _| vrc_key(kind, remote, id) != key);
        }
    }
    if let Some(v) = value {
        let remote = str_field(v, "remote")?;
        let id = str_field(v, "id")?;
        if vrc_key(kind, remote, id) != key {
            return Err("credential does not match its key".to_string());
        }
        let credential = v.get("credential").cloned().unwrap_or(Value::Null);
        map.entry(remote.to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("unexpected credential store shape")?
            .insert(id.to_string(), credential);
    }
    map.retain(|_, by_id| by_id.as_object().is_none_or(|o| !o.is_empty()));
    *vrcs = decode(&whole)?;
    Ok(())
}
