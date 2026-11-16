//! Configuration information that needs to be protected
//!   but is not as critical as private key information which is stored in the OS Secure Store

use crate::operational::SeenDocuments;
use crate::witness::Witnessings;
use std::{collections::HashMap, sync::Arc};

use crate::{
    agent_name::CachedAgentName,
    config::account::Account,
    config::secured_config::{aead_open, open, seal},
    errors::OpenVTCError,
    logs::{LogFamily, Logs},
    relationships::Relationships,
    tasks::Tasks,
    tsp_store::TspRelationships,
    vetting::VettingBook,
    vrc::Vrcs,
    vta_sync::SyncState,
};
use affinidi_tdk::TDK;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

/// Current schema version of the encrypted [`ProtectedConfig`] payload.
/// Increment when the shape changes in a way `#[serde(default)]` can't absorb
/// (e.g. renaming/removing fields, or changing enum variants in nested types
/// like `CommunityStatus`/`RelationshipState`).
///
/// Bump-and-migrate pattern for the next editor:
/// 1. Increment this constant.
/// 2. In [`ProtectedConfig::load`], inspect the deserialized `schema_version`
///    (or pre-parse to `serde_json::Value` if the new shape can't deserialize
///    the old payload) and migrate older payloads forward instead of
///    resetting the user.
///
/// Payloads saved before this field existed deserialize as version 1 via the
/// serde default — v1 is the shape at the time the field was introduced.
pub const PROTECTED_SCHEMA_VERSION: u32 = 1;

/// Serde default for [`ProtectedConfig::schema_version`]: payloads written
/// before the field existed are the v1 shape. Deliberately a literal `1`
/// (not [`PROTECTED_SCHEMA_VERSION`]) so that bumping the constant doesn't
/// silently relabel old unversioned payloads as the new version.
fn default_protected_schema_version() -> u32 {
    1
}

/// An inbound message awaiting its off-loop check, kept across a restart
/// ([`ProtectedConfig::deferred_inbound`]).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeferredInbound {
    /// The sender the transport authenticated, which equalled the message's
    /// `from` (only such a message is kept). With the message id, the key.
    pub sender: String,
    /// The message as it arrived.
    pub message: affinidi_tdk::didcomm::Message,
    /// The transport it arrived on.
    pub transport: crate::didcomm::MessagingTransport,
}

/// A record for a single known Contact
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Contact {
    /// DID representing the contact
    pub did: Arc<String>,

    /// Optional alias for the DID
    pub alias: Option<String>,
}

// ****************************************************************************
// Contacts Collection
// ****************************************************************************

/// Contains all known contacts
/// Uses Reference Counters to avoid duplicating Contact instances
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(from = "ContactsShadow")]
pub struct Contacts {
    /// Contacts with key being DID
    pub contacts: HashMap<Arc<String>, Arc<Contact>>,

    /// Helps with finding a DID by it's alias
    #[serde(skip)]
    pub aliases: HashMap<String, Arc<Contact>>,
}
impl Contacts {
    /// True when no contacts are held.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Adds a new contact
    /// tdk: Trust Development Kit instance
    /// contact_did: DID of the contact to add
    /// alias: Optional alias for the contact
    /// check_did: Whether to check if the DID is valid
    pub async fn add_contact(
        &mut self,
        tdk: &TDK,
        contact_did: &str,
        alias: Option<String>,
        check_did: bool,
        logs: &mut Logs,
    ) -> Result<Arc<Contact>, OpenVTCError> {
        if check_did {
            match tdk.did_resolver().resolve(contact_did).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Couldn't resolve DID ({contact_did}). Reason: {e}");
                    return Err(OpenVTCError::Resolver(format!(
                        "Couldn't resolve DID ({}). Reason: {}",
                        contact_did, e
                    )));
                }
            }
        }

        let contact_did = Arc::new(contact_did.to_string());

        if let Some(alias) = &alias
            && self.aliases.contains_key(alias)
        {
            warn!("Duplicate alias ({alias}) detected! Existing alias must be removed first!");
            return Err(OpenVTCError::Contact(format!(
                "Duplicate alias ({alias}) detected! Existing alias must be removed first!"
            )));
        }

        let contact = Arc::new(Contact {
            did: contact_did.clone(),
            alias: alias.clone(),
        });

        self.contacts.insert(contact_did.clone(), contact.clone());

        if let Some(alias) = &alias {
            self.aliases.insert(alias.clone(), contact.clone());
        }

        logs.insert(
            LogFamily::Contact,
            format!(
                "Added contact ({}) alias({})",
                contact_did,
                alias.as_deref().unwrap_or("N/A")
            ),
        );

        Ok(contact)
    }

    /// Removes a contact (by DID or Alias)
    /// Returns Contact if contact was found and removed
    pub fn remove_contact(&mut self, logs: &mut Logs, id: &str) -> Option<Arc<Contact>> {
        if let Some(contact) = self.find_contact(id) {
            if let Some(alias) = &contact.alias {
                self.aliases.remove(alias);
            }

            let result = self.contacts.remove(&contact.did);

            if result.is_some() {
                logs.insert(
                    LogFamily::Contact,
                    format!(
                        "Removed contact ({}) alias({})",
                        contact.did,
                        contact.alias.as_deref().unwrap_or("N/A")
                    ),
                );
            }
            result
        } else {
            None
        }
    }

    /// Finds a contact by alias or DID
    /// will look for alias first, then DID
    pub fn find_contact(&self, id: &str) -> Option<Arc<Contact>> {
        if let Some(contact) = self.aliases.get(id) {
            Some(contact.clone())
        } else {
            #[allow(clippy::unnecessary_to_owned)] // Because using RC's
            self.contacts.get(&(id.to_string())).cloned()
        }
    }
}

/// Private Shadow struct to help with deserializing Contacts and recreating the aliases map
#[derive(Deserialize)]
struct ContactsShadow {
    contacts: HashMap<Arc<String>, Arc<Contact>>,
}

impl From<ContactsShadow> for Contacts {
    fn from(shadow: ContactsShadow) -> Self {
        let mut contacts = Contacts {
            contacts: shadow.contacts,
            aliases: HashMap::new(),
        };

        for contact in contacts.contacts.values() {
            if let Some(alias) = &contact.alias {
                contacts.aliases.insert(alias.clone(), contact.clone());
            }
        }

        contacts
    }
}

/// Primary structure used for storing protected [crate::config::Config] data that is sensitive but
/// not key data
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProtectedConfig {
    /// Internal schema version of this encrypted payload.
    /// See [`PROTECTED_SCHEMA_VERSION`] for the bump-and-migrate pattern.
    /// Defaults to 1 when absent — payloads saved before this field existed.
    #[serde(default = "default_protected_schema_version")]
    pub schema_version: u32,

    /// Config v2 multi-community account model (personas + communities).
    ///
    /// The encrypted source of truth for the account's personas and community
    /// memberships. Empty in v1 (singleton) configs; populated on the first v2
    /// save. `Config::load_step2` reads it back to rebuild the runtime
    /// [`crate::identity::IdentityContext`]s and drive DID resolution.
    #[serde(default)]
    pub account: Account,

    /// Known contacts and associated information
    pub contacts: Contacts,

    /// Relationships information
    #[serde(default)]
    pub relationships: Relationships,

    /// Durable TSP Rev 3 relationship state — the opaque store the SDK's
    /// `PersistentRelationshipStore` reads and writes, mirrored here so a peer's
    /// §7.2.2 relationship survives a restart instead of being silently re-formed
    /// (or its traffic dropped until it is). Deliberately **separate** from
    /// `relationships` above, which is the DIDComm pairwise model — a different
    /// keyspace and lifecycle. Skipped when empty so a config that has never
    /// spoken TSP round-trips byte-identically. See [`crate::tsp_store`].
    #[serde(default, skip_serializing_if = "TspRelationships::is_empty")]
    pub tsp_relationships: TspRelationships,

    /// Known Tasks
    #[serde(default)]
    pub tasks: Tasks,

    /// VRCs Issued
    /// key = remote P-DID
    pub vrcs_issued: Vrcs,

    /// VRCs received
    /// key = remote P-DID
    pub vrcs_received: Vrcs,

    /// Verified agent-name lookups, keyed by DID. Additive persisted cache so a
    /// DID's human-memorable name (`example.com/@alice`) shows at launch without
    /// a network round-trip; the background refresh re-verifies stale entries.
    /// One map covers every DID the UI shows (personas, communities,
    /// relationships, contacts). `#[serde(default)]` keeps older configs loading
    /// without a schema bump. Keyed by a plain `String` DID — unlike the
    /// contact/relationship maps, these keys are not shared with any object, so
    /// there is nothing to `Arc`. See [`crate::agent_name`].
    #[serde(default)]
    pub agent_names: HashMap<String, CachedAgentName>,

    /// DIDs whose cached name in [`Self::agent_names`] arrived through VTA
    /// state sync and has not yet been verified on this device. Such a name is
    /// not displayed (see [`Self::cached_agent_name`]) until the background
    /// sweep has done the full round-trip here; the sweep's write clears the
    /// mark. Local only — not projected into a sync record — so the synced
    /// entry itself stays byte-identical and is not pushed back.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub agent_names_unverified: std::collections::BTreeSet<String>,

    /// Peer identity vetting: our applications, and our desk as a vetter
    /// ([`crate::vetting`]). Skipped when empty, so a config that has never
    /// vetted round-trips byte-identically.
    #[serde(default, skip_serializing_if = "VettingBook::is_empty")]
    pub vetting: VettingBook,

    /// Ids of operational documents already acted on (removal notices,
    /// community answers), each kept until its freshness window has passed, so
    /// a replayed document is refused across restarts too
    /// ([`crate::operational`]).
    #[serde(default, skip_serializing_if = "SeenDocuments::is_empty")]
    pub seen_documents: SeenDocuments,

    /// Inbound messages from communities we belong to that were set aside for
    /// an off-loop check and not yet applied. The mediator deleted them on
    /// delivery, so without this a removal notice or credential still queued
    /// at exit would be lost; they are queued again on the next start, and
    /// removed once applied. Only a message whose transport-authenticated
    /// sender is a community we belong to is kept, at most
    /// `MAX_KEPT_DEFERRED` of them.
    ///
    /// After a long downtime a kept message is still checked as of the
    /// restart: an operational document past its freshness window (a day for
    /// an answer, thirty-one for a removal notice) or a credential past its
    /// validity is refused then, exactly as if it had just arrived that late.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred_inbound: Vec<DeferredInbound>,

    /// What this device last agreed with the VTA's application-state store on,
    /// and changes pulled from it that wait for the next launch
    /// ([`crate::vta_sync`]). Skipped when empty, so a config that has never
    /// synced round-trips byte-identically.
    #[serde(default, skip_serializing_if = "SyncState::is_empty")]
    pub vta_sync: SyncState,

    /// Witnessings this account completed through its VTA — the VWC's vault handle, the
    /// witness, and the session's outcome evidence a community needs beside the VWC
    /// ([`crate::witness`]). Skipped when empty, so a config that has never witnessed
    /// round-trips byte-identically.
    #[serde(default, skip_serializing_if = "Witnessings::is_empty")]
    pub witnessings: Witnessings,

    /// The activity log (contacts added, relationships formed, credentials
    /// accepted, community lifecycle). Encrypted here because its entries
    /// name the DIDs and aliases this tier exists to hide (#568). Configs
    /// written before this field kept it in the plaintext `PublicConfig`;
    /// `Config::load_step2` moves those entries in.
    #[serde(default)]
    pub logs: Logs,

    /// Fields written by a newer build, preserved verbatim (D19).
    ///
    /// The protected tier is where the account lives, so an older build
    /// round-tripping this blob is the highest-stakes instance of the problem:
    /// without the catch-all it would read the config, drop everything it does
    /// not recognise, and write it back stripped.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ProtectedConfig {
    /// The verified agent name cached for `did`, if one is known.
    ///
    /// `Some` only for a positive lookup; a cached *negative* (the DID has no
    /// verifiable name) reads as `None`, same as an uncached DID. That
    /// collapsing is the point — a caller rendering a label must not be able to
    /// tell the two apart and accidentally show something unverified.
    ///
    /// [`Config::agent_name_for`](crate::config::Config::agent_name_for)
    /// delegates here so the rule has one definition; the config-loading path
    /// needs it before a `Config` exists.
    #[must_use]
    pub fn cached_agent_name(&self, did: &str) -> Option<&str> {
        if self.agent_names_unverified.contains(did) {
            return None;
        }
        self.agent_names.get(did).and_then(|c| c.name.as_deref())
    }

    /// Drop every cached *negative* agent-name lookup, returning how many went.
    ///
    /// Called on load. A negative records only that a name could not be verified
    /// at some past moment, and the usual causes do not survive a restart: no
    /// network at the time, the naming host briefly down, or a name claimed
    /// moments before its redirect went live. Persisting those across a relaunch
    /// means the operator's instinctive fix — restart it — provably cannot work,
    /// which is exactly the trap this cache fell into.
    ///
    /// Verified names are kept: showing them instantly at launch without a
    /// network round-trip is the reason the cache is persisted at all.
    pub fn prune_agent_name_negatives(&mut self) -> usize {
        let before = self.agent_names.len();
        self.agent_names.retain(|_, cached| cached.name.is_some());
        before - self.agent_names.len()
    }
}

/// Manual impl so freshly created configs are stamped with the current
/// schema version (a derived `Default` would set `schema_version` to 0).
impl Default for ProtectedConfig {
    fn default() -> Self {
        ProtectedConfig {
            extra: serde_json::Map::new(),
            schema_version: PROTECTED_SCHEMA_VERSION,
            account: Account::default(),
            contacts: Contacts::default(),
            relationships: Relationships::default(),
            tsp_relationships: TspRelationships::default(),
            tasks: Tasks::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
            agent_names: HashMap::default(),
            agent_names_unverified: std::collections::BTreeSet::new(),
            vetting: VettingBook::default(),
            seen_documents: SeenDocuments::default(),
            deferred_inbound: Vec::new(),
            vta_sync: SyncState::default(),
            witnessings: Witnessings::default(),
            logs: Logs::default(),
        }
    }
}

/// Magic prefix of the current protected-blob format (`"OPC2"`). The legacy
/// format has none: it starts with its random nonce.
const PROTECTED_MAGIC: &[u8; 4] = b"OPC2";
/// HKDF label of the current protected-blob format.
const PROTECTED_INFO: &[u8] = b"openvtc/protected-config/v2";
/// Associated-data prefix of the current protected-blob format; the binding
/// ([`ProtectedBinding`]) follows it.
const PROTECTED_AAD: &[u8] = b"openvtc/protected-config/v2\0";

/// What an encrypted [`ProtectedConfig`] blob is bound to, as associated data.
///
/// A blob opens only in the context it was written for, so one copied into
/// another profile's `config.json` (or substituted from an export) fails
/// authentication instead of loading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedBinding<'a> {
    /// The `private` blob of this profile's `config.json`.
    Profile(&'a str),
    /// The `private` blob inside an export file. Deliberately bound to no
    /// profile: an export is imported into a profile of the importer's
    /// choosing, usually not the one it came from.
    Export,
}

impl ProtectedBinding<'_> {
    fn aad(self) -> Vec<u8> {
        let mut aad = PROTECTED_AAD.to_vec();
        match self {
            ProtectedBinding::Profile(profile) => {
                aad.extend_from_slice(b"profile\0");
                aad.extend_from_slice(profile.as_bytes());
            }
            ProtectedBinding::Export => aad.extend_from_slice(b"export"),
        }
        aad
    }
}

impl ProtectedConfig {
    /// Encrypts this config into the BASE64 string stored in `config.json`.
    ///
    /// Format: `"OPC2" | nonce(12) | ct+tag`, AES-256-GCM under an HKDF key
    /// labelled `openvtc/protected-config/v2`, with `binding` as associated
    /// data.
    pub fn save(
        &self,
        seed_bytes: &SecretBox<Vec<u8>>,
        binding: ProtectedBinding<'_>,
    ) -> Result<String, OpenVTCError> {
        let bytes = Zeroizing::new(serde_json::to_vec(self)?);
        let key = seed_bytes
            .expose_secret()
            .first_chunk::<32>()
            .ok_or_else(|| {
                OpenVTCError::Encrypt("Seed bytes are not at least 32 bytes".to_string())
            })?;
        let mut out = PROTECTED_MAGIC.to_vec();
        out.extend_from_slice(&seal(key, PROTECTED_INFO, &binding.aad(), &bytes)?);
        Ok(BASE64_URL_SAFE_NO_PAD.encode(&out))
    }

    /// Decrypts a blob written by [`ProtectedConfig::save`] for `binding`, or
    /// one in the legacy format (no magic, no associated data, the shared
    /// `openvtc-key-v2` label), which is rewritten in the current format by
    /// the next save.
    ///
    /// A blob carrying the magic is tried in the current format first; a
    /// legacy blob whose random nonce happens to begin with the magic still
    /// opens, because the legacy format is tried whenever that fails.
    pub fn load(
        seed_bytes: &SecretBox<Vec<u8>>,
        input: &str,
        binding: ProtectedBinding<'_>,
    ) -> Result<ProtectedConfig, OpenVTCError> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(input)?;
        let key = seed_bytes
            .expose_secret()
            .first_chunk::<32>()
            .ok_or_else(|| {
                OpenVTCError::Decrypt("Seed bytes are not at least 32 bytes".to_string())
            })?;

        if let Some(body) = bytes.strip_prefix(PROTECTED_MAGIC.as_slice())
            && body.len() > 12
            && let Some(plaintext) = open(key, PROTECTED_INFO, &binding.aad(), body)?
        {
            return Self::parse(&plaintext);
        }

        match aead_open(key, &bytes)? {
            Some(plaintext) => Self::parse(&plaintext),
            None => {
                error!("Couldn't decrypt data. Likely due to incorrect unlock code!");
                Err(OpenVTCError::Decrypt(
                    "Couldn't decrypt the protected config: wrong key, or a blob written \
                     for another profile"
                        .to_string(),
                ))
            }
        }
    }
    /// Deserialize a [`ProtectedConfig`] from already-decrypted plaintext JSON —
    /// the post-decrypt half of [`load`](Self::load), split out so the
    /// deserializer can be exercised directly (e.g. by fuzz harnesses) without a
    /// keyring or real keys.
    ///
    /// Credentials stored by an earlier build that do not conform to DTG
    /// Credentials v1 are set aside here, each with a logged reason and a
    /// notice the UI shows (see [`crate::dtg`]); relationship credentials and
    /// tasks do the same as they deserialize ([`Vrcs`]). Hidden-vetting keys a
    /// build that ran the engine on this device stored are dropped the same way
    /// ([`crate::vetting::VettingBook::forget_local_engines`]): the VTA holds
    /// them now.
    pub fn parse(plaintext: &[u8]) -> Result<ProtectedConfig, OpenVTCError> {
        let mut config: ProtectedConfig = serde_json::from_slice(plaintext)?;
        config.vetting.retire_nonconformant();
        config.vetting.forget_local_engines();
        Ok(config)
    }

    /// Derives the seed at BIP32 `path` below `bip32`: the derived signing key's
    /// private bytes. The profile's pre-D12 encryption seed comes from `m/0'/0'/0'`.
    pub fn get_seed(
        bip32: &ExtendedSigningKey,
        path: &str,
    ) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        let derived = bip32
            .derive(&path.parse::<DerivationPath>().map_err(|e| {
                OpenVTCError::BIP32(format!("Couldn't parse derivation path ({}): {}", path, e))
            })?)
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Couldn't derive secret key for path ({}): {}",
                    path, e
                ))
            })?;
        Ok(SecretBox::new(Box::new(
            derived.signing_key.as_bytes().to_vec(),
        )))
    }

    /// Legacy seed derivation using the verifying (public) key.
    ///
    /// Used only for migrating configs encrypted with the old (pre-0.1.4) seed
    /// derivation. New code should always use [`ProtectedConfig::get_seed`].
    pub fn get_seed_legacy(
        bip32: &ExtendedSigningKey,
        path: &str,
    ) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        let derived = bip32
            .derive(&path.parse::<DerivationPath>().map_err(|e| {
                OpenVTCError::BIP32(format!("Couldn't parse derivation path ({}): {}", path, e))
            })?)
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Couldn't derive secret key for path ({}): {}",
                    path, e
                ))
            })?;
        Ok(SecretBox::new(Box::new(
            derived.verifying_key().to_bytes().to_vec(),
        )))
    }

    /// Derives an encryption seed from a VTA credential's private key multibase.
    ///
    /// Uses HKDF-SHA256 with domain separation to derive a 32-byte seed from the
    /// credential's private key. This ensures the derived seed is cryptographically
    /// bound to its purpose and cannot be confused with keys derived for other uses.
    pub fn get_seed_from_credential(
        private_key_multibase: &str,
    ) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        debug!("deriving encryption seed from credential via HKDF");
        let hk = Hkdf::<Sha256>::new(None, private_key_multibase.as_bytes());
        let mut seed = vec![0u8; 32];
        hk.expand(b"openvtc-protected-config-seed-v1", &mut seed)
            .map_err(|e| {
                OpenVTCError::Encrypt(format!("HKDF expansion failed for credential seed: {e}"))
            })?;
        Ok(SecretBox::new(Box::new(seed)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_plaintext_json_and_rejects_garbage() {
        // `parse` is the post-decrypt serde half of `load` — no keyring needed.
        let bytes = serde_json::to_vec(&ProtectedConfig::default()).unwrap();
        assert!(ProtectedConfig::parse(&bytes).is_ok());
        assert!(ProtectedConfig::parse(b"not json at all").is_err());
        assert!(ProtectedConfig::parse(&[]).is_err());
    }

    /// A config written before the `agent_names` field existed has no such key;
    /// `#[serde(default)]` must load it as an empty map rather than failing, so
    /// the feature stays additive with no schema bump.
    #[test]
    fn parse_tolerates_config_without_agent_names() {
        // Derive an "old config" by serialising a current one and dropping the
        // `agent_names` key, so the fixture tracks the real struct shape rather
        // than a hand-written approximation of it.
        let mut value = serde_json::to_value(ProtectedConfig::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("agent_names")
            .expect("current config serialises agent_names");
        let bytes = serde_json::to_vec(&value).unwrap();

        let parsed = ProtectedConfig::parse(&bytes).expect("legacy config must load");
        assert!(parsed.agent_names.is_empty());
    }

    fn test_seed() -> SecretBox<Vec<u8>> {
        SecretBox::new(Box::new(vec![42u8; 32]))
    }

    #[test]
    fn test_protected_config_save_load_roundtrip() {
        let config = ProtectedConfig::default();
        let seed = test_seed();

        let saved = config
            .save(&seed, ProtectedBinding::Profile("default"))
            .unwrap();
        assert!(!saved.is_empty());

        let loaded =
            ProtectedConfig::load(&seed, &saved, ProtectedBinding::Profile("default")).unwrap();
        assert!(loaded.contacts.is_empty());
    }

    #[test]
    fn test_protected_config_account_round_trips() {
        use crate::config::account::{Account, PersonaId, PersonaRecord};
        use chrono::Utc;

        let mut config = ProtectedConfig::default();
        let pid = PersonaId::new();
        config.account = Account {
            vta_did: "did:webvh:vta.example".into(),
            vta_url: "https://vta.example".into(),
            top_context_id: "openvtc".into(),
            ..Account::default()
        };
        config.account.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: "did:webvh:example:p".into(),
                did_document: None,
                did_locator: None,
                key_refs: Vec::new(),
                mediator_did: Some("did:webvh:mediator".into()),
                origin_context_id: String::new(),
                created_at: Utc::now(),
                label: Some("alice".into()),
            },
        );

        let seed = test_seed();
        let saved = config
            .save(&seed, ProtectedBinding::Profile("default"))
            .unwrap();
        let loaded =
            ProtectedConfig::load(&seed, &saved, ProtectedBinding::Profile("default")).unwrap();

        assert_eq!(loaded.account.vta_did, "did:webvh:vta.example");
        assert_eq!(loaded.account.personas.len(), 1);
        assert_eq!(loaded.account.personas[&pid].did, "did:webvh:example:p");
    }

    #[test]
    fn test_protected_config_wrong_seed_fails() {
        let config = ProtectedConfig::default();
        let seed = test_seed();
        let wrong_seed = SecretBox::new(Box::new(vec![99u8; 32]));

        let saved = config
            .save(&seed, ProtectedBinding::Profile("default"))
            .unwrap();
        let result =
            ProtectedConfig::load(&wrong_seed, &saved, ProtectedBinding::Profile("default"));
        assert!(result.is_err());
    }

    /// The blob is bound to its profile. One copied into another profile's
    /// config, or presented as an export, does not open (#569).
    #[test]
    fn a_blob_bound_to_one_profile_does_not_open_in_another() {
        let seed = test_seed();
        let saved = ProtectedConfig::default()
            .save(&seed, ProtectedBinding::Profile("alice"))
            .unwrap();
        let raw = BASE64_URL_SAFE_NO_PAD.decode(&saved).unwrap();
        assert_eq!(&raw[..4], PROTECTED_MAGIC);

        assert!(ProtectedConfig::load(&seed, &saved, ProtectedBinding::Profile("alice")).is_ok());
        assert!(ProtectedConfig::load(&seed, &saved, ProtectedBinding::Profile("bob")).is_err());
        assert!(ProtectedConfig::load(&seed, &saved, ProtectedBinding::Export).is_err());

        let export = ProtectedConfig::default()
            .save(&seed, ProtectedBinding::Export)
            .unwrap();
        assert!(ProtectedConfig::load(&seed, &export, ProtectedBinding::Export).is_ok());
        assert!(ProtectedConfig::load(&seed, &export, ProtectedBinding::Profile("alice")).is_err());
    }

    /// A blob written before the AAD format (no magic, shared HKDF label, no
    /// associated data) still opens under any binding, so existing profiles
    /// and older exports load; the next save rewrites it.
    #[test]
    fn a_legacy_blob_still_opens() {
        let seed = test_seed();
        let mut cfg = ProtectedConfig::default();
        cfg.logs
            .insert(LogFamily::Config, "from before".to_string());
        let plaintext = serde_json::to_vec(&cfg).unwrap();
        let legacy = BASE64_URL_SAFE_NO_PAD.encode(
            crate::config::secured_config::unlock_code_encrypt(
                seed.expose_secret().first_chunk::<32>().unwrap(),
                &plaintext,
            )
            .unwrap(),
        );
        for binding in [
            ProtectedBinding::Profile("default"),
            ProtectedBinding::Export,
        ] {
            let loaded = ProtectedConfig::load(&seed, &legacy, binding).expect("legacy opens");
            assert_eq!(loaded.logs.messages.len(), 1);
        }
        let wrong = SecretBox::new(Box::new(vec![1u8; 32]));
        assert!(ProtectedConfig::load(&wrong, &legacy, ProtectedBinding::Export).is_err());
    }

    /// A config written before `logs` moved here has no such key.
    #[test]
    fn parse_tolerates_config_without_logs() {
        let mut value = serde_json::to_value(ProtectedConfig::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("logs")
            .expect("logs serialised");
        let parsed = ProtectedConfig::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(parsed.logs.messages.is_empty());
        assert!(
            parsed.extra.is_empty(),
            "logs is a field, not an unknown key"
        );
    }

    #[test]
    fn test_protected_config_serialization_preserves_data() {
        let config = ProtectedConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ProtectedConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.contacts.is_empty());
    }

    #[test]
    fn test_schema_version_defaults_to_one_when_absent() {
        // Simulates configs saved before schema_version existed — they must
        // deserialize as the v1 shape, not 0.
        let json = r#"{
            "contacts": { "contacts": {} },
            "vrcs_issued": { "vrcs": {} },
            "vrcs_received": { "vrcs": {} }
        }"#;
        let config: ProtectedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.schema_version, 1);
    }

    #[test]
    fn test_schema_version_round_trips() {
        let config = ProtectedConfig::default();
        assert_eq!(config.schema_version, PROTECTED_SCHEMA_VERSION);

        // Plain serde round-trip preserves the field.
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"schema_version\":"));
        let deserialized: ProtectedConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.schema_version, PROTECTED_SCHEMA_VERSION);

        // Encrypted save/load round-trip preserves the field too.
        let seed = test_seed();
        let saved = config
            .save(&seed, ProtectedBinding::Profile("default"))
            .unwrap();
        let loaded =
            ProtectedConfig::load(&seed, &saved, ProtectedBinding::Profile("default")).unwrap();
        assert_eq!(loaded.schema_version, PROTECTED_SCHEMA_VERSION);
    }

    #[test]
    fn test_contacts_find_by_did() {
        let mut contacts = Contacts::default();
        let did = Arc::new("did:example:123".to_string());
        let contact = Arc::new(Contact {
            did: did.clone(),
            alias: Some("alice".to_string()),
        });
        contacts.contacts.insert(did.clone(), contact.clone());
        contacts
            .aliases
            .insert("alice".to_string(), contact.clone());

        assert!(contacts.find_contact("did:example:123").is_some());
        assert!(contacts.find_contact("alice").is_some());
        assert!(contacts.find_contact("unknown").is_none());
    }

    #[test]
    fn test_contacts_remove() {
        let mut contacts = Contacts::default();
        let did = Arc::new("did:example:123".to_string());
        let contact = Arc::new(Contact {
            did: did.clone(),
            alias: Some("bob".to_string()),
        });
        contacts.contacts.insert(did.clone(), contact.clone());
        contacts.aliases.insert("bob".to_string(), contact.clone());

        let mut logs = Logs::default();
        let removed = contacts.remove_contact(&mut logs, "bob");
        assert!(removed.is_some());
        assert!(contacts.find_contact("bob").is_none());
        assert!(contacts.find_contact("did:example:123").is_none());
    }

    #[test]
    fn test_get_seed_from_credential_deterministic() {
        let key = "z6MkTestKey123";
        let seed1 = ProtectedConfig::get_seed_from_credential(key).unwrap();
        let seed2 = ProtectedConfig::get_seed_from_credential(key).unwrap();
        assert_eq!(seed1.expose_secret(), seed2.expose_secret(),);
    }

    #[test]
    fn test_get_seed_from_credential_different_keys_differ() {
        let seed1 = ProtectedConfig::get_seed_from_credential("key1").unwrap();
        let seed2 = ProtectedConfig::get_seed_from_credential("key2").unwrap();
        assert_ne!(seed1.expose_secret(), seed2.expose_secret(),);
    }

    /// Negatives are dropped on load so a restart re-checks them; verified names
    /// survive, since instant display at launch is why the cache is persisted.
    #[test]
    fn pruning_drops_negatives_and_keeps_verified_names() {
        use crate::agent_name::CachedAgentName;

        let now = chrono::Utc::now();
        let mut cfg = ProtectedConfig::default();
        cfg.agent_names.insert(
            "did:webvh:us:example.com".to_string(),
            CachedAgentName {
                name: Some("example.com/@alice".to_string()),
                checked_at: now,
            },
        );
        cfg.agent_names.insert(
            "did:webvh:us:nameless.example".to_string(),
            CachedAgentName {
                name: None,
                checked_at: now,
            },
        );

        assert_eq!(cfg.prune_agent_name_negatives(), 1);
        assert_eq!(cfg.agent_names.len(), 1);
        assert!(cfg.agent_names.contains_key("did:webvh:us:example.com"));
        assert!(
            !cfg.agent_names
                .contains_key("did:webvh:us:nameless.example")
        );

        // Idempotent: a second prune has nothing left to drop.
        assert_eq!(cfg.prune_agent_name_negatives(), 0);
    }
}
