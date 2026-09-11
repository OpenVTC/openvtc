/*! Configuration information that needs to be protected
*   but is not as critical as private key information which is stored in the OS Secure Store
*/

use std::{collections::HashMap, sync::Arc};

use crate::{
    agent_name::CachedAgentName,
    config::account::Account,
    config::secured_config::{unlock_code_decrypt, unlock_code_encrypt},
    errors::OpenVTCError,
    logs::{LogFamily, Logs},
    relationships::Relationships,
    tasks::Tasks,
    vetting::VettingBook,
    vrc::Vrcs,
};
use affinidi_tdk::TDK;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSigningKey};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};

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

    /// Peer identity vetting: our applications, and our desk as a vetter
    /// ([`crate::vetting`]). Skipped when empty, so a config that has never
    /// vetted round-trips byte-identically.
    #[serde(default, skip_serializing_if = "VettingBook::is_empty")]
    pub vetting: VettingBook,

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
            tasks: Tasks::default(),
            vrcs_issued: Vrcs::default(),
            vrcs_received: Vrcs::default(),
            agent_names: HashMap::default(),
            vetting: VettingBook::default(),
        }
    }
}

impl ProtectedConfig {
    /// Converts ProtectedConfig to an encrypted BASE64 string for saving to disk
    pub fn save(&self, seed_bytes: &SecretBox<Vec<u8>>) -> Result<String, OpenVTCError> {
        let bytes = serde_json::to_vec(self)?;

        match unlock_code_encrypt(
            seed_bytes
                .expose_secret()
                .first_chunk::<32>()
                .ok_or_else(|| {
                    OpenVTCError::Encrypt("Seed bytes are not at least 32 bytes".to_string())
                })?,
            &bytes,
        ) {
            Ok(result) => Ok(BASE64_URL_SAFE_NO_PAD.encode(&result)),
            Err(e) => Err(e),
        }
    }

    pub fn load(
        seed_bytes: &SecretBox<Vec<u8>>,
        input: &str,
    ) -> Result<ProtectedConfig, OpenVTCError> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(input)?;

        let bytes = unlock_code_decrypt(
            seed_bytes
                .expose_secret()
                .first_chunk::<32>()
                .ok_or_else(|| {
                    OpenVTCError::Decrypt("Seed bytes are not at least 32 bytes".to_string())
                })?,
            &bytes,
        )?;

        Self::parse(&bytes)
    }

    /// Deserialize a [`ProtectedConfig`] from already-decrypted plaintext JSON —
    /// the post-decrypt half of [`load`](Self::load), split out so the
    /// deserializer can be exercised directly (e.g. by fuzz harnesses) without a
    /// keyring or real keys.
    pub fn parse(plaintext: &[u8]) -> Result<ProtectedConfig, OpenVTCError> {
        Ok(serde_json::from_slice(plaintext)?)
    }

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

        let saved = config.save(&seed).unwrap();
        assert!(!saved.is_empty());

        let loaded = ProtectedConfig::load(&seed, &saved).unwrap();
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
                key_refs: Vec::new(),
                mediator_did: Some("did:webvh:mediator".into()),
                origin_context_id: String::new(),
                created_at: Utc::now(),
                label: Some("alice".into()),
            },
        );

        let seed = test_seed();
        let saved = config.save(&seed).unwrap();
        let loaded = ProtectedConfig::load(&seed, &saved).unwrap();

        assert_eq!(loaded.account.vta_did, "did:webvh:vta.example");
        assert_eq!(loaded.account.personas.len(), 1);
        assert_eq!(loaded.account.personas[&pid].did, "did:webvh:example:p");
    }

    #[test]
    fn test_protected_config_wrong_seed_fails() {
        let config = ProtectedConfig::default();
        let seed = test_seed();
        let wrong_seed = SecretBox::new(Box::new(vec![99u8; 32]));

        let saved = config.save(&seed).unwrap();
        let result = ProtectedConfig::load(&wrong_seed, &saved);
        assert!(result.is_err());
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
        let saved = config.save(&seed).unwrap();
        let loaded = ProtectedConfig::load(&seed, &saved).unwrap();
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
