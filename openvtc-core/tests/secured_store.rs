//! The secured tier against a credential store: the salted unlock-key format
//! (#566), its profile binding (#569), the one-time migration from the legacy
//! fixed-salt format and what a failure part-way through it leaves behind, and
//! the skipped keyring write (#564).
//!
//! Runs against an in-memory store this file installs as the process default,
//! so it needs no OS keyring. Every test uses its own profile name, because the
//! store and the write-skip record are process-wide.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use keyring_core::{
    Entry, Error, Result,
    api::{CredentialApi, CredentialPersistence, CredentialStoreApi},
};
use openvtc_core::config::{
    UnlockCode, UnlockKey, derive_passphrase_key,
    secured_config::{ProtectionMethod, SecuredConfig, UnlockCodeCheck, unlock_code_encrypt},
};
use secrecy::SecretString;
use std::{
    any::Any,
    collections::HashMap,
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicUsize, Ordering},
    },
};

// ---------------------------------------------------------------------------
// An in-memory store with fault injection
// ---------------------------------------------------------------------------

/// What the next `set_secret` for a profile does instead of storing.
#[derive(Clone, Copy)]
enum Fault {
    /// Fails, storing nothing — a refused write, or a crash before it.
    Fail,
    /// Reports success but stores garbage — a write that did not land intact.
    Corrupt,
}

#[derive(Default)]
struct Shared {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
    writes: Mutex<HashMap<String, usize>>,
    faults: Mutex<HashMap<String, Fault>>,
}

static SHARED: std::sync::LazyLock<Arc<Shared>> =
    std::sync::LazyLock::new(|| Arc::new(Shared::default()));
static INSTALL: Once = Once::new();
static PROFILE_SEQ: AtomicUsize = AtomicUsize::new(0);

fn install() {
    INSTALL.call_once(|| {
        keyring_core::set_default_store(Arc::new(MemStore));
    });
}

/// A fresh profile name, so tests never share an entry.
fn profile(tag: &str) -> String {
    install();
    format!("{tag}-{}", PROFILE_SEQ.fetch_add(1, Ordering::Relaxed))
}

fn writes(profile: &str) -> usize {
    *SHARED.writes.lock().unwrap().get(profile).unwrap_or(&0)
}

fn stored(profile: &str) -> Vec<u8> {
    SHARED.secrets.lock().unwrap()[profile].clone()
}

fn put(profile: &str, bytes: &[u8]) {
    SHARED
        .secrets
        .lock()
        .unwrap()
        .insert(profile.to_string(), bytes.to_vec());
}

fn inject(profile: &str, fault: Fault) {
    SHARED
        .faults
        .lock()
        .unwrap()
        .insert(profile.to_string(), fault);
}

#[derive(Debug)]
struct MemStore;

#[derive(Debug)]
struct MemCred {
    user: String,
}

impl CredentialApi for MemCred {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        *SHARED
            .writes
            .lock()
            .unwrap()
            .entry(self.user.clone())
            .or_default() += 1;
        match SHARED.faults.lock().unwrap().remove(&self.user) {
            Some(Fault::Fail) => Err(Error::NoStorageAccess(Box::new(std::io::Error::other(
                "injected write failure",
            )))),
            Some(Fault::Corrupt) => {
                put(
                    &self.user,
                    b"{\"format\":\"PlainText\",\"text\":\"garbage\"}",
                );
                Ok(())
            }
            None => {
                put(&self.user, secret);
                Ok(())
            }
        }
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        SHARED
            .secrets
            .lock()
            .unwrap()
            .get(&self.user)
            .cloned()
            .ok_or(Error::NoEntry)
    }

    fn delete_credential(&self) -> Result<()> {
        SHARED
            .secrets
            .lock()
            .unwrap()
            .remove(&self.user)
            .map(|_| ())
            .ok_or(Error::NoEntry)
    }

    fn get_credential(&self) -> Result<Option<Arc<keyring_core::api::Credential>>> {
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some(("openvtc".to_string(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CredentialStoreApi for MemStore {
    fn vendor(&self) -> String {
        "test".to_string()
    }

    fn id(&self) -> String {
        "test in-memory store".to_string()
    }

    fn build(
        &self,
        _service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        Ok(Entry::new_with_credential(Arc::new(MemCred {
            user: user.to_string(),
        })))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CODE: &str = "correct horse battery";
const WRONG: &str = "correct horse battery!";

fn secured(marker: &str) -> SecuredConfig {
    SecuredConfig {
        bip32_seed: None,
        credential_bundle: Some(SecretString::new("bundle".into())),
        protected_key: None,
        vta_url: None,
        vta_did: Some(marker.to_string()),
        mediator_did: None,
        key_info: HashMap::new(),
        protection_method: ProtectionMethod::default(),
    }
}

#[cfg(feature = "openpgp-card")]
struct NoTouch;
#[cfg(feature = "openpgp-card")]
impl openvtc_core::config::TokenInteractions for NoTouch {
    fn touch_notify(&self) {}
    fn touch_completed(&self) {}
}

fn save(sc: &SecuredConfig, profile: &str, key: Option<&UnlockKey>) {
    sc.save(
        profile,
        None,
        key,
        #[cfg(feature = "openpgp-card")]
        &|| {},
    )
    .expect("save");
}

fn load(profile: &str, code: &str) -> std::result::Result<SecuredConfig, String> {
    let unlock = UnlockCode::for_existing(code).unwrap();
    SecuredConfig::load(
        profile,
        #[cfg(feature = "openpgp-card")]
        &SecretString::new("".into()),
        None,
        Some(&unlock),
        #[cfg(feature = "openpgp-card")]
        &NoTouch,
    )
    .map_err(|e| e.to_string())
}

fn check(profile: &str, code: &str) -> UnlockCodeCheck {
    SecuredConfig::check_unlock_code(profile, &UnlockCode::for_existing(code).unwrap())
        .expect("check")
}

/// Store `sc` the way releases before #566 did: the fixed-salt key, no
/// associated data, tagged (or, `untagged`, the even older shape).
fn put_legacy(profile: &str, sc: &SecuredConfig, untagged: bool) -> Vec<u8> {
    let key = derive_passphrase_key(CODE.as_bytes(), b"openvtc-unlock-code-v1").unwrap();
    let data = BASE64_URL_SAFE_NO_PAD
        .encode(unlock_code_encrypt(&key, &serde_json::to_vec(sc).unwrap()).unwrap());
    let blob = if untagged {
        format!("{{\"data\":\"{data}\"}}")
    } else {
        format!("{{\"format\":\"PasswordEncrypted\",\"data\":\"{data}\"}}")
    };
    put(profile, blob.as_bytes());
    blob.into_bytes()
}

fn is_sealed(profile: &str) -> bool {
    String::from_utf8(stored(profile))
        .unwrap()
        .contains("\"format\":\"PasswordSealed\"")
}

// ---------------------------------------------------------------------------
// #566 — salted format, and migration from the legacy one
// ---------------------------------------------------------------------------

#[test]
fn a_new_profile_round_trips_in_the_salted_format() {
    let p = profile("roundtrip");
    let key = UnlockKey::derive(CODE.as_bytes()).unwrap();
    save(&secured("did:example:a"), &p, Some(&key));
    assert!(is_sealed(&p));

    assert_eq!(check(&p, CODE), UnlockCodeCheck::Accepted);
    assert_eq!(check(&p, WRONG), UnlockCodeCheck::Rejected);
    assert_eq!(
        load(&p, CODE).unwrap().vta_did.as_deref(),
        Some("did:example:a")
    );
    assert!(load(&p, WRONG).is_err());
}

#[test]
fn a_legacy_blob_opens_and_is_migrated_on_unlock() {
    for untagged in [false, true] {
        let p = profile("migrate");
        put_legacy(&p, &secured("did:example:legacy"), untagged);

        // The unlock prompt's check works on the legacy format, and does not
        // migrate anything.
        assert_eq!(check(&p, CODE), UnlockCodeCheck::Accepted);
        assert_eq!(check(&p, WRONG), UnlockCodeCheck::Rejected);
        assert!(!is_sealed(&p));
        assert!(load(&p, WRONG).is_err(), "a wrong code opens nothing");
        assert!(!is_sealed(&p), "nor migrates anything");

        let sc = load(&p, CODE).expect("legacy blob opens");
        assert_eq!(sc.vta_did.as_deref(), Some("did:example:legacy"));
        assert!(is_sealed(&p), "rewritten in the salted format");

        // ...and the migrated blob opens with the same code, and only it.
        assert_eq!(check(&p, CODE), UnlockCodeCheck::Accepted);
        assert_eq!(check(&p, WRONG), UnlockCodeCheck::Rejected);
        assert_eq!(
            load(&p, CODE).unwrap().vta_did.as_deref(),
            Some("did:example:legacy")
        );
    }
}

/// Two profiles with the same code do not share a key: their salts differ.
#[test]
fn the_same_code_on_two_profiles_gets_two_salts() {
    let (a, b) = (profile("salt-a"), profile("salt-b"));
    put_legacy(&a, &secured("x"), false);
    put_legacy(&b, &secured("x"), false);
    load(&a, CODE).unwrap();
    load(&b, CODE).unwrap();
    let salt = |p: &str| {
        let v: serde_json::Value = serde_json::from_slice(&stored(p)).unwrap();
        v["salt"].as_str().unwrap().to_string()
    };
    assert_ne!(salt(&a), salt(&b));
}

/// The write fails (or the process dies before it): the legacy blob is still
/// what is stored, still opens, and the next unlock migrates it.
#[test]
fn a_failed_migration_write_leaves_the_legacy_blob_working() {
    let p = profile("crash-before");
    let original = put_legacy(&p, &secured("did:example:keep"), false);

    inject(&p, Fault::Fail);
    let sc = load(&p, CODE).expect("the load still succeeds");
    assert_eq!(sc.vta_did.as_deref(), Some("did:example:keep"));
    assert_eq!(stored(&p), original, "untouched");
    assert_eq!(check(&p, CODE), UnlockCodeCheck::Accepted);

    load(&p, CODE).expect("opens");
    assert!(is_sealed(&p), "migrated on the next unlock");
}

/// The write reports success but what landed does not read back: the
/// original blob is put back, so the profile still opens.
#[test]
fn a_migration_that_does_not_read_back_restores_the_original() {
    let p = profile("crash-after");
    let original = put_legacy(&p, &secured("did:example:keep"), false);

    inject(&p, Fault::Corrupt);
    load(&p, CODE).expect("the load still succeeds");
    assert_eq!(stored(&p), original, "original restored");
    assert_eq!(
        load(&p, CODE).unwrap().vta_did.as_deref(),
        Some("did:example:keep")
    );
}

// ---------------------------------------------------------------------------
// #569 — the sealed blob is bound to its profile
// ---------------------------------------------------------------------------

#[test]
fn a_sealed_blob_moved_to_another_profile_does_not_open() {
    let (a, b) = (profile("aad-a"), profile("aad-b"));
    let key = UnlockKey::derive(CODE.as_bytes()).unwrap();
    save(&secured("did:example:a"), &a, Some(&key));

    put(&b, &stored(&a));
    assert_eq!(check(&b, CODE), UnlockCodeCheck::Rejected);
    assert!(load(&b, CODE).is_err());
    assert_eq!(check(&a, CODE), UnlockCodeCheck::Accepted);
}

// ---------------------------------------------------------------------------
// #564 — an unchanged secured tier is not rewritten
// ---------------------------------------------------------------------------

#[test]
fn an_unchanged_save_skips_the_keyring_write() {
    let p = profile("skip");
    let key = UnlockKey::derive(CODE.as_bytes()).unwrap();
    let sc = secured("did:example:same");

    save(&sc, &p, Some(&key));
    assert_eq!(writes(&p), 1);
    save(&sc, &p, Some(&key));
    save(&sc, &p, Some(&key));
    assert_eq!(writes(&p), 1, "unchanged: no further writes");

    save(&secured("did:example:changed"), &p, Some(&key));
    assert_eq!(writes(&p), 2, "changed content writes");

    let new_key = UnlockKey::derive(b"another unlock code").unwrap();
    save(&secured("did:example:changed"), &p, Some(&new_key));
    assert_eq!(writes(&p), 3, "a new passphrase writes");
    assert_eq!(check(&p, "another unlock code"), UnlockCodeCheck::Accepted);

    save(&secured("did:example:changed"), &p, None);
    assert_eq!(writes(&p), 4, "removing the passphrase writes");
}

/// After a failed write the record is cleared, so the retry writes.
#[test]
fn a_failed_write_is_retried_not_skipped() {
    let p = profile("retry");
    let key = UnlockKey::derive(CODE.as_bytes()).unwrap();
    let sc = secured("did:example:r");
    save(&sc, &p, Some(&key));
    save(&secured("did:example:r2"), &p, Some(&key));
    assert_eq!(writes(&p), 2);

    inject(&p, Fault::Fail);
    assert!(
        sc.save(
            &p,
            None,
            Some(&key),
            #[cfg(feature = "openpgp-card")]
            &|| {},
        )
        .is_err()
    );
    save(&sc, &p, Some(&key));
    assert_eq!(writes(&p), 4, "the retry wrote");
    assert_eq!(
        load(&p, CODE).unwrap().vta_did.as_deref(),
        Some("did:example:r")
    );
}

/// A load means the stored blob is whatever was read, so the next save
/// writes even if this process wrote the same content before.
#[test]
fn a_load_clears_the_skip_record() {
    let p = profile("reload");
    let key = UnlockKey::derive(CODE.as_bytes()).unwrap();
    let sc = secured("did:example:l");
    save(&sc, &p, Some(&key));
    load(&p, CODE).unwrap();
    save(&sc, &p, Some(&key));
    assert_eq!(writes(&p), 2);
}
