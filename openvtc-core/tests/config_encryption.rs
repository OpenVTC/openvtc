//! Integration tests for configuration encryption/decryption lifecycle.
//!
//! These tests verify the full round-trip of encrypting and decrypting
//! configuration data using the Argon2id KDF and AES-256-GCM.

use openvtc_core::config::{
    derive_passphrase_key,
    secured_config::{
        passphrase_decrypt, passphrase_encrypt_v2, unlock_code_decrypt, unlock_code_encrypt,
    },
};

#[test]
fn encrypt_decrypt_roundtrip_with_argon2_key() {
    let passphrase = b"integration-test-passphrase-2026";
    let key = derive_passphrase_key(passphrase, b"test-info").unwrap();

    let plaintext = b"sensitive configuration data with unicode: \xc3\xa9\xc3\xa0\xc3\xbc";
    let encrypted = unlock_code_encrypt(&key, plaintext).expect("encryption should succeed");

    assert_ne!(encrypted.as_slice(), plaintext.as_slice());
    assert!(
        encrypted.len() > plaintext.len(),
        "ciphertext includes nonce + auth tag"
    );

    let decrypted = unlock_code_decrypt(&key, &encrypted).expect("decryption should succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn wrong_passphrase_fails_decryption() {
    let correct_key = derive_passphrase_key(b"correct-passphrase", b"info").unwrap();
    let wrong_key = derive_passphrase_key(b"wrong-passphrase", b"info").unwrap();

    let plaintext = b"secret data";
    let encrypted =
        unlock_code_encrypt(&correct_key, plaintext).expect("encryption should succeed");

    let result = unlock_code_decrypt(&wrong_key, &encrypted);
    assert!(result.is_err(), "Wrong passphrase should fail decryption");
}

#[test]
fn domain_separation_prevents_cross_context_decryption() {
    let passphrase = b"same-passphrase";
    let unlock_key = derive_passphrase_key(passphrase, b"openvtc-unlock-code-v1").unwrap();
    let export_key = derive_passphrase_key(passphrase, b"openvtc-export-v1").unwrap();

    assert_ne!(
        unlock_key, export_key,
        "Different info labels must produce different keys"
    );

    let plaintext = b"config data";
    let encrypted = unlock_code_encrypt(&unlock_key, plaintext).expect("encryption should succeed");

    let result = unlock_code_decrypt(&export_key, &encrypted);
    assert!(
        result.is_err(),
        "Export key should not decrypt data encrypted with unlock key"
    );
}

#[test]
fn encryption_is_non_deterministic() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let plaintext = b"same data";

    let enc1 = unlock_code_encrypt(&key, plaintext).expect("encrypt 1");
    let enc2 = unlock_code_encrypt(&key, plaintext).expect("encrypt 2");

    assert_ne!(
        enc1, enc2,
        "Two encryptions of the same data must differ (random nonce)"
    );

    // But both must decrypt to the same plaintext
    let dec1 = unlock_code_decrypt(&key, &enc1).expect("decrypt 1");
    let dec2 = unlock_code_decrypt(&key, &enc2).expect("decrypt 2");
    assert_eq!(dec1, dec2);
    assert_eq!(dec1.as_slice(), plaintext);
}

#[test]
fn empty_plaintext_roundtrip() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let plaintext = b"";

    let encrypted = unlock_code_encrypt(&key, plaintext).expect("encrypt empty");
    let decrypted = unlock_code_decrypt(&key, &encrypted).expect("decrypt empty");
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

#[test]
fn large_payload_roundtrip() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    let encrypted = unlock_code_encrypt(&key, &plaintext).expect("encrypt large");
    let decrypted = unlock_code_decrypt(&key, &encrypted).expect("decrypt large");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn too_short_ciphertext_fails() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    assert!(
        unlock_code_decrypt(&key, &[0u8; 5]).is_err(),
        "Input shorter than nonce should fail"
    );
    assert!(
        unlock_code_decrypt(&key, &[]).is_err(),
        "Empty input should fail"
    );
}

// ---------------------------------------------------------------------------
// Tampering tests — the AEAD must reject any modification to the stored
// ciphertext, including bit-flips in the nonce, ciphertext body, and
// authentication tag. These are the cheap-and-loud failure modes that
// catch silent corruption / on-disk-data-edit attacks.
// ---------------------------------------------------------------------------

#[test]
fn tamper_with_nonce_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"my secret").expect("encrypt");
    // First 12 bytes are the AES-GCM nonce.
    encrypted[0] ^= 0x01;
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "flipping a nonce byte must fail decryption"
    );
}

#[test]
fn tamper_with_ciphertext_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"my secret payload").expect("encrypt");
    // Flip a byte in the middle of the ciphertext (skip 12-byte nonce).
    let mid = 12 + (encrypted.len() - 12) / 2;
    encrypted[mid] ^= 0x80;
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "flipping a ciphertext byte must fail authentication"
    );
}

#[test]
fn tamper_with_tag_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"x").expect("encrypt");
    // Last 16 bytes are the GCM tag.
    let tag_idx = encrypted.len() - 1;
    encrypted[tag_idx] ^= 0xFF;
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "flipping the GCM tag must fail authentication"
    );
}

#[test]
fn truncated_tag_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let encrypted = unlock_code_encrypt(&key, b"y").expect("encrypt");
    // Drop one byte off the end — partial tag.
    let truncated = &encrypted[..encrypted.len() - 1];
    assert!(
        unlock_code_decrypt(&key, truncated).is_err(),
        "truncating any byte off the ciphertext must fail"
    );
}

#[test]
fn appended_byte_fails_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let mut encrypted = unlock_code_encrypt(&key, b"z").expect("encrypt");
    encrypted.push(0x42);
    assert!(
        unlock_code_decrypt(&key, &encrypted).is_err(),
        "appending an extra byte must fail authentication"
    );
}

#[test]
fn swapped_ciphertexts_fail_decryption() {
    let key = derive_passphrase_key(b"passphrase", b"info").unwrap();
    let enc1 = unlock_code_encrypt(&key, b"first message").expect("encrypt 1");
    let enc2 = unlock_code_encrypt(&key, b"second message").expect("encrypt 2");
    // Splice the nonce of #1 onto the body+tag of #2 — must fail; the
    // (key, nonce) pair won't authenticate the substituted body.
    let mut frankenstein = enc1[..12].to_vec();
    frankenstein.extend_from_slice(&enc2[12..]);
    assert!(
        unlock_code_decrypt(&key, &frankenstein).is_err(),
        "splicing nonce from one ciphertext onto another's body must fail"
    );
}

// ---------------------------------------------------------------------------
// v2 passphrase-AEAD format with per-entry random Argon2 salt.
//
// Behavioural contract:
//   * `passphrase_encrypt_v2` always writes a v2 blob (magic prefix + salt).
//   * `passphrase_decrypt` auto-detects format and decrypts both v1 and v2.
//   * Two encrypts of the same plaintext under the same passphrase produce
//     different ciphertexts (random salt + random nonce).
//   * Two operators with the same passphrase produce independent blobs —
//     the deterministic-salt cross-user correlation in v1 is gone.
// ---------------------------------------------------------------------------

const V2_MAGIC: &[u8; 4] = b"OPV2";

#[test]
fn v2_roundtrip_succeeds() {
    let pass = b"my-passphrase-2026";
    let info = b"openvtc-export-v1";
    let plaintext = b"sensitive config blob";
    let blob = passphrase_encrypt_v2(pass, info, plaintext).expect("encrypt v2");
    assert_eq!(&blob[..4], V2_MAGIC, "v2 blob must begin with OPV2 magic");
    let recovered = passphrase_decrypt(pass, info, &blob).expect("decrypt v2");
    assert_eq!(recovered, plaintext);
}

// ── R12: off-runtime (spawn_blocking) Argon2 wrappers ─────────────────────────
//
// These prove the async wrappers produce artifacts identical in shape to the
// sync path (decryptable by the unchanged `passphrase_decrypt` / matching the
// sync derive), and that the `spawn_blocking` derive runs without panicking
// under a tokio runtime.

/// `passphrase_encrypt_v2_blocking` must produce a v2 blob decryptable by the
/// existing (sync) `passphrase_decrypt` — behaviour parity with
/// `passphrase_encrypt_v2`, only the derive runs off the runtime.
#[tokio::test]
async fn v2_blocking_roundtrip_decryptable_by_sync_decrypt() {
    use openvtc_core::config::secured_config::passphrase_encrypt_v2_blocking;
    let pass = b"my-passphrase-2026";
    let info = b"openvtc-export-v1";
    let plaintext = b"sensitive config blob";
    let blob = passphrase_encrypt_v2_blocking(pass.to_vec(), info.to_vec(), plaintext.to_vec())
        .await
        .expect("blocking encrypt v2 should not panic under a runtime");
    assert_eq!(
        &blob[..4],
        V2_MAGIC,
        "blocking v2 blob must begin with OPV2 magic, same as sync"
    );
    let recovered = passphrase_decrypt(pass, info, &blob).expect("sync decrypt of blocking blob");
    assert_eq!(recovered, plaintext);
}

/// `derive_passphrase_key_blocking` must return the *same* key as the sync
/// `derive_passphrase_key` for the same inputs — only the thread it runs on
/// changes. Also exercises the `spawn_blocking` path without panicking.
#[tokio::test]
async fn derive_passphrase_key_blocking_matches_sync() {
    use openvtc_core::config::derive_passphrase_key_blocking;
    let pass = b"unlock-passphrase";
    let info = b"openvtc-unlock-code-v1";
    let sync_key = derive_passphrase_key(pass, info).expect("sync derive");
    let blocking_key = derive_passphrase_key_blocking(pass.to_vec(), info.to_vec())
        .await
        .expect("blocking derive should not panic under a runtime");
    assert_eq!(
        sync_key, blocking_key,
        "off-runtime derive must produce an identical key (same KDF params + salt)"
    );
}

#[test]
fn v2_two_encrypts_produce_distinct_blobs() {
    let pass = b"same-passphrase";
    let info = b"context";
    let plaintext = b"same plaintext";
    let blob_a = passphrase_encrypt_v2(pass, info, plaintext).unwrap();
    let blob_b = passphrase_encrypt_v2(pass, info, plaintext).unwrap();
    // Random salt + random nonce mean even identical inputs produce
    // unrelated ciphertext bytes — no determinism leak.
    assert_ne!(blob_a, blob_b);
    // First byte after the magic+salt header is the AES-GCM nonce; both
    // halves must differ.
    assert_ne!(&blob_a[..20], &blob_b[..20]);
}

#[test]
fn v1_legacy_blob_decrypts_through_passphrase_decrypt() {
    let pass = b"legacy-passphrase";
    let info = b"openvtc-export-v1";
    let plaintext = b"legacy-encrypted payload";
    // Reproduce the v1 path: derive key with deterministic info-salt,
    // run unlock_code_encrypt to produce the [nonce | ct+tag] blob.
    let key = derive_passphrase_key(pass, info).unwrap();
    let v1_blob = unlock_code_encrypt(&key, plaintext).unwrap();
    assert_ne!(&v1_blob[..4], V2_MAGIC);
    // The new auto-detecting decrypt must read it back.
    let recovered = passphrase_decrypt(pass, info, &v1_blob).expect("decrypt v1 via new API");
    assert_eq!(recovered, plaintext);
}

#[test]
fn v2_decrypt_with_wrong_passphrase_fails() {
    let blob = passphrase_encrypt_v2(b"correct", b"context", b"secret").expect("encrypt");
    assert!(passphrase_decrypt(b"wrong", b"context", &blob).is_err());
}

#[test]
fn v2_decrypt_with_wrong_info_for_v1_blob_fails() {
    // For v1 blobs the info-label is part of the (deterministic) salt.
    // Decrypting a v1 blob under a different info must fail because the
    // derived key won't match.
    let pass = b"pass";
    let v1_blob =
        unlock_code_encrypt(&derive_passphrase_key(pass, b"info-a").unwrap(), b"data").unwrap();
    assert!(passphrase_decrypt(pass, b"info-b", &v1_blob).is_err());
}

#[test]
fn v2_decrypt_with_wrong_info_for_v2_blob_still_succeeds() {
    // For v2 the info label is no longer part of the salt — the salt is
    // random and stored alongside the ciphertext. So as long as the
    // passphrase is right, the info argument is currently advisory.
    // (It's preserved in the API for future domain-separation use.)
    let pass = b"pass";
    let blob = passphrase_encrypt_v2(pass, b"info-a", b"data").unwrap();
    let recovered = passphrase_decrypt(pass, b"info-b", &blob).expect("v2 ignores info");
    assert_eq!(recovered, b"data");
}

#[test]
fn v2_blob_tampering_fails_decrypt() {
    let mut blob = passphrase_encrypt_v2(b"pass", b"info", b"plaintext").expect("encrypt");
    // Flip a byte in the salt portion.
    blob[8] ^= 0x01;
    assert!(passphrase_decrypt(b"pass", b"info", &blob).is_err());
}

// ---------------------------------------------------------------------------
// Known-answer vectors: on-disk format stability across crypto-crate upgrades
//
// Every other test here round-trips within a single build, so a change that
// silently altered the stored layout — a different nonce length, a reordered
// header, a KDF whose parameters moved — would still pass. These two blobs
// were produced by the build before the aes-gcm 0.10 → 0.11 upgrade and are
// checked in verbatim. They stand in for what is already sitting in a user's
// OS keychain: if a future dependency bump makes these fail to decrypt, it
// locks that user out of their config, and the failure belongs here rather
// than on their machine.
// ---------------------------------------------------------------------------

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn v1_blob_from_previous_release_still_decrypts() {
    // [nonce(12) | ct+tag], key = HKDF-SHA256(ikm = unlock, salt = nonce).
    let blob = unhex(
        "7bf0396f20d789d71a928b217201718defc55d46ebc066bceb9ab64206bb6b71\
         c77a7f02d3706613e9b9e8fc3f668cc62925fe1469d1aef5e88af2e6",
    );
    let unlock: [u8; 32] = core::array::from_fn(|i| i as u8);
    let recovered = unlock_code_decrypt(&unlock, &blob).expect("v1 blob from previous release");
    assert_eq!(recovered, b"openvtc format regression vector");
}

#[test]
fn v2_blob_from_previous_release_still_decrypts() {
    // [magic "OPV2" | salt(16) | nonce(12) | ct+tag], Argon2id over the salt.
    let blob = unhex(
        "4f505632b4c10d6b3333ae7cdd2fa944eb70a237e26fba713575548095ea1684\
         3f66fc65ff46f10426d3e839f4a1888dca1b7b10a91801de9d65b8686edc1291b1",
    );
    let recovered = passphrase_decrypt(b"correct horse battery staple", b"kat", &blob)
        .expect("v2 blob from previous release");
    assert_eq!(recovered, b"openvtc v2 vector");
}

// ---------------------------------------------------------------------------
// Export → import round-trip (task R1).
//
// `Config::export` writes a v2 blob (`passphrase_encrypt_v2`, OPV2 magic +
// random salt). The TUI import path must therefore decrypt through the
// format-auto-detecting `passphrase_decrypt` with the same domain-separation
// label. These tests pin that contract at the openvtc-core layer, exercising
// the exact decrypt steps the import site performs.
// ---------------------------------------------------------------------------

mod export_import {
    use super::*;
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use ed25519_dalek_bip32::ExtendedSigningKey;
    use openvtc_core::{
        config::{
            Config, ConfigProtectionType, ExportedConfig, KeyBackend,
            account::Account,
            protected_config::ProtectedConfig,
            public_config::{CONFIG_VERSION, PublicConfig},
            secured_config::ProtectionMethod,
        },
        logs::Logs,
    };
    use secrecy::{ExposeSecret, SecretString};
    use std::collections::HashMap;

    const EXPORT_INFO: &[u8] = b"openvtc-export-v1";

    /// Builds a populated Config with a BIP32 key backend, suitable for
    /// exercising `Config::export`.
    fn populated_config(seed_b64: &str) -> Config {
        let seed_bytes = BASE64_URL_SAFE_NO_PAD.decode(seed_b64).unwrap();
        let root = ExtendedSigningKey::from_seed(&seed_bytes).unwrap();
        Config {
            protected_key: None,
            integrity: Default::default(),
            public: PublicConfig {
                config_version: CONFIG_VERSION,
                protection: ConfigProtectionType::Encrypted,
                friendly_name: "R1 Round Trip".to_string(),
                logs: Logs::default(),
                private: None,
            },
            private: ProtectedConfig::default(),
            key_backend: KeyBackend::Bip32 {
                root,
                seed: SecretString::new(seed_b64.into()),
            },
            key_info: HashMap::new(),
            protection_method: ProtectionMethod::default(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: SecretString::new(String::new().into()),
            unlock_code: None,
            account: Account::default(),
            // Type-inferred so this fixture is agnostic to the `identities`
            // map type (HashMap today, BTreeMap after the determinism fix).
            identities: Default::default(),
            active_persona: None,
            runtime_trust_overrides: None,
        }
    }

    /// Reproduces the import-side decrypt-and-parse steps performed by the
    /// TUI (`ConfigExtension::import`): base64url decode the file contents,
    /// decrypt via the format-auto-detecting `passphrase_decrypt`, then
    /// deserialize the `ExportedConfig`.
    fn import_decrypt(
        content: &str,
        passphrase: &str,
    ) -> Result<ExportedConfig, Box<dyn std::error::Error>> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(content)?;
        let decrypted = passphrase_decrypt(passphrase.as_bytes(), EXPORT_INFO, &decoded)?;
        Ok(serde_json::from_slice(&decrypted)?)
    }

    /// (a) A real `Config::export` output must round-trip through the
    /// import decrypt path on a populated config.
    ///
    /// `Config::export` is async (R12 runs its Argon2 derive on
    /// `spawn_blocking`), so this drives it under a tokio runtime and asserts
    /// the produced blob is still decryptable by the unchanged import path —
    /// proving behaviour parity with the old sync export.
    #[tokio::test]
    async fn export_import_roundtrip_with_populated_config() {
        let seed_b64 = BASE64_URL_SAFE_NO_PAD.encode([7u8; 32]);
        let config = populated_config(&seed_b64);
        let passphrase = "round-trip-passphrase";

        let file =
            std::env::temp_dir().join(format!("openvtc-r1-roundtrip-{}", std::process::id()));
        let file = file.to_str().unwrap().to_string();
        config
            .export(SecretString::new(passphrase.into()), &file)
            .await
            .expect("export should succeed");

        let content = std::fs::read_to_string(&file).expect("read export file");
        let _ = std::fs::remove_file(&file);

        let imported = import_decrypt(&content, passphrase)
            .expect("import decrypt path must read the current export format");
        assert_eq!(imported.pc.friendly_name, "R1 Round Trip");
        let imported_seed = imported
            .sc
            .bip32_seed
            .as_ref()
            .expect("exported SecuredConfig carries the BIP32 seed");
        assert_eq!(imported_seed.expose_secret(), seed_b64);
    }

    /// Pins the R1 root cause: the legacy v1 decrypt path the import used
    /// to hard-code (deterministic info-salt key + `unlock_code_decrypt`)
    /// cannot read a v2 export blob — it misreads the OPV2 header as the
    /// AES-GCM nonce and fails authentication.
    #[test]
    fn v1_decrypt_path_cannot_read_v2_export() {
        let passphrase = b"round-trip-passphrase";
        let blob = passphrase_encrypt_v2(passphrase, EXPORT_INFO, b"{\"any\":\"payload\"}")
            .expect("encrypt v2");
        let v1_key = derive_passphrase_key(passphrase, EXPORT_INFO).unwrap();
        assert!(
            unlock_code_decrypt(&v1_key, &blob).is_err(),
            "the legacy v1 path must not be used to import v2 exports"
        );
    }

    /// (b) A legacy v1-format export (deterministic info-salt key +
    /// `unlock_code_encrypt`, no OPV2 magic) must still decrypt through the
    /// import path — `passphrase_decrypt` falls back to the v1 KDF.
    #[test]
    fn legacy_v1_export_still_imports() {
        let seed_b64 = BASE64_URL_SAFE_NO_PAD.encode([9u8; 32]);
        let config = populated_config(&seed_b64);
        let passphrase = "legacy-export-passphrase";

        // Reproduce the pre-v2 export format byte-for-byte.
        let serialized = serde_json::to_vec(&ExportedConfig {
            pc: PublicConfig::from(&config),
            sc: openvtc_core::config::secured_config::SecuredConfig::from(&config),
        })
        .unwrap();
        let v1_key = derive_passphrase_key(passphrase.as_bytes(), EXPORT_INFO).unwrap();
        let v1_blob = unlock_code_encrypt(&v1_key, &serialized).unwrap();
        let content = BASE64_URL_SAFE_NO_PAD.encode(&v1_blob);

        let imported =
            import_decrypt(&content, passphrase).expect("legacy v1 exports must remain importable");
        assert_eq!(
            imported
                .sc
                .bip32_seed
                .as_ref()
                .expect("seed present")
                .expose_secret(),
            seed_b64
        );
    }

    /// (c) A tampered v2 export must fail with a clear error — never panic.
    #[tokio::test]
    async fn tampered_v2_export_fails_with_error() {
        let seed_b64 = BASE64_URL_SAFE_NO_PAD.encode([11u8; 32]);
        let config = populated_config(&seed_b64);
        let passphrase = "tamper-test-passphrase";

        let file = std::env::temp_dir().join(format!("openvtc-r1-tamper-{}", std::process::id()));
        let file = file.to_str().unwrap().to_string();
        config
            .export(SecretString::new(passphrase.into()), &file)
            .await
            .expect("export should succeed");
        let content = std::fs::read_to_string(&file).expect("read export file");
        let _ = std::fs::remove_file(&file);

        // Flip a byte in the middle of the ciphertext body and re-encode.
        let mut blob = BASE64_URL_SAFE_NO_PAD.decode(&content).unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0x80;
        let tampered = BASE64_URL_SAFE_NO_PAD.encode(&blob);

        let err = match import_decrypt(&tampered, passphrase) {
            Ok(_) => panic!("tampered export must fail decryption"),
            Err(e) => e,
        };
        assert!(
            err.to_string().to_lowercase().contains("decrypt"),
            "error should clearly indicate a decryption failure, got: {err}"
        );
    }
}
