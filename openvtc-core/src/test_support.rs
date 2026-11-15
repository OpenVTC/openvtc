//! Shared fixtures for this crate's own unit tests.

use crate::config::{
    Config, KeyBackend, account::Account, protected_config::ProtectedConfig,
    public_config::PublicConfig, secured_config::ProtectionMethod,
};

/// An offline TDK: no environment file, no network, no mediator.
pub(crate) async fn test_tdk() -> affinidi_tdk::TDK {
    affinidi_tdk::TDK::new(
        affinidi_tdk::common::config::TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .expect("TDK config builds"),
        None,
    )
    .await
    .expect("TDK builds offline")
}

/// A minimal BIP32-backed [`Config`] with no personas, identities or
/// memberships.
pub(crate) fn test_config() -> Config {
    Config {
        protected_key: None,
        integrity: Default::default(),
        public: PublicConfig::default(),
        private: ProtectedConfig::default(),
        key_backend: KeyBackend::Bip32 {
            root: ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&[7u8; 32]).unwrap(),
            seed: secrecy::SecretString::new("seed".into()),
        },
        key_info: std::collections::HashMap::new(),
        protection_method: ProtectionMethod::default(),
        #[cfg(feature = "openpgp-card")]
        token_admin_pin: None,
        #[cfg(feature = "openpgp-card")]
        token_user_pin: secrecy::SecretString::new("".into()),
        unlock_code: None,
        account: Account::default(),
        identities: std::collections::BTreeMap::new(),
        active_persona: None,
        runtime_trust_overrides: None,
    }
}
