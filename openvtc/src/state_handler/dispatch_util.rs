//! Shared helpers for the post-action "save / sync / status / log" ritual that
//! every panel's action handlers perform after a state-mutating operation.
//!
//! Before this module existed, the same ~8-line success/error block was copied
//! inline across the inbox, relationship, credential, and settings handlers:
//!
//! 1. set the panel's `status_message`,
//! 2. persist the config (now `SaveScheduler::mark_dirty`),
//! 3. rebuild the panels that read what changed (`sync_panels`),
//! 4. push an activity-log entry (`log` or `log_detailed`).
//!
//! The helpers here generalize that block over the panel-specific status slot
//! (reached via an accessor closure, since each panel stores its
//! `status_message` in a different sub-struct) without changing any behavior.
//! Panel/mode transitions stay at the call site because they vary per panel.

use openvtc_core::config::Config;

use crate::state_handler::main_page::status::Status;
use crate::state_handler::main_page::{MainPageState, Panels};
use crate::state_handler::save_coalesce::SaveScheduler;

/// Activity-log entry to write after an action completes.
pub(crate) enum SyncLog {
    /// A plain, single-line summary (`log`).
    Plain(String),
    /// A summary plus a detail pane (`log_detailed`).
    Detailed { summary: String, detail: String },
}

impl SyncLog {
    fn write(self, main_page: &mut MainPageState) {
        match self {
            SyncLog::Plain(summary) => main_page.log(summary),
            SyncLog::Detailed { summary, detail } => main_page.log_detailed(summary, detail),
        }
    }
}

/// How to persist + refresh UI after a successful action.
pub(crate) enum Persist {
    /// Request a **coalesced** save (mark the config dirty — R11), then sync
    /// the panels that read what the action changed, immediately. The
    /// persistence is debounced + offloaded to a blocking thread by the loop's
    /// [`SaveScheduler`]; the UI rebuild happens synchronously on the loop
    /// thread.
    SaveAndSync(Panels),
    /// The action already requested/performed the save itself; only sync the
    /// panels that read what it changed.
    SyncOnly(Panels),
    /// The action already requested/performed the save and no UI sync is required.
    None,
}

impl Persist {
    fn apply(self, main_page: &mut MainPageState, config: &Config, save: &mut SaveScheduler) {
        match self {
            // R11: was a synchronous `Config::save` on the loop thread. Now it
            // only marks the config dirty — the actual save is debounced and run
            // on a blocking thread. The UI sync stays immediate.
            Persist::SaveAndSync(panels) => {
                save.mark_dirty();
                main_page.sync_panels(config, panels);
            }
            Persist::SyncOnly(panels) => main_page.sync_panels(config, panels),
            Persist::None => {}
        }
    }
}

/// Finish a successful action: persist/refresh per `persist`, set the panel's
/// `status_message` (reached via `status`), then write the activity log entry.
///
/// `status` returns a mutable reference to the panel's status slot, e.g.
/// `|mp| &mut mp.content_panel.inbox.status_message`.
///
/// R11: `save` is the loop's coalescing scheduler. A `Persist::SaveAndSync`
/// marks it dirty rather than saving inline; the loop persists later (debounced,
/// off the runtime).
pub(crate) fn save_and_sync(
    main_page: &mut MainPageState,
    config: &Config,
    save: &mut SaveScheduler,
    persist: Persist,
    status: impl FnOnce(&mut MainPageState) -> &mut Option<Status>,
    success_status: impl Into<String>,
    log: SyncLog,
) {
    *status(main_page) = Some(Status::success(success_status));
    persist.apply(main_page, config, save);
    log.write(main_page);
}

/// Record a failed action: set the panel's `status_message` to `Error: {err:#}`
/// (reached via `status`) and log the error with `context`.
pub(crate) fn record_error(
    main_page: &mut MainPageState,
    status: impl FnOnce(&mut MainPageState) -> &mut Option<Status>,
    context: impl Into<String>,
    err: &anyhow::Error,
) {
    *status(main_page) = Some(Status::error(format!("Error: {err:#}")));
    main_page.log_error(context, err);
}

/// Build a minimal BIP32-backed [`Config`] for the pure `apply`/`apply_outcome`
/// tests across the `state_handler` modules. Mirrors openvtc-core's own (private)
/// `test_config`; all fields are public so no cross-crate test constructor is
/// needed.
/// An offline TDK: no environment file, no network, no mediator.
///
/// The thing that made the runtime loop untestable was believed to be its
/// dependencies; this is the one that looked hardest, and it builds in
/// milliseconds with nothing listening.
#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    use openvtc_core::config::{
        KeyBackend, account::Account, protected_config::ProtectedConfig,
        public_config::PublicConfig, secured_config::ProtectionMethod,
    };
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
