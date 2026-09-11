//! Settings action handlers for the TUI.

use anyhow::Result;
use openvtc_core::{config::Config, logs::LogFamily};
use secrecy::{SecretBox, SecretString};
use tracing::info;

/// Save the config to disk using the profile name.
pub fn save_config(config: &Config, profile: &str) -> Result<()> {
    config.save(
        profile,
        #[cfg(feature = "openpgp-card")]
        &|| {},
    )?;
    Ok(())
}

/// Update the friendly name.
///
/// R11: mutates + logs only; persistence is the caller's responsibility (the
/// loop marks the config dirty for a coalesced save via `Persist::SaveAndSync`).
/// This is a routine, non-durability-critical setting (no key re-derivation),
/// so coalescing is safe — the Exit force-flush guarantees it is persisted.
pub fn update_friendly_name(config: &mut Config, name: &str) {
    config.public.friendly_name = name.to_string();
    config.public.logs.insert(
        LogFamily::Config,
        format!("Friendly name changed to '{}'", name),
    );
    info!(name = %name, "friendly name updated");
}

// There is deliberately no `update_mediator_did`. A persona's mediator is chosen
// when the persona is minted and published in its DID document, so the Settings
// row is read-only (see `settings_panel::MEDIATOR_ROW`). The `OPENVTC_MEDIATOR_DID`
// override in `env_overrides.rs` is not a write path: it exists only in
// `dev-overrides` builds and calls `Config::set_active_mediator_did_runtime`,
// which never touches the persisted account record.

/// Update the organization DID.
///
/// R11: mutates + logs only (see [`update_friendly_name`]).
pub fn update_org_did(config: &mut Config, did: &str) {
    config.account.org_did = did.to_string();
    config
        .public
        .logs
        .insert(LogFamily::Config, format!("Org DID changed to '{}'", did));
    info!(did = %did, "org DID updated");
}

/// Set a passphrase to encrypt the config in the keyring.
///
/// R12: the Argon2id unlock-key derivation (~0.5–1 s of pure CPU) runs on a
/// `spawn_blocking` thread via `derive_passphrase_key_blocking` so it does
/// not peg the async event-loop / render task. The passphrase bytes are owned
/// by the blocking closure and zeroized there; the derived key is the only
/// thing returned. The subsequent `save_config` does not run Argon2 (it
/// AES-encrypts with the already-derived key), so this is the only KDF on this
/// path.
pub async fn set_passphrase(config: &mut Config, profile: &str, passphrase: &str) -> Result<()> {
    use openvtc_core::config::{
        ConfigProtectionType, derive_passphrase_key_blocking, validate_passphrase,
    };

    validate_passphrase(passphrase)?;
    let key = derive_passphrase_key_blocking(
        passphrase.as_bytes().to_vec(),
        b"openvtc-unlock-code-v1".to_vec(),
    )
    .await?;
    config.unlock_code = Some(SecretBox::new(Box::new(key.to_vec())));
    config.public.protection = ConfigProtectionType::Encrypted;
    config.public.logs.insert(
        LogFamily::Config,
        "Config protection changed to passphrase encrypted".to_string(),
    );
    save_config(config, profile)?;
    info!("config protection set to passphrase encrypted");
    Ok(())
}

/// Remove passphrase protection, reverting to keyring-only.
pub fn remove_passphrase(config: &mut Config, profile: &str) -> Result<()> {
    use openvtc_core::config::ConfigProtectionType;

    config.unlock_code = None;
    config.public.protection = ConfigProtectionType::Plaintext;
    config.public.logs.insert(
        LogFamily::Config,
        "Config protection changed to keyring only (no additional encryption)".to_string(),
    );
    save_config(config, profile)?;
    info!("config protection reverted to keyring only");
    Ok(())
}

/// Validate a file path for export/import operations.
fn validate_file_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        anyhow::bail!("File path cannot be empty");
    }
    if path.contains("..") {
        anyhow::bail!("Path traversal (..) is not allowed");
    }
    Ok(())
}

/// Export the config to a file, encrypted with the given passphrase.
///
/// R12: `Config::export` now derives its Argon2 export key off the runtime
/// (`spawn_blocking`), so this awaits it instead of blocking the loop.
pub async fn export_config(config: &Config, path: &str, passphrase: &str) -> Result<()> {
    validate_file_path(path)?;
    let secret = SecretString::new(passphrase.to_string().into());
    config.export(secret, path).await?;
    info!(path = %path, "config exported");
    Ok(())
}

/// Validate an import file, then direct the operator to the real restore flow.
///
/// Importing into a *running* profile would require swapping the live config
/// and reconnecting messaging, so it is intentionally not performed from the
/// Settings panel. The supported restore path lives in the setup wizard:
/// run `openvtc setup` and choose "Import" / "Restore Backup".
pub fn import_config(path: &str, _passphrase: &str) -> Result<String> {
    validate_file_path(path)?;
    // Validate the file exists
    if !std::path::Path::new(path).exists() {
        anyhow::bail!("File not found: {}", path);
    }
    Ok(format!(
        "Import from {} is not supported here — run `openvtc setup` and choose \
         Import / Restore Backup to restore an exported config.",
        path
    ))
}

// ============================================================
// State-handler dispatch wrappers
// ============================================================

use crate::state_handler::{
    actions::SettingsAction,
    dispatch_util,
    main_page::content::SettingsMode,
    save_coalesce::SaveScheduler,
    state::{self, State},
};
use tokio::sync::watch;

fn handle_select(state: &mut State, index: usize) {
    #[cfg(feature = "openpgp-card")]
    if let SettingsMode::TokenManagement { selected_index } =
        &mut state.main_page.content_panel.settings.mode
    {
        *selected_index = index;
    } else {
        state.main_page.content_panel.settings.selected_index = index;
    }
    #[cfg(not(feature = "openpgp-card"))]
    {
        state.main_page.content_panel.settings.selected_index = index;
    }
}

fn handle_start_edit(state: &mut State) {
    let idx = state.main_page.content_panel.settings.selected_index;
    let s = &state.main_page.content_panel.settings;
    state.main_page.content_panel.settings.mode = match idx {
        0 => SettingsMode::EditFriendlyName {
            input: s.friendly_name.clone(),
        },
        // `MEDIATOR_ROW` (1) is deliberately absent: the mediator is read-only,
        // so Enter on it falls through to `View` like any other unedittable row.
        2 => SettingsMode::EditOrgDid {
            input: s.org_did.clone(),
        },
        5 => SettingsMode::ExportConfig {
            path_input: "openvtc-export.enc".to_string(),
            passphrase_len: 0,
            active_field: 0,
        },
        6 => SettingsMode::ImportConfig {
            path_input: "openvtc-export.enc".to_string(),
            passphrase_len: 0,
            active_field: 0,
        },
        _ => SettingsMode::View,
    };
}

fn handle_field_update(state: &mut State, value: String) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::EditFriendlyName { input } | SettingsMode::EditOrgDid { input } => {
            *input = value;
        }
        _ => {}
    }
}

fn handle_form_field_update(state: &mut State, field: usize, value: String) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { path_input, .. }
        | SettingsMode::ImportConfig { path_input, .. }
            if field == 0 =>
        {
            *path_input = value;
        }
        _ => {}
    }
}

fn handle_passphrase_len(state: &mut State, len: usize) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { passphrase_len, .. }
        | SettingsMode::ImportConfig { passphrase_len, .. } => {
            *passphrase_len = len;
        }
        _ => {}
    }
}

fn handle_form_tab_switch(state: &mut State) {
    match &mut state.main_page.content_panel.settings.mode {
        SettingsMode::ExportConfig { active_field, .. }
        | SettingsMode::ImportConfig { active_field, .. } => {
            *active_field = if *active_field == 0 { 1 } else { 0 };
        }
        _ => {}
    }
}

fn handle_protection_option_select(state: &mut State, option: usize) {
    if let SettingsMode::ChangeProtection {
        selected_option, ..
    } = &mut state.main_page.content_panel.settings.mode
    {
        *selected_option = option;
    }
}

fn handle_protection_start_input(state: &mut State) {
    if let SettingsMode::ChangeProtection { active_field, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *active_field = 1;
    }
}

fn handle_protection_passphrase_len(state: &mut State, len: usize) {
    if let SettingsMode::ChangeProtection { passphrase_len, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *passphrase_len = len;
    }
}

fn handle_protection_confirm_len(state: &mut State, len: usize) {
    if let SettingsMode::ChangeProtection { confirm_len, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *confirm_len = len;
    }
}

fn handle_protection_tab_switch(state: &mut State, next_field: usize) {
    if let SettingsMode::ChangeProtection { active_field, .. } =
        &mut state.main_page.content_panel.settings.mode
    {
        *active_field = next_field;
    }
}

/// Commit the in-progress settings edit.
///
/// R11: the per-setting save is coalesced (`Persist::SaveAndSync` marks the
/// config dirty rather than saving inline).
///
/// No row here can decline to apply, and none triggers a mediator reconnect. The
/// mediator DID used to be the exception on both counts: it is a *per-persona*
/// field, so on a profile with no persona the write vanished while the panel
/// still said "Setting saved" over a field that read back empty ("it did not
/// take"), and it still asked for a reconnect that had nothing new to dial —
/// leaving the header on "Connecting…" under a success message. The row is now
/// read-only (`MEDIATOR_ROW` never opens an edit mode), so that whole shape is
/// gone rather than merely reported honestly.
fn handle_submit_edit(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    value: &str,
) {
    let idx = state.main_page.content_panel.settings.selected_index;
    match idx {
        0 => update_friendly_name(config, value),
        2 => update_org_did(config, value),
        _ => {}
    }
    let setting_name = match idx {
        0 => "Friendly name",
        2 => "Organization DID",
        _ => "Setting",
    };
    state.main_page.content_panel.settings.mode = SettingsMode::View;

    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        dispatch_util::Persist::SaveAndSync,
        |mp| &mut mp.content_panel.settings.status_message,
        "Setting saved",
        dispatch_util::SyncLog::Plain(format!("{} updated", setting_name)),
    );
}

async fn handle_export_config_action(
    config: &mut Box<Config>,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    save: &mut SaveScheduler,
    profile: &str,
    path: &str,
    passphrase: &str,
) {
    // R12: surface a "deriving" status *before* the blocking Argon2 derive so
    // the user sees progress while the key is computed off the runtime. Push it
    // to the render task now — `export_config` then awaits a `spawn_blocking`
    // derive, during which the loop is parked here but the render task keeps
    // drawing this status (the runtime is no longer pegged by the KDF).
    state.main_page.content_panel.settings.status_message =
        Some("Deriving encryption key…".to_string());
    let _ = state_tx.send(state.clone());

    match export_config(config, path, passphrase).await {
        Ok(()) => {
            config
                .public
                .logs
                .insert(LogFamily::Config, format!("Config exported to {}", path));
            // R11 force-flush: export is durability-critical (the exported file
            // must reflect persisted state and the export-log entry must hit
            // disk now). Keep this save synchronous on the loop thread — it is a
            // deliberate force-flush point, not the coalesced hot path. It also
            // clears any pending coalesced dirty state, so we drop the scheduler's
            // deadline below.
            if let Err(e) = save_config(config, profile) {
                state
                    .main_page
                    .log_error("Failed to persist export-log entry", &e);
            } else {
                save.clear_after_external_save();
            }
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                dispatch_util::Persist::None,
                |mp| &mut mp.content_panel.settings.status_message,
                format!("Config exported to {}", path),
                dispatch_util::SyncLog::Plain(format!("Config exported to {}", path)),
            );
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message =
                Some(format!("Export failed: {e:#}"));
            state.main_page.log_error("Config export failed", &e);
        }
    }
}

fn handle_import_config_action(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    profile: &str,
    path: &str,
    passphrase: &str,
) {
    match import_config(path, passphrase) {
        Ok(msg) => {
            config
                .public
                .logs
                .insert(LogFamily::Config, format!("Config imported from {}", path));
            // Force-flush the import-log entry (see export handler).
            if let Err(e) = save_config(config, profile) {
                state
                    .main_page
                    .log_error("Failed to persist import-log entry", &e);
            } else {
                save.clear_after_external_save();
            }
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                dispatch_util::Persist::None,
                |mp| &mut mp.content_panel.settings.status_message,
                msg.clone(),
                dispatch_util::SyncLog::Plain(msg),
            );
        }
        Err(e) => {
            state.main_page.content_panel.settings.status_message =
                Some(format!("Import failed: {e:#}"));
            state.main_page.log_error("Config import failed", &e);
        }
    }
}

fn handle_change_protection(state: &mut State) {
    state.main_page.content_panel.settings.mode = SettingsMode::ChangeProtection {
        selected_option: 0,
        passphrase_len: 0,
        confirm_len: 0,
        active_field: 0,
    };
}

async fn handle_set_passphrase(
    config: &mut Box<Config>,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    save: &mut SaveScheduler,
    profile: &str,
    passphrase: &str,
) {
    // R12: surface a "deriving" status *before* the blocking Argon2 derive so
    // the user sees progress while the unlock key is computed off the runtime.
    // Push it to the render task now; `set_passphrase` then awaits a
    // `spawn_blocking` derive, during which the render task keeps drawing.
    state.main_page.content_panel.settings.status_message =
        Some("Deriving encryption key…".to_string());
    let _ = state_tx.send(state.clone());

    // R11 force-flush: a protection change re-derives the unlock key and rewrites
    // the secured config; it MUST be persisted before reporting success (the
    // keyring entry now requires the new passphrase to decrypt). `set_passphrase`
    // saves synchronously — a deliberate force-flush point. (R12 moves its Argon2
    // derivation off the runtime.)
    match set_passphrase(config, profile, passphrase).await {
        Ok(()) => {
            // The synchronous save above already persisted the latest state;
            // drop any pending coalesced dirty mark so we don't redundantly
            // re-save.
            save.clear_after_external_save();
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                dispatch_util::Persist::SyncOnly,
                |mp| &mut mp.content_panel.settings.status_message,
                "Passphrase protection enabled",
                dispatch_util::SyncLog::Plain("Passphrase protection enabled".to_string()),
            );
            // Setting a passphrase can move the secret to durable storage (the
            // file store only accepts an encrypted blob), so the volatile
            // warning may have just become untrue. Re-probe rather than leave a
            // stale warning telling the user to do what they just did.
            state.main_page.refresh_storage_warning(profile);
        }
        Err(e) => {
            dispatch_util::record_error(
                &mut state.main_page,
                |mp| &mut mp.content_panel.settings.status_message,
                "Failed to set passphrase",
                &e,
            );
        }
    }
}

fn handle_remove_passphrase(
    config: &mut Box<Config>,
    state: &mut State,
    save: &mut SaveScheduler,
    profile: &str,
) {
    // R11 force-flush: same rationale as `handle_set_passphrase` — a protection
    // change must be on disk before reporting success. `remove_passphrase` saves
    // synchronously.
    match remove_passphrase(config, profile) {
        Ok(()) => {
            save.clear_after_external_save();
            state.main_page.content_panel.settings.mode = SettingsMode::View;
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                dispatch_util::Persist::SyncOnly,
                |mp| &mut mp.content_panel.settings.status_message,
                "Protection reverted to keyring only",
                dispatch_util::SyncLog::Plain("Protection reverted to keyring only".to_string()),
            );
            // The mirror of the set-passphrase case: dropping protection can
            // push the secret back to a volatile store, and the user should be
            // told that is what just happened.
            state.main_page.refresh_storage_warning(profile);
            if let Some(warning) = state
                .main_page
                .content_panel
                .settings
                .storage_warning
                .clone()
            {
                state.main_page.log(format!("WARNING: {warning}"));
            }
        }
        Err(e) => {
            dispatch_util::record_error(
                &mut state.main_page,
                |mp| &mut mp.content_panel.settings.status_message,
                "Failed to remove passphrase",
                &e,
            );
        }
    }
}

fn handle_wipe_start(state: &mut State) {
    state.main_page.content_panel.settings.mode = SettingsMode::WipeConfirm {
        confirm_input: String::new(),
    };
}

fn handle_wipe_input(state: &mut State, value: String) {
    if let SettingsMode::WipeConfirm { confirm_input } =
        &mut state.main_page.content_panel.settings.mode
    {
        *confirm_input = value;
    }
}

const WIPE_CONFIRM_TOKEN: &str = "WIPE";

fn handle_wipe_confirm(state: &mut State, profile: &str) -> bool {
    let typed = match &state.main_page.content_panel.settings.mode {
        SettingsMode::WipeConfirm { confirm_input } => confirm_input.trim().to_string(),
        _ => return false,
    };
    if !typed.eq_ignore_ascii_case(WIPE_CONFIRM_TOKEN) {
        state.main_page.content_panel.settings.status_message = Some(format!(
            "Type {WIPE_CONFIRM_TOKEN} (exactly) to confirm — wipe cancelled."
        ));
        state.main_page.content_panel.settings.mode = SettingsMode::View;
        return false;
    }

    if let Some(info) = state.main_page.content_panel.settings.did_git_sign.clone() {
        match did_git_sign::init::uninstall(true, &info.did_key_id) {
            Ok(summary) => {
                if let Some(path) = &summary.removed_config_file {
                    state
                        .main_page
                        .log(format!("Removed did-git-sign config: {}", path.display()));
                }
                if !summary.removed_keyring_entries.is_empty() {
                    state.main_page.log(format!(
                        "Removed did-git-sign keyring entries: {}",
                        summary.removed_keyring_entries.join(", ")
                    ));
                }
                if summary.allowed_signers_entry_removed {
                    state
                        .main_page
                        .log("Removed did-git-sign allowed_signers entry");
                }
                for w in &summary.warnings {
                    state.main_page.log(format!("did-git-sign uninstall: {w}"));
                }
            }
            Err(e) => {
                state
                    .main_page
                    .log_error("did-git-sign uninstall failed", &e);
            }
        }
    }

    match openvtc_core::config::public_config::PublicConfig::delete_profile(profile) {
        Ok(summary) => {
            if let Some(path) = &summary.removed_config_file {
                state
                    .main_page
                    .log(format!("Removed openvtc config: {path}"));
            }
            if summary.removed_keyring_entry {
                state.main_page.log("Removed openvtc keyring entry");
            }
            for w in &summary.warnings {
                state.main_page.log(format!("openvtc wipe: {w}"));
            }
        }
        Err(e) => {
            state
                .main_page
                .log_error("Failed to wipe openvtc profile", &e);
            state.main_page.content_panel.settings.status_message =
                Some(format!("Wipe failed: {e:#}"));
            return false;
        }
    }

    state.main_page.log("Profile wiped — exiting.");
    true
}

#[cfg(feature = "openpgp-card")]
fn handle_token_management(state: &mut State) {
    state.main_page.content_panel.settings.mode =
        SettingsMode::TokenManagement { selected_index: 0 };
    match openvtc_core::openpgp_card::get_cards() {
        Ok(cards) => {
            state.main_page.content_panel.settings.token.detected_count = cards.len();
            state
                .main_page
                .content_panel
                .settings
                .token
                .messages
                .clear();
        }
        Err(e) => {
            state.main_page.content_panel.settings.token.detected_count = 0;
            state.main_page.content_panel.settings.token.messages =
                vec![format!("Error detecting tokens: {e}")];
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_token_detect(state: &mut State) {
    match openvtc_core::openpgp_card::get_cards() {
        Ok(cards) => {
            state.main_page.content_panel.settings.token.detected_count = cards.len();
            state.main_page.content_panel.settings.token.messages =
                vec![format!("{} token(s) detected", cards.len())];
        }
        Err(e) => {
            state.main_page.content_panel.settings.token.detected_count = 0;
            state.main_page.content_panel.settings.token.messages = vec![format!("Error: {e}")];
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_token_factory_reset(state: &mut State) {
    match openvtc_core::openpgp_card::get_cards() {
        Ok(cards) if !cards.is_empty() => {
            match openvtc_core::openpgp_card::factory_reset(cards[0].clone()) {
                Ok(()) => {
                    state.main_page.content_panel.settings.token.messages =
                        vec!["Factory reset completed successfully.".to_string()];
                    state.main_page.content_panel.settings.token.reset_completed = true;
                }
                Err(e) => {
                    state.main_page.content_panel.settings.token.messages =
                        vec![format!("Factory reset failed: {e}")];
                }
            }
        }
        Ok(_) => {
            state.main_page.content_panel.settings.token.messages =
                vec!["No tokens detected. Insert a token first.".to_string()];
        }
        Err(e) => {
            state.main_page.content_panel.settings.token.messages = vec![format!("Error: {e}")];
        }
    }
}

#[cfg(feature = "openpgp-card")]
fn handle_token_back(state: &mut State) {
    state.main_page.content_panel.settings.mode = SettingsMode::View;
    state
        .main_page
        .content_panel
        .settings
        .token
        .messages
        .clear();
    state.main_page.content_panel.settings.token.reset_completed = false;
}

/// Set the synchronous "reconnecting" state — the immediate, non-blocking part
/// of a mediator reconnect. The slow `wait_connected` I/O is performed by a
/// background task spawned by the runtime loop (R13); its completion drives the
/// final `Connected`/`Failed` state via
/// [`crate::state_handler::background_dispatch::apply_outcome`]. The strings here
/// match the pre-R13 inline path so the activity log is unchanged.
fn begin_reconnect_status(state: &mut State) {
    state.connection.status = state::MediatorStatus::Connecting;
    state.connection.messaging_active = false;
    state.main_page.log("Reconnecting to mediator...");
}

/// Outcome of dispatching a `SettingsAction`.
///
/// The TUI loop ignores `Continue`, breaks out with `UserInt` when the operator
/// wipes the profile (the binary can no longer authenticate after a wipe), and
/// on `ReconnectMediator` spawns a background mediator reconnect (R13) — the slow
/// `wait_connected` wait runs off the select loop so the UI stays responsive.
pub(crate) enum SettingsOutcome {
    Continue,
    ExitUserInt,
    /// A mediator change or manual reconnect was requested. The loop builds the
    /// listener config and spawns the I/O; `begin_reconnect_status` has already
    /// set the synchronous "Connecting" state.
    ReconnectMediator,
}

/// Dispatch a single `SettingsAction`. Returns `ExitUserInt` if the
/// operator confirmed a profile wipe — caller is responsible for
/// driving the terminator afterwards.
pub(crate) async fn dispatch(
    action: SettingsAction,
    config: &mut Box<Config>,
    state: &mut State,
    state_tx: &watch::Sender<State>,
    save: &mut SaveScheduler,
    profile: &str,
) -> SettingsOutcome {
    match action {
        SettingsAction::Select(index) => handle_select(state, index),
        SettingsAction::StartEdit => handle_start_edit(state),
        SettingsAction::CancelEdit => {
            state.main_page.content_panel.settings.mode = SettingsMode::View;
        }
        SettingsAction::FieldUpdate(value) => handle_field_update(state, value),
        SettingsAction::FormFieldUpdate { field, value } => {
            handle_form_field_update(state, field, value)
        }
        SettingsAction::FormTabSwitch => handle_form_tab_switch(state),
        SettingsAction::ProtectionOptionSelect(option) => {
            handle_protection_option_select(state, option)
        }
        SettingsAction::ProtectionStartInput => handle_protection_start_input(state),
        SettingsAction::ProtectionPassphraseLen(len) => {
            handle_protection_passphrase_len(state, len)
        }
        SettingsAction::ProtectionConfirmLen(len) => handle_protection_confirm_len(state, len),
        SettingsAction::ProtectionTabSwitch(next_field) => {
            handle_protection_tab_switch(state, next_field)
        }
        SettingsAction::PassphraseLen(len) => handle_passphrase_len(state, len),
        // No editable setting changes the mediator any more, so committing one
        // never implies a reconnect. `SettingsAction::ReconnectMediator` is the
        // remaining (explicit, operator-driven) way to ask for one.
        SettingsAction::SubmitEdit { value } => handle_submit_edit(config, state, save, &value),
        SettingsAction::ExportConfig { path, passphrase } => {
            handle_export_config_action(config, state, state_tx, save, profile, &path, &passphrase)
                .await
        }
        SettingsAction::ImportConfig { path, passphrase } => {
            handle_import_config_action(config, state, save, profile, &path, &passphrase)
        }
        SettingsAction::ChangeProtection => handle_change_protection(state),
        SettingsAction::SetPassphrase { passphrase } => {
            handle_set_passphrase(config, state, state_tx, save, profile, &passphrase).await
        }
        SettingsAction::RemovePassphrase => handle_remove_passphrase(config, state, save, profile),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenManagement => handle_token_management(state),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenDetect => handle_token_detect(state),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenFactoryReset => handle_token_factory_reset(state),
        #[cfg(feature = "openpgp-card")]
        SettingsAction::TokenBack => handle_token_back(state),
        SettingsAction::ClipboardCopied(msg) => {
            state.main_page.content_panel.settings.status_message = Some(msg.clone());
            state.main_page.log(msg);
        }
        SettingsAction::WipeProfileStart => handle_wipe_start(state),
        SettingsAction::WipeProfileInput(value) => handle_wipe_input(state, value),
        SettingsAction::WipeProfileConfirm => {
            if handle_wipe_confirm(state, profile) {
                return SettingsOutcome::ExitUserInt;
            }
        }
        SettingsAction::ReconnectMediator => {
            begin_reconnect_status(state);
            return SettingsOutcome::ReconnectMediator;
        }
    }
    SettingsOutcome::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_file_path_rejects_empty() {
        assert!(validate_file_path("").is_err());
        assert!(validate_file_path("   ").is_err());
    }

    #[test]
    fn test_validate_file_path_rejects_traversal() {
        assert!(validate_file_path("../../etc/passwd").is_err());
        assert!(validate_file_path("foo/../bar").is_err());
    }

    #[test]
    fn test_validate_file_path_accepts_normal() {
        assert!(validate_file_path("export.enc").is_ok());
        assert!(validate_file_path("/home/user/backup.enc").is_ok());
    }

    #[test]
    fn test_validate_file_path_accepts_dot_slash() {
        assert!(validate_file_path("./local-file.dat").is_ok());
    }

    #[test]
    fn test_validate_file_path_rejects_hidden_traversal() {
        assert!(validate_file_path("/tmp/safe/../../../etc/shadow").is_err());
    }

    /// The reported bug, closed at the source: pressing Enter on the Mediator
    /// DID row must not open an edit mode at all. It used to, and on a profile
    /// with no persona the write then vanished while the panel said "Setting
    /// saved" over a field that read back empty ("it did not take").
    #[test]
    fn mediator_row_does_not_open_an_edit_mode() {
        let mut state = State::default();
        state.main_page.content_panel.settings.mediator_did = "did:webvh:example:mediator".into();
        state.main_page.content_panel.settings.selected_index =
            crate::ui::pages::main::components::settings_panel::MEDIATOR_ROW;

        handle_start_edit(&mut state);

        assert!(
            matches!(settings(&state), SettingsMode::View),
            "the mediator row is read-only, so Enter stays in View"
        );
    }

    /// A committed edit no longer implies a mediator reconnect — nothing
    /// editable can move the mediator, so the reconnect that used to fire (and
    /// hang on "Connecting…") has no trigger left.
    #[tokio::test]
    async fn submitting_an_edit_never_asks_for_a_reconnect() {
        let mut config = Box::new(crate::state_handler::dispatch_util::test_config());
        let mut state = State::default();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        let (state_tx, _rx) = watch::channel(State::default());

        for idx in [0usize, 1, 2] {
            state.main_page.content_panel.settings.selected_index = idx;
            let outcome = dispatch(
                SettingsAction::SubmitEdit {
                    value: "value".to_string(),
                },
                &mut config,
                &mut state,
                &state_tx,
                &mut save,
                "test",
            )
            .await;
            assert!(
                matches!(outcome, SettingsOutcome::Continue),
                "row {idx} must not request a mediator reconnect"
            );
        }
        assert_eq!(config.mediator_did(), "", "and no row wrote a mediator DID");
    }

    /// The other half: an editable row still reports success and keeps the
    /// existing coalesced-save behaviour, so removing the mediator edit has not
    /// disturbed the ordinary path.
    #[test]
    fn friendly_name_edit_still_reports_a_save() {
        let mut config = Box::new(crate::state_handler::dispatch_util::test_config());
        let mut state = State::default();
        let mut save = crate::state_handler::save_coalesce::SaveScheduler::new("test");
        state.main_page.content_panel.settings.selected_index = 0;

        handle_submit_edit(&mut config, &mut state, &mut save, "Alice");

        assert_eq!(
            state
                .main_page
                .content_panel
                .settings
                .status_message
                .as_deref(),
            Some("Setting saved")
        );
        assert_eq!(config.public.friendly_name, "Alice");
    }

    // ----------------------------------------------------------------
    // Table tests for the pure mode-transition handlers. Each is a pure
    // function of `&mut State`; the tables drive the handler from a starting
    // `State` and assert on the resulting settings-panel mode. Mirrors the
    // table-test style in `ui/pages/setup_flow/navigation.rs`.
    // ----------------------------------------------------------------

    fn settings(state: &State) -> &super::SettingsMode {
        &state.main_page.content_panel.settings.mode
    }

    /// A constructor for a representative `SettingsMode`, used by the tables to
    /// seed a starting mode / check a target discriminant.
    type ModeFn = fn() -> SettingsMode;

    /// `handle_start_edit` maps the selected setting index to the matching edit
    /// mode, seeding the input from the current value; unknown indices fall back
    /// to `View`. Table-driven over (selected_index, expected mode discriminant).
    #[test]
    fn start_edit_maps_index_to_mode() {
        // Closures returning a representative mode for the discriminant check.
        let cases: &[(usize, ModeFn)] = &[
            (0, || SettingsMode::EditFriendlyName {
                input: String::new(),
            }),
            // Row 1 is the read-only Mediator DID: it falls through to `View`
            // like any other unedittable row.
            (1, || SettingsMode::View),
            (2, || SettingsMode::EditOrgDid {
                input: String::new(),
            }),
            (5, || SettingsMode::ExportConfig {
                path_input: String::new(),
                passphrase_len: 0,
                active_field: 0,
            }),
            (6, || SettingsMode::ImportConfig {
                path_input: String::new(),
                passphrase_len: 0,
                active_field: 0,
            }),
            (3, || SettingsMode::View),
            (99, || SettingsMode::View),
        ];
        for (idx, expected) in cases {
            let mut state = State::default();
            state.main_page.content_panel.settings.friendly_name = "Alice".to_string();
            state.main_page.content_panel.settings.mediator_did = "did:med".to_string();
            state.main_page.content_panel.settings.org_did = "did:org".to_string();
            state.main_page.content_panel.settings.selected_index = *idx;
            handle_start_edit(&mut state);
            assert_eq!(
                std::mem::discriminant(settings(&state)),
                std::mem::discriminant(&expected()),
                "start_edit index {idx}"
            );
        }
        // The edit modes seed `input` from the current value.
        let mut state = State::default();
        state.main_page.content_panel.settings.friendly_name = "Alice".to_string();
        state.main_page.content_panel.settings.selected_index = 0;
        handle_start_edit(&mut state);
        assert!(matches!(
            settings(&state),
            SettingsMode::EditFriendlyName { input } if input == "Alice"
        ));
    }

    /// `handle_field_update` writes the single-line input for the two remaining
    /// edit modes and is a no-op elsewhere.
    #[test]
    fn field_update_writes_edit_input() {
        let edit_modes: &[ModeFn] = &[
            || SettingsMode::EditFriendlyName {
                input: String::new(),
            },
            || SettingsMode::EditOrgDid {
                input: String::new(),
            },
        ];
        for make in edit_modes {
            let mut state = State::default();
            state.main_page.content_panel.settings.mode = make();
            handle_field_update(&mut state, "new-value".to_string());
            let input = match settings(&state) {
                SettingsMode::EditFriendlyName { input } | SettingsMode::EditOrgDid { input } => {
                    input.clone()
                }
                other => panic!("unexpected mode {other:?}"),
            };
            assert_eq!(input, "new-value");
        }
        // No-op in View.
        let mut state = State::default();
        handle_field_update(&mut state, "ignored".to_string());
        assert!(matches!(settings(&state), SettingsMode::View));
    }

    /// `handle_change_protection` enters the `ChangeProtection` form zeroed, and
    /// the protection sub-field handlers then mutate exactly their field.
    #[test]
    fn change_protection_form_field_transitions() {
        let mut state = State::default();
        handle_change_protection(&mut state);
        assert!(matches!(
            settings(&state),
            SettingsMode::ChangeProtection {
                selected_option: 0,
                passphrase_len: 0,
                confirm_len: 0,
                active_field: 0,
            }
        ));

        handle_protection_option_select(&mut state, 1);
        handle_protection_passphrase_len(&mut state, 7);
        handle_protection_confirm_len(&mut state, 9);
        handle_protection_tab_switch(&mut state, 2);
        assert!(matches!(
            settings(&state),
            SettingsMode::ChangeProtection {
                selected_option: 1,
                passphrase_len: 7,
                confirm_len: 9,
                active_field: 2,
            }
        ));

        // `handle_protection_start_input` forces the active field to the
        // passphrase (1).
        let mut state = State::default();
        handle_change_protection(&mut state);
        handle_protection_start_input(&mut state);
        assert!(matches!(
            settings(&state),
            SettingsMode::ChangeProtection {
                active_field: 1,
                ..
            }
        ));
    }

    /// `handle_form_tab_switch` toggles the export/import form active field
    /// between 0 and 1; `handle_form_field_update`/`handle_passphrase_len`
    /// populate the path/passphrase-length.
    #[test]
    fn export_import_form_field_transitions() {
        for make in [
            (|| SettingsMode::ExportConfig {
                path_input: String::new(),
                passphrase_len: 0,
                active_field: 0,
            }) as ModeFn,
            || SettingsMode::ImportConfig {
                path_input: String::new(),
                passphrase_len: 0,
                active_field: 0,
            },
        ] {
            let mut state = State::default();
            state.main_page.content_panel.settings.mode = make();
            handle_form_field_update(&mut state, 0, "backup.enc".to_string());
            handle_passphrase_len(&mut state, 4);
            handle_form_tab_switch(&mut state); // 0 -> 1
            let (path, plen, field) = match settings(&state) {
                SettingsMode::ExportConfig {
                    path_input,
                    passphrase_len,
                    active_field,
                }
                | SettingsMode::ImportConfig {
                    path_input,
                    passphrase_len,
                    active_field,
                } => (path_input.clone(), *passphrase_len, *active_field),
                other => panic!("unexpected mode {other:?}"),
            };
            assert_eq!(path, "backup.enc");
            assert_eq!(plen, 4);
            assert_eq!(field, 1, "tab switch toggled 0 -> 1");
            handle_form_tab_switch(&mut state); // 1 -> 0
            let field = match settings(&state) {
                SettingsMode::ExportConfig { active_field, .. }
                | SettingsMode::ImportConfig { active_field, .. } => *active_field,
                other => panic!("unexpected mode {other:?}"),
            };
            assert_eq!(field, 0, "tab switch toggled 1 -> 0");
        }
    }

    /// `handle_wipe_start` enters `WipeConfirm` (empty input) and
    /// `handle_wipe_input` records the typed confirmation token.
    #[test]
    fn wipe_start_and_input_transitions() {
        let mut state = State::default();
        handle_wipe_start(&mut state);
        assert!(matches!(
            settings(&state),
            SettingsMode::WipeConfirm { confirm_input } if confirm_input.is_empty()
        ));
        handle_wipe_input(&mut state, "WIPE".to_string());
        assert!(matches!(
            settings(&state),
            SettingsMode::WipeConfirm { confirm_input } if confirm_input == "WIPE"
        ));

        // `handle_wipe_input` is a no-op outside WipeConfirm.
        let mut state = State::default();
        handle_wipe_input(&mut state, "WIPE".to_string());
        assert!(matches!(settings(&state), SettingsMode::View));
    }

    /// `handle_select` updates the selected index in `View`.
    #[test]
    fn select_updates_index() {
        let mut state = State::default();
        handle_select(&mut state, 4);
        assert_eq!(state.main_page.content_panel.settings.selected_index, 4);
    }
}
