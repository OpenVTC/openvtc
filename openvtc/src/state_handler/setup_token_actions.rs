#[cfg(feature = "openpgp-card")]
use std::sync::Arc;

#[cfg(feature = "openpgp-card")]
use crate::state_handler::{
    setup_sequence::{ConfigProtection, MessageType, SetupPage},
    state::State,
};
#[cfg(feature = "openpgp-card")]
use openpgp_card::{Card, state::Open};
#[cfg(feature = "openpgp-card")]
use openvtc_core::openpgp_card::{factory_reset, get_cards};
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;
#[cfg(feature = "openpgp-card")]
use tokio::sync::{Mutex, watch};

/// Handle the `GetTokens` action: fetch connected PGP hardware tokens.
#[cfg(feature = "openpgp-card")]
pub(crate) fn handle_get_tokens(state: &mut State) {
    state.setup.active_page = SetupPage::TokenSelect;
    match get_cards() {
        Ok(cards) => {
            state.setup.tokens.tokens = cards;
        }
        Err(e) => {
            state.setup.tokens.messages = vec![format!("Error fetching tokens: {}", e)];
            state.setup.tokens.tokens = vec![];
        }
    }
}

/// Handle the `SetAdminPin` action.
#[cfg(feature = "openpgp-card")]
pub(crate) fn handle_set_admin_pin(state: &mut State, token: String, admin_pin: SecretString) {
    state.setup.protection = ConfigProtection::Token(token);
    state.token_admin_pin = Some(Arc::new(admin_pin));
    state.setup.active_page = SetupPage::TokenFactoryReset;
}

/// Handle the `FactoryReset` action.
#[cfg(feature = "openpgp-card")]
pub(crate) async fn handle_factory_reset(state: &mut State, token: Option<Arc<Mutex<Card<Open>>>>) {
    if let Some(token) = token {
        state
            .setup
            .token_reset
            .messages
            .push(MessageType::Info("Starting factory reset...".to_string()));
        let mut state_clone = state.clone();
        let reset = tokio::spawn(async move {
            match factory_reset(token) {
                Ok(_) => {
                    state_clone
                        .setup
                        .token_reset
                        .messages
                        .push(MessageType::Info(
                            "Factory reset completed successfully.".to_string(),
                        ));
                    state_clone.setup.token_reset.completed_reset = true;
                }
                Err(e) => state_clone
                    .setup
                    .token_reset
                    .messages
                    .push(MessageType::Error(format!("Factory reset failed: {}", e))),
            }
            state_clone.setup.token_reset
        })
        .await;
        match reset {
            Ok(token_reset) => state.setup.token_reset = token_reset,
            Err(e) => state
                .setup
                .token_reset
                .messages
                .push(MessageType::Error(format!(
                    "Factory reset task failed: {e}"
                ))),
        }
    } else {
        state
            .setup
            .token_reset
            .messages
            .push(MessageType::Error("No token was specified.".to_string()));
    }
    state.setup.active_page = SetupPage::TokenFactoryReset;
}

/// Handle the `TokenWriteKeys` action.
#[cfg(feature = "openpgp-card")]
pub(crate) async fn handle_token_write_keys(
    state: &mut State,
    state_tx: &watch::Sender<std::sync::Arc<State>>,
    token: Option<Arc<Mutex<Card<Open>>>>,
) {
    use crate::state_handler::setup_sequence::openpgp_card::write_keys_to_card;

    if let Some(token) = token {
        let state_tx_clone = state_tx.clone();
        let mut state_clone = state.clone();
        let result = tokio::spawn(async move {
            match write_keys_to_card(&mut state_clone, &state_tx_clone, token) {
                Ok(_) => {
                    state_clone
                        .setup
                        .token_reset
                        .messages
                        .push(MessageType::Info(
                            "Keys written to token successfully.".to_string(),
                        ));
                    state_clone.setup.token_reset.completed_writing = true;
                }
                Err(e) => {
                    state_clone
                        .setup
                        .token_reset
                        .messages
                        .push(MessageType::Error(format!(
                            "Error writing keys to token: {}",
                            e
                        )));
                }
            }
            state_clone.setup.token_reset
        })
        .await;
        match result {
            Ok(token_reset) => state.setup.token_reset = token_reset,
            Err(e) => state
                .setup
                .token_reset
                .messages
                .push(MessageType::Error(format!("Write keys task failed: {e}"))),
        }
    } else {
        state
            .setup
            .token_reset
            .messages
            .push(MessageType::Error("No token was specified.".to_string()));
    }
}

/// Handle the `SetTouchPolicy` action.
#[cfg(feature = "openpgp-card")]
pub(crate) fn handle_set_touch_policy(
    state: &mut State,
    state_tx: &watch::Sender<std::sync::Arc<State>>,
    token: Option<Arc<Mutex<Card<Open>>>>,
) {
    use crate::state_handler::setup_sequence::openpgp_card::set_signing_touch_policy;

    state.setup.active_page = SetupPage::TokenSetTouch;
    if let Some(token) = token {
        match set_signing_touch_policy(state, state_tx, token) {
            Ok(_) => state.setup.token_set_touch.completed = true,
            Err(e) => {
                state
                    .setup
                    .token_set_touch
                    .messages
                    .push(MessageType::Error(format!(
                        "An error occurred when setting touch policy: {e}"
                    )));
            }
        }
    } else {
        state
            .setup
            .token_set_touch
            .messages
            .push(MessageType::Error("No token was specified.".to_string()));
    }
}

/// Handle the `SetTokenName` action.
#[cfg(feature = "openpgp-card")]
pub(crate) fn handle_set_token_name(
    state: &mut State,
    state_tx: &watch::Sender<std::sync::Arc<State>>,
    token: Option<Arc<Mutex<Card<Open>>>>,
    name: &str,
) {
    use crate::state_handler::setup_sequence::openpgp_card::set_cardholder_name;

    state.setup.active_page = SetupPage::TokenSetCardholderName;
    if let Some(token) = token {
        match set_cardholder_name(state, state_tx, token, name) {
            Ok(_) => state.setup.token_cardholder_name.completed = true,
            Err(e) => {
                state
                    .setup
                    .token_cardholder_name
                    .messages
                    .push(MessageType::Error(format!(
                        "An error occurred when setting cardholder name: {e}"
                    )));
            }
        }
    } else {
        state
            .setup
            .token_cardholder_name
            .messages
            .push(MessageType::Error("No token was specified.".to_string()));
    }
}
