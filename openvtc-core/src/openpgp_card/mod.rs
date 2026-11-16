//!   Handles everything todo with openpgp-card tokens

use crate::errors::OpenVTCError;
use card_backend_pcsc::PcscBackend;
use openpgp_card::{Card, state::Open};
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod crypt;

/// Get a list of active cards on this system
/// Returns a Vector containg Arc as the PGP Card struct doesn't allow copy/clone
pub fn get_cards() -> Result<Vec<Arc<Mutex<Card<Open>>>>, OpenVTCError> {
    let mut cards = vec![];

    for backend in PcscBackend::cards(None)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't get list of tokens. Reason: {e}")))?
    {
        let card =
            Card::<Open>::new(backend.map_err(|e| {
                OpenVTCError::Token(format!("Couldn't get card backend. Reason: {e}"))
            })?)
            .map_err(|e| OpenVTCError::Token(format!("Couldn't open card. Reason: {e}")))?;
        cards.push(Arc::new(Mutex::new(card)));
    }

    Ok(cards)
}

/// Opens a specific openpgp-card by an identifier
pub fn open_card(token_id: &str) -> Result<Card<Open>, OpenVTCError> {
    let cards = PcscBackend::card_backends(None)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't get PGP cards backend: {}", e)))?;
    let card = Card::<Open>::open_by_ident(cards, token_id)
        .map_err(|e| OpenVTCError::Token(format!("Couldn't open card ({token_id}): {e}")))?;

    Ok(card)
}

/// The card's application identifier (`ident`) and manufacturer name — what a
/// person needs to tell one connected card from another.
pub fn card_identity(card: &Arc<Mutex<Card<Open>>>) -> Result<(String, String), OpenVTCError> {
    let mut lock = card
        .try_lock()
        .map_err(|e| OpenVTCError::Token(format!("Couldn't lock card: {e}")))?;
    let tx = lock
        .transaction()
        .map_err(|e| OpenVTCError::Token(format!("Couldn't get card transaction: {e}")))?;
    let id = tx
        .application_identifier()
        .map_err(|e| OpenVTCError::Token(format!("Couldn't read card identifier: {e}")))?;
    Ok((id.ident(), id.manufacturer_name().to_string()))
}

/// Performs a factory reset on the card, erasing all keys and data
pub fn factory_reset(card: Arc<Mutex<Card<Open>>>) -> Result<(), OpenVTCError> {
    let mut lock = card
        .try_lock()
        .map_err(|e| OpenVTCError::Token(format!("Couldn't lock card for factory reset: {e}")))?;
    let mut card = lock.transaction().map_err(|e| {
        OpenVTCError::Token(format!("Couldn't get transaction for factory reset: {e}"))
    })?;
    card.factory_reset()
        .map_err(|e| OpenVTCError::Token(format!("Factory reset failed: {e}")))?;

    Ok(())
}
