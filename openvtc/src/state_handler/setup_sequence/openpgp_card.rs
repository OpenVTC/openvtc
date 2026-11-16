//!   Handles writing of data to the OpenPGP Card

use crate::state_handler::state::PublishState;

use anyhow::{Result, bail};
use ed25519_dalek_bip32::VerifyingKey;
use openpgp_card::{
    Card,
    ocard::{KeyType, data::TouchPolicy},
    state::Open,
};
use openpgp_card_rpgp::UploadableKey;
use openvtc_core::{KeyPurpose, config::KeyInfo};
use pgp::types::Timestamp;
use pgp::{
    crypto::{self, ed25519::Mode, public_key::PublicKeyAlgorithm},
    packet::{PacketHeader, PublicKey, SecretKey},
    types::{
        EcdhKdfType, EcdhPublicParams, EddsaLegacyPublicParams, KeyVersion, PlainSecretParams,
        PublicParams, SecretParams, Tag,
    },
};
use std::sync::Arc;
use tokio::sync::{Mutex, watch};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::state_handler::{setup_sequence::MessageType, state::State};

/// Writes keys to the card
pub fn write_keys_to_card(
    state: &mut State,
    action_tx: &watch::Sender<std::sync::Arc<State>>,
    card: Arc<Mutex<Card<Open>>>,
) -> Result<()> {
    state
        .setup
        .token_reset
        .messages
        .push(MessageType::Info("Writing keys to token...".to_string()));

    let Some(keys) = &state.setup.did_keys else {
        bail!("DID persona Keys don't exist");
    };

    state.setup.token_reset.messages.push(MessageType::Info(
        "Unlocking token in admin mode...".to_string(),
    ));
    let _ = action_tx.publish(state);
    // Try unlocking the card with the admin PIN
    let mut lock = card
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Failed to acquire lock on hardware token"))?;
    let mut open_card = lock.transaction()?;
    open_card.verify_admin_pin(
        state
            .token_admin_pin
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Admin PIN not set"))?
            .as_ref()
            .clone(),
    )?;
    let mut card = open_card.as_admin_card(None)?;
    if let Some(last) = state.setup.token_reset.messages.last_mut() {
        *last = MessageType::Info("✓ Unlocked token in admin mode".to_string());
    }
    let _ = action_tx.publish(state);

    // Create a PGP secret key packet
    state.setup.token_reset.messages.push(MessageType::Info(
        "Writing signing key to token...".to_string(),
    ));
    let _ = action_tx.publish(state);
    let uk = create_pgp_secret_packet(&keys.signing, KeyPurpose::Signing)?;
    card.import_key(&uk, KeyType::Signing)?;
    if let Some(last) = state.setup.token_reset.messages.last_mut() {
        *last = MessageType::Info("✓ Signing key written to token".to_string());
    }

    state.setup.token_reset.messages.push(MessageType::Info(
        "Writing authentication key to token...".to_string(),
    ));
    let _ = action_tx.publish(state);
    let uk = create_pgp_secret_packet(&keys.authentication, KeyPurpose::Authentication)?;
    card.import_key(&uk, KeyType::Authentication)?;
    if let Some(last) = state.setup.token_reset.messages.last_mut() {
        *last = MessageType::Info("✓ Authentication key written to token".to_string());
    }

    state.setup.token_reset.messages.push(MessageType::Info(
        "Writing decryption key to token...".to_string(),
    ));
    let _ = action_tx.publish(state);
    let uk = create_pgp_secret_packet(&keys.decryption, KeyPurpose::Encryption)?;
    card.import_key(&uk, KeyType::Decryption)?;
    if let Some(last) = state.setup.token_reset.messages.last_mut() {
        *last = MessageType::Info("✓ Decryption key written to token".to_string());
    }

    Ok(())
}

/// Creates a PGP secret key packet from key details
fn create_pgp_secret_packet(key: &KeyInfo, kp: KeyPurpose) -> Result<UploadableKey> {
    let (pk, sp) = match kp {
        KeyPurpose::Signing => {
            // Packet Length is 51 octets for EdDSA Legacy Keys (which is what is most supported)
            let packet_header = PacketHeader::new_fixed(Tag::PublicKey, 51);

            let pk = PublicKey::new_with_header(
                packet_header,
                KeyVersion::V4,
                PublicKeyAlgorithm::EdDSALegacy,
                Timestamp::now(),
                key.expiry.map(|e| e.num_days() as u16),
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
                    key: VerifyingKey::from_bytes(
                        key.secret
                            .get_public_bytes()
                            .first_chunk::<32>()
                            .ok_or_else(|| {
                                anyhow::anyhow!("Public key bytes shorter than 32 bytes")
                            })?,
                    )?,
                }),
            )?;

            // Create SecretParams
            let sp = SecretParams::Plain(PlainSecretParams::EdDSALegacy(
                crypto::eddsa_legacy::SecretKey::Ed25519(
                    crypto::ed25519::SecretKey::try_from_bytes(
                        *key.secret
                            .get_private_bytes()
                            .first_chunk::<32>()
                            .ok_or_else(|| {
                                anyhow::anyhow!("Private key bytes shorter than 32 bytes")
                            })?,
                        Mode::EdDSALegacy,
                    )?,
                ),
            ));

            (pk, sp)
        }
        KeyPurpose::Authentication => {
            // Packet Length is 51 octets for EdDSA Legacy Keys (which is what is most supported)
            let packet_header = PacketHeader::new_fixed(Tag::PublicKey, 51);

            let pk = PublicKey::new_with_header(
                packet_header,
                KeyVersion::V4,
                PublicKeyAlgorithm::EdDSALegacy,
                Timestamp::now(),
                key.expiry.map(|e| e.num_days() as u16),
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 {
                    key: VerifyingKey::from_bytes(
                        key.secret
                            .get_public_bytes()
                            .first_chunk::<32>()
                            .ok_or_else(|| {
                                anyhow::anyhow!("Public key bytes shorter than 32 bytes")
                            })?,
                    )?,
                }),
            )?;

            // Create SecretParams
            let sp = SecretParams::Plain(PlainSecretParams::EdDSALegacy(
                crypto::eddsa_legacy::SecretKey::Ed25519(
                    crypto::ed25519::SecretKey::try_from_bytes(
                        *key.secret
                            .get_private_bytes()
                            .first_chunk::<32>()
                            .ok_or_else(|| {
                                anyhow::anyhow!("Private key bytes shorter than 32 bytes")
                            })?,
                        Mode::EdDSALegacy,
                    )?,
                ),
            ));

            (pk, sp)
        }
        KeyPurpose::Encryption => {
            // Packet Length is 56 octets for ECDH
            let packet_header = PacketHeader::new_fixed(Tag::PublicKey, 56);

            let x25519_sk = StaticSecret::from(
                *key.secret
                    .get_private_bytes()
                    .first_chunk::<32>()
                    .ok_or_else(|| anyhow::anyhow!("Private key bytes shorter than 32 bytes"))?,
            );
            let x25519_pk = X25519PublicKey::from(&x25519_sk);

            let pk = PublicKey::new_with_header(
                packet_header,
                KeyVersion::V4,
                PublicKeyAlgorithm::ECDH,
                Timestamp::now(),
                key.expiry.map(|e| e.num_days() as u16),
                PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy {
                    p: x25519_pk,
                    hash: crypto::hash::HashAlgorithm::Sha256,
                    alg_sym: crypto::sym::SymmetricKeyAlgorithm::AES256,
                    ecdh_kdf_type: EcdhKdfType::Native,
                }),
            )?;

            // Create SecretParams
            let sp = SecretParams::Plain(PlainSecretParams::ECDH(
                crypto::ecdh::SecretKey::Curve25519Legacy(x25519_sk.into()),
            ));

            (pk, sp)
        }
        _ => bail!("Invalid Key Purpose being used to import secret key to hardware token"),
    };

    // Convert to uploadable key
    Ok(SecretKey::new(pk, sp)?.into())
}

pub fn set_signing_touch_policy(
    state: &mut State,
    action_tx: &watch::Sender<std::sync::Arc<State>>,
    card: Arc<Mutex<Card<Open>>>,
) -> Result<()> {
    let mut lock = card
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Failed to acquire lock on hardware token"))?;
    let mut open_card = lock.transaction()?;
    open_card.verify_admin_pin(
        state
            .token_admin_pin
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Admin PIN not set"))?
            .as_ref()
            .clone(),
    )?;
    let mut card = open_card.as_admin_card(None)?;

    state.setup.token_set_touch.messages.push(MessageType::Info(
        "Setting touch policy on signing key...".to_string(),
    ));
    let _ = action_tx.publish(state);

    card.set_touch_policy(KeyType::Signing, TouchPolicy::On)?;
    state.setup.token_set_touch.messages.push(MessageType::Info(
        "✓ Successfully enabled touch policy.".to_string(),
    ));

    Ok(())
}

/// Sets the cardholder name
/// name: Max length is 39 characters
pub fn set_cardholder_name(
    state: &mut State,
    action_tx: &watch::Sender<std::sync::Arc<State>>,
    card: Arc<Mutex<Card<Open>>>,
    name: &str,
) -> Result<()> {
    let mut lock = card
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Failed to acquire lock on hardware token"))?;
    let mut open_card = lock.transaction()?;
    open_card.verify_admin_pin(
        state
            .token_admin_pin
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Admin PIN not set"))?
            .as_ref()
            .clone(),
    )?;
    let mut card = open_card.as_admin_card(None)?;

    state
        .setup
        .token_cardholder_name
        .messages
        .push(MessageType::Info(format!(
            "Setting cardholder name to ({name})..."
        )));
    let _ = action_tx.publish(state);
    card.set_cardholder_name(name)?;
    state
        .setup
        .token_cardholder_name
        .messages
        .push(MessageType::Info(
            "✓ Successfully set cardholder name!".to_string(),
        ));

    Ok(())
}
