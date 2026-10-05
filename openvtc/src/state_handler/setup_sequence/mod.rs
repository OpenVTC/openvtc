// ****************************************************************************
// Setup Sequence Pages
// ****************************************************************************

#[cfg(feature = "openpgp-card")]
use ::openpgp_card::{Card, state::Open};
use affinidi_tdk::did_common::Document;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use openvtc_core::config::PersonaDIDKeys;
use secrecy::SecretBox;
use std::fmt;
use std::sync::Arc;
#[cfg(feature = "openpgp-card")]
use tokio::sync::Mutex;
use vta_sdk::provision_client::{AdminCredentialReply, DiagEntry, EphemeralSetupKey, Protocol};

pub mod config;
#[cfg(feature = "openpgp-card")]
pub mod openpgp_card;
pub mod provision_failure;
pub mod vta;

/// Setup flow has many pages, they are listed here
#[derive(Debug, Clone, Copy, Default)]
pub enum SetupPage {
    #[default]
    StartAsk,
    ConfigImport, // Optional path where user will import existing config
    /// Online provisioning entry — operator enters the VTA DID.
    VtaEnterDid,
    /// Operator runs `pnm contexts create … --admin-did <setup>` and presses Enter.
    VtaAclInstructions,
    /// Live diagnostics list while `provision_client::run_connection_test` runs.
    VtaProvisioning,
    /// The chosen Trust Context already holds an account (D5). Shown only when
    /// the probe found something, so a genuine first run never sees it.
    ContextOccupied,
    /// What recovering that context would restore, and what it would not.
    /// Reached from [`SetupPage::ContextOccupied`] via `[R]`.
    RecoverConfirm,

    /// Optional PGP Token setup occurs here
    #[cfg(feature = "openpgp-card")]
    TokenStart,
    #[cfg(feature = "openpgp-card")]
    TokenSelect,
    #[cfg(feature = "openpgp-card")]
    TokenFactoryReset,
    #[cfg(feature = "openpgp-card")]
    TokenSetTouch,
    #[cfg(feature = "openpgp-card")]
    TokenSetCardholderName,

    UnlockCodeAsk,
    UnlockCodeSet,
    UnlockCodeWarn,
    FinalPage,
}

// R-A-5 moved persona minting out of setup and into the State-B join flow, which
// drives it headlessly from `JoinProgress` rather than through wizard pages. The
// pages that used to walk an operator through it — mediator choice, display name,
// webvh address/server, DID-key display and export, did-git-sign install — were
// left behind unreachable, and stayed that way long enough to start reading as
// live code. They are gone; `SetupState` keeps the *fields* they wrote, because
// the join flow now fills the same struct itself before calling
// `Config::mint_persona_into`.

// ****************************************************************************
// State Management for the Setup Sequence
//
// All setup state is kept in a single struct
// ****************************************************************************

#[derive(Clone, Default, Debug)]
pub struct SetupState {
    pub active_page: SetupPage,

    pub config_import: ConfigImport,

    /// VTA setup state
    pub vta: VtaSetupState,

    /// Persona DID keys minted for the identity currently being created.
    ///
    /// Written by the State-B join flow / standalone persona mint, then read by
    /// `Config::mint_persona_into`. Setup itself no longer fills this in.
    pub did_keys: Option<PersonaDIDKeys>,

    /// How is the config protected?
    pub protection: ConfigProtection,

    /// PGP Hardware Tokens that are connected
    #[cfg(feature = "openpgp-card")]
    pub tokens: DetectedTokens,

    /// Hardware Token Reset State
    #[cfg(feature = "openpgp-card")]
    pub token_reset: FactoryResetToken,

    /// Hardware Touch Policy
    #[cfg(feature = "openpgp-card")]
    pub token_set_touch: TokenSetTouchPolicy,

    /// Hardware Cardholder Name
    #[cfg(feature = "openpgp-card")]
    pub token_cardholder_name: TokenSetCardholderName,

    /// Has the user selected to use a custom Mediator?
    pub custom_mediator: Option<String>,

    /// What username is the user using?
    pub username: String,

    /// What address to use for WebVH?
    pub webvh_address: WebVHAddress,

    pub final_page: FinalSetupPage,
}

/// A recovery plan and the account it would produce.
///
/// Held together because the confirmation page needs both: the plan carries
/// what was rejected and why, the account carries what will actually be
/// written and which personas had to be skipped.
#[derive(Clone, Debug)]
pub struct RebuildOutcome {
    /// What the VTA holds, verified.
    pub plan: openvtc_core::rebuild::RebuildPlan,
    /// The account that would be written.
    pub account: openvtc_core::rebuild_apply::RebuiltAccount,
}

/// VTA-specific setup state
///
/// `Debug` is implemented manually because `EphemeralSetupKey` doesn't expose
/// `Debug` (and shouldn't — its private key would otherwise leak into logs).
#[derive(Clone, Default)]
pub struct VtaSetupState {
    pub vta_url: String,
    pub vta_did: String,
    pub credential_did: String,
    pub authenticated: bool,
    pub access_token: Option<String>,
    pub messages: Vec<MessageType>,
    pub completed: Completion,
    pub context_id: Option<String>,
    pub update_secret: Option<Secret>,
    pub next_update_secret: Option<Secret>,
    /// Ephemeral did:key minted at VtaEnterDid; used as the admin DID the
    /// operator authorises via `pnm contexts create --admin-did …`.
    /// `Arc` because `EphemeralSetupKey` isn't `Clone` and `SetupState`
    /// derives `Clone` for the watch channel.
    pub setup_key: Option<Arc<EphemeralSetupKey>>,
    /// What the chosen Trust Context already contained, once provisioning has
    /// authenticated far enough to look (D5–D7).
    ///
    /// `None` until the probe runs. `Occupied` routes the wizard through
    /// [`SetupPage::ContextOccupied`] before anything is written, so pointing a
    /// fresh install at a context already in use is a decision rather than a
    /// silent collision.
    pub context_probe: Option<openvtc_core::context_probe::ProbeOutcome>,

    /// What a recovery of this context would restore, once the operator has
    /// asked. `None` until `[R]` is pressed; `Some(Err(..))` when the plan
    /// could not be built, so the page can say why rather than showing an
    /// empty result.
    pub rebuild: Option<Result<RebuildOutcome, String>>,

    /// Live diagnostics list streamed from `provision_client::run_connection_test`.
    pub diagnostics: Vec<DiagEntry>,
    /// Admin credential issued by the VTA on successful provisioning. The
    /// `admin_did` becomes the new `credential_did` and the matching private
    /// key is what `challenge_response` re-authenticates with.
    pub admin_credential: Option<AdminCredentialReply>,
    /// Transport the bootstrap actually used. `Some(Protocol::Tsp)` /
    /// `Some(Protocol::DidComm)` mean downstream calls must reuse that
    /// transport — the VTA may advertise no REST service at all, in which case
    /// there is no URL to fall back to; `Some(Protocol::Rest)` means REST.
    /// `None` until provisioning completes.
    pub protocol: Option<Protocol>,
    /// Mediator DID that carried the bootstrap, captured from
    /// `VtaEvent::Connected`: the `#tsp` mediator when the chosen transport is
    /// TSP, the `#DIDCommMessaging` one when it is DIDComm. Required to open
    /// further sessions on either transport post-bootstrap; `None` on REST.
    pub mediator_did: Option<String>,
}

impl fmt::Debug for VtaSetupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VtaSetupState")
            .field("vta_url", &self.vta_url)
            .field("vta_did", &self.vta_did)
            .field("credential_did", &self.credential_did)
            .field("authenticated", &self.authenticated)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("messages", &self.messages)
            .field("completed", &self.completed)
            .field("context_id", &self.context_id)
            .field(
                "update_secret",
                &self.update_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "next_update_secret",
                &self.next_update_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "setup_key",
                &self
                    .setup_key
                    .as_ref()
                    .map(|k| format!("<setup_key did={}>", k.did)),
            )
            .field("diagnostics", &self.diagnostics)
            .field(
                "admin_credential",
                &self
                    .admin_credential
                    .as_ref()
                    .map(|a| format!("<admin_did={}>", a.admin_did)),
            )
            .field("protocol", &self.protocol)
            .field("mediator_did", &self.mediator_did)
            .finish()
    }
}

/// How is the configuration protected?
#[derive(Clone, Default)]
pub enum ConfigProtection {
    #[default]
    PlainText,
    #[cfg(feature = "openpgp-card")]
    Token(String),
    /// Is a SHA256 digest of the input passcode
    Passcode(Arc<SecretBox<Vec<u8>>>),
}

impl std::fmt::Debug for ConfigProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigProtection::PlainText => write!(f, "ConfigProtection::PlainText"),
            #[cfg(feature = "openpgp-card")]
            ConfigProtection::Token(token_id) => {
                write!(f, "ConfigProtection::Token({})", token_id)
            }
            ConfigProtection::Passcode(_) => write!(f, "ConfigProtection::Passcode(****)"),
        }
    }
}

/// Helps format messages from backend to the frontend
#[derive(Clone, Debug)]
pub enum MessageType {
    Info(String),
    Error(String),
}

/// Completion States for tasks
#[derive(Clone, Debug, Default)]
pub enum Completion {
    #[default]
    NotFinished,
    CompletedOK,
    CompletedFail,
}

/// State relating to importing configuration
#[derive(Clone, Default, Debug)]
pub struct ConfigImport {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
}

/// State relating to detecting attached hardware tokens
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default)]
pub struct DetectedTokens {
    pub tokens: Vec<Arc<Mutex<Card<Open>>>>,
    pub messages: Vec<String>,
}

#[cfg(feature = "openpgp-card")]
impl fmt::Debug for DetectedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DetectedTokens {{ tokens: {}, messages: {:?} }}",
            self.tokens.len(),
            self.messages
        )
    }
}

/// State relating to factory reset of hardware token
/// Also contains writing keys to the token
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default, Debug)]
pub struct FactoryResetToken {
    pub completed_reset: bool,
    pub completed_writing: bool,
    pub messages: Vec<MessageType>,
}

/// State relating to token touch policy
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default, Debug)]
pub struct TokenSetTouchPolicy {
    pub completed: bool,
    pub messages: Vec<MessageType>,
}

/// State relating to token cardholder name
#[cfg(feature = "openpgp-card")]
#[derive(Clone, Default, Debug)]
pub struct TokenSetCardholderName {
    pub completed: bool,
    pub messages: Vec<MessageType>,
}

/// The `did:webvh` minted for the persona currently being created — filled in
/// by the join flow / standalone mint, read by `Config::mint_persona_into`.
#[derive(Clone, Default, Debug)]
pub struct WebVHAddress {
    pub did: String,
    pub document: Document,
}

/// Final Setup Page State
#[derive(Clone, Default, Debug)]
pub struct FinalSetupPage {
    pub completed: Completion,
    pub messages: Vec<MessageType>,
}
