//! Shared integration-test scaffolding.
//!
//! Wraps [`affinidi-messaging-test-mediator`]'s `TestMediator::with_users`
//! helper so each integration test gets the same mediator-plus-two-DIDs
//! setup without repeating the boilerplate. The fixture handles port
//! pre-bind, the mediator's `did:peer` (with `dm`/`#auth`/`#ws`
//! services), the JWT signing keypair, ALLOW_ALL ACL registration, and
//! — crucially — mints user DIDs whose service URI is the mediator's
//! DID rather than its HTTP URL. That last part is what makes
//! routing/2.0 forwards short-circuit to local delivery instead of
//! being enqueued to FORWARD_Q for external HTTP forwarding.
//!
//! Tests that boot the mediator are slow (~1s) so they're marked
//! `#[ignore]` by default. Run via:
//!
//!     cargo test -p openvtc-core -- --ignored
//!
//! CI's coverage job runs `--include-ignored` so the integration suite
//! still contributes to the report.
//!
//! ## Which messaging stack this builds
//!
//! [`ProfileMessaging`] / [`start_profile_messaging`] stand a profile up on the
//! **delivery layer** (`affinidi-messaging-delivery`'s `MessagingService` over a
//! `DidCommTransport`), not the `affinidi-messaging-didcomm-service` framework the
//! production code still uses. That is deliberate and it is the point: the harness
//! builds its own messaging stack, so had it stayed on the framework these tests
//! would keep passing while covering none of the migrated path (#189). Migrating it
//! first makes the suite the regression net for the production swap rather than a
//! green light that proves nothing.

#![allow(dead_code)]

use affinidi_messaging_core::{ConnState, MessageTransport};
use affinidi_messaging_delivery::{
    Delivery, InMemoryOutboxStore, MessagingService, OutboxStore, Sent, drain_loop_via,
};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_messaging_test_mediator::{TestMediator, TestMediatorHandle, TestMediatorUser};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use futures_util::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

/// A DIDComm profile generated for use by integration tests.
pub struct TestProfile {
    pub alias: String,
    pub did: String,
    pub secrets: Vec<Secret>,
    pub mediator_did: String,
}

/// In-process test mediator with two pre-registered DIDComm profiles
/// (Alice + Bob). Holds the [`TestMediatorHandle`] so the mediator
/// stays up for the lifetime of the test; tearing down on drop is
/// handled by the underlying handle.
pub struct MockMediator {
    pub handle: TestMediatorHandle,
    pub mediator_did: String,
    pub mediator_url: String,
    pub alice: TestProfile,
    pub bob: TestProfile,
}

impl MockMediator {
    /// Spawn the test mediator and register Alice + Bob as ALLOW_ALL
    /// local accounts via [`TestMediator::with_users`].
    pub async fn start() -> Result<Self> {
        let (handle, users) = TestMediator::with_users(["alice", "bob"]).await?;
        let mediator_did = handle.did().to_string();
        let mediator_url = handle.endpoint().to_string();

        let mut iter = users.into_iter();
        let alice = into_profile(iter.next().expect("alice"), &mediator_did);
        let bob = into_profile(iter.next().expect("bob"), &mediator_did);

        Ok(Self {
            handle,
            mediator_did,
            mediator_url,
            alice,
            bob,
        })
    }

    /// Convenience: clone the named profile (one of `"alice"` /
    /// `"bob"`). Tests typically destructure `mediator.alice` /
    /// `.bob` directly; this is for cases where the alias is dynamic.
    pub fn profile(&self, alias: &str) -> Option<TestProfile> {
        match alias {
            "alice" => Some(clone_profile(&self.alice)),
            "bob" => Some(clone_profile(&self.bob)),
            _ => None,
        }
    }
}

fn into_profile(user: TestMediatorUser, mediator_did: &str) -> TestProfile {
    TestProfile {
        alias: user.alias,
        did: user.did,
        secrets: user.secrets,
        mediator_did: mediator_did.to_string(),
    }
}

fn clone_profile(p: &TestProfile) -> TestProfile {
    TestProfile {
        alias: p.alias.clone(),
        did: p.did.clone(),
        secrets: p.secrets.clone(),
        mediator_did: p.mediator_did.clone(),
    }
}

/// Install a tracing subscriber so the mediator's logs surface in
/// `cargo test -- --nocapture`. Idempotent — subsequent calls are
/// no-ops once a global subscriber is installed.
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

/// A profile's messaging stack on the **delivery layer** — the replacement for
/// the `DIDCommService` the framework harness used to build.
///
/// Holds the pieces a test needs to send, plus the dispatcher task that pumps
/// inbound messages into the test's channel. Dropping it aborts the dispatcher.
///
/// The ATM and profile are kept because outbound is now a two-step the framework
/// used to hide: the delivery layer's `MessageTransport::send` takes **already
/// packed** bytes, so packing is the caller's job (`MessagingProtocol`'s concern,
/// not the transport's). This mirrors what `vtc-service` does on the same layer.
pub struct ProfileMessaging {
    pub service: Arc<MessagingService>,
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
    /// The transport id this profile is installed under — its own DID, matching
    /// the production convention where the transport *is* the identity.
    pub transport_id: String,
    did: String,
    dispatcher: tokio::task::JoinHandle<()>,
}

impl Drop for ProfileMessaging {
    fn drop(&mut self) {
        self.dispatcher.abort();
    }
}

impl ProfileMessaging {
    /// Wait until this profile's transport reports `Connected`, or `timeout`.
    ///
    /// Replaces the framework's `wait_connected`. Polls
    /// `transport_state`, which reads the transport's live connection signal
    /// rather than a boot-time latch — so a transport that connects, drops and
    /// reconnects is reported truthfully throughout (R6.2).
    pub async fn wait_connected(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.service.transport_state(&self.transport_id) == Some(ConnState::Connected) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "transport {} did not reach Connected within {timeout:?} (last state: {:?})",
                    self.transport_id,
                    self.service.transport_state(&self.transport_id)
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Pack `message` authcrypt (from this profile's DID to `to`) and send it over
    /// this profile's transport.
    ///
    /// `Delivery::Guaranteed` rather than `BestEffort`, because the framework call
    /// this replaces (`send_message_with_retry`) retried on a disconnected
    /// listener. The outbox is that retry, so a send issued while the socket is
    /// reconnecting still lands instead of failing the test flakily.
    pub async fn send(&self, message: &Message, to: &str) -> Result<Sent> {
        let (packed, _meta) = self
            .atm
            .pack_encrypted(message, to, Some(&self.did), Some(&self.did))
            .await?;
        let sent = self
            .service
            .send_via(
                &self.transport_id,
                to,
                packed.into_bytes(),
                Delivery::Guaranteed {
                    idempotency_key: Some(message.id.clone()),
                    ordering_key: None,
                    deliver_by: Duration::from_secs(30),
                },
            )
            .await?;
        Ok(sent)
    }
}

/// Build a profile's messaging stack on the delivery layer, capturing inbound
/// messages whose type is in `routes` into `inbound_tx`.
///
/// The construction sequence is the canonical one (secrets seeded **before**
/// `ATM::new`, profile via `from_tdk_profile`, then `profile_add(_, true)` to
/// bring the websocket up before binding the transport) — `DidCommTransport::new`
/// fails on a profile with no websocket running.
///
/// The transport is installed under the profile's **DID** rather than the
/// `"default"` id, so this harness exercises the same
/// one-transport-per-identity shape the production code uses.
///
/// Type filtering replaces the old `Router`: the delivery layer has no
/// type-routed dispatch, so a consumer matches on the message itself — the same
/// move `vtc-service` made when it cut over.
pub async fn start_profile_messaging(
    profile: TestProfile,
    routes: &[&'static str],
    inbound_tx: mpsc::UnboundedSender<Message>,
) -> Result<ProfileMessaging> {
    let wanted: Vec<String> = routes.iter().map(|r| (*r).to_string()).collect();
    start_profile(profile, move |received: Received| {
        if wanted.contains(&received.message.typ) {
            let _ = inbound_tx.send(received.message);
        }
    })
    .await
}

/// A message as the transport delivered it: unpacked, with the sender the
/// transport *verified* (authcrypt), or `None` when it could not.
pub struct Received {
    pub message: Message,
    pub authenticated: Option<String>,
}

/// Like [`start_profile_messaging`], but every inbound message — whatever its
/// type — goes to `inbound_tx` with its authenticated sender, so a test can put
/// it through the inbound gate and the dispatcher exactly as the app does.
pub async fn start_profile_inbound(
    profile: TestProfile,
    inbound_tx: mpsc::UnboundedSender<Received>,
) -> Result<ProfileMessaging> {
    start_profile(profile, move |received| {
        let _ = inbound_tx.send(received);
    })
    .await
}

async fn start_profile(
    profile: TestProfile,
    sink: impl Fn(Received) + Send + 'static,
) -> Result<ProfileMessaging> {
    let TestProfile {
        alias,
        did,
        secrets,
        mediator_did,
    } = profile;

    let tdk_profile = TDKProfile::new(&alias, &did, Some(&mediator_did), secrets.clone());
    let tdk = Arc::new(TDKSharedState::new(TDKConfig::builder().build()?).await?);
    for secret in secrets {
        tdk.secrets_resolver().insert(secret).await;
    }
    let atm = ATM::new(ATMConfig::builder().build()?, tdk).await?;
    let atm_profile = ATMProfile::from_tdk_profile(&atm, &tdk_profile).await?;
    let profile = atm.profile_add(&atm_profile, true).await?;

    let transport: Arc<dyn MessageTransport> =
        Arc::new(DidCommTransport::new(atm.clone(), profile.clone()).await?);
    // The store is held here as well as handed to the service: `MessagingService`
    // does not expose its outbox, and the drain needs the same one the service
    // enqueues into.
    let store: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
    // `empty` + `add_transport` rather than `new`, which would install the
    // transport as `"default"`. Keying it by DID is what makes this harness
    // exercise the production one-transport-per-identity shape.
    let service = Arc::new(MessagingService::empty(store.clone()));
    service.add_transport(did.clone(), transport.clone());

    // One drain per identity, keyed by the same id the transport is installed
    // under, so a `Guaranteed` send is retried over its own socket rather than
    // another identity's.
    let drain = tokio::spawn(drain_loop_via(
        store,
        did.clone(),
        transport,
        Duration::from_millis(200),
    ));

    let dispatcher = {
        let mut inbound = service.subscribe();
        tokio::spawn(async move {
            // Keep the drain alive for as long as the dispatcher: both die with
            // the `ProfileMessaging` that owns them.
            let _drain = drain;
            while let Some(item) = inbound.next().await {
                let Ok(message) = serde_json::from_slice::<Message>(&item.message.payload) else {
                    continue;
                };
                // The delivery layer reports the hop it unwrapped (the
                // mediator's forward) as `sender`, not the authcrypt sender of
                // the inner message, and keeps the unpack metadata to itself.
                // Every message in these tests is authcrypt-packed by the
                // harness (`ProfileMessaging::send`), so the inner `from` is
                // the sealing party; it stands in for what the app reads from
                // `encrypted_from_kid`. A plaintext message gets none.
                let authenticated = message.from.clone().filter(|_| item.message.encrypted);
                sink(Received {
                    message,
                    authenticated,
                });
            }
        })
    };

    Ok(ProfileMessaging {
        service,
        atm,
        profile,
        transport_id: did.clone(),
        did,
        dispatcher,
    })
}
