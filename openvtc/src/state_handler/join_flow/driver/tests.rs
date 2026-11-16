//! The join driver, offline (#529).
//!
//! Everything the join does that touches the network, the disk or a live
//! messaging account goes through [`JoinIo`]; [`Fake`] stands in for it, so a
//! whole launch runs on an offline TDK, a listener-less messaging service and a
//! bare config — and fails wherever a test says, which is what shows the saga
//! undoing exactly what it made.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use openvtc_core::config::account::PersonaRecord;
use openvtc_core::didcomm::DIDCommEvent;
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::state_handler::dispatch_util::{test_config, test_tdk};

const COMMUNITY: &str = "did:web:community.example";
const MEDIATOR: &str = "did:web:mediator.example";
const MINTED_DID: &str = "did:webvh:minted.example";
const REUSED_DID: &str = "did:webvh:reused.example";

/// Where a fake launch stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fail {
    Nowhere,
    /// The community offers no messaging transport.
    NoTransport,
    Context,
    Mint,
    /// The answers from the face are refused.
    Answers,
    HiddenRefusal,
    SubmitSend,
    SubmitSigner,
    /// The invitation stage never finishes — for a cancel to land in.
    HangInInvite,
    /// The submit waits for the test to release it — the request is on the
    /// wire while it waits.
    GatedSubmit,
}

struct Fake {
    fail: Fail,
    /// Listeners the compensation removed.
    removed: Mutex<Vec<String>>,
    saves: AtomicUsize,
    /// A resolve that waits for the test to answer it.
    resolve_gate: Mutex<Option<oneshot::Receiver<Result<String, String>>>>,
    /// Released by the test to let a `GatedSubmit` submit finish.
    submit_gate: Mutex<Option<oneshot::Receiver<()>>>,
}

impl Fake {
    fn new(fail: Fail) -> Arc<Self> {
        Arc::new(Self {
            fail,
            removed: Mutex::new(Vec::new()),
            saves: AtomicUsize::new(0),
            resolve_gate: Mutex::new(None),
            submit_gate: Mutex::new(None),
        })
    }

    fn removed(&self) -> Vec<String> {
        self.removed.lock().unwrap().clone()
    }
}

impl JoinIo for Fake {
    fn resolve(
        &self,
        _resolver: DIDCacheClient,
        _name: String,
    ) -> IoFuture<'static, Result<String, String>> {
        let gate = self.resolve_gate.lock().unwrap().take();
        Box::pin(async move {
            match gate {
                Some(gate) => gate.await.unwrap_or_else(|_| Err("gate dropped".into())),
                None => Ok(COMMUNITY.to_string()),
            }
        })
    }

    fn discover(&self, req: DiscoverReq) -> IoFuture<'static, Discovered> {
        Box::pin(async move {
            Discovered {
                invitations: req.invitations.map(|_| Vec::new()),
                manifest: req.manifest.then(|| {
                    Err(NotLearned::Unresolvable(
                        "it could not be resolved (offline)".into(),
                    ))
                }),
                document: None,
            }
        })
    }

    fn reach(&self, _req: ReachReq, _progress: Progress) -> IoFuture<'static, Reached> {
        let fail = self.fail;
        Box::pin(async move {
            Reached {
                display_name: None,
                transports: PeerTransports {
                    tsp_mediator: None,
                    didcomm_mediator: (fail != Fail::NoTransport).then(|| MEDIATOR.to_string()),
                },
            }
        })
    }

    fn context(&self, _req: ContextReq) -> IoFuture<'static, Result<bool, String>> {
        let fail = self.fail;
        Box::pin(async move {
            if fail == Fail::Context {
                Err("the VTA refused".into())
            } else {
                Ok(true)
            }
        })
    }

    fn mint(&self, _req: MintReq, _progress: Progress) -> IoFuture<'static, MintedParts> {
        let fail = self.fail;
        Box::pin(async move {
            MintedParts {
                failure: (fail == Fail::Mint)
                    .then(|| "Failed to create persona keys: the VTA refused".to_string()),
                ..MintedParts::default()
            }
        })
    }

    fn invite(&self, req: InviteReq, _progress: Progress) -> IoFuture<'static, Invited> {
        let fail = self.fail;
        Box::pin(async move {
            if fail == Fail::HangInInvite {
                std::future::pending::<()>().await;
            }
            Invited {
                listener_up: req.listener.as_ref().map(|_| true),
                presentable: None,
            }
        })
    }

    fn present(&self, _req: PresentReq, _progress: Progress) -> IoFuture<'static, Presented> {
        let fail = self.fail;
        Box::pin(async move {
            let failure = match fail {
                Fail::Answers => Some("Could not put your face on this persona: refused".into()),
                Fail::HiddenRefusal => Some(NO_ATTESTATION.to_string()),
                _ => None,
            };
            Presented {
                linkage: None,
                attributes: Vec::new(),
                proof: None,
                failure,
            }
        })
    }

    fn submit(&self, req: SubmitReq, _progress: Progress) -> IoFuture<'static, Submitted> {
        let fail = self.fail;
        let gate = self.submit_gate.lock().unwrap().take();
        Box::pin(async move {
            if fail == Fail::GatedSubmit
                && let Some(gate) = gate
            {
                let _ = gate.await;
            }
            let request = match req.prepared {
                Err(e) => Err(e),
                Ok(_) if fail == Fail::SubmitSend => Err(SubmitError::Send(OpenVTCError::Config(
                    "our mediator refused the frame".into(),
                ))),
                Ok(_) => Ok(uuid::Uuid::new_v4()),
            };
            Submitted {
                transport: MessagingTransport::DidComm,
                online: true,
                request,
            }
        })
    }

    fn persist_mint<'a>(
        &'a self,
        config: &'a mut Config,
        _setup: &'a SetupState,
        _tdk: &'a TDK,
        _profile: &'a str,
    ) -> IoFuture<'a, anyhow::Result<PersonaId>> {
        Box::pin(async move { Ok(seed_persona(config, MINTED_DID, "")) })
    }

    fn can_message(&self, _tdk: &TDK) -> bool {
        true
    }

    fn identity(&self, config: &Config, persona: PersonaId) -> Option<(String, String)> {
        config
            .account
            .personas
            .get(&persona)
            .map(|p| (p.did.clone(), MEDIATOR.to_string()))
    }

    fn listener_spec<'a>(
        &'a self,
        messaging: Option<&'a Messaging>,
        _config: &'a Config,
        _tdk: &'a TDK,
        _persona: PersonaId,
        did: &'a str,
    ) -> IoFuture<'a, Option<ListenerSpec>> {
        Box::pin(async move {
            messaging.map(|_| ListenerSpec {
                id: openvtc_core::didcomm::persona_listener_id(did),
                did: did.to_string(),
                mediator_did: MEDIATOR.to_string(),
                label: "applicant".into(),
                secrets: Vec::new(),
                collection: None,
            })
        })
    }

    fn prepare_submit<'a>(
        &'a self,
        _config: &'a Config,
        _tdk: &'a TDK,
        _persona: PersonaId,
    ) -> IoFuture<'a, Result<Option<PreparedSubmit>, SubmitError>> {
        let fail = self.fail;
        Box::pin(async move {
            if fail == Fail::SubmitSigner {
                Err(SubmitError::Signer(OpenVTCError::Secret(
                    "the key could not be read".into(),
                )))
            } else {
                Ok(None)
            }
        })
    }

    fn remove_listener<'a>(&'a self, _messaging: &'a Messaging, id: &'a str) -> IoFuture<'a, ()> {
        self.removed.lock().unwrap().push(id.to_string());
        Box::pin(async {})
    }

    fn save<'a>(
        &'a self,
        _save: &'a mut SaveScheduler,
        _config: &'a Config,
    ) -> IoFuture<'a, Result<(), OpenVTCError>> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

fn seed_persona(config: &mut Config, did: &str, origin_context_id: &str) -> PersonaId {
    let persona_id = PersonaId::new();
    config.account.personas.insert(
        persona_id,
        PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id,
            did: did.into(),
            did_document: None,
            did_locator: None,
            key_refs: vec![],
            mediator_did: None,
            origin_context_id: origin_context_id.into(),
            created_at: Utc::now(),
            label: None,
        },
    );
    persona_id
}

/// The loop a join is driven from, played by the test.
struct Harness {
    state: State,
    config: Config,
    tdk: TDK,
    admin: VtaClient,
    messaging: Messaging,
    save: SaveScheduler,
    dispatch_tx: UnboundedSender<DispatchOutcome>,
    dispatch_rx: UnboundedReceiver<DispatchOutcome>,
    in_flight: InFlight,
    state_tx: watch::Sender<Arc<State>>,
    driver: JoinDriver,
    fake: Arc<Fake>,
    _events: mpsc::UnboundedReceiver<DIDCommEvent>,
}

impl Harness {
    async fn new(fail: Fail) -> Self {
        let fake = Fake::new(fail);
        let (event_tx, events) = mpsc::unbounded_channel();
        let messaging = openvtc_core::didcomm::start_empty_service(
            event_tx,
            tokio_util::sync::CancellationToken::new(),
        );
        let (dispatch_tx, dispatch_rx) = mpsc::unbounded_channel();
        let (state_tx, _) = watch::channel(Arc::new(State::default()));
        let mut config = test_config();
        // A VTA account with a mediator, which a mint requires.
        config.key_backend = openvtc_core::config::KeyBackend::Vta {
            credential_bundle: secrecy::SecretString::new("bundle".into()),
            credential_did: "did:key:admin".into(),
            credential_private_key: secrecy::SecretString::new("key".into()),
            vta_did: "did:web:vta.example".into(),
            vta_url: String::new(),
            mediator_did: Some(MEDIATOR.into()),
            encryption_seed: secrecy::SecretBox::new(Box::new(vec![0u8; 32])),
        };
        Self {
            state: State::default(),
            config,
            tdk: test_tdk().await,
            // Never dialled: every VTA call goes through the fake.
            admin: VtaClient::new("http://127.0.0.1:1"),
            messaging,
            // Never flushed either: saves go through the fake too.
            save: SaveScheduler::new("join-driver-test"),
            dispatch_tx,
            dispatch_rx,
            in_flight: InFlight::default(),
            state_tx,
            driver: JoinDriver::with_io(true, fake.clone()),
            fake,
            _events: events,
        }
    }

    fn parts(&mut self) -> (&mut JoinDriver, JoinCtx<'_>) {
        let Harness {
            state,
            config,
            tdk,
            admin,
            messaging,
            save,
            dispatch_tx,
            in_flight,
            state_tx,
            driver,
            ..
        } = self;
        (
            driver,
            JoinCtx {
                state,
                config,
                tdk,
                admin_vta: Some(admin),
                messaging: Some(messaging),
                profile: "join-driver-test",
                save,
                dispatch_tx,
                in_flight,
                state_tx,
            },
        )
    }

    async fn enter(&mut self, entry: JoinEntry) -> JoinStep {
        let (driver, mut ctx) = self.parts();
        driver.enter(&mut ctx, entry).await
    }

    async fn act(&mut self, action: Action) -> JoinStep {
        let (driver, mut ctx) = self.parts();
        driver.on_action(&mut ctx, action).await
    }

    async fn cancel(&mut self) {
        let (driver, mut ctx) = self.parts();
        driver.cancel(&mut ctx).await;
    }

    fn job_in_flight(&self) -> bool {
        self.driver
            .session
            .as_ref()
            .is_some_and(|s| s.job.is_some())
    }

    /// Apply outcomes until no join job is in flight.
    async fn run_jobs(&mut self) -> JoinStep {
        let mut step = JoinStep::Continue;
        while self.job_in_flight() {
            let outcome = tokio::time::timeout(Duration::from_secs(5), self.dispatch_rx.recv())
                .await
                .expect("a join job finishes")
                .expect("the dispatch channel is open");
            match outcome {
                DispatchOutcome::Join(outcome) => {
                    let (driver, mut ctx) = self.parts();
                    step = driver.on_outcome(&mut ctx, *outcome).await;
                }
                DispatchOutcome::Progress(ProgressUpdate::Join { generation, line }) => {
                    self.driver.on_progress(&mut self.state, generation, line);
                }
                _ => {}
            }
        }
        step
    }

    /// Run the launch stages one at a time until `stop` says the launch is
    /// parked where the test wants it.
    async fn run_until(&mut self, stop: impl Fn(&Harness) -> bool) {
        while self.job_in_flight() && !stop(self) {
            let outcome = tokio::time::timeout(Duration::from_secs(5), self.dispatch_rx.recv())
                .await
                .expect("a join job finishes")
                .expect("the dispatch channel is open");
            if let DispatchOutcome::Join(outcome) = outcome {
                let (driver, mut ctx) = self.parts();
                driver.on_outcome(&mut ctx, *outcome).await;
            }
        }
    }

    /// Open the join and launch it as `pick`, with the registry question
    /// answered — the last page before anything is sent.
    async fn launch(&mut self, pick: IdentityPick) {
        assert!(matches!(
            self.enter(JoinEntry::Fresh).await,
            JoinStep::Continue
        ));
        self.state.join.registry = Some(RegistryChoice {
            publish: false,
            community: COMMUNITY.to_string(),
            community_name: None,
            confirmed: false,
            parked: Some((pick, COMMUNITY.to_string(), "acct/community".to_string())),
            review: None,
            directory: None,
        });
        assert!(matches!(
            self.act(Action::JoinRegistryConfirm).await,
            JoinStep::Continue
        ));
        assert!(
            self.job_in_flight(),
            "the launch's first stage runs off the loop"
        );
        assert!(self.state.join.processing, "input is locked while it runs");
    }

    fn last_error(&self) -> Option<&str> {
        self.state.join.messages.iter().rev().find_map(|m| match m {
            MessageType::Error(e) => Some(e.as_str()),
            MessageType::Info(_) => None,
        })
    }

    fn said(&self, needle: &str) -> bool {
        self.state.join.messages.iter().any(|m| match m {
            MessageType::Info(t) | MessageType::Error(t) => t.contains(needle),
        })
    }

    fn persona(&self, did: &str) -> bool {
        self.config.account.personas.values().any(|p| p.did == did)
    }

    /// The launch is over and the join page is unlocked, with the domain free.
    fn assert_settled(&self) {
        assert!(!self.job_in_flight());
        assert!(self.driver.saga().is_none(), "the launch has ended");
        assert!(!self.state.join.processing, "input unlocks");
        assert!(!self.in_flight.is_busy(DispatchDomain::Join));
        assert!(self.driver.is_active(), "the join page stays up");
    }
}

fn listener_of(did: &str) -> String {
    openvtc_core::didcomm::persona_listener_id(did)
}

// ---- The launch saga, failed at each stage ----

#[tokio::test]
async fn no_transport_fails_before_anything_is_made() {
    let mut h = Harness::new(Fail::NoTransport).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert!(
        h.last_error()
            .is_some_and(|e| e.contains("advertises no messaging transport")
                && e.contains("Nothing was created"))
    );
    assert!(h.config.account.personas.is_empty());
    assert!(h.fake.removed().is_empty());
    assert_eq!(h.fake.saves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_context_failure_stops_before_the_mint() {
    let mut h = Harness::new(Fail::Context).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert_eq!(
        h.last_error(),
        Some("Could not prepare context acct/community: the VTA refused. Nothing was created.")
    );
    assert!(h.said("Community reachable over"));
    assert!(h.config.account.personas.is_empty());
    assert_eq!(h.fake.saves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_mint_failure_leaves_no_persona() {
    let mut h = Harness::new(Fail::Mint).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert_eq!(
        h.last_error(),
        Some("Failed to create persona keys: the VTA refused")
    );
    assert!(h.said("Created context acct/community."));
    assert!(h.config.account.personas.is_empty());
    assert!(h.fake.removed().is_empty());
}

#[tokio::test]
async fn refused_answers_undo_the_minted_persona_and_its_listener() {
    let mut h = Harness::new(Fail::Answers).await;
    h.config.public.friendly_name = "before the join".into();
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert_eq!(
        h.last_error(),
        Some("Could not put your face on this persona: refused")
    );
    assert!(!h.persona(MINTED_DID), "the minted persona is rolled back");
    assert_eq!(h.fake.removed(), vec![listener_of(MINTED_DID)]);
    assert_eq!(h.config.public.friendly_name, "before the join");
    assert_eq!(
        h.fake.saves.load(Ordering::SeqCst),
        1,
        "the rollback is saved at once"
    );
}

#[tokio::test]
async fn a_hidden_refusal_undoes_the_minted_persona_and_its_listener() {
    let mut h = Harness::new(Fail::HiddenRefusal).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert_eq!(h.last_error(), Some(NO_ATTESTATION));
    assert!(!h.persona(MINTED_DID));
    assert_eq!(h.fake.removed(), vec![listener_of(MINTED_DID)]);
}

#[tokio::test]
async fn a_failed_send_undoes_a_minted_persona_and_its_listener() {
    let mut h = Harness::new(Fail::SubmitSend).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert!(
        h.last_error()
            .is_some_and(|e| e.starts_with("Failed to submit join request:"))
    );
    assert!(!h.persona(MINTED_DID));
    assert_eq!(h.fake.removed(), vec![listener_of(MINTED_DID)]);
    assert!(h.config.account.memberships().next().is_none());
}

/// A failed send as a *reused* persona must not delete that persona from the
/// account (#529). The saga never records a reused persona as minted, so only
/// the listener this launch opened is undone.
#[tokio::test]
async fn a_failed_send_never_removes_a_reused_persona() {
    let mut h = Harness::new(Fail::SubmitSend).await;
    let reused = seed_persona(&mut h.config, REUSED_DID, "");
    h.launch(IdentityPick::Reuse(reused)).await;
    h.run_jobs().await;
    h.assert_settled();
    assert!(
        h.last_error()
            .is_some_and(|e| e.starts_with("Failed to submit join request:"))
    );
    assert!(h.said(&format!("Reusing persona {REUSED_DID}…")));
    assert!(h.persona(REUSED_DID), "a reused persona is never forgotten");
    assert_eq!(h.fake.removed(), vec![listener_of(REUSED_DID)]);
    assert_eq!(h.fake.saves.load(Ordering::SeqCst), 0, "nothing to save");
}

/// An unreadable signing key undoes nothing — the persona and its listener
/// stay, as they always did on this path.
#[tokio::test]
async fn a_signer_failure_keeps_the_persona_and_its_listener() {
    let mut h = Harness::new(Fail::SubmitSigner).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert!(
        h.last_error()
            .is_some_and(|e| e.starts_with("Couldn't sign the application:"))
    );
    assert!(h.persona(MINTED_DID));
    assert!(h.fake.removed().is_empty());
}

#[tokio::test]
async fn a_sent_join_is_recorded_and_nothing_is_undone() {
    let mut h = Harness::new(Fail::Nowhere).await;
    h.launch(IdentityPick::Mint).await;
    h.run_jobs().await;
    h.assert_settled();
    assert!(h.last_error().is_none());
    assert!(matches!(h.state.join.completed, Completion::CompletedOK));
    let record = h
        .state
        .join
        .created_community
        .clone()
        .expect("the pending membership is on the page");
    assert_eq!(record.vtc_did, COMMUNITY);
    assert!(
        h.config
            .account
            .memberships()
            .any(|m| m.vtc_did == COMMUNITY)
    );
    assert!(h.persona(MINTED_DID));
    assert!(h.fake.removed().is_empty());
    assert_eq!(
        h.fake.saves.load(Ordering::SeqCst),
        1,
        "the membership is saved"
    );
    // Enter on the finished page leaves with the joined session.
    let step = h.act(Action::JoinCancel).await;
    assert!(matches!(step, JoinStep::Returned(Some(_))));
    assert!(!h.driver.is_active());
}

/// A cancel lands mid-stage — the listener is claimed and connecting — and
/// undoes the launch from its saga, at once.
#[tokio::test]
async fn a_cancel_mid_stage_undoes_the_launch() {
    let mut h = Harness::new(Fail::HangInInvite).await;
    h.launch(IdentityPick::Mint).await;
    h.run_until(|h| h.driver.saga().is_some_and(|s| s.listener().is_some()))
        .await;
    let saga = h.driver.saga().cloned().expect("the launch is in flight");
    assert!(saga.minted_persona().is_some());
    assert!(h.job_in_flight(), "parked in the invitation stage");

    let step = h.act(Action::Exit).await;
    assert!(matches!(step, JoinStep::Exit(Interrupted::UserInt)));
    assert!(!h.driver.is_active());
    assert!(!h.in_flight.is_busy(DispatchDomain::Join));
    assert!(!h.persona(MINTED_DID), "the minted persona is rolled back");
    assert_eq!(h.fake.removed(), vec![listener_of(MINTED_DID)]);
    assert!(h.said(
        "Join cancelled. Any partially-minted persona was rolled back; a sub-context may remain at the VTA."
    ));
    assert!(
        h.state
            .main_page
            .activity_log
            .iter()
            .any(|e| e.summary.contains("Join cancelled by user."))
    );
}

/// The loop stopping (an interrupt) cancels the same way, and a reused
/// persona survives it.
#[tokio::test]
async fn an_interrupt_mid_stage_keeps_a_reused_persona() {
    let mut h = Harness::new(Fail::HangInInvite).await;
    let reused = seed_persona(&mut h.config, REUSED_DID, "");
    h.launch(IdentityPick::Reuse(reused)).await;
    h.run_until(|h| h.driver.saga().is_some_and(|s| s.listener().is_some()))
        .await;
    h.cancel().await;
    assert!(!h.driver.is_active());
    assert!(h.persona(REUSED_DID));
    assert_eq!(h.fake.removed(), vec![listener_of(REUSED_DID)]);
}

// ---- Resolve: off the loop, cancellable, keys queued behind it ----

#[tokio::test]
async fn keys_pressed_while_a_name_resolves_are_queued_and_replayed() {
    let mut h = Harness::new(Fail::Nowhere).await;
    let (answer, gate) = oneshot::channel();
    *h.fake.resolve_gate.lock().unwrap() = Some(gate);
    h.enter(JoinEntry::Fresh).await;
    h.act(Action::JoinSubmitVtc("example.com/@acme".into()))
        .await;
    assert!(h.job_in_flight(), "the name resolves off the loop");
    assert!(h.said("Resolving example.com/@acme…"));

    let before = h.state.join.new_persona_did_method;
    h.act(Action::JoinNewPersonaMethodCycle).await;
    assert_eq!(
        h.state.join.new_persona_did_method, before,
        "held back while the job runs"
    );

    answer.send(Ok(COMMUNITY.to_string())).unwrap();
    h.run_jobs().await;
    // Resolved, then read: the fake community does not resolve.
    assert_eq!(h.state.join.page, JoinPage::Vetting);
    assert_eq!(h.state.join.pending_vtc.as_deref(), Some(COMMUNITY));

    // Due now, ahead of anything new on the channel.
    let (_tx, mut rx) = mpsc::unbounded_channel();
    let replay = h
        .driver
        .next_action(&mut rx)
        .await
        .expect("the held-back key is replayed");
    h.act(replay).await;
    assert_eq!(
        h.state.join.new_persona_did_method,
        next_did_method(before),
        "and acted on"
    );
}

#[tokio::test]
async fn esc_while_a_name_resolves_aborts_it() {
    let mut h = Harness::new(Fail::Nowhere).await;
    let (answer, gate) = oneshot::channel::<Result<String, String>>();
    *h.fake.resolve_gate.lock().unwrap() = Some(gate);
    h.enter(JoinEntry::Fresh).await;
    h.act(Action::JoinSubmitVtc("example.com/@acme".into()))
        .await;
    assert!(h.in_flight.is_busy(DispatchDomain::Join));

    let step = h.act(Action::JoinCancel).await;
    assert!(matches!(step, JoinStep::Returned(None)));
    assert!(matches!(h.state.active_page, ActivePage::Main));
    assert!(!h.driver.is_active());
    assert!(!h.in_flight.is_busy(DispatchDomain::Join));
    // The resolve was dropped where it waited.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(answer.is_closed(), "the aborted resolve no longer listens");
    assert!(h.dispatch_rx.try_recv().is_err(), "and reports nothing");
}

#[tokio::test]
async fn a_stale_outcome_is_ignored() {
    let mut h = Harness::new(Fail::Nowhere).await;
    h.enter(JoinEntry::Fresh).await;
    let (driver, mut ctx) = h.parts();
    let step = driver
        .on_outcome(
            &mut ctx,
            JoinOutcome {
                generation: 99,
                result: JobResult::Resolved(Ok(COMMUNITY.into())),
            },
        )
        .await;
    assert!(matches!(step, JoinStep::Continue));
    assert_eq!(h.state.join.page, JoinPage::EnterDid);
    assert!(!h.job_in_flight());
}

// ---- The submit: past the point of no return ----

/// The job in flight is the submit.
fn submitting(h: &Harness) -> bool {
    h.driver.submitting_to().is_some()
}

/// F10 while the request is on the wire waits for it: the request is
/// recorded and the persona kept, then the join exits.
#[tokio::test]
async fn an_exit_during_the_submit_waits_for_it_and_records_the_join() {
    let mut h = Harness::new(Fail::GatedSubmit).await;
    let (release, gate) = oneshot::channel();
    *h.fake.submit_gate.lock().unwrap() = Some(gate);
    h.launch(IdentityPick::Mint).await;
    h.run_until(submitting).await;
    assert!(submitting(&h), "parked in the submit");
    assert_eq!(h.driver.submitting_to(), Some(COMMUNITY));

    let step = h.act(Action::Exit).await;
    assert!(matches!(step, JoinStep::Continue), "the exit waits");
    assert!(h.said("stopping once it has been sent"));
    assert!(h.persona(MINTED_DID), "nothing is undone while it sends");

    release.send(()).unwrap();
    h.run_jobs().await;
    assert!(
        h.config
            .account
            .memberships()
            .any(|m| m.vtc_did == COMMUNITY),
        "the sent request is recorded"
    );
    assert!(
        h.persona(MINTED_DID),
        "the persona the community holds is kept"
    );
    assert!(h.fake.removed().is_empty(), "its listener stays");
    // The loop takes the queued exit next (`next_action`), as it does any key
    // held back behind a job.
    let queued = h.driver.leftover.pop_front();
    assert!(matches!(queued, Some(Action::Exit)), "the exit was kept");
    let step = h.act(Action::Exit).await;
    assert!(
        matches!(step, JoinStep::Exit(Interrupted::UserInt)),
        "then the exit is taken"
    );
    assert!(h.persona(MINTED_DID), "and nothing is undone by it");
}

/// The loop stopping mid-submit cannot wait, so it keeps the persona rather
/// than forget a DID the community may now hold.
#[tokio::test]
async fn an_interrupt_during_the_submit_keeps_the_persona() {
    let mut h = Harness::new(Fail::GatedSubmit).await;
    let (_release, gate) = oneshot::channel::<()>();
    *h.fake.submit_gate.lock().unwrap() = Some(gate);
    h.launch(IdentityPick::Mint).await;
    h.run_until(submitting).await;
    h.cancel().await;
    assert!(!h.driver.is_active());
    assert!(h.persona(MINTED_DID));
    assert!(h.fake.removed().is_empty());
    assert!(h.said("It may have been sent; the persona was kept."));
}
