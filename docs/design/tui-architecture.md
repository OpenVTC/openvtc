# TUI Architecture

> Status: **IMPLEMENTED** — describes the code as it stands. A navigational map
> of the `openvtc` ratatui TUI: the data-flow loop, where key handling vs.
> business logic live, the `state_handler/` module layout, the background-dispatch
> pattern, and three "how do I…" recipes.

## 1. The core data-flow loop

OpenVTC is a **single-mutator, unidirectional** design built on two tokio tasks
joined in [`openvtc/src/main.rs`](../../openvtc/src/main.rs):

```text
        Action (mpsc::unbounded)                State (watch)
  UI ─────────────────────────────▶ StateHandler ─────────────────────────────▶ UI
  (renders State, emits Actions)    (the ONLY mutator of State)   (re-renders on change)
```

- **`Action`** ([`state_handler/actions/mod.rs`](../../openvtc/src/state_handler/actions/mod.rs))
  flows UI → StateHandler over a `tokio::sync::mpsc::unbounded_channel`. The
  sender (`action_tx`) lives in `UiManager` / every UI page; the receiver
  (`action_rx`) is owned by the StateHandler loop.
- **`State`** ([`state_handler/state.rs`](../../openvtc/src/state_handler/state.rs))
  flows StateHandler → UI over a `tokio::sync::watch` channel created in
  [`StateHandler::new`](../../openvtc/src/state_handler/mod.rs) (`state_tx` /
  `state_rx`). After handling each event the loop publishes the new state as
  an `Arc<State>` (`PublishState::publish`).
- The **StateHandler loop** is the `tokio::select!` in
  [`Runtime::run`](../../openvtc/src/state_handler/runtime/mod.rs), one method
  per arm (`runtime/arms.rs`, `runtime/inbound_arm.rs`, `runtime/timers.rs`).
  It is the *only* place `State` and `Config` are mutated. Every other producer
  (background tasks, the token-touch notifier, the DIDComm router) hands data
  back over a channel and the loop applies it.
- The **UI loop** is [`UiManager::main_loop`](../../openvtc/src/ui/mod.rs): it
  draws the current `State` via `AppRouter::render`, then `select!`s on crossterm
  events (→ `handle_key_event`) and `state_rx.changed()` (→ rebuild the router
  from the new `State` with `move_with_state`). The UI **never mutates `State`**;
  it only reads the latest snapshot and emits `Action`s.

A third channel, `broadcast::<Interrupted>` (created in `main.rs::create_termination`),
is the shutdown bus both loops watch.

## 2. Key handling vs. business logic

The split is strict:

- **UI pages translate `KeyEvent`s into `Action`s** and own only *ephemeral view
  state* (scroll offset, input buffers, cursor). Every page implements the
  [`Component`](../../openvtc/src/ui/component.rs) trait
  (`handle_key_event`, `move_with_state`, `render`). The
  [`AppRouter`](../../openvtc/src/ui/pages/mod.rs) dispatches the key to the
  page for the current `ActivePage` (`Loading` / `Main` / `Setup` / `Join`).
  The main page's handlers live in
  [`ui/pages/main/mod.rs`](../../openvtc/src/ui/pages/main/mod.rs) and, per
  panel, in `components/*/keys.rs` — e.g. `n` on Communities →
  `action_tx.send(Action::StartJoin)`. Pages have **no access to
  `Config`, the VTA client, or the DIDComm service**.
- **The StateHandler owns mutation and business logic.** Each `Action` is
  handled in [`runtime_actions::handle_action`](../../openvtc/src/state_handler/runtime_actions.rs):
  it either runs a pure-state nav update (`handle_nav_action` in
  [`state_handler/mod.rs`](../../openvtc/src/state_handler/mod.rs), shared
  with the degraded loop) or delegates to a **dispatch module** through an
  `ActionCtx` holding `&mut Config`, the `TDK`, the messaging service,
  `&mut State` and the save scheduler.

So: "what does pressing X do?" is answered in `ui/pages/…`; "what happens to the
data?" is answered in `state_handler/…`.

## 3. `state_handler/` module layout

[`mod.rs`](../../openvtc/src/state_handler/mod.rs) holds the start-up and
degraded (no-messaging) loops, the shared nav reducer and helpers; the runtime
loop is [`runtime/`](../../openvtc/src/state_handler/runtime/mod.rs) and its
action handling `runtime_actions.rs`. The feature work is in focused modules:

| Module | Owns |
|--------|------|
| `actions/` | The `Action` enum + domain sub-enums (`InboxAction`, `RelationshipAction`, `CredentialAction`, `SettingsAction`). |
| `state.rs` | The `State` struct + sub-states (`MainPageState`, `ConnectionState`, `MediatorStatus`, `ActivePage`, `LoadingProgress`). |
| `background_dispatch.rs` | Off-loop network dispatch plumbing (see §4). |
| `save_coalesce.rs` | Coalesced, off-runtime `Config` persistence (see §4). |
| `agent_name_refresh.rs` | Off-loop batch resolution of agent names (DID→name), applied via background-dispatch (see §4). |
| `inbox_actions.rs`, `relationship_actions.rs`, `credential_actions.rs`, `settings_actions.rs` | Per-panel business logic — each exposes a `dispatch(...)` entry point the matching `Action` arm calls. |
| `persona_actions.rs` | The identity pane. `apply(&mut State, &PersonaAction)` is pure and returns a `PersonaEffect` naming any network work; the loop spawns it and folds the result back through `PersonaOutcome::apply`. Reads and writes share one `DispatchDomain`. |
| `community_context_actions.rs` | A membership's VTA context: deletion and device access. `reduce` handles the view-only actions (shared with the degraded loop); `plan(&mut State, &Config, own_did, action)` is pure and returns a `ContextEffect`, whose request `run` claims and spawns, applying the effect's `Commit` only once the claim succeeded. |
| `vetting_actions/` | The Vetting page. `dispatch::reduce` makes the view-only changes; `dispatch::plan(&mut State, &mut Config, busy, has_vta, action)` is pure — it makes the book changes a handler makes before any save or signing — and returns a `VettingEffect`, an ordered list of `Step`s (save, status, key lookup and signing, send or job spawn claimed through `dispatch`, follow-ups planned on the state the steps before left, and `Always` steps run even after one before gave up) that `effect::run` carries out. Every action is plan + run. |
| `rooms_actions.rs`, `elections_actions.rs`, `community_request.rs` | Rooms and Elections, on the shared request/reply engine. `plan` / `plan_next` are pure and return the steps an action or an answer's `Next` owes; the runner does the key lookup (`community_request::sender`), builds the document, claims the panel's lane, arms the view on the request's thread and applies the step's `Commit` once claimed. |
| `repos_actions.rs`, `repos_workspace.rs` | The Repos panel: `plan` returns a `ReposEffect` (git-ns sends as steps, run the same way) or a workspace `WorkspaceEffect` (a local job claimed on `GitWorkspace`, its busy mark applied once claimed). |
| `didcomm` | A re-export of `openvtc_core::didcomm`: the messaging service, listener config/ids and lifecycle events. |
| `runtime/`, `runtime_actions.rs` | The runtime loop (`Runtime`, one method per `select!` arm) and its action handler. |
| `main_page/` | Maps `Config` → display state, menu/content models. `sync_panels(config, Panels)` rebuilds a set of panels, each from `Config` and its own state only; a caller syncs the panels that read what it changed (the `Panels::FROM_*` sets name them by source), and `sync_from_config` (every panel) at startup, on a load, and for a change of reach that is global — the working persona, the personas or memberships, the agent-name cache, an inbound message. |
| `setup_wizard.rs`, `setup_sequence/`, `setup_*_actions.rs` | The setup sub-flow (runs its own scoped `select!` loop, then returns control to `main_loop`). |
| `join.rs`, `join_flow.rs`, `join_flow/driver.rs` | The join flow. `join.rs` is its page state; `join_flow.rs` its pure page logic and the bounded sends it makes while waiting on a community; `driver.rs` the `JoinDriver` state machine the runtime loop (and the State-A loop) drives — no loop of its own (see §4). |
| `dispatch_util.rs` | Shared helpers + test fixtures (`test_config`). |

**Protocol logic does not live here.** The pure validators, handlers (join-receipt,
credential-issue), VRC vetting/proof verification, and the replay guard
(`SeenMessages`) were moved to
[`openvtc-core/src/messaging.rs`](../../openvtc-core/src/messaging.rs) so they are
testable without the TUI crate. Inbound dispatch itself (`process_inbound_message`,
`InboundEffects`, the off-loop `VerifyJob`s) lives in
[`openvtc-core/src/inbound/`](../../openvtc-core/src/inbound/mod.rs); the runtime
loop calls it and applies the returned `InboundEffects` to `State`.
The `MessageType` protocol enum lives in
[`openvtc-core/src/lib.rs`](../../openvtc-core/src/lib.rs).

## 4. Off-loop work (the loop must never block)

Because one `select!` services one arm at a time, any inline `.await` of network
or disk I/O parks the *whole* UI. Two mechanisms keep the loop live:

**Background dispatch** ([`background_dispatch.rs`](../../openvtc/src/state_handler/background_dispatch.rs)) —
for network-bound actions (mediator reconnect, relationship create/ping/remove,
inbox accept/reject, context-DID delete):

1. Cheap loop-thread prep builds a `…Job` from owned values: a type
   implementing `background_dispatch::Job`, which names its `DispatchDomain`
   and its **I/O only** (`execute`, returning the `DispatchOutcome`).
2. `background_dispatch::dispatch(job, in_flight, dispatch_tx, on_busy)` claims
   the job's domain via `InFlight::try_begin` (a per-domain busy-guard) and
   spawns it off-thread. A job for a busy domain is dropped unrun and
   `on_busy` gets the busy message, to show or to remember as a deferred
   retry — a second action is rejected or deferred, never run alongside. Work
   due only once the claim succeeded (locking an overlay, arming a view on a
   thread id) is done by the caller when `dispatch` returns `true`. Where
   building the job itself changes state (inbox and relationship sends,
   identity removal, a VRC request, a witnessing, a mediator reconnect, the
   vetting sends), the caller first checks `InFlight::is_busy` and prepares
   only when the domain is free; the loop runs one arm at a time, so the
   claim `dispatch` then makes cannot be lost in between.
   `background_dispatch::spawn_unclaimed` runs a job without claiming: for
   work the client starts on its own (a revocation check, a step of hidden
   vetting) that must never be refused or block a person's job. Its outcome
   comes back as `DispatchOutcome::Unclaimed` and is applied like any other,
   but frees no domain: a person's job may hold it.
3. The job returns a `DispatchOutcome` over an mpsc the loop owns. The dedicated
   `Some(outcome) = dispatch_rx.recv()` arm calls `apply_outcome`, which mutates
   `State`/`Config` **on the loop thread** and clears the busy-flag. Mutation
   never happens in the spawned task — preserving the single-mutator invariant.

**Coalesced config persistence** ([`save_coalesce.rs`](../../openvtc/src/state_handler/save_coalesce.rs)) —
`Config::save` is expensive (serialize + encrypt + keyring + smart-card I/O).
Mutation sites call `SaveScheduler::mark_dirty()` instead of saving inline. The
loop's `save.wait_deadline()` arm debounces a burst (`DEBOUNCE = 750ms`) into a
single `spawn_blocking` save, with at most one in flight. Durability-critical
points (Exit, passphrase/protection change) force-flush synchronously. The
startup load uses the same shape: a spawned task streams progress back into the
loading-screen `select!`.

**Agent-name refresh** ([`agent_name_refresh.rs`](../../openvtc/src/state_handler/agent_name_refresh.rs)) —
a concrete instance of the background-dispatch pattern. A 5-minute interval arm
collects the DIDs whose agent name is uncached or stale
(`Config::agent_name_refresh_targets`) and hands the whole list to **one**
background job on the `DispatchDomain::AgentName` domain (one job, not one per
DID: the busy-guard is per-domain). Inside the job the DIDs resolve with bounded
concurrency (a sliding window of 4). The job does I/O only; `apply_outcome` folds
the verified `(did, name)` results into `Config::agent_names` on the loop thread.

**The join flow** ([`join_flow/driver.rs`](../../openvtc/src/state_handler/join_flow/driver.rs)) —
the largest user of the pattern. It has no loop of its own — saves, VTA
supervision, inbound messages and timers carry on while the join screen is up
— and is a `JoinDriver` state machine the loop drives:

1. While a join is open the loop's action arm hands every action to
   `JoinDriver::on_action`; page logic runs there, on the loop.
2. Network work — resolving an agent name, reading a community (invitations,
   manifest, DID document), and each stage of a launch — runs as one job at a
   time on `DispatchDomain::Join`. The result comes back as
   `DispatchOutcome::Join` and progress lines as `ProgressUpdate::Join`, both
   carrying the job's generation; the loop gives them to the driver *before*
   `apply_outcome`, and the driver ignores any that are not for the job it is
   waiting on (an aborted one).
3. Join actions that arrive while a job is in flight are queued and replayed
   in order when it finishes. `JoinCancel` and `Exit` are not: they
   abort the job at once (`AbortHandle`; the driver frees the domain).
4. A launch is a saga (`openvtc_core::join::saga::JoinSaga`): context
   registered → persona minted → listener up → submitted → persisted, with
   on-loop applies between off-loop stages. Any failure, cancel or interrupt
   undoes the launch from `JoinSaga::compensations` — remove the listener it
   installed, forget the persona it minted (never a reused one) — rather than
   from wherever a dropped future happened to stop.

Short, bounded sends (asking a community for its requirements, a challenge, a
wallet session — each behind a 15 s timeout) and the VTA reads behind the
Answers page stay inline awaits, as elsewhere in the runtime. Everything the
join does over the network, to disk or through a live messaging account goes
through the `JoinIo` trait, so tests drive whole launches offline and fail them
at each stage.

## 5. Recipes

### Add a keybinding

1. Find the page that has focus for your key: a `Component` under
   [`openvtc/src/ui/pages/`](../../openvtc/src/ui/pages/) (most likely
   `main/mod.rs` and its `handle_*_key_event` helpers).
2. In that page's `handle_key_event`, match your `KeyCode` and call
   `self.action_tx.send(Action::…)`. **Do not mutate shared state here** —
   only emit an `Action` (or update page-local view state like scroll/buffer).
3. If the key needs a *new* behaviour, also do "Add an Action" below.

### Add an `Action`

1. Add the variant to the `Action` enum (or the right domain sub-enum) in
   [`state_handler/actions/mod.rs`](../../openvtc/src/state_handler/actions/mod.rs).
2. Emit it from the relevant UI page (see "Add a keybinding").
3. Handle it in [`runtime_actions::handle_action`](../../openvtc/src/state_handler/runtime_actions.rs)
   (its `match` is exhaustive, so the compiler points there):
   - **Pure nav / view change** → add an arm to `handle_nav_action`
     ([`state_handler/mod.rs`](../../openvtc/src/state_handler/mod.rs)) so it is
     shared by the runtime and degraded loops.
   - **Local business logic** → add an arm that calls into the matching
     `*_actions::dispatch`.
   - **Network/blocking work** → follow the background-dispatch pattern (§4):
     implement `Job` for the work, hand it to `background_dispatch::dispatch`,
     and apply the result in `apply_outcome` (extend `DispatchOutcome` if it is
     a new kind of work).
4. If the handler mutates `Config`, call `save.mark_dirty()` (not an inline
   save); where the change must be on disk before success is reported, await
   `save.flush(&config)`. Every TUI save goes through the `SaveScheduler`.

### Add a (DIDComm) message type

1. Add the variant to `MessageType` and wire its protocol-URL string into the
   `From`/`TryFrom` impls in
   [`openvtc-core/src/lib.rs`](../../openvtc-core/src/lib.rs).
2. Put the **pure** handling logic (validation, body parsing, state derivation)
   in [`openvtc-core/src/messaging.rs`](../../openvtc-core/src/messaging.rs) so it
   is unit-testable without the TUI.
3. Add a `Family` variant and its route to the inbound registry
   ([`openvtc-core/src/inbound/registry.rs`](../../openvtc-core/src/inbound/registry.rs)).
   The transport's accept gate and the dispatcher both read that one table, so
   the type is admitted exactly when it is routed. The dispatcher's
   `match family` is exhaustive: add the family's handler in
   [`openvtc-core/src/inbound/mod.rs`](../../openvtc-core/src/inbound/mod.rs),
   calling the core logic and returning `Ok(true)` if it mutated `Config` (the
   loop then `mark_dirty`s and re-syncs the UI). Add the type to the census in
   `openvtc-core/tests/inbound_gate_census.rs`.
4. If sending the message is user-initiated, add the corresponding `Action` +
   key (recipes above) and build the outbound message with
   `openvtc_core::messaging::build_didcomm_message`.
