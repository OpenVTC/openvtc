# TUI Architecture

> Status: **IMPLEMENTED** — describes the code as it stands. A navigational map
> of the `openvtc` ratatui TUI: the data-flow loop, where key handling vs.
> business logic live, the `state_handler/` module layout, the background-dispatch
> pattern, and three "how do I…" recipes.

## 1. The core data-flow loop

OpenVTC is a **single-mutator, unidirectional** design built on two tokio tasks
joined in [`openvtc/src/main.rs:246`](../../openvtc/src/main.rs):

```text
        Action (mpsc::unbounded)                State (watch)
  UI ─────────────────────────────▶ StateHandler ─────────────────────────────▶ UI
  (renders State, emits Actions)    (the ONLY mutator of State)   (re-renders on change)
```

- **`Action`** ([`state_handler/actions/mod.rs:176`](../../openvtc/src/state_handler/actions/mod.rs))
  flows UI → StateHandler over a `tokio::sync::mpsc::unbounded_channel`. The
  sender (`action_tx`) lives in `UiManager` / every UI page; the receiver
  (`action_rx`) is owned by the StateHandler loop.
- **`State`** ([`state_handler/state.rs`](../../openvtc/src/state_handler/state.rs))
  flows StateHandler → UI over a `tokio::sync::watch` channel created in
  [`StateHandler::new`](../../openvtc/src/state_handler/mod.rs) (`state_tx` /
  `state_rx`). After handling each event the loop sends a fresh clone:
  `self.state_tx.send(state.clone())` (e.g.
  [`mod.rs:1173`](../../openvtc/src/state_handler/mod.rs)).
- The **StateHandler loop** is the single `tokio::select!` in
  [`StateHandler::main_loop`](../../openvtc/src/state_handler/mod.rs) (~line 594).
  It is the *only* place `State` and `Config` are mutated. Every other producer
  (background tasks, the token-touch notifier, the DIDComm router) hands data
  back over a channel and the loop applies it.
- The **UI loop** is [`UiManager::main_loop`](../../openvtc/src/ui/mod.rs:34): it
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
  [`AppRouter`](../../openvtc/src/ui/pages/mod.rs:38) dispatches the key to the
  page for the current `ActivePage` (`Loading` / `Main` / `Setup` / `Join`).
  Example handlers live in
  [`ui/pages/main/mod.rs`](../../openvtc/src/ui/pages/main/mod.rs) — e.g. `'j'`
  → `action_tx.send(Action::StartJoin)` (line ~398). Pages have **no access to
  `Config`, the VTA client, or the DIDComm service**.
- **The StateHandler owns mutation and business logic.** Each `Action` arm in
  `main_loop` either runs a pure-state nav update (`handle_nav_action`, the
  shared reducer at [`mod.rs:1544`](../../openvtc/src/state_handler/mod.rs)) or
  delegates to a **dispatch module** that takes `&mut Config`, the `TDK`, the
  `DIDCommService`, `&mut State`, and the save scheduler.

So: "what does pressing X do?" is answered in `ui/pages/…`; "what happens to the
data?" is answered in `state_handler/…`.

## 3. `state_handler/` module layout

The loop in [`mod.rs`](../../openvtc/src/state_handler/mod.rs) is a thin router;
the real work is decomposed into focused modules (declared at `mod.rs:50`):

| Module | Owns |
|--------|------|
| `actions/` | The `Action` enum + domain sub-enums (`InboxAction`, `RelationshipAction`, `CredentialAction`, `SettingsAction`). |
| `state.rs` | The `State` struct + sub-states (`MainPageState`, `ConnectionState`, `MediatorStatus`, `ActivePage`, `LoadingProgress`). |
| `background_dispatch.rs` | Off-loop network dispatch plumbing (see §4). |
| `save_coalesce.rs` | Coalesced, off-runtime `Config` persistence (see §4). |
| `agent_name_refresh.rs` | Off-loop batch resolution of agent names (DID→name), applied via background-dispatch (see §4). |
| `inbox_actions.rs`, `relationship_actions.rs`, `credential_actions.rs`, `settings_actions.rs` | Per-panel business logic — each exposes a `dispatch(...)` entry point the matching `Action` arm calls. |
| `persona_actions.rs` | The identity pane. `apply(&mut State, &PersonaAction)` is pure and returns a `PersonaEffect` naming any network work; the loop spawns it and folds the result back through `PersonaOutcome::apply`. Reads and writes share one `DispatchDomain`. |
| `didcomm.rs` | `DIDCommService` integration: service start, listener config/ids, the `DIDCommEvent` enum, lifecycle logging. |
| `main_page/` | Maps `Config` → display state (`sync_from_config`), menu/content models. |
| `setup_wizard.rs`, `setup_sequence/`, `setup_*_actions.rs`, `join.rs`, `join_flow.rs` | The setup and join sub-flows (each runs its own scoped `select!` loop, then returns control to `main_loop`). |
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
[`openvtc-core/src/lib.rs:171`](../../openvtc-core/src/lib.rs).

## 4. Off-loop work (the loop must never block)

Because one `select!` services one arm at a time, any inline `.await` of network
or disk I/O parks the *whole* UI. Two mechanisms keep the loop live:

**Background dispatch** ([`background_dispatch.rs`](../../openvtc/src/state_handler/background_dispatch.rs)) —
for network-bound actions (mediator reconnect, relationship create/ping/remove,
inbox accept/reject, context-DID delete):

1. The action's loop arm claims a `DispatchDomain` via
   `InFlight::try_begin` (a per-domain busy-guard; a second action on a busy
   domain is rejected with a status, not queued).
2. Cheap loop-thread prep builds a `…Job`; `spawn_dispatch` runs the job's **I/O
   only** off-thread.
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
3. Handle it in [`StateHandler::main_loop`](../../openvtc/src/state_handler/mod.rs):
   - **Pure nav / view change** → add an arm to `handle_nav_action`
     ([`mod.rs:1544`](../../openvtc/src/state_handler/mod.rs)) so it is shared by
     the runtime and degraded loops.
   - **Local business logic** → add an arm that calls into the matching
     `*_actions::dispatch`.
   - **Network/blocking work** → follow the background-dispatch pattern (§4):
     claim a `DispatchDomain`, `spawn_dispatch` the I/O, and apply the result in
     `apply_outcome` (extend `DispatchOutcome` if it is a new kind of work).
4. If the handler mutates `Config`, call `save.mark_dirty()` (not an inline save).

### Add a (DIDComm) message type

1. Add the variant to `MessageType` and wire its protocol-URL string into the
   `From`/`TryFrom` impls in
   [`openvtc-core/src/lib.rs:171`](../../openvtc-core/src/lib.rs).
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
