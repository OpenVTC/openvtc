# T1 — Active-Identity & Session-Manager API Sketch

> Status: **IMPLEMENTED** — T1 shipped (`PersonaId` and `CommunityRecord` in
> `openvtc-core/src/config/account.rs`, `openvtc/src/state_handler/session_manager.rs`).
> Originally written as the API-shapes sign-off gate before T1 foundation code.
> Companion to [`multi-community-support.md`](./multi-community-support.md)
> (spec) and [`../../tasks/archive/todo.md`](../../tasks/archive/todo.md) (T1).

This sketch pins down the three new surfaces T1 introduces and how the existing
singleton consumers map onto them. Names are proposals; types reference the
real current code.

---

## 0. Grounding — what exists today

- **`Config`** (`openvtc-core/src/config/mod.rs:230`) is a flat singleton:
  `persona_did: PersonaDID`, `key_backend: KeyBackend`, `key_info: HashMap`,
  `atm_profiles: HashMap` (relationship profiles), `vrcs`, plus `public`
  (`PublicConfig`) and `private` (`ProtectedConfig`).
- **`PersonaDID { document: Document, profile: Arc<ATMProfile> }`** (`mod.rs:287`).
- **`KeyBackend::{Bip32, Vta}`** (`mod.rs:174`) — the `Vta` variant already holds
  `credential_bundle / credential_did / credential_private_key / vta_did /
  vta_url / mediator_did / encryption_seed`. This becomes the **account
  credential**.
- **DIDComm** (`openvtc/src/state_handler/didcomm.rs`) runs **one
  `DIDCommService`** with a `"persona"` listener + per-relationship listeners;
  inbound messages → `DIDCommEvent` channel → the `select!` loop in
  `state_handler/mod.rs:456`. **Multiplexing already exists** — the session
  manager generalises it.
- **Key resolution** (`openvtc-core/src/config/keys.rs`) maps verification-method
  ids → secrets via `key_info` purpose/source. Per-persona today; becomes
  per-`IdentityContext`.

---

## 1. Config v2 data model (`openvtc-core`)

The flat singleton fields on `Config` are replaced by one `account: Account`.

```rust
// config/account.rs  (new)
pub type PersonaId = String;   // see Fork B
pub type VtcDid    = String;

pub struct Account {
    pub vta_did: String,
    pub vta_url: String,
    pub admin_credential: KeyBackend,          // today's KeyBackend::Vta (account-level)
    pub top_context_id: String,                // OpenVTC is admin here
    pub personas:    HashMap<PersonaId, Persona>,
    pub communities: HashMap<VtcDid,   Community>,
}

pub struct Persona {
    pub persona_id: PersonaId,
    pub did: String,                           // did:webvh
    pub document: Document,                     // resolved (runtime-built on load)
    pub key_refs: HashMap<String, KeyInfoConfig>, // this persona's slice of today's key_info
    pub mediator_did: Option<String>,          // default = VTA mediator; override at mint (D7)
    pub origin_context_id: String,             // provenance only (D6)
    pub created_at: DateTime<Utc>,
    pub label: Option<String>,
    pub profile: Arc<ATMProfile>,              // runtime; built on load (not persisted)
}

pub struct Community {
    pub vtc_did: VtcDid,
    pub display_name: Option<String>,
    pub sub_context_id: String,                // <top>/<slug> (D9)
    pub persona_ref: PersonaId,                // D1/D6 — must resolve (R-P-1)
    pub status: CommunityStatus,
    pub favourite: bool,
    pub archived: bool,
    pub member_since: Option<DateTime<Utc>>,
    pub requested_at: Option<DateTime<Utc>>,   // 7-day timeout anchor (D16)
    pub relationships: Relationships,          // moved here, scoped per community
    pub vrcs_issued:   Vrcs,
    pub vrcs_received: Vrcs,
}

pub enum CommunityStatus {
    Pending { request_id: Uuid }, Active, Left, Rejected, Removed, Expired,
}
```

**Tier placement** (spec §10.2):
- `PublicConfig` — unchanged minus the persona fields: `config_version`,
  `protection`, `friendly_name`, `logs`.
- `ProtectedConfig` — `personas` + `communities` **metadata** (everything above
  except key material), plus per-community `relationships` / `vrcs`.
- `SecuredConfig` / keyring — only `account.admin_credential`. Persona keys are
  **VTA-managed** (`key_refs` are ids; D12), fetched at runtime.

**Breaking reset (D13), not migration.** `CONFIG_VERSION = 2`. On load,
`migrate_config` detects `config_version < 2` and returns a dedicated
`ConfigError::IncompatibleVersionResetRequired`. `main.rs` turns that into the
warn → confirm → delete (config file + keyring) → State-A flow (R-RST-*). No
v1→v2 data path.

---

## 2. Active-identity abstraction (`openvtc-core/src/identity.rs`, new)

An **`IdentityContext`** is everything needed to act *as a persona within a
community*. An **`IdentityRegistry`** holds one per Active community plus the
shared account credential. The *selected working community* (which one the main
page shows) lives in the TUI `State`, not here.

```rust
pub struct IdentityContext {
    pub community: VtcDid,
    pub persona_id: PersonaId,
    pub persona_did: String,
    pub document: Document,
    pub profile: Arc<ATMProfile>,
    pub mediator_did: Option<String>,
    // key/secret resolution scoped to THIS persona (replaces flat key_info walk):
    key_refs: HashMap<String, KeyInfoConfig>,
    account_credential: KeyBackend,            // shared ref for VTA-managed fetch
}

impl IdentityContext {
    pub fn persona_did(&self) -> &str;
    pub fn document(&self) -> &Document;
    pub fn profile(&self) -> &Arc<ATMProfile>;
    pub fn key_ids(&self) -> impl Iterator<Item = &str>;
    /// Resolve signing/auth/decryption secrets for this persona into the TDK.
    pub async fn load_secrets(&self, tdk: &TDK) -> Result<(), OpenVTCError>;
    /// Build a VTA client authenticated with the account credential.
    pub async fn vta_client(&self, tdk: &TDK) -> Result<VtaClient, OpenVTCError>;
}

pub struct IdentityRegistry {
    contexts: HashMap<VtcDid, IdentityContext>,   // one per Active community
    account: AccountRef,                          // vta_did/url + admin credential
}

impl IdentityRegistry {
    pub fn build(account: &Account, tdk: &TDK) -> Result<Self, OpenVTCError>; // on load
    pub fn get(&self, c: &VtcDid) -> Option<&IdentityContext>;
    pub fn by_persona(&self, p: &PersonaId) -> impl Iterator<Item = &IdentityContext>;
    pub fn active(&self) -> impl Iterator<Item = &IdentityContext>;
    pub fn account(&self) -> &AccountRef;
}
```

**Why a registry, not just "the active one":** inbound messages and per-session
work must resolve a *specific* community's identity (to sign a reply as the
right persona), independent of what the UI currently shows. The UI selection is
just `registry.get(state.selected_community)`.

---

## 3. Multi-session manager (`openvtc/src/state_handler/sessions.rs`, new)

**Built as a thin layer over the existing single `DIDCommService`**, which
already runs **one independent `tokio` task per listener** with its own
connection, child cancel token, and `run_with_restart()` (per-listener
auto-retry + lifecycle events via `subscribe()`), plus dynamic
`add_listener()` / `remove_listener()`. We do **not** spawn a service per
community (redundant — see Fork 1).

**Sessions are keyed by persona (DID), not community.** The service enforces
one listener per DID (`DuplicateDid`), and personas can be **reused** across
communities (D1) — so a persona = one shared listener/connection, and a
community's connectivity is *its persona's* session status (many communities →
one persona session). Inbound events are **tagged with the receiving persona**;
the dispatch loop maps persona → community(ies) → `IdentityContext`.

```rust
pub struct SessionManager {
    service: DIDCommService,                      // the single shared service
    sessions: HashMap<PersonaId, PersonaSession>, // keyed by persona (DID), not community
    events_tx: mpsc::Sender<TaggedEvent>,         // TaggedEvent { persona_id, DIDCommEvent }
    max_listeners: usize,                         // bounded fan-out (no runaway)
}

pub struct PersonaSession {
    persona_id: PersonaId,
    listener_ids: Vec<String>,                    // persona listener + its relationship listeners
    refcount: usize,                              // communities sharing this persona
    status: SessionStatus,                        // derived from listener lifecycle events
}

impl SessionManager {
    /// Bring up (or ref-bump) the persona's session for a community's identity.
    pub async fn register(&mut self, ctx: &IdentityContext, tdk: &TDK) -> Result<()>;
    /// Drop a community's hold; tears down the listener group only when refcount hits 0.
    pub async fn deregister(&mut self, ctx: &IdentityContext);   // leave/inactivate (R-S-3)
    pub fn status_for(&self, persona: &PersonaId) -> SessionStatus;
}
```

- **Failure isolation (D15):** comes for free from the library — each listener
  is an independent task; a stalled mediator on one persona adds no latency to
  others and never kills them. Launch is partial-failure-tolerant.
- **`ConnectionState`** in TUI `State` goes from one status to **per-persona**
  (derived from the manager); the Communities page (R-C) maps each community to
  its persona's status.

---

## 4. Consumer-refactor pattern

The ~100 singleton reads collapse into "resolve an `IdentityContext`, then ask
it". Representative before/after:

```rust
// before — implicit single persona
let from = config.persona_did.clone();
sign_with(&config.persona_did.profile, ...);

// after — explicit, community-scoped
let id = registry.get(&community).ok_or(NoActiveIdentity)?;
let from = id.persona_did();
sign_with(id.profile(), ...);
```

- **Inbound handlers** (`inbox_actions.rs`, `relationship_actions.rs`,
  `message_dispatch.rs`) take a `&IdentityContext` param (resolved from the
  event's `community` tag) instead of reading `config.persona_did`.
- **DIDComm listener build** (`didcomm.rs:build_listener_configs`) is invoked
  *per community* by the session manager (persona listener + that community's
  relationship listeners), keyed by `community`.
- **Main page** (`main_page/mod.rs`, `ui/pages/main/*`) reads the *selected*
  community's `IdentityContext`; renders a "no active community" state when the
  account has zero Active communities.
- **Key resolution** (`config/keys.rs`) operates on a persona's `key_refs`
  rather than the global `key_info` map.

---

## 5. Scope & sequencing of T1 (so the app stays runnable)

After T1 alone (State A/B split is T3/T5), the **existing setup wizard is
re-pointed to emit v2**: it produces one `account` + one `Persona` + one
`Active` `Community`. The app then boots that single community as the selected
working context and brings up **one** session — exercising the registry +
manager at **N=1**. T3 later splits the wizard into bootstrap/join; T5 adds the
real multi-community joins. So T1 ships a fully-working single-community app on
the new architecture, with the machinery already N-capable (unit-tested with
≥2 simulated sessions).

**T1 does NOT include:** the Communities page UI (T4), State A/B flows (T3/T5),
join/lifecycle (T5/T6), VP (deferred).

---

## 6. Forks — resolved

1. **Session isolation model** → **Shared `DIDCommService`, sessions keyed by
   persona.** Investigation of `affinidi-messaging-didcomm-service 0.3.3`
   confirmed each listener is an independent `tokio` task (own connection, child
   cancel token, `run_with_restart` auto-retry, lifecycle events) with dynamic
   `add_listener`/`remove_listener`. A slow mediator on one listener does **not**
   impact others' latency; drops auto-retry; listeners add/remove on the fly.
   A per-community service would duplicate isolation the library already
   provides. The service's `DuplicateDid` guard makes **persona (DID)** the
   correct session key, with reused personas sharing one listener (§3).
2. **`PersonaId` scheme** → **Stable UUID**; `did:webvh` is a field (rotation-safe).
3. **Relationships/VRCs** → **Inside each `Community`** (scoped).
4. **`IdentityContext` location** → **`openvtc-core`**.
