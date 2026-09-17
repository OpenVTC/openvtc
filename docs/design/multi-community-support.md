# SPEC — Multi-Community Support for the OpenVTC CLI

> Status: **DRAFT v5** — decisions D1–D17 settled. **Hierarchical contexts are
> now real and VTA-enforced** (VTI #257): D2/D9 updated, sub-context
> authorization resolved (ancestry ACL), and a real **MockVta** harness exists
> for T9 (VTI #256). Only open item: VP discovery (deferred, D4). Task breakdown
> in `tasks/plan.md` + `tasks/todo.md`.
> Scope: the `openvtc` CLI (ratatui TUI) and `openvtc-core` config model. No
> changes to the verifiable-trust-infrastructure repo are in scope here; where
> infra/SDK changes are required they are called out as **external
> dependencies**.

---

## 1. Objective

Today OpenVTC is a **profile-singleton**: one profile = one persona DID, one
VTA, one mediator, one flat `context_id`, all created in a single ~19-step
setup wizard. There is no concept of belonging to a community.

This feature makes OpenVTC **multi-community**: a user connects to a VTA once,
then joins any number of Verifiable Trust Communities (VTCs), each active
simultaneously, and manages them from a dedicated overview page.

### Target users
- **Community members** — individuals who join one or more VTCs to participate.
- **Operators** (secondary) — the same person during State A bootstrap, acting
  as admin of their own top-level context.

### Success definition
A user can: bootstrap an account against a VTA without creating any persona
DID; later join multiple VTCs by DID; choose per-join whether to mint a fresh
`did:webvh` or reuse an existing persona; and see all their communities, each
with live status, on a Communities overview page.

---

## 2. Key decisions (already agreed)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Persona DID per community vs shared | **User chooses per join.** Personas are account-level resources referenced by communities. |
| D2 | Context hierarchy mechanism | **Real hierarchical contexts — VTA-enforced (VTI #257).** A context id *is* its `/`-separated path (`<top>/<community>`); the VTA validates depth/segments and enforces **ancestry-aware ACL** (a parent-context admin covers the whole subtree). No longer a migrate-later convention. Path logic lives in one `context_path` module mirroring `vti-common::context_path`; **no `vta-sdk` change needed** (`create_context` already takes a path id). |
| D3 | Join semantics | **VP-based with pending-approval state** … |
| D4 | VP construction (join step 4) | **…but deferred.** Stub the presentation; land everything around it. |
| D5 | Persona creation timing | **Lazy.** No `did:webvh` at bootstrap; first persona minted on first join. |
| D6 | Persona ↔ context coupling | **Self-contained persona.** A persona is a complete `did:webvh` + its own keys, independent of context. Reuse presents the *same* DID/keys to multiple communities; a sub-context is purely VTA-side organisation. `origin_context_id` is provenance only. |
| D7 | Mediator / routing | **Default to the VTA mediator, optionally overridable per DID/persona.** Each persona's DIDComm service endpoint (its mediator) defaults to the VTA-provided mediator; at mint time the user may opt to use a different mediator instead. The mediator is a property of the DID document, so the choice is **per-DID** — which, because a fresh DID is typically minted per community (D1), reads as per-community in the common case. A *reused* persona keeps the mediator baked into its DID doc. |
| D8 | Community lifecycle states | **Pending, Active, Left, Rejected, Removed** (see §5.6). |
| D9 | Sub-context id derivation | **`<top>/<slug-from-name>`** — slug from the VTC display name, with a collision-suffix rule, under the top context. Each segment must be a valid context identifier (`vti-common` rules); **max depth 8** (top/community = depth 2). |
| D10 | Migration strategy | **Full refactor, no compatibility shim.** Replace the singleton with an explicit active-identity abstraction everywhere; core model + `openvtc` consumer refactor land in one PR. |
| D11 | Runtime session model | **Concurrent live sessions.** Each active community's persona holds its own live DIDComm/mediator session simultaneously. The single message loop becomes a **multi-session manager** (built in T1, running N=1 at first); joining registers a new session, leaving deregisters one. |
| D12 | System of record | **The VTA stores persona DIDs, key info, and credentials.** Local config holds only the account **admin credential** (bootstrap secret), community-membership metadata, persona *references*, and UX prefs (favourites). This is the backup/restore story — the VTA is the store, not a local export. Aligns with the existing `KeySourceMaterial::VtaManaged { key_id }` model. |
| D13 | Old-config compatibility | **Breaking reset, not migration.** An incompatible (v1) config is **not** migrated. The CLI detects it, **informs the user it will delete the existing config and reset**, then runs State A from scratch. (OpenVTC is pre-1.0; acceptable.) |
| D14 | Inactive communities | **Non-Active communities are read-only.** Left / Rejected / Removed / Expired communities have their session torn down and become read-only. The user may then **Archive** (retain data, hide from the main list) or **Delete** (purge local data). |
| D15 | Session isolation | **One supervised task per community session.** Each runs independently with its own retry/recovery; a failure (e.g. mediator down) is contained and never blocks or kills other sessions. |
| D16 | Join request lifecycle | **Persona + live session created *before* submit** (so the VTC's reply is receivable). Pending requests **time out client-side after 7 days** → `Expired`. The VTC sets its own server-side policy; best practice is for it to send a reject / request-more-info message (content at the VTC's discretion); a "more info required" reply raises actions-required. |
| D17 | did-git-sign identity | **Selectable signing persona.** `did-git-sign` chooses which community persona to sign with via an **env var** and/or **per-repo git config**, rather than a single global persona. |

---

## 3. Background — current architecture (for reviewers)

- **Setup state machine:** `openvtc/src/state_handler/setup_sequence/mod.rs:26`
  (`SetupPage` enum, ~19 linear steps). Entry decision in
  `openvtc/src/main.rs:156` (`Config::load_step1` → `ConfigNotFound` ⇒ setup).
- **Config tiers** (`openvtc-core/src/config/`):
  - `PublicConfig` (plaintext JSON on disk; `public_config.rs:34`) — holds
    singleton `persona_did`, `mediator_did`, `lk_did`, `config_version`.
  - `ProtectedConfig` (AES-256-GCM, embedded; `protected_config.rs:176`) —
    contacts, relationships, VRCs.
  - `SecuredConfig` (OS keyring; `secured_config.rs:295`) — credential bundle,
    `vta_did`, `vta_url`, key material.
  - `KeyBackend::Vta { vta_did, vta_url, … }` (`mod.rs:174`) — single VTA.
- **`context_id`** is a single flat string defaulting to `DEFAULT_CONTEXT_ID`
  (`setup_vta_actions.rs:135`), passed to VTA `create_key` / provisioning.
- **vta-sdk 0.9.6 already provides:**
  - Context CRUD — `create_context`, `list_contexts`, `get_context`,
    `update_context_did`, `delete_context`. The `ContextResponse` has no
    `parent_id` field because **hierarchy is encoded in the id itself** — a
    context id *is* its `/`-separated path (VTI #257). The VTA validates the
    path (depth/segments) and enforces ancestry-aware ACL server-side, so
    `create_context` with a path id like `<top>/<community>` is all the CLI
    needs. Each context also has a BIP32 `base_path` and optional `did`.
  - **VTC join protocol** — `vta_sdk::protocols::join_requests`:
    `JOIN_REQUEST_SUBMIT_TYPE`, a submit receipt with `status` (e.g.
    `"pending"`), and `MEMBER_SELF_REMOVE`. Submit body carries a Verifiable
    Presentation (`vp`) + `registry_consent`.

---

## 4. Data model (config v2)

New `config_version` **2**. A v1 config is **not migrated** — it triggers a
breaking reset (D13, R-RST-*). The **VTA is the system of record** (D12) for
persona DIDs, key material, and credentials; local config holds the admin
credential, membership metadata, persona *references*, and UX prefs.
Conceptual shape (final field names settled in implementation):

```
Config
├── account                              // produced by State A (bootstrap)
│   ├── vta_did, vta_url
│   ├── admin_credential_bundle          // bootstrap secret — kept LOCAL (D12)
│   ├── top_context_id                   // OpenVTC is admin of this context
│   └── personas: Map<PersonaId, Persona>     // self-contained refs (D6, D12)
│        └── Persona {
│              persona_id,
│              did,                       // did:webvh — complete identity
│              key_refs,                  // VtaManaged key_ids — keys live at
│                                         //   the VTA, not stored locally (D12)
│              mediator_did,              // defaults to VTA mediator; optional
│                                         //   override chosen at mint (D7)
│              origin_context_id,         // provenance only; persona is
│                                         //   context-independent (D6)
│              created_at,
│              label?                     // optional human name
│            }
└── communities: Map<VtcDid, Community>   // each = one State-B join
     ├── vtc_did
     ├── sub_context_id                   // <top>/<slug-from-name> (D9)
     ├── persona_ref: PersonaId           // identity presented to this VTC
     ├── archived: bool                   // user-archived inactive community (D14)
     ├── requested_at?                    // join submit time → 7-day timeout (D16)
     ├── status: Pending{request_id} | Active | Left | Rejected | Removed | Expired  (D8)
     ├── joined_at? / member_since?       // set when status → Active
     ├── favourite: bool
     ├── display_name?                    // resolved from VTC DID doc
     └── vrcs_issued / vrcs_received       // scoped per community
```

Notes:
- **Personas are account-level**, not owned by a community — this is what makes
  "choose new or reuse" (D1) uniform. A reused persona is referenced by
  multiple communities.
- **VTA is the store (D12):** `key_refs` are VTA `key_id`s; key material and
  persona credentials are fetched from the VTA, not persisted locally. Only the
  account admin credential is a local secret.
- **No migration (D13):** a v1 config is detected, the user is warned, and it is
  deleted + reset. No lossless v1→v2 path.
- **Referential integrity:** every `community.persona_ref` must resolve to an
  existing persona; a persona cannot be deleted while any community references
  it (see §5.7).

---

## 5. Functional requirements & acceptance criteria

IDs are referenced by the task breakdown.

### 5.1 Config reset (breaking, D13)
- **R-RST-1** On load, an incompatible/older `config_version` (i.e. v1) is
  detected before any decryption that assumes the v2 shape.
- **R-RST-2** The user is shown a clear, explicit warning that the existing
  config is incompatible and **will be deleted**, requiring a fresh setup, and
  must confirm before deletion proceeds.
- **R-RST-3** On confirmation the old config (and its keyring/secured entries)
  is removed and State A bootstrap runs from scratch. No lossless migration.
- **R-RST-4** A brand-new install (no config at all) goes straight to State A
  without any reset prompt.

### 5.2 State A — account bootstrap
- **R-A-1** When no config exists, the bootstrap flow runs (reusing today's
  entry decision in `main.rs`).
- **R-A-2** Steps: enter VTA DID → resolve service URL + mint ephemeral setup
  `did:key` → operator ACL / `vta_admin_rotated` → receive admin credential.
- **R-A-3** Create the **top-level context** (`create_context`) of which this
  account is admin; persist `top_context_id`.
- **R-A-4** Config protection (passcode / token / plaintext) as today.
  did-git-sign is **not** configured here — it now selects a community persona
  (D17, §5.8), and no persona exists at bootstrap.
- **R-A-5** Bootstrap completes and persists config with **no `did:webvh`, no
  mediator selection, no community**. (D5)
- **R-A-6** After bootstrap the user lands on the Communities overview page
  (empty state), and may immediately start a join.

### 5.3 State B — join a community
- **R-B-1** Reachable (a) immediately after bootstrap and (b) anytime from the
  Communities overview page ("Join community" action).
- **R-B-2** Enter the **VTC DID**; resolve it; capture a display name from its
  DID document if available.
- **R-B-3** **Identity choice (D1):** offer "use an existing persona" (list
  account personas) or "create a new identity for this community". When reusing,
  show a clear warning that it links the user across those communities.
- **R-B-4** Create the **sub-context** for this community via the
  `context_path` module — `<top>/<slug-from-name>` with collision suffixing
  (D2, D9). If minting a new persona, create its `did:webvh` here; the persona
  is otherwise **self-contained and context-independent** (D6). The mint
  sub-flow defaults the mediator to the VTA mediator, with an **optional**
  "use a different mediator" step (D7). Reusing an existing persona inherits
  its mediator (no prompt).
- **R-B-5** **Persona + session live before submit (D16):** the chosen persona's
  live DIDComm session is registered with the multi-session manager *before*
  the join is submitted, so the VTC's asynchronous reply is receivable.
- **R-B-6** **Join submit (D3, with D4 deferred):** submit a
  `join-requests/submit` with a **stubbed/placeholder VP** (see §8), receive a
  receipt, persist the community with status from the receipt
  (`Pending{request_id}` or `Active`), and record `requested_at`.
- **R-B-7** A `Pending` community whose request is unanswered for **7 days**
  transitions client-side to `Expired` (D16) and raises actions-required. (The
  VTC enforces its own server-side policy independently.)
- **R-B-8** A pending community resolves to `Active`, `Rejected`, `Removed`, or
  a **"more info required"** state when the corresponding inbound DIDComm
  message arrives, via the multi-session manager (D11/D15). The transition is
  persisted and may raise actions-required (R-C-3). "More info required" content
  is at the VTC's discretion (real handling waits on D4).
- **R-B-9** Joining a community already present (same `vtc_did`) is **idempotent
  / detected**: an existing `Pending` is surfaced (no duplicate submit); re-join
  of an inactive (`Left`/`Rejected`/`Removed`/`Expired`) community is allowed and
  cycles through `Pending`.

### 5.4 Communities overview page
- **R-C-1** A dedicated page lists all communities the account belongs to (or
  has pending/left), one row each.
- **R-C-2** Each row shows: display name (or VTC DID), **status** (any of the
  §5.6 states), **member-since** date (when Active), and the persona presented.
- **R-C-3** **Actions-required indicator:** a per-community flag/badge when the
  community needs user attention (e.g. pending receipt, inbound request,
  rejection to acknowledge). The set of "action" triggers is enumerated in
  implementation; the page must render the indicator and a count.
- **R-C-4** **Star/favourite:** the user can toggle a favourite flag per
  community; favourites sort to the top and persist across restarts (D-config).
- **R-C-5** Empty state (post-bootstrap, no communities) shows a **playful,
  welcoming message** nudging the user to go find a community to join (not a
  dry "no items") and offers the join entry point.
- **R-C-6** **Selecting an Active community sets it as the working context (D1
  #1):** the existing main page (relationships, contacts, VRCs, messaging) is
  **community-scoped** and switches to that community's context. The detail
  surface is **deliberately minimal in v1** but must be **structured for easy
  extension** (new actions/sections without reworking page or navigation).
- **R-C-7** **Active-community chrome:** the active community's name is shown at
  the **top of the screen**, with a **dropdown selector** to switch the working
  community quickly. With zero communities the main page shows a clear
  "no active community" state (it cannot operate without one).
- **R-C-8** **Archive / Delete:** an **inactive** community (Left / Rejected /
  Removed / Expired) is **read-only** (D14). The user may **Archive** it (retain
  data, hide from the default list) or **Delete** it (purge local data, with
  confirmation). Active communities cannot be deleted without leaving first.

### 5.5 Leaving a community
- **R-L-1** A member can leave via `MEMBER_SELF_REMOVE`; on success the
  community status becomes `Left`, its session is deregistered (D15), and the
  record is retained read-only for history / re-join.

### 5.6 Community lifecycle states (D8)
The `status` of a community is one of (only **Active** is live; all others are
read-only, D14):

| State | Live? | Meaning | Entered when |
|-------|-------|---------|--------------|
| **Pending** | session up to receive reply | Join request submitted, awaiting VTC decision. Carries `request_id` + `requested_at`. | After `join-requests/submit` returns a pending receipt (R-B-6). |
| **Active** | **yes** | Member in good standing. Sets `member_since`. | Receipt is immediate-accept, or inbound acceptance resolves a Pending (R-B-8). |
| **Rejected** | read-only | Join request denied by the VTC. | Inbound rejection resolves a Pending. Actions-required until acknowledged. |
| **Left** | read-only | Member voluntarily left (`MEMBER_SELF_REMOVE`). | R-L-1 succeeds. |
| **Removed** | read-only | Member removed by the VTC (involuntary). | Inbound removal notice for an Active member. Actions-required until acknowledged. |
| **Expired** | read-only | Pending join unanswered for 7 days. | Client-side timeout (R-B-7). Actions-required until acknowledged. |

- **R-S-1** Records are retained for all inactive states (history + re-join).
  Re-joining an inactive community cycles back through `Pending`/`Active`.
  The user may instead Archive or Delete inactive communities (R-C-8).
- **R-S-2** `Rejected`, `Removed`, `Expired`, and any "more info required" reply
  raise the actions-required indicator (R-C-3) until acknowledged.
- **R-S-3** Entering any non-Active state **deregisters** the community's
  session from the multi-session manager (D15).
- **R-S-4** A `Rejected` or `Removed` record persists the community's own
  **decision evidence** (code, reason, deciding authority, decision time, and —
  for a removal — the record disposition), surfaced in the expanded detail
  block. A rejection carries what its verdict / problem-report / trust-task-error
  / status-poll gave; a removal reads `vtc/members/removal-notice/0.1`. When the
  community gave no reason the row reads "no reason given" — an explicit absence,
  not a blank. The deciding authority is only independently attestable on a
  removal notice; a rejection's is not, and is not shown as if it were.

### 5.7 Persona lifecycle & referential integrity
- **R-P-1** A persona cannot be deleted while any community references it
  (`persona_ref`); deletion is blocked with a clear message.
- **R-P-2** Deleting the last community that references a persona leaves the
  persona orphaned-but-retained; explicit persona deletion is a separate action.
- **R-P-3** (Future-friendly) persona key rotation uses the WebVH pre-rotation
  keys already provisioned; not implemented in this spec but the model must not
  preclude it.

### 5.8 did-git-sign identity selection (D17)
- **R-G-1** `did-git-sign` selects which community persona signs via an **env
  var** (e.g. per-invocation override) and/or a **per-repo git config** setting,
  resolved against the account's personas. No global single-persona assumption.
- **R-G-2** If no persona is selected/resolvable, signing fails with a clear
  message rather than silently using an arbitrary persona.

---

## 6. Architecture & project structure

- **`context_path` module** — the hierarchy is **real and VTA-enforced** now
  (`vti-common::context_path`: `/`-separated paths, `MAX_CONTEXT_DEPTH = 8`,
  segment-aware ancestry, parent-admin-covers-subtree ACL — pure, store-free).
  The CLI module builds/validates sub-context paths from `(top_context_id, vtc)`
  (`child_path`, `validate_context_path`) and renders them for display; the
  **VTA is the enforcement source of truth** (it re-validates). **Reuse
  `vti-common`'s helpers if consumable, otherwise mirror them** (CLAUDE.md:
  prefer existing libs; raise re-exporting them from `vta-sdk` to avoid drift on
  the security-critical rules). `create_context` is unchanged — it already takes
  a path id, so **no `vta-sdk` API change is required**.
  - Proposed location: `openvtc-core/src/config/context_path.rs`.
- **Config types** — extend `openvtc-core/src/config/`:
  - New `account` / `Persona` / `Community` types; `personas` and `communities`
    collections. **No migration (D13):** detect a v1 `config_version`, warn +
    delete + reset (R-RST-*); do **not** write a v1→v2 migration path.
  - **VTA as store (D12):** personas hold VTA `key_refs`, not key material;
    keys/credentials are fetched from the VTA. Only the account admin credential
    is a local secret in `SecuredConfig`/keyring.
  - **Full refactor, no shim (D10):** the implicit singleton (`persona_did`,
    `key_backend`, single ATM profile) is replaced everywhere by an explicit
    **active-identity** abstraction — the *selected working community* (R-C-6/7)
    resolves to its persona via the registry rather than a single field.
    Core model change + `openvtc` consumer refactor land **together**.
  - Tier placement (§10.2): community + persona *metadata* in `ProtectedConfig`;
    admin credential in `SecuredConfig`/keyring.
- **Per-community main page (R-C-6/7)** — `MainPageState`
  (relationships/contacts/VRCs/messaging) becomes **scoped to the selected
  working community**; add active-community chrome (top-of-screen name +
  dropdown switcher) and a "no active community" state.
- **Setup state machine** — refactor `SetupPage` (`setup_sequence/mod.rs:26`)
  into **two entry points**: bootstrap (State A) and join (State B). Join is
  also invokable outside first-run (from the Communities page), so its steps
  must not assume an empty config. The existing **`MediatorAsk` /
  `MediatorCustom` steps relocate** into the new-persona mint sub-flow of State
  B as an *optional* override defaulting to the VTA mediator (D7); WebVH-server
  selection for DID hosting likewise lives only in that mint sub-flow.
- **UI** — new Communities overview page under `openvtc/src/ui/pages/`; new
  actions in the `Action` enum (`actions/mod.rs:186`) for join / leave / star /
  switch-community / archive / delete; state additions in `state.rs`
  (a `communities` view model + the selected working community).
- **Message loop → multi-session manager (D11, D15)** — replace the single ATM
  session / `connection.messaging_active` with a manager that runs **one
  supervised task per active community session, concurrently**. Each task has
  **independent retry/recovery** — a mediator outage on one community must not
  block or kill the others — and a bounded maximum number of concurrent sessions
  (no unbounded fan-out). Sessions come up at launch for all Active communities
  (partial-failure tolerant); join registers a session, leave/inactivation
  deregisters one. Aggregates inbound events to the UI and resolves pending join
  outcomes per session (R-B-7/8).
- **did-git-sign (D17)** — extend the `did-git-sign` crate to resolve the
  signing persona from an env var and/or per-repo git config against the
  account's personas (`R-G-*`); drop the single-persona assumption.

---

## 7. Code style & conventions
- Follow existing repo conventions; `cargo fmt` before every commit; DCO `-s`
  sign-off on all commits.
- **did:webvh:** always use `didwebvh-rs` APIs for DID⇄URL mapping (per
  `CLAUDE.md`); never hand-roll string manipulation.
- Prefer extending existing modules over new crates; reuse vta-sdk APIs rather
  than reimplementing protocol logic.
- Internal dep version pins use `major.minor`.

---

## 8. Explicitly deferred / out of scope (this spec)
- **D4 — Verifiable Presentation construction.** Join step 4 submits a
  **stub/placeholder VP**; real credential selection & presentation is a
  separate spec. The join flow, pending state, receipt handling, and persistence
  must be built so that dropping in real VP construction is a localized change.
- **VP requirement discovery** — how a VTC advertises which credentials its VP
  must contain (DID-doc service entry? discovery message? out-of-band?) is
  **undecided / infra-side** and blocks D4. Tracked as an open question (§10).
- *New* per-community capabilities beyond porting today's main page
  (relationships/contacts/VRCs/messaging) to the community scope. Persona key
  rotation (R-P-3).

---

## 9. Testing strategy
- **Config reset (R-RST-*):** unit tests that a v1 `config_version` is detected,
  the reset is gated on confirmation, and a fresh install skips the prompt.
- **`context_path`:** unit tests for build/parse/render round-trips and edge
  cases (slugging, collisions, no-name fallback).
- **State machine:** bootstrap (State A) never produces a persona DID; join
  (State B) runnable from a non-empty config; pending → active/rejected/expired
  transitions persist; referential integrity (R-P-1) enforced.
- **Multi-session manager (D11/D15):** unit tests with ≥2 simulated sessions —
  isolation (one failing session doesn't affect others), recovery/retry, bounded
  concurrency, register/deregister on join/leave.
- **Communities page:** view-model tests for sorting (favourites first), status
  + read-only rendering, actions-required counting, archive/delete.
- **Mock VTA/mediator harness (nice-to-have):** integration tests against a mock
  VTA/VTC (user to supply a mock VTA externally; the repo already has
  `affinidi-messaging-test-mediator` in dev-deps). Not required for v1.
- Full local CI gate before any PR: `cargo fmt --check`, `clippy -D warnings`,
  `test --workspace`, `doc -D warnings`, `cargo deny`.

---

## 10. Open questions

### Still open
1. **VP requirement discovery** (blocks D4) — where do a VTC's join requirements
   come from (DID-doc service entry? discovery message? out-of-band)? Deferred
   with D4; does not block this spec.

### Locked (proposed defaults — override anytime)
2. **Config tier placement** — `Community` records (vtc_did, sub_context_id,
   status, persona_ref, member_since, favourite, display_name) and `Persona`
   metadata (did, mediator_did, origin_context_id, created_at, label) live in
   **`ProtectedConfig`** (encrypted; membership is private). Persona **key
   material** stays in `SecuredConfig` / OS keyring. Favourites/stars persist
   here (R-C-4).
3. **"Actions required" trigger set (v1)** — exactly three, extensibly defined:
   (a) `Pending` awaiting a decision; (b) unacknowledged `Rejected`;
   (c) unacknowledged `Removed`. The indicator counts communities matching any
   trigger; the trigger set is a single predicate so new triggers are additive.
4. **Slug rule for `<top>/<slug-from-name>` (D9)** — lowercase the VTC display
   name; keep `[a-z0-9]` and `-`; collapse runs of other chars to a single `-`;
   trim leading/trailing `-`; cap at 32 chars. On collision within the top
   context, append `-2`, `-3`, … When the VTC DID doc has no usable name, fall
   back to a short stable token derived from the VTC DID via `didwebvh-rs`
   (no hand-rolled string surgery — per `CLAUDE.md`). The slug must be a valid
   **context identifier** (`vti-common::validate_identifier`) and the full
   `<top>/<slug>` path must satisfy `validate_context_path` (depth ≤ 8); the VTA
   re-validates server-side.

### Resolved (folded into decisions)
- ~~Backup/restore~~ → **D12**: the VTA is the store of persona DIDs/keys/
  credentials; local config is membership metadata + admin credential.
- ~~Forward/old-config compatibility~~ → **D13**: breaking reset (warn + delete
  + fresh setup), not migration.
- ~~Per-community main-page / navigation~~ → **D1 #1 / R-C-6/7**: existing main
  page becomes community-scoped with a top-of-screen switcher.
- ~~Inactive-community handling~~ → **D14**: read-only + Archive/Delete.
- ~~Concurrent-session runtime model~~ → **D11/D15**: concurrent supervised
  sessions, one isolated task per community.
- ~~Persona key derivation on reuse~~ → **D6**: personas are self-contained and
  context-independent; reuse presents the same DID/keys.
- ~~Slug vs hash vs label for sub-context id~~ → **D9**: slug-from-name.
- ~~Sub-context authorization (infra-side)~~ → **resolved by VTI #257**: the VTA
  enforces ancestry-aware ACL — admin of the top context automatically covers
  its subtree, so per-community sub-context creation is authorized. Hierarchy
  validation (depth, segments) is server-enforced.
- ~~Real hierarchical context API~~ → **shipped (VTI #257)**: contexts are
  `/`-separated paths; no `vta-sdk` change needed (path ids via `create_context`).
- ~~Mediator selection~~ → **D7**: defaults to the VTA mediator, optionally
  overridable per DID/persona at mint time.
