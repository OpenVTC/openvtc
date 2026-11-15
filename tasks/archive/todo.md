# Task List — Multi-Community Support

Live checklist. See [`tasks/plan.md`](./plan.md) for rationale, dependency
graph, and checkpoints; [`docs/design/multi-community-support.md`](../../docs/design/multi-community-support.md)
for the spec and requirement IDs.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## Phase 0 — Foundation (`openvtc-core`)

### [x] T1 (PRs #67–#80, #110, #111) — Config v2 model + breaking reset + **full consumer refactor** + **community-scoped main page** + **supervised multi-session manager**

> **AUDIT (2026-06-12):** An initial multi-community implementation already
> merged to `main` ahead of the remediation work — PRs **#65–#80** (#67 = "T1
> config v2 model + active-identity"; #69–#80 = join/lifecycle/UI; #79 = "one
> DIDComm listener per persona"). The remediation (R0–R27, #82–#109) then
> hardened that code. `main` is green. Per-criterion verdict vs the current
> DRAFT-v5 spec:
>
> | Criterion | Verdict | Evidence / Gap |
> |---|---|---|
> | R-RST-1..4 breaking reset | **DONE** | detect `public_config.rs:260`; warn+confirm `main.rs:168`; delete `delete_profile` `public_config.rs:203`; test `public_config.rs:353` |
> | D8 lifecycle states + needs-attention | **DONE** | `account.rs:105` enum; predicates `:125–169`; transitions `:354–432`; tests `:742` |
> | D12 VTA-as-store (key_refs, not material) | **DONE** | `KeyRef` `account.rs:62`; `key_refs` `:88`; admin cred in `SecuredConfig` |
> | R-P-1/2 referential integrity | **DONE** | `can_delete_persona` `account.rs:476`; enforced `join_flow.rs:128`; test `:784`. (No standalone delete-persona UI yet — fine, that's later.) |
> | D10 active-identity abstraction | **PARTIAL** | singleton fields removed + `Account` registry ✓, but `active_identity()` = first-in-BTreeMap heuristic (`mod.rs:356`); **no "selected working community" field in runtime `State`** (`state.rs:10`). |
> | R-C-6 community-scoped main page | **PARTIAL** | `NoActiveCommunity` state ✓ + zero-community chrome ✓, but main-page content (inbox/relationships/VRCs) is **global, not scoped** to a selected community; selecting a community doesn't change context. Depends on the D10 gap. |
> | D11/D15 supervised session manager | **MISSING** | per-persona listeners on a single `DIDCommService` exist (#79, `didcomm.rs:287`), but **no manager**: no register/deregister API, no bounded concurrency, no launch orchestration, **no ≥2-session isolation/recovery tests**. |
>
> **Remaining T1 work = the three interlocking runtime gaps** (deferred "Stage 5"
> in the original branch): (a) D10 selected-working-community in `State` +
> resolve active identity from it; (b) R-C-6 scope main-page content to it;
> (c) D11/D15 supervised multi-session manager (N=1) with register/deregister +
> bounded concurrency + isolation/recovery tests. (a)+(b) are coupled; (c) builds
> on them. Config-model half of T1 is fully delivered and need not be redone.
>
> **PR-1 (D10 + R-C-6) — OPEN as #110** (`t1-pr1-community-scope`): community-scoped
> main page via **attribution-filter** (chosen over physical-move after hitting a
> BIP32 `path_pointer` key-collision hazard). Runtime `Config.active_persona`
> drives `active_identity()`; `Relationship`/`Task` carry an `our_persona` tag;
> `sync_from_config` filters panels via `persona_in_scope`; `SetActiveCommunity`
> action + Enter-to-switch. Gated green + code-reviewed (1 MEDIUM fixed).
> **PR-2 (D11/D15) — OPEN as #111** (`t1-pr2-session-manager`): `SessionManager`
> wrapping the existing `DIDCommService` — persona-keyed sessions, register/
> deregister, bounded concurrency (logged, not silent), per-session status driving
> the global indicator, ≥2-session isolation/recovery/teardown tests. Gated green +
> code-reviewed (1 must-fix `AtCapacity` log fixed). **T1 complete** once #111
> merges (mid-session leave/reject→deregister deferred to T6/T7 as designed).
>
> **T1 COMPLETE — both PRs MERGED** (#110 `b0e103a`, #111 `b924a9d`). Next: T2
> `context_path` (already partly present — audit before building) then T3–T9.

- **Crate:** `openvtc-core` **and** `openvtc` (must land together — workspace
  won't build otherwise)
- **Satisfies:** R-RST-1..4 · R-P-1, R-P-2 · D1(#1), D6, D7, D8, D10, D11, D12,
  D13, D14, D15 · §4 model
- **Largest PR in the plan.** Organise as reviewable commits (core model →
  reset detection → active-identity abstraction → main-page scoping →
  supervised session manager → consumer migration).
- **Description:**
  - Add `Account`, `Persona`, `Community` types; `personas: Map<PersonaId,
    Persona>`, `communities: Map<VtcDid, Community>`.
  - `CommunityStatus` enum: `Pending { request_id }`, `Active`, `Left`,
    `Rejected`, `Removed`, `Expired` (D8); `favourite`, `archived`,
    `requested_at`; `member_since` set on Active.
  - **VTA as store (D12):** personas hold VTA `key_refs`, not key material;
    only the account admin credential is a local secret. Tier placement §10.2.
  - **Breaking reset, no migration (D13):** bump `CONFIG_VERSION` to 2; on load,
    detect a v1 config → warn the user it will be deleted → on confirm, delete
    config + keyring entries → run State A (R-RST-1..4). New install skips the
    prompt.
  - **Referential integrity (R-P-1/2):** `community.persona_ref` must resolve;
    block persona deletion while referenced.
  - **Active-identity abstraction (no shim, D10):** explicit persona registry +
    a **selected working community** in runtime `State`. **Refactor every
    consumer** of the singleton (`persona_did`, `key_backend`, single ATM
    profile) to resolve via the abstraction.
  - **Community-scoped main page (R-C-6, D1#1):** `MainPageState`
    (relationships/contacts/VRCs/messaging) operates on the selected working
    community; add a "no active community" state (zero communities).
  - **Supervised multi-session manager (D11, D15):** replace the single ATM
    session / `connection.messaging_active` with a manager running **one
    supervised task per active community session**, each independently
    recoverable (a mediator outage on one must not affect others), bounded max
    concurrency, partial-failure-tolerant launch. Built now at **N=1**; exposes
    register/deregister APIs for Phase 3.
- **Acceptance criteria:**
  - Workspace builds; full CI gate green. No reference to removed singleton
    fields remains (grep clean).
  - A v1 config triggers the warn-and-reset path (gated on confirm); a fresh
    install goes straight to State A with empty collections (R-RST-*).
  - Messaging runs through the supervised manager at N=1 with identical behavior;
    manager unit-tested with ≥2 simulated sessions for isolation + recovery +
    register/deregister.
  - Main page renders the selected community's context and a clean "no active
    community" state.
  - Persona deletion blocked while referenced (R-P-1).
- **Verification:** `cargo test --workspace`; manual: confirm an old config is
  detected and reset; confirm fresh bootstrap.
- **Depends on:** —

### [x] T2 (PR #112, squash `34bb558`) — `context_path` module (hierarchy convention)

> **AUDIT (2026-06-13):** The build/parse/render/slug surface already
> existed in `context_path.rs` (slugify, fallback_token, build_sub_context_id
> with collision suffix, parse_sub_context_id, render_for_display — wired into
> `mod.rs`, used by `join_flow.rs`). The **validation half** T2 requires was
> missing. `vti-common` is **not consumable** here (not a `vta-sdk` dep, not
> re-exported — only a doc-comment mention), so per spec §6 the rules are
> **mirrored** from the local canonical source
> (`verifiable-trust-infrastructure/vti-common/src/{context_path,identifier}.rs`):
> `validate_identifier` ([A-Za-z0-9._-], ≤64B), `validate_context_path`
> (non-empty, no leading/trailing/doubled `/`, ≤ MAX_CONTEXT_DEPTH=8 segments,
> every segment valid), `child_path`, + constants. `build_sub_context_id` now
> builds via `child_path` so every returned id satisfies the VTA's re-validated
> rules. The ancestry/ACL helper (`is_ancestor_or_self`) is **deliberately not
> mirrored** — authorization is VTA-enforced; a client copy would be dead code.
> No `vta-sdk` / dependency change (Cargo.lock untouched). Gate green:
> fmt/clippy(-D warnings)/test (default + `--no-default-features`) all pass;
> `cargo deny` unaffected (no dep change). 19 context_path unit tests pass.

- **Crate:** `openvtc-core`
- **Satisfies:** D2, D9 · spec §6, §10.4
- **Description:**
  - New module (proposed `openvtc-core/src/config/context_path.rs`): build a
    sub-context id `<top>/<slug-from-name>`, parse one back, render for display.
  - Slug rule (§10.4): lowercase; keep `[a-z0-9-]`; collapse other runs to `-`;
    trim; cap 32; collision suffix `-2`, `-3`, …; name-less fallback derives a
    stable token from the VTC DID via `didwebvh-rs` (no hand-rolled parsing).
    Each segment must be a valid context identifier and the full path satisfy
    `validate_context_path` (depth ≤ 8) — **mirror `vti-common::context_path`**
    (reuse if consumable; else replicate its rules to avoid drift).
  - **Hierarchy is VTA-enforced (VTI #257)** — the VTA validates depth/segments
    and ancestry ACL server-side; this module just builds/validates paths. **No
    `vta-sdk` change needed** (`create_context` already takes a path id).
- **Acceptance criteria:**
  - build/parse/render round-trip tests pass; slug + collision + fallback cases
    covered; paths satisfy the `vti-common` rules; no `format!`-style DID
    surgery (uses `didwebvh-rs`).
- **Verification:** `cargo test -p openvtc-core` (context_path unit tests).
- **Depends on:** — (parallelizable with T1)

> **CHECKPOINT 0** before Phase 1 (see plan §3).

---

## Phase 1 — Bootstrap (`openvtc`)

### [x] T3 (PR #113, squash `cde1dbc`) — State A: split wizard, account bootstrap (no persona DID)

> **AUDIT (2026-06-13):** The State-A/State-B split was already built under the
> pre-remediation "R-A-5" work. Verified against R-A-1..6:
> - **R-A-1** ✓ `main.rs:159–207`: existing config → `MainPageDeferred` (no
>   re-bootstrap); `ConfigNotFound` → wizard; v1 → breaking reset (R-RST).
> - **R-A-2/3** ✓ `VtaEnterDid → VtaAclInstructions → VtaProvisioning`;
>   `create_account` sets `top_context_id` from the VTA.
> - **R-A-4** ✓ Navigation (`navigation.rs:126`) routes `VtaAuthCompleted →
>   protection_entry()`, skipping DID-keys-export AND did-git-sign. **Note: the
>   todo "+ did-git-sign" wording is STALE — spec R-A-4 explicitly says
>   did-git-sign is NOT configured at bootstrap** (it selects a community persona;
>   none exists yet). Implementation already correct.
> - **R-A-5** ✓ `create_account` builds an account-only v2 config (empty
>   personas/communities, `active_persona: None`, empty `identities`/`key_info`,
>   no `did:webvh`/mediator). The persona-minting `SetupPage` variants are
>   `#[allow(dead_code)]`, earmarked for T5's join mint sub-flow.
> - **R-A-6** ✓ lands on `ActivePage::Main`, which already carries T1's
>   zero-community / "no active community" state — the empty placeholder until
>   T4 builds the dedicated Communities overview page.
>
> **Gap closed by this PR (the only real T3 work):** no test exercised the
> bootstrap output shape. Refactored `create_account` to split pure config
> construction (`build_state_a_config`, no disk/keyring I/O) from the `save`, and
> added 3 unit tests asserting the R-A-3/4/5 shape (account-only, no unlock code
> on plaintext, errors without admin credential). Also did the **Stage-5 cleanup**
> the split left pending: removed the dead monolithic `ConfigExtension::create`
> (superseded by `create_account` + `mint_persona_into`) and its now-unused
> `SetupFlow` import. Gate green (fmt/clippy -D/test default + `--no-default`);
> no dep change. Navigation split already covered by
> `navigation.rs` tests (`vta_auth_completed_routes_to_protection`).

- **Crate:** `openvtc` (uses `openvtc-core` from T1/T2)
- **Satisfies:** R-A-1, R-A-2, R-A-3, R-A-4, R-A-5, R-A-6 · D5, D7
- **Description:**
  - Refactor `SetupPage` (`setup_sequence/mod.rs:26`) into two entry points:
    bootstrap (State A) and join (State B, stubbed page for now). Join steps
    must not assume an empty config.
  - State A steps: enter VTA DID → resolve + ephemeral `did:key` →
    `vta_admin_rotated` → admin credential → `create_context` top-level context
    (persist `top_context_id`) → protection + did-git-sign → save v2 `account`.
  - **No** `did:webvh`, **no** mediator selection (relocate `MediatorAsk` /
    `MediatorCustom` to T5's mint sub-flow), no community at bootstrap.
  - On completion land on the Communities surface (empty placeholder until T4).
- **Acceptance criteria:**
  - Fresh install (no config) → bootstrap → v2 config with `account` set,
    `personas` and `communities` empty, no DID created (R-A-5).
  - Re-running with existing config does **not** re-bootstrap.
- **Verification:** `cargo test -p openvtc`; manual run of `openvtc setup`
  against a test VTA; inspect persisted config has no persona DID.
- **Depends on:** T1, T2

> **CHECKPOINT 1** before Phase 2.

---

## Phase 2 — Communities display (`openvtc`)

### [x] T4 (PR #114, squash `9be2bca`) — Communities overview page + active-community switcher

> **AUDIT (2026-06-13):** Most of T4 already landed in T1 (#110/#111): the
> Communities panel lists rows with status/member-since/persona/★/actions-required
> badge (R-C-1/2/3), the playful empty state + join entry (R-C-5), navigation,
> `SetActiveCommunity` Enter-to-switch (R-C-6), the favourites-first sort
> (`communities_for_display`), the `favourite`/`archived` model fields +
> `toggle_favourite()`, and the `NoActiveCommunity` chrome. R-S-2's display side
> (the `needs_attention` predicate + badge) is also done; the lifecycle
> transitions that raise it are T6, and archive/delete/leave are T7.
>
> **Genuine gaps this PR closes:**
> - **R-C-4 favourite toggle** — the field/sort/★ existed but nothing flipped it.
>   Added `Action::ToggleFavourite(usize)` + `f` key on the panel + a
>   config-mutating loop handler (`toggle_favourite()` → coalesced `mark_dirty` →
>   resync, with the highlight following the row as it re-sorts to the top).
> - **R-C-7a active community name** — added `MainMenuConfigState.community`,
>   resolved in `From<&Config>` from `active_persona` (kept in lockstep with the
>   selected working community), rendered top-left with a ▾ affordance.
> - **R-C-7b quick switcher (Ctrl+K)** — chosen UX: a global-hotkey centered
>   popup overlay listing Active communities. New `CommunitySwitcherState` on
>   `MainPageState`; actions `OpenCommunitySwitcher` / `CommunitySwitcherMove` /
>   `CommunitySwitcherSelect` / `CloseCommunitySwitcher`; global interception in
>   `handle_key_event` (overlay owns input while open; Ctrl+K opens it anywhere);
>   pure move/close in `handle_nav_action`, config-mutating open/select in the
>   loop; centered overlay render mirroring the token-touch popup.
>
> Tests: 4 key-handler tests (favourite `f`, Ctrl+K open, switcher nav/select/
> close) + nav-reducer tests (switcher move clamps / close; loop-local arms
> deferred). Gate green (fmt/clippy -D/test default + `--no-default`); no dep
> change. Header `.find()` map left to model-level + manual coverage (full
> `Config` has no `Default`; sort/filter already unit-tested in `account.rs`).

- **Crate:** `openvtc`
- **Satisfies:** R-C-1, R-C-2, R-C-3, R-C-4, R-C-5, R-C-6, R-C-7 · R-S-2
- **Description:**
  - New page under `openvtc/src/ui/pages/`; `communities` view model in
    `state.rs`; `Action` variants (`actions/mod.rs:186`) for star / open /
    join-nav / switch-community.
  - Row renders: display name (or VTC DID), status (all §5.6 states, read-only
    styling for inactive), member-since (Active), persona presented.
  - Actions-required badge + count via a single predicate (triggers: Pending,
    unacknowledged Rejected/Removed/Expired, "more info required" — §10.3).
  - Favourite toggle → sorts favourites first → persists (ProtectedConfig).
  - Empty-state: a **playful, welcoming message** nudging the user to go find a
    community to join (not a dry "no items") + the join entry point (R-C-5).
  - **Active-community chrome (R-C-7):** top-of-screen active community name +
    **dropdown switcher**; selecting an Active community sets the working
    context that the (community-scoped, from T1) main page renders.
  - Minimal but **extensible** detail view (status / persona / leave) (R-C-6).
- **Acceptance criteria:**
  - With seeded community fixtures, list renders correct status/member-since/
    persona/badges; favourites sort first and survive reload.
  - Empty state shown when no communities; offers join entry point.
  - Switching the active community via the dropdown updates the main-page
    working context; "no active community" handled.
- **Verification:** `cargo test -p openvtc` (view-model sort/render/badge-count
  + switch tests); manual render with fixtures.
- **Depends on:** T1, T3

> **CHECKPOINT 2** before Phase 3.

---

## Phase 3 — Join & lifecycle (`openvtc`)

### [x] T5 (PR-A #115 `ac4a0df` + PR-B #116 `6af6ce5`, both MERGED) — State B: join a community (stubbed VP)

> **AUDIT (2026-06-13):** The join flow (`join_flow.rs`, `ActivePage::Join`) was
> already built in T1: enter VTC DID → mint persona → sub-context (`build_sub_context_id`,
> T2) → submit `join-requests/submit` with a **stub VP isolated to one call site**
> → persist `Pending`. Verdicts: R-B-1 entry ✓, R-B-4 sub-context/VP/mediator-default ✓,
> R-B-6 submit+receipt→status ✓, R-B-9 duplicate/re-join ✓ (all tested). **Gaps:**
> R-B-3 identity choice (flow always minted) and R-B-5 session registration
> (new session not registered → async receipt needs a restart). Deferred (not in
> acceptance criteria; spec marks optional): R-B-2 display-name capture (stays
> deterministic None) and the R-B-4 mediator *override* step. Split into 2 PRs
> (user decision), mirroring T1's #110/#111.
>
> **PR-A (R-B-3 identity choice) — branch `t5-pr1-identity-choice`:** new
> `JoinPage::IdentityChoice` between EnterDid and Progress, listing existing
> personas (reuse) + a "mint new" row; reuse arms a cross-community **linkage
> warning** (lists the communities already using that persona) requiring y/n
> confirm (D1). `run_join_sequence` now takes a `JoinIdentityChoice` (Mint |
> Reuse): reuse skips the mint and references the existing persona (inheriting its
> mediator), and is **never rolled back** (only minted personas are). Duplicate
> check moved to submit-time (before the choice). Actions: `JoinIdentitySelect` /
> `JoinIdentityChoose` / `JoinReuseConfirm` / `JoinReuseCancel`. Tests: identity-page
> key routing (4) + `mint_row` helpers. Gate green; no dep change.
> **PR-B (R-B-5 session registration) — DONE, branch `t5-pr2-session-register`.**
> `join_flow` now returns `JoinExit::Returned(Option<JoinedSession>)` (persona_id +
> did + vtc) on success. The **runtime-loop** StartJoin handler calls
> `register_joined_session`: `SessionManager::register` → `Created` builds the
> persona's listener (new `didcomm::persona_listener_config_for`) and
> `service.add_listener` (returns promptly; the `ListenerEvent::Connected` handler
> flips status to Connected — no 30s block); `JoinedExisting` shares the reused
> persona's live session (D1); `AtCapacity` logs (no silent cap, D15). The
> **degraded-loop** first join still registers via its existing `Joined`→restart
> path (startup `IdentityRegistry` registration), so PR-B only touches the runtime
> loop. Session-count/isolation semantics already covered by `session_manager`
> tests; added a `joined_session` extraction test. No dep change; gate green.
> **T5 COMPLETE once PR-B merges.**

- **Crate:** `openvtc`
- **Satisfies:** R-B-1, R-B-2, R-B-3, R-B-4, R-B-5, R-B-6, R-B-9 · D1, D3, D4, D6, D7, D16
- **Description:**
  - Join entry from Communities page (and immediately post-bootstrap).
  - Enter VTC DID → resolve → capture display name from DID doc.
  - Identity choice (D1/D6): reuse an existing persona (list) or mint a new one;
    reuse shows the cross-community linkage warning.
  - Mint sub-flow: WebVH-server select + create `did:webvh`; **optional**
    mediator override defaulting to the VTA mediator (D7).
  - Create sub-context via `context_path` (T2).
  - Submit `join-requests/submit` with a **stub/placeholder VP** isolated in one
    function (D4); persist `Community` with status from the receipt
    (`Pending{request_id}` or `Active`).
  - **Register a live session** for the new community/persona with the
    multi-session manager (D11) so it becomes concurrently active.
  - Duplicate `vtc_did` detected and surfaced; re-join of `Left` allowed (R-B-7).
- **Acceptance criteria:**
  - Join → community persisted and visible on the overview page with the
    receipt's status and the chosen persona.
  - Mint path creates exactly one new persona + sub-context; reuse path creates
    none and references the existing persona.
  - **Joining a second community brings up a concurrent live session without
    disrupting the first** (D11).
  - VP construction confined to one stub function (grep shows a single call site).
- **Verification:** `cargo test -p openvtc`; manual join against a test VTC;
  confirm config + overview reflect it.
- **Depends on:** T1, T2, T3, T4

### [x] T6 (PR #117, squash `f8250cd`) — Lifecycle: pending resolution, timeout, more-info

> **AUDIT + BUILD (2026-06-13):** The transition *methods* (`activate`/`reject`/
> `expire_if_stale`/`acknowledge`) + `expire_stale_pending`/`needs_attention` +
> `SessionManager::deregister` all existed and were tested, but were **unwired**:
> no inbound resolution beyond submit-receipt + VMC-activate, the timeout method
> was never called, no acknowledge action/UI, and inbound transitions never
> deregistered sessions (T1 explicitly deferred R-S-3 to T6/T7). Single PR (user
> decision). Protocol grounding: `join-requests/status-response` (`status:
> pending|deferred|approved|rejected|withdrawn`, correlated by `requestId`) is the
> resolution carrier; vta-sdk 0.11 has **no VTC→client "removed" push**, so
> Active→Removed is **deferred** (method kept) — noted for a future protocol type.
>
> **Built:**
> - **Inbound resolution (R-B-8):** `handle_join_status_response` (core/messaging) +
>   routed on `JOIN_REQUEST_STATUS_RESPONSE_TYPE` in `message_dispatch`. approved→
>   Active(+member_since), rejected→Rejected(+badge, inactivates), deferred→stays
>   Pending ("more info required", content = **D4 stub**), pending/withdrawn/unknown→
>   no-op. Anti-spoof (sender=community VTC) + request_id correlation.
> - **7-day timeout (R-B-7):** hourly `tokio::time::interval` arm in the runtime
>   loop (first tick immediate → expires on launch) → `expire_stale_pending` →
>   Expired + badge + deregister.
> - **Session deregistration (R-S-3):** `process_inbound_message` now threads an
>   `inactivated: &mut Vec<VtcDid>`; the loop calls the new
>   `deregister_inactive_community` helper (deregisters + tears the persona's
>   listener down when its last live community goes inactive; record retained R-S-1;
>   drops global indicator to NoActiveCommunity). The timeout sweep reuses it. (The
>   user-delete path keeps its own inline teardown — it deletes the record first.)
> - **Acknowledge (R-S-2):** `Action::AcknowledgeCommunity` + `a` key on the
>   Communities panel + loop handler (`acknowledge()` → mark_dirty → sync); panel
>   hint updated.
>
> Tests: 5 status-response handler tests (approved/rejected/deferred/mismatched-id/
> unknown-community) + `a`-key routing; transition/timeout/badge methods already
> covered in account.rs; session semantics in session_manager tests. No dep change;
> gate green (fmt/clippy -D/test default + `--no-default`).

- **Crate:** `openvtc`
- **Satisfies:** R-B-7, R-B-8, R-S-1, R-S-2, R-S-3 · D16
- **Description:**
  - In the multi-session manager (D11/D15), match an inbound message to its
    community session + `request_id`, transitioning Pending → Active / Rejected
    / Removed / "more info required"; persist; set member-since on Active; raise
    actions-required for Rejected/Removed/more-info until acknowledged (R-S-2).
  - **7-day client-side timeout (R-B-7):** an unanswered Pending → `Expired`
    (actions-required). "More info required" content handling is a stub until D4.
  - Inactivation **deregisters** the session (R-S-3); records retained (R-S-1).
- **Acceptance criteria:**
  - Simulated acceptance flips Pending → Active + member-since; rejection →
    Rejected + badge; a Pending older than 7 days → Expired + badge.
  - Acknowledging Rejected/Removed/Expired clears the badge; session deregistered
    on inactivation.
- **Verification:** `cargo test -p openvtc` (transition + timeout tests with
  simulated inbound + clock injection).
- **Depends on:** T5

### [x] T7 (PR #118, squash `de541bb`) — Leave + read-only + archive/delete

> **AUDIT + BUILD (2026-06-13):** Single PR (user decision). Leave was MISSING (no
> `MEMBER_SELF_REMOVE` send — `leave()` only set local state, and `d` silently
> leave-then-deleted an Active community); Archive was MISSING UI (`archive_community`
> existed); Delete was inactive-guarded but reachable on Active via the silent
> leave; read-only (D14) was already implied (working community can only be Active).
>
> **Built:**
> - **Leave (R-L-1):** `openvtc_core::join::submit_self_remove` (sends
>   `MEMBER_SELF_REMOVE`, mirrors `submit_join_request`). `Action::LeaveCommunity`
>   with a y/n confirm + `l` key (gated to Active rows). Handler sends via the
>   persona's ATM profile/mediator, then on **send success** sets `Left` +
>   deregisters the session (reuses T6's `deregister_inactive_community`) + saves;
>   the self-remove-receipt is advisory (user choice). Records retained read-only
>   (R-S-1).
> - **Delete fix (R-C-8):** removed `remove_community`'s silent `leave()`; delete is
>   now genuinely inactive-only (`d` key gated to inactive rows + `delete_community`
>   guard). Persona retained even if orphaned (R-P-2, already in core).
> - **Archive (R-C-8):** `Action::ArchiveCommunity` + `x` key (inactive rows) +
>   handler (`archive_community`, inactive-only). `Action::ToggleShowArchived` +
>   `v` key + handler so archived records stay discoverable (else invisible →
>   undeletable). Index→vtc mapping switched to `communities_for_display(show_archived)`
>   everywhere so the panel and handlers share one basis when archived is shown.
> - **Read-only (D14):** inactive rows dimmed + archived marker in the panel;
>   the working community can only ever be Active (SetActiveCommunity/reconcile
>   filter `is_active`), so inactive communities can't send/act by construction.
>
> Tests: 6 panel key-routing tests (leave/archive/delete status-gating, leave
> confirm commit/cancel, show-archived toggle) + nav-reducer (confirm-leave arms;
> Leave/Archive/ToggleShowArchived deferred to the loop). Archive/delete guards +
> `leave()` already covered in account.rs. No dep change; gate green
> (fmt/clippy -D/test default + `--no-default`).

- **Crate:** `openvtc`
- **Satisfies:** R-L-1 · R-C-8 · R-S-1, R-S-3 · D14
- **Description:**
  - Leave action → `MEMBER_SELF_REMOVE` → on success set `Left`, **deregister
    the session** (D15/R-S-3), retain record read-only.
  - **Read-only enforcement (D14):** inactive communities (Left / Rejected /
    Removed / Expired) cannot send/act; the working-context UI reflects this.
  - **Archive** (set `archived`, hide from default list) and **Delete** (purge
    local data, with confirmation) actions for inactive communities (R-C-8).
    Active communities require leaving before delete. Persona referential
    integrity respected on delete (R-P-1).
- **Acceptance criteria:**
  - Leaving an Active community → Left, session gone, record listed read-only;
    re-join allowed (cycles through Pending).
  - Archive hides from default list (still discoverable); Delete purges after
    confirm; deleting a community doesn't orphan a still-referenced persona.
- **Verification:** `cargo test -p openvtc`; manual leave → archive → delete →
  re-join.
- **Depends on:** T5

### [x] T8 (PR #119, squash `8cb3122`) — did-git-sign: select signing community persona

> **AUDIT + BUILD (2026-06-13):** `did-git-sign` is **standalone** — its own
> `SigningConfig { did_key_id }` + per-DID VTA creds in the keyring (keyed by
> `did:webvh:…#key-N`); it does **not** read the OpenVTC account (so no
> `openvtc-core` dep is needed — "resolved against the account's personas" =
> resolved against the per-persona keyring credentials each `init` stored). The
> single-persona assumption was: git invokes the signer with one fixed `-f
> <config>`. Selector form chosen (user): **by `did:webvh:…#key-N`** (not a label
> registry).
>
> **Built (sign.rs):** at sign time, resolve the effective signing key with
> precedence **env `DID_GIT_SIGN_KEY` > per-repo `git config did-git-sign.key` >
> the `-f` config's `did_key_id`** (R-G-1; pure `select_signing_key` +
> `KeySource`). When an override names a persona with **no keyring credentials**,
> bail with a clear message naming the persona + source (R-G-2) instead of
> silently signing as the config-file persona. No override → unchanged behaviour
> (back-compat). README documents the selector.
>
> Tests: `select_signing_key` precedence + blank/whitespace-ignored + trim, and
> `KeySource` messages name the origin. (The git-config read + keyring lookup are
> I/O, covered by manual verification.) No dep change; gate green
> (fmt/clippy -D/test default + `--no-default`).

- **Crate:** `did-git-sign`
- **Satisfies:** R-G-1, R-G-2 · D17
- **Description:**
  - Resolve the signing persona from an **env var** and/or **per-repo git
    config** against the account's personas; drop the single-persona assumption.
  - Fail clearly when no persona is selected/resolvable (no silent fallback).
- **Acceptance criteria:**
  - Signing uses the persona named by env var / git config; with multiple
    personas the correct one signs; unset/unresolvable → clear error.
- **Verification:** `cargo test -p did-git-sign`; manual sign in a repo with
  the git-config / env override set.
- **Depends on:** T1 (persona model) · independent of T3–T7 otherwise.

### [x] T9 (PR #120 part A + #121 part B + #122 mint) — MockVta integration harness

> **AUDIT + BUILD (2026-06-13):** Driving the **full** bootstrap→join→resolve
> against `vta-service`'s `MockVta` is blocked by infra-layer gaps: (1) MockVta
> serves a non-resolvable `did:key` sentinel over plain HTTP (vta-sdk's only URL
> fallback emits `https://`), (2) vta-sdk exposes no URL-direct `AdminRotated`
> provision (`run_connection_test`/`run_provision` re-resolve the DID; the only
> URL-taking primitive `provision_via_rest` is FullSetup-only), (3) `build_test_app`
> seeds no webvh server (join's DID-mint fails). All three are protocol/infra
> changes that belong in the VTI repo per CLAUDE.md — filed as
> **OpenVTC/verifiable-trust-infrastructure#406**.
>
> **Mediator-only slice delivered now (user decision):** join-request submission +
> lifecycle resolution are **pure DIDComm** (applicant ↔ VTC via a mediator, never
> the VTA), so the existing `affinidi-messaging-test-mediator` `MockMediator`
> harness drives them end-to-end. New `openvtc-core/tests/join_lifecycle_e2e.rs`
> (3 `#[ignore]`d tests, alice=persona / bob=VTC): **approval** (real
> `JoinRequestSubmitBody` over the wire → VTC deserialises → `approved`
> `JoinRequestStatusResponseBody` fed to the production `handle_join_status_response`
> reducer → Pending→Active + member_since, R-B-8); **rejection** (Pending→Rejected +
> deregister + badge, R-B-8/R-S-2/R-S-3); **self-remove round-trip** (real
> `SelfRemoveBody` → Left, R-L-1). Factored `init_test_tracing` +
> `start_profile_service` out of `relationship_e2e.rs` into `tests/common`.
>
> **Deferred to VTI#406:** the VTA-side half (State-A admin-rotation + webvh mint
> against MockVta) → so **no `vta-service` dep added** and **deny.toml unchanged**
> (the git-source / `cargo deny check sources` work waits on #406). Gate green
> (fmt/clippy -D/test --workspace); 3 ignored e2e tests pass over the mediator;
> `Cargo.lock` untouched. **T9 part A (mediator slice) — PR #120.**
>
> **PART B — full bootstrap e2e — PR #121 (`f58378b`, stacked on #120).** Same
> session the deferred half was unblocked: VTI closed the gaps in #426/#427 and
> **published vta-sdk 0.12.0** with `provision_admin_rotated_via_rest` + DI-signed
> REST auth + the `MockVta::start_provisionable` test-support seams. Part B bumps
> **vta-sdk 0.11→0.12** (crates.io; additive), adds the **production bootstrap
> seam** (`OPENVTC_VTA_URL` env → `handle_vta_submit_did` skips resolution +
> `handle_vta_start_provision` provisions URL-direct via
> `provision_admin_rotated_via_rest`; unset = unchanged; pure
> `normalize_url_override` unit-tested), and a `#[ignore]`d **MockVta bootstrap
> e2e** (`mockvta_bootstrap_e2e.rs`: URL-direct admin-rotation round-trip + create
> top context + seeded webvh server) against a real `MockVta::start_provisionable`.
> **`vta-service` added as a git dev-dep** (VTA server crate, not on crates.io),
> version-pinned, git source allow-listed in `deny.toml` — `cargo deny check`
> green (all four). The earlier "add a VTI ACL-seed seam first" choice was **moot**
> — the ACL seed works via the public `acl_ks.insert` API. **Deferred VTI
> follow-ups (non-blocking):** #429 (ergonomic MockVta ACL-authorize helper), #431
> (`create_did_webvh` round-trip / webvh hosting in MockVta → the persona
> `did:webvh` mint is the next layer). Gate green (fmt/clippy -D/test --workspace;
> ignored e2e ×8 over MockVta + mediator; cargo deny). **#120 + #121 MERGED**
> (`68c85a1`, `9ffe0ff`); main green.
>
> **PART C — persona did:webvh mint — PR #122 (`t9-persona-mint`).** VTI closed
> both follow-ups (#429 ergonomic ACL seam, #431 create_did_webvh via in-process
> stub webvh host); bumped the `vta-service` git dev-dep to the #433 tip (0.9.4).
> Adopted `MockVta::grant_super_admin` (drops the raw `acl_ks.insert` stopgap) and
> added `persona_did_webvh_mint_round_trips` (`#[ignore]`d): against
> `MockVta::start_with_webvh_host`, `create_did_webvh` mints a server-managed
> did:webvh persona (the State-B mint that previously 500'd). Harness now covers
> State-A bootstrap → State-B persona mint + mediator join/lifecycle. Gate green.
> **T9 fully delivered (incl. the persona mint) once #122 merges.**
- **Crate:** test-only — **`MockVta` now exists** (VTI #256, in the `vta-service`
  crate: `MockVta::start()` → `base_url()` → `shutdown()`).
- **Satisfies:** spec §9 testing
- **Description:**
  - Add `vta-service` as a **git dev-dependency** (VTI repo) and write
    integration tests that start a `MockVta`, point the CLI at `base_url()`, and
    exercise bootstrap (State A) → join (State B) → lifecycle.
  - **CI prerequisite:** add the VTI git URL to `deny.toml` `[sources].allow-git`
    (currently `[]` with `unknown-git = "deny"`), or `cargo deny check sources`
    fails.
- **Acceptance criteria:** end-to-end bootstrap→join→resolve runs against a live
  `MockVta` in CI or locally; `cargo deny` passes with the git source allowed.
- **Depends on:** T5 · promoted from nice-to-have now that MockVta exists.

> **CHECKPOINT 3** — feature complete (minus deferred VP). See plan §3.

---

## Deferred (not scheduled here)
- D4 VP construction + VP requirement discovery (spec §8, §10.1).
- *(Resolved — VTI #257)* hierarchical contexts + sub-context authorization are
  now VTA-enforced; `context_path` (T2) mirrors `vti-common::context_path`.
- *New* per-community capabilities beyond porting today's main page; persona
  key rotation (R-P-3).
