# Implementation Plan — Multi-Community Support

Source spec: [`docs/design/multi-community-support.md`](../../docs/design/multi-community-support.md) (DRAFT v2).
This plan slices that spec into dependency-ordered, independently shippable PRs.

> Companion: [`tasks/todo.md`](./todo.md) holds the live task checklist with
> acceptance criteria. This file holds the rationale, dependency graph, and
> checkpoints.

---

## 1. Guiding constraints

- **Each task is one shippable PR** that compiles, passes the full CI gate
  (`fmt`, `clippy -D warnings`, `test --workspace`, `doc -D warnings`,
  `cargo deny`), and leaves `main` releasable.
- **Vertical slices, not horizontal layers** — every task after the foundation
  delivers a complete user-observable path, not a dangling internal layer.
- **The app must be coherent and releasable after every PR.** The config
  refactor (T1) is the one unavoidable foundation. Per **D10** it is a *full*
  refactor with **no compatibility shim** (the singleton becomes an explicit
  active-identity abstraction); core model + `openvtc` consumer refactor land in
  one PR (the workspace won't build otherwise). Per **D13** there is **no
  migration** — an existing v1 config is detected and reset behind a confirmed
  warning, and a fresh bootstrap is the supported post-T1 path (pre-1.0).
- VP construction (D4) is **stubbed** throughout; the join path is built so real
  VP construction drops into one place later.

---

## 2. Component dependency graph

```
            ┌──────────────────────────────────┐
            │ T1  config v2 + BREAKING RESET +  │  (openvtc-core + openvtc)
            │     full refactor + community-    │  FOUNDATION — largest PR
            │     scoped main page + supervised │  (D10–D15)
            │     session mgr (N=1)             │
            └──────────────┬───────────────────┘
                           │
            ┌──────────────┴───────────────┐
            │ T2  context_path module (D9) │  (openvtc-core) — independent of T1
            └──────────────┬───────────────┘
                           │
            ┌──────────────▼───────────────┐
            │ T3  State A — bootstrap split │  (openvtc) — needs T1, T2
            └──────────────┬───────────────┘
                           │
            ┌──────────────▼─────────────────────┐
            │ T4  Communities page + switcher     │  (openvtc) — needs T1, T3
            └──────────────┬─────────────────────┘
                           │
            ┌──────────────▼───────────────┐
            │ T5  State B — join (stub VP)  │  (openvtc) — needs T1,T2,T3,T4
            └──────┬───────────┬────────┬───┘
                   │           │        │
        ┌──────────▼──┐  ┌─────▼─────┐  └─►┌────────────────────┐
        │ T6 lifecycle│  │ T7 leave  │     │ T9 mock harness     │
        │ /timeout/   │  │ /readonly/│     │ (nice-to-have)      │
        │ more-info   │  │ archive/  │     └────────────────────┘
        └─────────────┘  │ delete    │
                         └───────────┘

        ┌────────────────────────────────┐
        │ T8  did-git-sign persona select │  needs T1 only (parallelizable)
        └────────────────────────────────┘
```

T1 gates everything. T2 is independent and parallel with T1. T8 needs only T1.
T6, T7, T9 are independent of each other (all need T5).

---

## 3. Phases & checkpoints

### Phase 0 — Foundation (`openvtc-core` + `openvtc`)
**T1, T2.** Establishes the v2 data model, breaking-reset handling for old
configs, the active-identity abstraction, the community-scoped main page, the
supervised multi-session manager (running N=1), and the hierarchy-convention
module. (T8 — did-git-sign — also unblocks here but isn't on the critical path.)

> **CHECKPOINT 0** — A v1 config is detected and triggers the warn-and-reset
> path (gated on confirm); a fresh install boots to State A with empty
> collections. Messaging runs through the supervised session manager at N=1
> (unit-tested with ≥2 simulated sessions for isolation + recovery). The main
> page is community-scoped with a clean "no active community" state.
> `context_path` round-trips and slugs correctly. *Gate to Phase 1.*

### Phase 1 — Bootstrap (`openvtc`)
**T3.** Split the monolithic wizard; State A creates an account + top-level
context and persists v2 config with **no persona DID**. Mediator steps relocate
(D7). Landing lands on a minimal/placeholder Communities surface.

> **CHECKPOINT 1** — A fresh install bootstraps against a VTA and writes a v2
> config containing an `account` and zero personas/communities. No `did:webvh`
> is created. *Gate to Phase 2.*

### Phase 2 — Communities display (`openvtc`)
**T4.** The read/display path: overview page renders communities (verified with
fixtures), favourites toggle/sort/persist, empty state, actions-required badge.

> **CHECKPOINT 2** — From the post-bootstrap empty state the page guides the
> user to join; with seeded community fixtures the list renders status,
> member-since, persona, badges, and favourite ordering correctly. *Gate to
> Phase 3.*

### Phase 3 — Join & lifecycle (`openvtc`)
**T5** (join with stub VP), then **T6** (pending resolution) and **T7** (leave),
which may land in parallel.

> **CHECKPOINT 3** — End to end: from the Communities page a user joins a VTC by
> DID, choosing to mint or reuse a persona; the community appears with the
> receipt's status; a simulated inbound decision transitions Pending →
> Active/Rejected; leaving moves a community to Left. *Feature complete (minus
> deferred VP).*

---

## 4. Vertical-slice rationale (why this order)

- **T1 first** because every other task reads/writes config; deferring it would
  force throwaway scaffolding. Per D10 it is a full refactor (no shim) and per
  D13 old configs are reset rather than migrated — so there is neither a
  compatibility shim nor a migration path to unwind later. T1 deliberately
  carries the heavy structural changes (active-identity, community-scoped main
  page, supervised sessions) so later tasks are additive.
- **T2 early** because both bootstrap (top context) and join (sub-context) need
  it; isolating it first de-risks the D2→hierarchy migration later.
- **T4 before T5** because the display path can be built and tested against
  fixtures, so when join lands there is already a place for communities to
  appear — join becomes a thin vertical addition rather than UI + flow at once.
- **T6/T7 last** because they extend an existing, observable join.

---

## 5. Key risks & mitigations

| Risk | Mitigation |
|------|------------|
| Full config refactor (D10) is large — many read sites of `persona_did`, `key_backend`. | All consumers routed through one **active-identity abstraction**; landed as reviewable commits; grep-clean of removed fields is an acceptance gate; full CI must be green. A fresh single-persona bootstrap exercises every refactored path. |
| Old config handled wrong (lockout / silent loss). | **No migration (D13):** v1 is detected and reset behind an explicit user-confirmed warning; tests cover detect→warn→delete→fresh-setup and the new-install path. The VTA is the store (D12), so the durable material isn't in the deleted local config. |
| Concurrent live sessions (D11) are a large runtime change to today's single loop. | The multi-session manager is built in T1 running **N=1** (identical behavior, unit-tested with ≥2 simulated sessions); join/leave register/deregister sessions; real N>1 concurrency is first exercised by T5. Avoids a later loop rewrite ("right from the start"). |
| Context-path rules drift from the VTA's enforcement. | Hierarchy is VTA-enforced (VTI #257); `context_path` (T2) mirrors `vti-common::context_path` (reuse if consumable) and the VTA re-validates server-side. No `vta-sdk` change needed. |
| VTC join requirements unknown (VP). | D4 stubbed; T5 isolates the VP into a single function returning a placeholder. |
| Setup wizard refactor is large and entangled. | T3 splits entry points but reuses existing step handlers; bootstrap is a *subset* of today's flow (drops persona/mediator/webvh steps), not a rewrite. |

---

## 6. Deferred (tracked, not in this plan)
- **D4 / VP construction** and **VP requirement discovery** (spec §8, §10.1).
- Rich per-community detail UX beyond status/persona/leave (R-C-6 keeps the
  page extensible).

---

## 7. Per-PR definition of done
1. Satisfies its listed requirement IDs; acceptance criteria demonstrably met.
2. Unit/integration tests for the slice; no reduction in coverage of touched
   areas.
3. Full local CI gate green (see §1).
4. `cargo fmt`; DCO `-s` sign-off; `major.minor` pins for internal deps.
5. Branch off `main` after the prior PR merges (per repo workflow).
