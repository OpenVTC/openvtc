# Design Documents

This folder holds design thinking for OpenVTC — specifications, architecture
decisions, and proposals — kept under version control so the *why* behind
changes is discoverable alongside the code.

## Conventions
- One document per feature/topic, kebab-case filename
  (e.g. `multi-community-support.md`).
- Each doc carries a **Status** line near the top: `DRAFT` → `ACCEPTED` →
  `IMPLEMENTED` (or `SUPERSEDED by …`).
- Specs use stable **requirement IDs** (e.g. `R-B-3`) so task breakdowns and
  PRs can reference them directly.

## Index

| Document | Status | Summary |
|----------|--------|---------|
| [multi-community-support.md](./multi-community-support.md) | IMPLEMENTED | Split setup into account bootstrap + per-community join; join multiple VTCs (concurrent live sessions); account-level personas; Communities overview page; VTA-as-store; breaking config reset. VP discovery (D4) is still open. |
| [multi-community-presentation.html](./multi-community-presentation.html) | Deck | Visual before/after walkthrough of the multi-community design — Mermaid flows + TUI mockups. Open in a browser; `←`/`→` to navigate. Loads `vendor/mermaid.min.js`. |
| [t1-active-identity-api.md](./t1-active-identity-api.md) | IMPLEMENTED | T1 foundation API sketch — config v2 model, `IdentityContext`/`IdentityRegistry`, persona-keyed session manager, consumer-refactor pattern, resolved forks. |
| [tui-architecture.md](./tui-architecture.md) | IMPLEMENTED | Map of the `openvtc` ratatui TUI: the data-flow loop, key handling vs. business logic, the `state_handler/` layout, the background-dispatch pattern, and "how do I…" recipes. |
| [vetting-process.md](./vetting-process.md) | DRAFT v3 | Vetted admission replacing the kernel PGP web of trust: VTC-advertised vetting requirements, vetter tickets, match-code sessions, signed Vetting Card (VDS), vetter-issued Vetting Statements (VEC), bundle-and-present admission with policy on both sides. |
| [vetting-hidden-vetters-pcs.md](./vetting-hidden-vetters-pcs.md) | DRAFT (research and integration proposal) | k-of-n hidden-vetter admission using the Predicate Credential System. The engine has since moved into the VTA (`vta/pcs/*`). |
| [hidden-vetting-live-run.md](./hidden-vetting-live-run.md) | Guide (no status line) | How to stand up a community that hides its vetters and take an applicant through it with the real client. |
| [vta-authoritative-state.md](./vta-authoritative-state.md) | DRAFT v6 | VTA-authoritative state and reinstall recovery: the VTA as the source of truth, and recovering an install from it. |
| [verifiable-trust-communities-presentation.html](./verifiable-trust-communities-presentation.html) | Deck | "From Credentials to Communities" — overview of the verifiable trust stack and the member journey. Open in a browser. |
