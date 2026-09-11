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
| [multi-community-support.md](./multi-community-support.md) | DRAFT v5 | Split setup into account bootstrap + per-community join; join multiple VTCs (concurrent live sessions); account-level personas; Communities overview page; VTA-as-store; breaking config reset. |
| [multi-community-presentation.html](./multi-community-presentation.html) | Deck | Visual before/after walkthrough of the multi-community design — Mermaid flows + TUI mockups. Open in a browser; `←`/`→` to navigate. |
| [vetting-process.md](./vetting-process.md) | DRAFT v2 | Vetted admission replacing the kernel PGP web of trust: VTC-advertised vetting requirements, vetter tickets, match-code sessions, signed Vetting Card (VDS), vetter-issued Vetting Statements (VEC), bundle-and-present admission with policy on both sides. |
| [t1-active-identity-api.md](./t1-active-identity-api.md) | For review | T1 foundation API sketch — config v2 model, `IdentityContext`/`IdentityRegistry`, persona-keyed session manager, consumer-refactor pattern, resolved forks. |
