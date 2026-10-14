# OpenVTC — Project Guidelines

## Project overview

OpenVTC (Open Verifiable Trust Communities) is a reference implementation
on top of the verifiable trust infrastructure. This repository hosts:

- `openvtc` — the CLI (ratatui TUI). Primary user-facing tool.
- `openvtc-core` — shared library code used by the CLI.
- `did-git-sign` — standalone DID-based git commit signing proxy.

The heavy lifting of the verifiable trust infrastructure (VTA, key
management, credential protocols, DIDComm services) lives in a separate
repository:

  https://github.com/OpenVTC/verifiable-trust-infrastructure

When something needs changing at the protocol or infrastructure layer,
that repo is usually the correct target — not this one. This repo should
stay focused on the CLI / UX / configuration surface.

## did:webvh interactions

When working with `did:webvh` identifiers, **always use the `didwebvh-rs`
library's APIs** for any DID ⇄ URL mapping, parsing, or formatting. Do not
hand-roll string manipulation for these conversions.

The library already provides:

- `didwebvh_rs::url::WebVHURL::parse_url(&url::Url)` — convert an HTTP URL
  into a `WebVHURL` (handles scheme/host/port/path correctly).
- `WebVHURL::parse_did_url(&str)` — parse a `did:webvh:...` string.
- `WebVHURL::to_did_base()` — emit the canonical `did:webvh:{SCID}:…` form
  with colon-separated path segments and `%3A`-encoded ports.
- `WebVHURL::get_http_url(...)`, `get_http_whois_url()`, `get_http_files_url()`
  — derive resolvable HTTP URLs from a DID.

Hand-rolling these conversions has already caused one bug: a manual
`format!("{host}{path}")` left a URL path slash inside the DID
(`did:webvh:{SCID}:r2.ic3.dev/vincent`) where the spec requires a colon,
producing a DID that resolved to the wrong URL. See
`openvtc-core/src/config/did.rs::normalize_webvh_url` for the canonical
entry point that now delegates to the library.

If the library appears to be missing a capability, prefer opening an issue
or extending the library over reimplementing it locally.

## Agent names (DID shortcuts)

An **agent name** is a human-memorable shortcut that resolves to a DID —
a URL whose path begins with `/@` (`example.com/@alice`). OpenVTC consumes
them; `openvtc-core/src/agent_name.rs` is the single entry point.

Rules, all enforced there:

- **Always use the `agent-names` crate** for parsing, canonicalisation, and
  `alsoKnownAs` matching — never hand-roll them. Canonicalisation is
  unspecified by the spec, so two implementations that normalise differently
  disagree about whether a name verifies. Same discipline as the `didwebvh-rs`
  rule above.
- **Never display an unverified name.** A name is shown only after a full
  round-trip: it forward-resolves (`DIDCacheClient::resolve_any`, which does the
  mandatory `alsoKnownAs` check) *and* lands back on the DID being labelled.
  `agent_name::verified_agent_name` is the gate; an unverified claim renders as
  the plain DID. Displaying a name straight from a document's `alsoKnownAs`
  would turn the TUI into a phishing surface — anyone can claim
  `bigbank.com/@support` in their own document.
- **Never persist a name in place of a DID.** A name is a mutable web redirect;
  storing one would let a redirect silently repoint a saved identity. On input,
  `agent_name::resolve_identifier` turns a name into a DID and the DID is what
  gets persisted.

Resolution needs the resolver's `agent-names` feature, enabled via the direct
`affinidi-did-resolver-cache-sdk` dependency in the root `Cargo.toml`. The
management side (claiming / parking / resuming a name for your own persona) goes
through the VTA's `did-management/agent-name` Trust Tasks — see
`tasks/follow-ups.md`.

## Cross-service networking & integration discipline

OpenVTC tooling drives the live VTA/VTC/webvh services over the network, so
it inherits the ecosystem's integration rules. Read the doc set in
`../design-docs/` before adding or changing any service call:

- **`vti-stack-development-guide.md`** — binding rules; paste its pre-merge
  checklist into PRs. Most relevant to a CLI/tooling repo: **R1.2** (every
  outbound client has finite timeouts — a hung service must produce an error,
  not a hung command), **R1.4** (polling loops are bounded and backed off),
  **R6.4** (error text must let the operator tell network-unreachable from
  auth-rejected from contract-mismatch — never one fixed hint for all
  failures), and **R3.6** (verify endpoint paths/shapes against the current
  services rather than assuming they haven't moved).
- **`vti-networking-remediation-plan.md`** — the confirmed-defect backlog
  across the ecosystem; check it before debugging an integration failure —
  the cause may already be catalogued.
- **`vti-architectural-direction.md`** — design-level rationale.

## Releases

Lockstep versioning: both crates carry `[workspace.package] version`, and the
`openvtc-core` dependency requires it exactly. Never bump a version by hand —
`scripts/release_lib.py` / `scripts/prepare-release.py` own them, and
`scripts/check-branch-rules.py` rejects a PR that edits one. Flow is main →
nightly → `release/X.Y`; fixes land on `main` and are backported with a
`backport release/X.Y` label. See `RELEASES.md`. Publishing is crates.io
Trusted Publishing from `publish.yml` only.
