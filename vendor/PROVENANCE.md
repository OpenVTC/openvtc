# Vendored: `predicate-credential-system`

**Temporary.** This directory holds a copy of a third-party crate so that the `zkp-pcs`
development branch builds with no network source. It leaves again as soon as the crate is
published; see [Leaving](#leaving).

| | |
|---|---|
| Upstream | https://github.com/etairi/predicate-credential-system (Erkan Tairi) |
| Base commit | `aa57efd` ("Add serialization support"), fetched 2026-09-22 |
| Licence | MIT (`predicate-credential-system/LICENSE`), kept verbatim. Apache-2.0 for the rest of this repository is unaffected: MIT is permissive and on `deny.toml`'s allow list |
| Local change | `0001-pcs-application-contexts.patch`, already applied to the tree here |
| crates.io | Not published. The name was free on 2026-09-19 |

## Why it is here

The crate is a research artifact and is not on crates.io, so there is no registry to depend on.
`deny.toml` denies unknown git sources, and the local branch that carries our change has not been
pushed anywhere. Vendoring is therefore the only source that resolves for everyone who checks out
this branch, and it keeps `[patch.crates-io]` empty.

## The local change

`0001-pcs-application-contexts.patch` is `git format-patch` output of one commit on top of
`aa57efd`. It adds **application contexts** to the construction: `attest_in_context`,
`check_attestation_in_context`, `prove_in_context`, `check_proof_in_context` and
`issue_in_context`, with the `*_context_with_app` builders behind them.

- Without an application context every Fiat-Shamir context is byte-identical to the one the paper
  specifies, so nothing that exists changes. The trait of the ten algorithms is untouched.
- `ctx_0` binds each attestation's context as well, so a prover cannot check an attestation under
  one context and prove under another.
- Tests: 432 pass (426 upstream plus 6 new, for `Σ-PS`, `Σ-BBS` and `Σ-EQ`). `cargo fmt`,
  `cargo clippy --all-targets --all-features` and rustdoc are clean with `-D warnings`.

Design: `docs/design/vetting-hidden-vetters-pcs.md` §4.1. The patch is kept as a patch, rather
than folded into the vendored sources, so that it can be offered upstream unchanged.

## Rules while it is here

- **Do not edit `predicate-credential-system/` in place.** Change the patch, re-apply it to a
  clean `aa57efd` checkout, and re-vendor. Otherwise the two drift and neither can be upstreamed.
- Nothing outside `openvtc-vetting-pcs` may depend on it.
- It is not part of any release: the workspace is `publish = false`.

## Leaving

Any of these ends the vendoring, in order of preference:

1. The change is merged upstream and Erkan publishes to crates.io. Replace the path dependency
   with a version, delete this directory.
2. We publish a fork under an organisation we control. Replace the path dependency with a git
   dependency, and add the repository to `allow-git` in `deny.toml` **and** to
   `[patch.crates-io]` in the root `Cargo.toml` — `deny.toml` explains why the two are edited
   together.
3. The work is abandoned. Delete this directory and the `openvtc-vetting-pcs` crate.
