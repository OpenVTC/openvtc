# Releases

What people install is a **release**, named by its `major.minor` version
(`0.7`, `0.8`, …). It is cut from `nightly`, stabilised and patched on its own
branch for as long as it is supported, and published from there as crates on
crates.io (`openvtc`, `openvtc-core`), a tag and a GitHub Release. Patches
(`0.7.1`, `0.7.2`, …) only ever happen on the release branch.

This follows the branching model of verifiable-trust-infrastructure, the DID
hosting service (`affinidi-webvh-service`) and `affinidi-messaging-mediator`.
Every crate in the workspace carries the release's version (lockstep).

## Branches

```
feat/*, fix/*  ──PR──▶  main  ──(nightly.yml: last fully green commit)──▶  nightly
                                                                              │
                              release/0.7 ◀── cut ────────────────────────────┤
                              release/0.8 ◀── cut ────────────────────────────┘
```

| Branch | What it is | Written by |
|---|---|---|
| `main` | Active development. Every PR lands here first. Carries the *next* release's version (`0.8.0` once `release/0.7` is cut) and publishes nothing. | PRs |
| `nightly` | The newest `main` commit on which **every** CI job passed. Fast-forward only. Releases are cut from here, never from `main`'s tip. | `nightly.yml`, daily at 02:00 UTC |
| `release/<major.minor>` | One release, from its cut to its end of life. Takes backported fixes only. | Backport and prep PRs |
| `feat/*`, `fix/*`, … | Short-lived work (CONTRIBUTING.md). A large effort lands on `main` behind a feature flag, not on a long-lived branch. | Anyone |

## Versions and tags

The workspace is versioned in lockstep: `[workspace.package] version` in the
root `Cargo.toml` is the version of every crate (`version.workspace = true`),
and the internal dependency requires exactly that version
(`openvtc-core = { version = "0.7.0", path = … }`). Nobody edits either by
hand; `scripts/release_lib.py` moves them together, and the `release guards` CI
job fails a tree where they disagree.

On a release branch the current version is its `RELEASE` file; the tag is `v`
+ that. `RELEASE` exists on release branches only.

| Step | `RELEASE` | Tag / GitHub Release | Crates (crates.io) |
|---|---|---|---|
| **Cut** `release/0.7` from `nightly` | `0.7.0-rc.0` | `v0.7.0-rc.0` (prerelease) | set to `0.7.0`, not published |
| **Stabilise** — backport fixes; each prep is another candidate | `0.7.0-rc.1`, … | `v0.7.0-rc.1`, … (prerelease) | — |
| **GA** | `0.7.0` | `v0.7.0` | publish `0.7.0` |
| **Patch** as fixes are backported | `0.7.1`, `0.7.2`, … | `v0.7.1`, … | publish `0.7.N` |
| **EOL** — marked in the table below; the branch stays, read-only | — | — | — |

A release candidate is a GitHub prerelease and never "latest".

`main` never publishes and never edits the version: the cut moves it to the
next minor. A patch never changes a public API in a breaking way — the
`semver (patch-compatible)` CI job runs `cargo semver-checks --release-type
patch` on every PR into a release branch — and a fix that needs a break stays
on `main` for the next release.

CHANGELOG.md follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):
every PR adds its entry under `## [Unreleased]` on `main`; the cut and the GA
prep turn that section into `## [0.7.0] - <date>`, which `release-tag.yml`
uses as the GitHub Release notes.

Up to `0.6.x` releases were made from `main` by hand. `0.7.0` is the first
release from a release branch.

## Schedule

| Release | Branch | First RC | GA | Latest | Status |
|---|---|---|---|---|---|
| ≤ 0.6 | — | — | — | `0.6.0` | released from `main` by hand |
| 0.7 | — | TBD | TBD | — | in development on `main` |

## Support

The newest two GA releases (N and N-1) are supported. When a release goes GA,
the release before N-1 reaches end of life. "Supported" means fixes for
security problems and for defects that break joining, credentials or the
connection to a VTA are backported and released. Features never are.

## What goes on a release branch

**Fix on `main` first, then backport.** Label the merged PR
`backport release/<major.minor>` (one label per target branch); `backport.yml`
opens the cherry-pick as a PR on that branch, as a draft carrying the conflict
if it does not apply cleanly. A conflict in `CHANGELOG.md` is expected —
main's `## [Unreleased]` is not on a GA'd branch — drop that hunk: a patch's
changelog is generated from the commit subjects it ships.

Only fix on the release branch directly when the code there no longer exists on
`main`: a maintainer adds the `release-direct` label to that PR, and its
description says why.

The `branch rules` check (`scripts/check-branch-rules.py`) holds all of this: a
PR into `release/**` is a bot backport, a prep PR or labelled `release-direct`;
only the release tooling changes the version or `RELEASE`, on any branch.

## Procedures

The scripts need Python ≥ 3.11 (`tomllib`), cargo, and `gh` authenticated.

### Cut

```sh
python3 scripts/cut-release.py 0.7 --dry-run   # builds both commits, pushes nothing
python3 scripts/cut-release.py 0.7
```

From a clean checkout with push access. It pushes `release/0.7` (workspace at
`0.7.0`, `RELEASE` = `0.7.0-rc.0`, which `release-tag.yml` tags), creates the
`backport release/0.7` label, and opens the `release-cut/0.7` PR that moves
`main` to `0.8.0` and closes `main`'s `## [Unreleased]` changelog section under
`## [0.7.0]`. Merge it, then update the schedule table above.

`--from <rev>` cuts from something other than `origin/nightly` — the first cut,
before `nightly` exists, is `--from origin/main` (or run `nightly.yml` by hand
first).

### Release candidate, GA, patch

Actions → **Prepare a release** → choose the release branch as the ref and
`rc`, `ga` or `patch`. It moves `RELEASE`, writes the changelog (GA: the
`## [Unreleased]` section becomes `## [0.7.0] - <date>`; patch: a new section
listing the commits since the last tag), moves the whole workspace for a
patch, and opens a `chore(release): v…` PR from
`release-prep/<major.minor>/<version>`.

**Merging it is the release.** On that push to the release branch:

- `release-tag.yml` tags `v<RELEASE>` and opens the GitHub Release (notes =
  that version's changelog section; an rc is a prerelease).
- `publish.yml` publishes the crates for a GA or patch (below).

### Publish (crates.io)

Automatic, by `publish.yml`, on every push to `release/**`. It publishes only
when `RELEASE` is a GA/patch version equal to the workspace version, and only
the crates whose version is not on crates.io yet — so it is a no-op on every
other push, and re-running it after a failure resumes from the first missing
crate. Order is dependency order from `cargo metadata` (`openvtc-core`, then
`openvtc`):

```sh
python3 .github/scripts/publish-crates.py plan
```

It authenticates with **crates.io Trusted Publishing only** — no registry token
is stored anywhere. Each crate is verify-built first (`cargo package`), then a
fresh 30-minute token is minted for its upload alone, so a long release never
outlives its token; a failed upload is retried with a new token.

**A new crate** cannot be published this way: Trusted Publishing can only
publish to a crate that already exists and names this workflow as a trusted
publisher. `publish.yml` stops with an explanation. To add a crate:

1. An owner publishes its first version by hand:
   `git switch --detach v<version> && cargo publish -p <crate>`.
2. On crates.io → the crate → Settings → Trusted Publishing, add GitHub
   repository `OpenVTC/openvtc`, workflow `publish.yml`, environment
   `release`.
3. Re-run `publish.yml` on the release branch for anything that waited on it.

### End of life

Set the status in the table. Nothing is deleted: the branch, its tags and its
crates stay.

## Repository settings this relies on

Settings, not files:

- **Ruleset on `release/**`:** require a PR, require the CI jobs and `branch
  rules`, block force pushes and deletion.
- **Ruleset on `main`:** require a PR, and require `branch rules`.
- **Ruleset on `nightly`:** block force pushes and deletion; only the
  workflow's identity may update it.
- **Environment `release`** — `publish.yml` runs in it; restrict it to
  `release/*` branches. Each crate's Trusted Publisher on crates.io
  (`openvtc`, `openvtc-core`) names this repository, `publish.yml` and this
  environment.
- **`RELEASE_TOKEN`** (required for backports and preps) — a fine-grained PAT
  or GitHub App token on this repository with contents and pull-requests
  write and actions read. A PR opened with `GITHUB_TOKEN` triggers no
  workflows, so a backport or prep PR opened with it could never pass CI.
  `nightly.yml`, `release-tag.yml` and `publish.yml` need no secret.
