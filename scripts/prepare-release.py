#!/usr/bin/env python3
"""Prepare the next rc, GA or patch on a release branch (RELEASES.md).

    python3 scripts/prepare-release.py --kind rc|ga|patch [--pr-body FILE]

Run by `release-prep.yml` from a checkout of `release/<major.minor>`; it
edits the tree and the workflow commits it as a `chore(release): v…` PR on a
`release-prep/<major.minor>/<version>` branch. Merging that PR is the
release: `release-tag.yml` tags `v<RELEASE>` and opens its GitHub Release,
and `publish.yml` publishes the crates for a GA or patch.

  rc     0.7.0-rc.N  -> 0.7.0-rc.N+1    RELEASE only.
  ga     0.7.0-rc.N  -> 0.7.0           RELEASE; CHANGELOG `## [Unreleased]`
                                        becomes `## [0.7.0] - <date>`.
  patch  0.7.N       -> 0.7.N+1         the workspace version (lockstep: every
                                        crate and internal requirement);
                                        RELEASE; a CHANGELOG section listing
                                        the commits since the last tag.

A patch's entries come from the commit subjects since the previous tag, not
from cherry-picked CHANGELOG hunks: a backport's hunk lands in main's
`## [Unreleased]`, which does not exist on a GA'd branch, so resolve such a
conflict by dropping the hunk. Commit subjects are conventional, so they read
as entries.
"""

import argparse
import datetime
import sys

from release_lib import (
    ROOT,
    git,
    parse_release,
    set_version,
    unreleased_split,
    version_heading,
    workspace_version,
)


def commits_since(tag):
    if git("rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode:
        return None
    out = git("log", "--no-merges", "--format=%s", f"{tag}..HEAD").stdout.splitlines()
    return [s for s in out if not s.startswith("chore(release)")]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kind", required=True, choices=["rc", "ga", "patch"])
    ap.add_argument("--pr-body", help="write the PR description here")
    args = ap.parse_args()

    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    release_file = ROOT / "RELEASE"
    if not release_file.exists():
        sys.exit("no RELEASE file: run this on a release/<major.minor> branch")
    current = release_file.read_text().strip()
    major, minor, patch, rc = parse_release(current)
    if branch not in ("HEAD", f"release/{major}.{minor}"):
        sys.exit(f"RELEASE says {current}, but this is {branch}")
    crates = workspace_version(ROOT)
    if crates != f"{major}.{minor}.{patch}":
        sys.exit(f"RELEASE says {current} but the workspace is at {crates}; fix the branch first")

    today = datetime.date.today().isoformat()
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        sys.exit("no CHANGELOG.md at the repository root")
    text = changelog.read_text()
    since = commits_since(f"v{current}")

    if args.kind == "rc":
        if rc is None:
            sys.exit(f"{current} is GA; an rc comes before GA. Use `patch`.")
        target = f"{major}.{minor}.{patch}-rc.{rc + 1}"
    elif args.kind == "ga":
        if rc is None:
            sys.exit(f"{current} is already GA. Use `patch`.")
        target = f"{major}.{minor}.{patch}"
        parts = unreleased_split(text)
        if not parts:
            sys.exit("CHANGELOG.md has no `## [Unreleased]` section to release")
        before, body, after = parts
        changelog.write_text(f"{before}{version_heading(target, today)}\n{body}{after}")
    else:
        if rc is not None:
            sys.exit(f"{current} is a release candidate; use `rc` or `ga` first.")
        if since is None:
            sys.exit(f"tag v{current} is missing: did release-tag.yml run for it?")
        if not since:
            sys.exit(f"nothing has changed since v{current}")
        target = f"{major}.{minor}.{patch + 1}"
        set_version(ROOT, target)
        entries = "".join(f"- {s}\n" for s in since)
        heading = version_heading(target, today)
        parts = unreleased_split(text)
        if parts:
            # A backport brought its own `## [Unreleased]` notes: they are this patch's.
            before, body, after = parts
            text = f"{before}{heading}\n{body.rstrip()}\n\n### Commits\n\n{entries}\n{after}"
        else:
            head, sep, rest = text.partition("\n## ")
            text = (
                f"{head}\n{heading}\n\n{entries}{sep}{rest}"
                if sep
                else f"{text}\n{heading}\n\n{entries}"
            )
        changelog.write_text(text)

    release_file.write_text(f"{target}\n")
    print(f"{current} -> {target}")

    if args.pr_body:
        lines = [f"Prepares **v{target}** on `release/{major}.{minor}` (was `v{current}`).", ""]
        lines.append("Merging this PR is the release: `release-tag.yml` tags it and opens its GitHub Release.")
        if "-rc." not in target:
            lines.append("`publish.yml` then publishes every crate at this version to crates.io.")
        if since:
            lines += ["", f"Changes since `v{current}`:", ""] + [f"- {s}" for s in since]
        with open(args.pr_body, "w") as f:
            f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
