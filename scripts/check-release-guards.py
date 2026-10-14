#!/usr/bin/env python3
"""Build-free guards that keep the release tooling's assumptions true.

    python3 scripts/check-release-guards.py [--base-sha SHA]

Run by the `release guards` job in ci.yml on every PR and push. Each guard is
a fact the release scripts (RELEASES.md) rely on and would otherwise discover
at the worst moment — mid-cut, or mid-publish:

  1. lockstep — every member inherits `version.workspace = true`, and every
     internal dependency requires exactly the workspace version
     (`{ version = "0.7.0", path = ... }`). `set_version` moves them together;
     a hand-edited one drifts, and a published crate then requires a sibling
     version that is never published.
  2. changelog — CHANGELOG.md exists at the root. On main it has an
     `## [Unreleased]` section (cut-release.py and the GA prep rename it). On a
     release branch at a GA or patch version it has that version's section,
     which release-tag.yml turns into the GitHub Release notes.
  3. RELEASE ↔ version — on a release branch, RELEASE's `major.minor.patch` is
     the workspace version, and a PR (with --base-sha) never moves RELEASE
     backwards. publish.yml refuses to publish when these disagree; this says
     so at review time instead.

Exit 1 with every problem listed; 0 when all hold.
"""

import argparse
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_lib import (  # noqa: E402
    ROOT,
    has_version_section,
    lockstep_problems,
    parse_release,
    workspace_version,
)


def git_show(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True, cwd=ROOT)
    return out.stdout if out.returncode == 0 else None


def release_problems(base_sha):
    problems = []
    version = workspace_version(ROOT)
    release_file = ROOT / "RELEASE"
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return ["CHANGELOG.md is missing at the repository root (the release tooling writes to it)"]
    text = changelog.read_text()

    if not release_file.exists():
        # main (or a feature branch off it).
        if not re.search(r"^## \[?Unreleased\]?", text, re.M):
            problems.append("CHANGELOG.md has no `## [Unreleased]` section (main always carries one)")
        return problems

    current = release_file.read_text().strip()
    major, minor, patch, rc = parse_release(current)
    if f"{major}.{minor}.{patch}" != version:
        problems.append(f"RELEASE is {current} but the workspace version is {version}")
    if rc is None and not has_version_section(text, current):
        problems.append(f"CHANGELOG.md has no `## [{current}]` section for the GA/patch RELEASE names")

    if base_sha:
        before = git_show(base_sha, "RELEASE")
        if before and before.strip() != current:
            b = parse_release(before)
            key = lambda t: (t[0], t[1], t[2], float("inf") if t[3] is None else t[3])  # noqa: E731
            if key((major, minor, patch, rc)) <= key(b):
                problems.append(f"RELEASE moves backwards: {before.strip()} -> {current}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-sha", help="the PR's base commit, to check RELEASE only moves forward")
    args = ap.parse_args()

    sections = [
        ("lockstep versions", lockstep_problems(ROOT)),
        ("changelog and RELEASE", release_problems(args.base_sha)),
    ]
    failed = False
    for name, problems in sections:
        if problems:
            failed = True
            print(f"FAIL  {name}:")
            for p in problems:
                print(f"        - {p}")
        else:
            print(f"ok    {name}")
    if failed:
        print("\nSee RELEASES.md. Versions are only ever moved by scripts/release_lib.py.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
