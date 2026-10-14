#!/usr/bin/env python3
"""Enforce where a PR may go and what it may change (RELEASES.md).

Run by `.github/workflows/branch-rules.yml` on every PR into `main` or
`release/**`, against the PR's merge commit (HEAD^1 = base, HEAD = merged).

Into `release/<major.minor>`:
  1. Only a bot backport (`backport-<pr>-to-release/<name>`, opened by
     backport.yml), a prep PR (`release-prep/<name>/<version>`), or a PR
     labelled `release-direct` by a maintainer. A fix lands on main first.
  2. Only a prep PR changes the workspace version or `RELEASE`.

Into `main`:
  3. Only a cut PR (`release-cut/<name>`, from cut-release.py) changes the
     workspace version: main carries the next release's version, set at the cut.
  4. No PR adds a `RELEASE` file: it marks a release branch.

"The workspace version" is lockstep (scripts/release_lib.py): the root
`[workspace.package] version`, plus any member that sets a literal
`[package] version` instead of inheriting it. A base that has no workspace
version yet (the repository's bootstrap) has nothing to protect, so the
version rules don't apply to the PR that creates it.

Environment: BASE_REF, HEAD_REF, LABELS (JSON list of label names).
"""

import json
import os
import re
import subprocess
import sys
import tomllib


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def manifest(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    if out.returncode:
        return None
    try:
        return tomllib.loads(out.stdout)
    except tomllib.TOMLDecodeError:
        return None


def version_of(data, path):
    if data is None:
        return None
    if path == "Cargo.toml":
        return data.get("workspace", {}).get("package", {}).get("version")
    v = data.get("package", {}).get("version")
    if isinstance(v, dict):
        return "workspace" if v.get("workspace") else None
    return v


def main():
    base = os.environ["BASE_REF"]
    head = os.environ["HEAD_REF"]
    labels = set(json.loads(os.environ.get("LABELS") or "[]"))
    changed = git("diff", "--name-only", "HEAD^1", "HEAD").split()

    # A base with no `[workspace.package] version` has no workspace version to
    # protect: this is the PR that creates the workspace (the repository's
    # bootstrap), and it necessarily sets every crate's version. Once it lands,
    # every later PR is checked as normal.
    bootstrap = version_of(manifest("HEAD^1", "Cargo.toml"), "Cargo.toml") is None

    versions = []
    for path in ([] if bootstrap else changed):
        if path == "Cargo.toml" or path.endswith("/Cargo.toml"):
            before = version_of(manifest("HEAD^1", path), path)
            after = version_of(manifest("HEAD", path), path)
            if before and after and before != after:
                versions.append(f"{path}: {before} -> {after}")
    release_file = "RELEASE" in changed

    problems = []
    if base.startswith("release/"):
        name = base.removeprefix("release/")
        backport = re.fullmatch(rf"backport-\d+-to-release/{re.escape(name)}", head)
        prep = head.startswith(f"release-prep/{name}/")
        if not (backport or prep or "release-direct" in labels):
            problems.append(
                f"A change reaches {base} by backport, not directly. Open this PR against main "
                f"instead; once it merges, label it `backport {base}` and backport.yml opens the "
                f"cherry-pick here. If the code no longer exists on main, a maintainer adds the "
                f"`release-direct` label, and the description says why."
            )
        if not prep and (versions or release_file):
            what = versions + (["RELEASE"] if release_file else [])
            problems.append(
                f"Only the *Prepare a release* workflow changes versions or RELEASE on {base}. "
                "Revert: " + "; ".join(what)
            )
    elif base == "main":
        if versions and not head.startswith("release-cut/"):
            problems.append(
                "A PR never edits the workspace version: main carries the next release's "
                "version, set when a release is cut (RELEASES.md). Revert: " + "; ".join(versions)
            )
        if release_file:
            problems.append("RELEASE marks a release branch; it never belongs on main. Remove it.")

    if problems:
        print(f"Branch rules ({head} -> {base}), RELEASES.md:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}\n", file=sys.stderr)
        return 1
    print(f"{head} -> {base}: branch rules hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
